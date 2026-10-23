# SPDX-License-Identifier: Apache-2.0
"""spec 1.2.6 用户态节点面（M02 §4.1）：GET /api/v1/user/nodes 与 POST .../unbind。

覆盖：成功 / 未认证 / 越权或不存在 / 边界 / 幂等（任务验收要求）。

隔离：沿用 ``tests/supply`` 的 ``api`` fixture（``router._connection`` 指向隔离 schema、
时钟钉死 NOW）；每个用例用独立账户造自己的节点，不共享断言数据。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.supply import errors, models
from supplykit import connect, seed_account

#: 与 ``tests/supply/conftest.py`` 的固定时钟一致（UTC 零点）
NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)
BASE = "/api/v1/user/nodes"


# --------------------------------------------------------------------------- 夹具
@pytest.fixture
def user_auth(api):
    """注入用方鉴权（合并时由 Lead 接 M01）：账户来自头，step-up 显式给。"""
    from app.supply import router as router_module

    def _authenticator(request):
        account = request.headers.get("X-User-Account")
        if not account:
            return None
        return {"account_id": account,
                "step_up": request.headers.get("X-User-Step-Up") == "1"}

    router_module.set_user_authenticator(_authenticator)
    try:
        yield
    finally:
        router_module.set_user_authenticator(None)


def _headers(account, *, step_up: bool = False, **extra: str) -> dict[str, str]:
    headers = {"X-User-Account": str(account)}
    if step_up:
        headers["X-User-Step-Up"] = "1"
    headers.update({key: value for key, value in extra.items() if value})
    return headers


def _error(response) -> dict:
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert {"type", "code", "message", "request_id"} <= set(error)
    assert isinstance(error["code"], int)
    return error


def _node(schema: str, *, account_id=None, state: str = "active",
          last_seen=NOW) -> tuple[str, str]:
    """造节点：注册 → 审核通过 →（可选）绑定 → 摆到指定生命周期 / 心跳时间。

    返回 ``(node_id, client_key)``；client_key 是注册时的一次性明文（用于验证解绑后失效）。
    """
    with connect(schema, autocommit=False) as c:
        result = models.register(c, platform="linux",
                                 hardware_fingerprint=f"fp-w3-{uuid.uuid4().hex}",
                                 client_version="1.4.0", protocol_version="1.0.0",
                                 capabilities=["capacity_announcement"], access_modes=["A1"],
                                 now=NOW, trace_id="t")
        node = models.review(c, node_id=result.node.id, decision="approve", reason="测试准入",
                             actor="admin-1", now=NOW, trace_id="t")
        if account_id is not None:
            code = models.issue_binding_code(c, node_id=node.id, account_id=account_id, now=NOW)
            _, node = models.bind(c, node_id=node.id, code=code.code, now=NOW, trace_id="t")
        with c.cursor() as cur:
            cur.execute("UPDATE nodes SET last_seen_at = %s WHERE id = %s",
                        (last_seen, node.id))
            if state in ("pending", "frozen"):
                cur.execute("UPDATE nodes SET state = %s WHERE id = %s", (state, node.id))
            elif state == "retired":
                cur.execute("UPDATE nodes SET state = 'retired', retired_at = %s "
                            "WHERE id = %s", (NOW, node.id))
        return node.id, result.client_key


def _owned_without_binding(schema: str, account_id) -> str:
    """存量口径：account_id 有值但 bound_account_id 为空 → 绑定视图 unbound。"""
    node_id, _key = _node(schema)
    with connect(schema, autocommit=False) as c:
        c.execute("UPDATE nodes SET account_id = %s, tenant_id = %s WHERE id = %s",
                  (account_id, account_id, node_id))
    return node_id


def _revoke_directly(schema: str, node_id: str) -> None:
    with connect(schema, autocommit=False) as c:
        c.execute("UPDATE nodes SET revoked_at = %s WHERE id = %s", (NOW, node_id))


def _events(schema: str, node_id: str, kind: str) -> list[tuple]:
    with connect(schema) as c:
        return list(c.execute(
            "SELECT kind, from_state, to_state, reason_code, reason, actor FROM node_events "
            "WHERE node_id = %s AND kind = %s ORDER BY seq", (node_id, kind)).fetchall())


def _row(schema: str, node_id: str) -> dict:
    with connect(schema) as c:
        cur = c.execute("SELECT account_id, bound_account_id, bound_at, revoked_at, "
                        "key_revoked_at FROM nodes WHERE id = %s", (node_id,))
        row = cur.fetchone()
        names = [item.name for item in cur.description]
    return dict(zip(names, row))


# --------------------------------------------------------------------------- 未认证
def test_requires_user_auth(api):
    response = api.get(BASE)                                  # 钩子未接线 → fail-closed
    assert response.status_code == 401
    assert _error(response)["code"] == 40101
    assert response.headers["X-Request-Id"]


def test_unauthenticated_unbind_is_401(api):
    response = api.post(f"{BASE}/n_missing/unbind", json={})
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_auth_hook_without_account_is_rejected(api, user_auth):   # noqa: ARG001
    response = api.get(BASE)
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


# --------------------------------------------------------------------------- 列表：映射
def test_list_state_mapping_and_ownership(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    active_id, _ = _node(schema, account_id=api_account)
    frozen_id, _ = _node(schema, account_id=api_account, state="frozen")
    retired_id, _ = _node(schema, account_id=api_account, state="retired")
    revoked_id, _ = _node(schema, account_id=api_account)
    _revoke_directly(schema, revoked_id)
    unbound_id = _owned_without_binding(schema, api_account)
    pending_id, _ = _node(schema, account_id=api_account, state="pending")
    other_id, _ = _node(schema, account_id=seed_account(schema))

    response = api.get(BASE, headers=_headers(api_account))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) >= {"data", "page"}
    node_map = {item["node_id"]: item for item in payload["data"]}

    assert node_map[active_id]["state"] == "bound"
    assert node_map[active_id]["lifecycle_state"] == "active"
    assert node_map[active_id]["restricted"] is False
    assert node_map[active_id]["last_seen"].endswith("Z")
    assert node_map[active_id]["applied_version"] is None
    assert node_map[active_id]["pending_reason"] is None

    assert node_map[frozen_id]["state"] == "bound"
    assert node_map[frozen_id]["restricted"] is True
    assert node_map[frozen_id]["lifecycle_state"] == "frozen"

    assert node_map[retired_id]["state"] == "revoked"
    assert node_map[retired_id]["lifecycle_state"] == "retired"

    assert node_map[revoked_id]["state"] == "revoked"
    assert node_map[revoked_id]["unbound_at"].endswith("Z")

    assert node_map[unbound_id]["state"] == "unbound"
    assert node_map[unbound_id]["lifecycle_state"] == "active"

    assert node_map[pending_id]["state"] == "pending_receipt"
    assert node_map[pending_id]["lifecycle_state"] == "pending"
    assert node_map[pending_id]["pending_reason"] == "awaiting_receipt"

    assert other_id not in node_map                            # 只返回本账户节点


def test_list_filters_and_bounds(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    _node(schema, account_id=api_account)
    _node(schema, account_id=api_account, state="frozen")

    bound = api.get(BASE, params={"state": "bound"}, headers=_headers(api_account))
    assert bound.status_code == 200
    assert {item["state"] for item in bound.json()["data"]} == {"bound"}
    assert len(bound.json()["data"]) == 2

    frozen = api.get(BASE, params={"lifecycle_state": "frozen"},
                     headers=_headers(api_account))
    assert frozen.status_code == 200 and len(frozen.json()["data"]) == 1

    revoked = api.get(BASE, params={"state": "revoked"}, headers=_headers(api_account))
    assert revoked.status_code == 200 and revoked.json()["data"] == []

    for params in ({"state": "bogus"}, {"lifecycle_state": "bogus"}):
        bad = api.get(BASE, params=params, headers=_headers(api_account))
        assert bad.status_code == 400
        assert _error(bad)["code"] == 40001


# --------------------------------------------------------------------------- 列表：分页
def test_list_pagination_is_cursor_based(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    newest, _ = _node(schema, account_id=api_account, last_seen=NOW)
    middle, _ = _node(schema, account_id=api_account, last_seen=NOW - timedelta(hours=1))
    oldest, _ = _node(schema, account_id=api_account, last_seen=NOW - timedelta(hours=2))
    never, _ = _node(schema, account_id=api_account, last_seen=None)

    first = api.get(BASE, params={"limit": 2}, headers=_headers(api_account))
    assert first.status_code == 200
    page1 = first.json()
    assert [item["node_id"] for item in page1["data"]] == [newest, middle]
    assert page1["page"]["has_more"] is True
    assert page1["page"]["next_cursor"]

    second = api.get(BASE, params={"limit": 2, "cursor": page1["page"]["next_cursor"]},
                     headers=_headers(api_account))
    page2 = second.json()
    assert [item["node_id"] for item in page2["data"]] == [oldest, never]   # 无心跳排后
    assert page2["page"]["has_more"] is False
    assert page2["page"]["next_cursor"] is None
    assert page2["page"]["cursor"] == page1["page"]["next_cursor"]

    assert len({item["node_id"] for item in page1["data"] + page2["data"]}) == 4


@pytest.mark.parametrize("params", [{"limit": "0"}, {"limit": "201"}, {"limit": "abc"},
                                    {"cursor": "bogus"}])
def test_list_rejects_bad_params(api, user_auth, api_account, params):   # noqa: ARG001
    response = api.get(BASE, params=params, headers=_headers(api_account))
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


# --------------------------------------------------------------------------- 解绑：成功 / 幂等
def test_unbind_revokes_key_and_is_idempotent(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    node_id, client_key = _node(schema, account_id=api_account)

    first = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "换机"},
                     headers=_headers(api_account, step_up=True))
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["node_id"] == node_id
    assert body["state"] == "revoked"
    assert body["lifecycle_state"] == "active"
    assert body["bound_at"].endswith("Z")
    assert body["unbound_at"].endswith("Z")
    assert first.headers["X-Request-Id"]

    row = _row(schema, node_id)
    assert row["account_id"] is None
    assert row["bound_account_id"] == api_account             # 历史归属保留
    assert row["revoked_at"] is not None
    assert row["key_revoked_at"] is not None

    with connect(schema) as c:
        with pytest.raises(errors.NodeKeyRevoked):
            models.authenticate(c, client_key, now=NOW)       # 旧 X-Client-Key 立即失效

    second = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "换机"},
                      headers=_headers(api_account, step_up=True))
    assert second.status_code == 200
    assert second.json()["unbound_at"] == body["unbound_at"]  # 幂等：时间不变
    assert second.json()["bound_at"] == body["bound_at"]
    assert len(_events(schema, node_id, "unbound")) == 1      # 不追加重复事件

    listed = api.get(BASE, params={"state": "revoked"}, headers=_headers(api_account))
    assert [item["node_id"] for item in listed.json()["data"]] == [node_id]


def test_unbind_writes_audit_trail(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    node_id, _ = _node(schema, account_id=api_account)
    response = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "用户主动解绑"},
                        headers=_headers(api_account, step_up=True))
    assert response.status_code == 200

    events = _events(schema, node_id, "unbound")
    assert len(events) == 1
    _, from_state, to_state, reason_code, reason, actor = events[0]
    assert (from_state, to_state) == ("active", "active")
    assert reason_code == "unbound"
    assert reason == "用户主动解绑"
    assert actor == f"account:{api_account}"

    with connect(schema) as c:
        queued = list(c.execute(
            "SELECT payload FROM supply_outbox WHERE aggregate_id = %s "
            "AND type = 'node.state.changed'", (node_id,)).fetchall())
    assert queued and queued[-1][0]["reason"] == "unbound"


# --------------------------------------------------------------------------- 解绑：错误分支
def test_unbind_requires_step_up(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    node_id, _ = _node(schema, account_id=api_account)
    response = api.post(f"{BASE}/{node_id}/unbind", json={}, headers=_headers(api_account))
    assert response.status_code == 424
    assert _error(response)["code"] == 42401
    assert _row(schema, node_id)["revoked_at"] is None         # 未产生副作用


def test_unbind_foreign_or_missing_is_404(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    other_id, _ = _node(schema, account_id=seed_account(schema))

    foreign = api.post(f"{BASE}/{other_id}/unbind", json={},
                       headers=_headers(api_account, step_up=True))
    assert foreign.status_code == 404
    assert _error(foreign)["code"] == 40401
    assert _row(schema, other_id)["revoked_at"] is None        # 他人节点不受影响

    missing = api.post(f"{BASE}/n_{uuid.uuid4().hex}/unbind", json={},
                       headers=_headers(api_account, step_up=True))
    assert missing.status_code == 404
    assert _error(missing)["code"] == 40401
    # 不泄露存在性：他人节点与不存在节点的响应体同形（仅 request_id 不同）
    assert set(foreign.json()["error"]) == set(missing.json()["error"])


def test_unbind_frozen_is_40903_and_retired_is_40902(api, user_auth, api_account):  # noqa: ARG001
    schema = api.schema
    frozen_id, _ = _node(schema, account_id=api_account, state="frozen")
    retired_id, _ = _node(schema, account_id=api_account, state="retired")

    frozen = api.post(f"{BASE}/{frozen_id}/unbind", json={},
                      headers=_headers(api_account, step_up=True))
    assert frozen.status_code == 409
    assert _error(frozen)["code"] == 40903

    retired = api.post(f"{BASE}/{retired_id}/unbind", json={},
                       headers=_headers(api_account, step_up=True))
    assert retired.status_code == 409
    assert _error(retired)["code"] == 40902


def test_unbind_unbound_node_is_40305(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    node_id = _owned_without_binding(schema, api_account)
    response = api.post(f"{BASE}/{node_id}/unbind", json={},
                        headers=_headers(api_account, step_up=True))
    assert response.status_code == 403
    assert _error(response)["code"] == 40305


def test_unbind_reason_bounds_and_malformed_body(api, user_auth, api_account):   # noqa: ARG001
    schema = api.schema
    node_id, _ = _node(schema, account_id=api_account)

    too_long = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "x" * 513},
                        headers=_headers(api_account, step_up=True))
    assert too_long.status_code == 400
    assert _error(too_long)["code"] == 40001

    wrong_type = api.post(f"{BASE}/{node_id}/unbind", json={"reason": 123},
                          headers=_headers(api_account, step_up=True))
    assert wrong_type.status_code == 400

    malformed = api.post(f"{BASE}/{node_id}/unbind", content=b"{not json",
                         headers={**_headers(api_account, step_up=True),
                                  "Content-Type": "application/json"})
    assert malformed.status_code == 400
    assert _error(malformed)["reason"] == "malformed_json"

    assert _row(schema, node_id)["revoked_at"] is None


# --------------------------------------------------------------------------- 解绑：幂等键
def test_unbind_idempotency_key_replays_first_response(api, user_auth, api_account):  # noqa: ARG001
    schema = api.schema
    node_id, _ = _node(schema, account_id=api_account)
    headers = _headers(api_account, step_up=True, **{"X-DJB-Idempotency-Key": "idem-w3-1"})

    first = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "第一次"}, headers=headers)
    assert first.status_code == 200
    replay = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "第一次"}, headers=headers)
    assert replay.status_code == 200
    assert replay.json() == first.json()

    conflict = api.post(f"{BASE}/{node_id}/unbind", json={"reason": "不同载荷"},
                        headers=headers)
    assert conflict.status_code == 409
    assert _error(conflict)["code"] == 40919
    assert len(_events(schema, node_id, "unbound")) == 1

# --------------------------------------------------------------------------- 契约（spec 1.2.6）

def _spec() -> dict:
    """spec 来源：$DJB_SPEC_FILE → 仓库 spec/ → 向上最多 4 级祖先的 spec/（CI 与工作区同一实现）。"""
    import os
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[2]
    candidates = [pathlib.Path(os.environ["DJB_SPEC_FILE"])] if os.environ.get("DJB_SPEC_FILE") \
        else []
    candidates.append(root / "spec" / "openapi.yaml")
    candidates += [parent / "spec" / "openapi.yaml" for parent in list(root.parents)[:4]]
    for candidate in candidates:
        if candidate.exists():
            return yaml.safe_load(candidate.read_text(encoding="utf-8"))
    pytest.skip("spec/openapi.yaml 缺失（设置 DJB_SPEC_FILE 或先同步 spec）")


def test_route_and_enums_match_spec_1_2_6():
    from app.supply import facts, router as router_module

    spec = _spec()
    list_op = spec["paths"]["/api/v1/user/nodes"]["get"]
    unbind_op = spec["paths"]["/api/v1/user/nodes/{node_id}/unbind"]["post"]
    assert list_op["operationId"] == "listUserNodes"
    assert unbind_op["operationId"] == "unbindUserNode"

    implemented = {(method.upper(), route.path) for route in router_module.router.routes
                   for method in (getattr(route, "methods", set()) or set())
                   - {"HEAD", "OPTIONS"}}
    assert ("GET", "/api/v1/user/nodes") in implemented
    assert ("POST", "/api/v1/user/nodes/{node_id}/unbind") in implemented

    node_schema = spec["components"]["schemas"]["UserNode"]["properties"]
    assert tuple(node_schema["state"]["enum"]) == facts.USER_NODE_VIEW_STATES
    assert tuple(node_schema["lifecycle_state"]["enum"]) == facts.NODE_STATES
    page = spec["components"]["schemas"]["UserNodePage"]
    assert set(page["required"]) == {"data", "page"}

