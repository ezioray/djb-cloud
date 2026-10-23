# SPDX-License-Identifier: Apache-2.0
"""契约测试：实现 vs ``spec/openapi.yaml``（spec 1.2.3）与 ``02-events.md``。

三件事：

1. 只实现 spec 声明过的端点（多了不行——合并进 ``app.api`` 后 CI 会按这个口径卡）；
2. 响应载荷含 spec 的 ``required`` 字段（``additionalProperties`` 允许我们多给）；
3. 事件矩阵里的每个事件都在 02-events §3 登记过，且本模块生产的事件名在契约里。
"""
from __future__ import annotations

import os
import pathlib
import uuid

import pytest

from app.notify import events, facts, signing
from app.notify.models import Notification, Preference, WebhookSubscription
from app.notify.router import create_router

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
#: spec 在仓库里被 .gitignore（CI 构建期拉取）；工作区根目录有一份权威副本（tag spec-1.2.3）
SPEC_CANDIDATES = (
    os.environ.get("DJB_SPEC_FILE"),
    REPO_ROOT / "spec" / "openapi.yaml",
    REPO_ROOT.parents[1] / "spec" / "openapi.yaml",
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def _spec() -> dict:
    yaml = pytest.importorskip("yaml")
    for candidate in SPEC_CANDIDATES:
        if candidate and pathlib.Path(candidate).exists():
            return yaml.safe_load(pathlib.Path(candidate).read_text(encoding="utf-8"))
    pytest.skip(f"spec 缺失（{SPEC_CANDIDATES}）；CI 会先拉固定版本")


def _product_module(name: str) -> pathlib.Path | None:
    for base in (REPO_ROOT.parent.parent, REPO_ROOT.parent, REPO_ROOT):
        candidate = base / "product" / "v4" / "modules" / name
        if candidate.exists():
            return candidate
    return None


def test_router_only_implements_declared_endpoints():
    spec = _spec()
    declared = {(method, path) for path, item in spec["paths"].items()
                for method in item if method in HTTP_METHODS}
    implemented = set()
    for route in create_router().routes:
        for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
            implemented.add((method.lower(), route.path))
    assert implemented, "路由为空"
    assert implemented <= declared, f"实现了 spec 未声明的端点：{sorted(implemented - declared)}"
    assert len(implemented) == 7, sorted(implemented)


def test_schemas_required_fields_are_present():
    spec = _spec()
    schemas = spec["components"]["schemas"]

    notification = Notification(
        id=uuid.uuid4(), account_id=uuid.uuid4(), level="P1", type="payment.paid",
        template_key="customer.payment.paid", template_scope="customer", payload={},
        channels=("in_app",), channel_count=1, dedupe_bucket=0, status="queued",
        created_at=facts_now())
    _assert_required(schemas["Notification"], notification.to_api())

    _assert_required(schemas["NotificationPreferences"], Preference().to_api())

    subscription = WebhookSubscription(
        id=uuid.uuid4(), account_id=uuid.uuid4(), url="https://hooks.example.com/cb",
        events=("payment.settled",), status="active", created_at=facts_now(),
        updated_at=facts_now(), secret_hash="0" * 64)
    _assert_required(schemas["WebhookSubscription"], subscription.to_api())
    assert "secret" not in subscription.to_api()

    # 列表 / 已读 / 创建响应的外层形状
    _assert_required(schemas["NotificationList"], {"data": [], "page": {"has_more": False}})
    _assert_required(schemas["NotificationReadAck"],
                     {"notification_id": None, "marked": 0, "unread": 0})
    created = dict(subscription.to_api(), secret=signing.new_secret())
    _assert_required(schemas["WebhookSubscriptionCreated"], created)


def test_error_envelope_matches_spec():
    spec = _spec()
    error = spec["components"]["schemas"]["Error"]["properties"]["error"]
    assert set(error["required"]) == {"type", "code", "message", "request_id"}
    from app.notify import errors

    body = {"error": {"type": errors.error_type_for(409), "code": 40902,
                      "message": "x", "request_id": "r", "reason": "p0_opt_out_rejected"}}
    _assert_required(spec["components"]["schemas"]["Error"], body)
    assert body["error"]["type"] in error["properties"]["type"]["enum"]


def test_webhook_event_enum_matches_spec():
    spec = _spec()
    enum = spec["components"]["schemas"]["WebhookSubscriptionRequest"]["properties"][
        "events"]["items"]["enum"]
    assert tuple(enum) == facts.WEBHOOK_EVENTS
    assert set(events.WEBHOOK_EVENT_MAP.values()) <= set(enum)


def test_preferences_p0_is_read_only_in_spec():
    spec = _spec()
    p0 = spec["components"]["schemas"]["NotificationPreferences"]["properties"]["p0_opt_out"]
    assert p0["enum"] == [False]


def test_event_matrix_is_registered_in_events_contract():
    path = _product_module("02-events.md")
    if path is None:
        pytest.skip("02-events.md 不在本工作树可读范围内")
    text = path.read_text(encoding="utf-8")
    missing = [event_type for event_type in events.EVENT_TEMPLATES if event_type not in text]
    assert not missing, f"事件矩阵含 02-events 未登记的事件：{missing}"
    for produced in ("notification.requested", "notification.delivered", "notification.failed"):
        assert produced in text
    # M12 被登记为消费方的关键事件（CR-1 已并入 02-events）
    for consumer_event in ("recon.completed", "exception.opened", "wallet.switched",
                           "risk.limit.hit"):
        assert consumer_event in events.EVENT_TEMPLATES


def _assert_required(schema: dict, payload: dict) -> None:
    if "allOf" in schema:
        for item in schema["allOf"]:
            _assert_required(item, payload)
        return
    required = set(schema.get("required", ()))
    assert required <= set(payload), f"缺必填字段：{sorted(required - set(payload))}"


def facts_now():
    from app.notify import clock

    return clock.now()
