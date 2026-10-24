# SPDX-License-Identifier: AGPL-3.0-or-later
"""M03-R2：真实 HTTP 网关路径（``DJB_GATEWAY_M03``）——切换安全 + 命中判定。

钉住三件事：

1. **默认（不设 env）**：``app.api`` 仍是 legacy demo——``/v1/models`` 200 + legacy 形态、
   不带 ``X-Request-Id``；``/v1/chat/completions`` 无 auth 回 FastAPI ``{"detail": …}``；
2. **``DJB_GATEWAY_M03=1``**：M03 gateway router **先注册**（同路径遮蔽 legacy），无 auth 回
   spec Error 信封（数字码 ``40101`` + ``request_id``）并回显 ``X-Request-Id``；带假 provider
   时 ``/v1/chat/completions`` 走完整 M03 链路（``api_request_log`` / ``m03_outbox`` 落在
   隔离 schema，不碰账本）；
3. **fail-closed**：开了 M03 却没有 ``DJB_DSN`` → 导入期 ``RuntimeError``（不静默回 legacy）。

``importlib.reload`` 会重建 app：每个用例由 fixture 负责「设 env → reload → 跑 → 恢复 env →
reload 回默认 + reset providers」，不污染其它测试文件（``tests/test_chat_chain.py`` 的 client
绑定在**首次导入**的 app 对象上，reload 不会改它）。
"""
from __future__ import annotations

import importlib
import os
import pathlib
import uuid
from contextlib import contextmanager

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

os.environ.setdefault(
    "DJB_PRICING_FILE",
    str(pathlib.Path(__file__).resolve().parents[2] / "config" / "pricing.dev.json"),
)

from fastapi.testclient import TestClient  # noqa: E402

import app.api as api_module  # noqa: E402
from app.gateway import channel as gateway_channel  # noqa: E402
from app.gateway import models as gateway_models  # noqa: E402
from app.gateway import providers  # noqa: E402
from app.wiring import Database  # noqa: E402
from app.wiring.nodes import EchoNodeClient  # noqa: E402

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"
#: M03 对话链路只需要自己的三张表（provider 全是假实现 → 不建 M01/M02/M04/M05 的表）
M03_MIGRATIONS = ("301_api_request_log.sql", "304_m03_outbox.sql", "305_m03_idempotency.sql")
_ENV_NAMES = ("DJB_GATEWAY_M03", "DJB_NODE_CHANNEL")
_ENV_AT_IMPORT = {name: os.environ.get(name) for name in _ENV_NAMES}


# ─────────────────────────────────────────────────────── 夹具
def _restore_env() -> None:
    for name, value in _ENV_AT_IMPORT.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _reload_default() -> None:
    """恢复默认（legacy）模块状态：env 复位 + providers 复位 + reload。"""
    _restore_env()
    providers.reset_providers()
    importlib.reload(api_module)


@pytest.fixture
def legacy_app():
    _reload_default()
    try:
        yield api_module
    finally:
        _reload_default()


@pytest.fixture
def m03_app():
    """打开 M03 路径（``DJB_GATEWAY_M03=1``，通道用默认 Echo）。"""
    if not os.environ.get("DJB_DSN"):
        pytest.skip("需要 DJB_DSN（install() 装配 Database 需要连接串）")
    _restore_env()
    os.environ["DJB_GATEWAY_M03"] = "1"
    try:
        yield importlib.reload(api_module)
    finally:
        _reload_default()


@pytest.fixture
def m03_app_with_channel():
    """再打开 ``DJB_NODE_CHANNEL=1``：上游走 ChannelNodeClient（内存队列）。"""
    if not os.environ.get("DJB_DSN"):
        pytest.skip("需要 DJB_DSN（install() 装配 Database 需要连接串）")
    _restore_env()
    os.environ["DJB_GATEWAY_M03"] = "1"
    os.environ["DJB_NODE_CHANNEL"] = "1"
    try:
        yield importlib.reload(api_module)
    finally:
        _reload_default()


@pytest.fixture(scope="module")
def m03_database():
    """隔离 schema（只跑 M03 的三条迁移），用例结束 DROP：不碰 public、不碰账本。"""
    if not os.environ.get("DJB_DSN"):
        pytest.skip("需要 DJB_DSN")
    database = Database.create(f"m03_r2_{os.getpid()}_{uuid.uuid4().hex[:6]}")
    database.create_schema()
    with database.connect() as conn:
        for name in M03_MIGRATIONS:
            conn.execute((MIGRATIONS_DIR / name).read_text(encoding="utf-8"))
    try:
        yield database
    finally:
        database.drop()


# ─────────────────────────────────────────────────────── 假 provider（不联网、不碰真库）
class _FakeAuth:
    def __init__(self) -> None:
        self.account_id = uuid.uuid4()
        self.tenant_id = uuid.uuid4()

    def __call__(self, raw_key: str, *, now, client_ip, trace_id) -> dict:
        return {"account_id": str(self.account_id), "tenant_id": str(self.tenant_id),
                "api_key_id": 7, "account_state": "normal", "ip_allowlist": [],
                "policy_version": "pv-1",
                "quotas": {"policy_version": "pv-1", "effective": {"qps": 100}}}


class _FakeRoute:
    def route(self, request: gateway_models.RouteRequest) -> dict:
        return {"decision_id": str(uuid.uuid4()),
                "chosen": {"node_id": "n_001", "upstream_id": "up_001", "access": "A1",
                           "model": request.model},
                "quote_version": "v1", "policy_version": "pv-1", "eta_seconds": 1,
                "price": {"amount": "2.50", "unit": "token"}, "node_qps": None}


class _FakeNode:
    def complete(self, call: gateway_models.NodeCall) -> gateway_models.NodeResult:
        return gateway_models.NodeResult(content="hello", finish_reason="stop",
                                         model=call.model, tokens_in=3, tokens_out=2,
                                         usage_source="actual", latency_ms=5, first_byte_ms=2)


class _FakeUsage:
    def __init__(self) -> None:
        self.drafts: list[gateway_models.UsageDraft] = []

    def record(self, draft: gateway_models.UsageDraft) -> gateway_models.UsageReceipt:
        self.drafts.append(draft)
        return gateway_models.UsageReceipt(usage_id=f"u_{len(self.drafts)}",
                                           amount_minor=draft.amount_minor)


class _FakeCatalog:
    def list_models(self) -> list[dict]:
        return [{"id": "m1", "object": "model", "owned_by": "djb"}]


def _wire_fakes(*, usage: _FakeUsage | None = None) -> _FakeUsage:
    fake_usage = usage or _FakeUsage()
    providers.set_auth_provider(_FakeAuth())
    providers.set_route_provider(_FakeRoute())
    providers.set_node_client(_FakeNode())
    providers.set_usage_provider(fake_usage)
    providers.set_model_catalog_provider(_FakeCatalog())
    return fake_usage


# ─────────────────────────────────────────────────────── 1) 默认 = legacy
def test_default_app_keeps_the_legacy_models_shape(legacy_app):
    response = TestClient(legacy_app.app).get("/v1/models")
    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "list" and body["data"]
    assert set(body["data"][0]) == {"id", "object", "owned_by"}   # legacy 三字段
    assert "X-Request-Id" not in response.headers                 # legacy 不生成该头


def test_default_app_keeps_the_legacy_chat_error_shape(legacy_app):
    response = TestClient(legacy_app.app).post(
        "/v1/chat/completions", json={"model": "djb/chat-lite", "messages": []})
    assert response.status_code == 401
    body = response.json()
    assert "detail" in body and "error" not in body                # FastAPI 默认形态


# ─────────────────────────────────────────────────────── 2) M03 开启：路由命中
def _flattened_routes(app_object) -> list:
    """摊平路由表：FastAPI 0.149 + Starlette 1.9 的 ``include_router`` 保留嵌套
    ``_IncludedRouter``（不再把子路由摊到 ``app.routes``），老版本是扁平 ``APIRoute``。"""
    flat: list = []
    for route in app_object.routes:
        nested = getattr(route, "original_router", None)      # _IncludedRouter.original_router
        if nested is not None:
            flat.extend(getattr(nested, "routes", ()) or ())
            continue
        flat.append(route)
    return flat


def test_m03_mode_registers_the_gateway_router_before_legacy(m03_app):
    routes = _flattened_routes(m03_app.app)
    models = [route for route in routes if getattr(route, "path", None) == "/v1/models"]
    chat = [route for route in routes if getattr(route, "path", None) == "/v1/chat/completions"]
    # 两条同路径都在；M03 在前（先注册 → 命中 M03，legacy 仅被遮蔽、未删除）
    assert [route.endpoint.__module__ for route in models] == ["app.gateway.router", "app.api"]
    assert [route.endpoint.__module__ for route in chat] == ["app.gateway.router", "app.api"]
    # M03 独有路径也挂上了（legacy 没有 /v1/batches）
    assert any(getattr(route, "path", None) == "/v1/batches" for route in routes)
    assert m03_app.M03_WIRING is not None
    wired = providers.current()
    assert all(wired[key] for key in ("auth", "route", "node", "usage", "model_catalog"))


def test_m03_models_requires_auth_with_the_spec_envelope(m03_app):
    request_id = str(uuid.uuid4())
    response = TestClient(m03_app.app).get("/v1/models",
                                           headers={"X-Request-Id": request_id})
    assert response.status_code == 401
    body = response.json()
    assert set(body) == {"error"}                                  # spec Error 信封
    error = body["error"]
    assert error["code"] == 40101 and error["type"] == "authentication_error"
    assert error["request_id"] == request_id
    assert response.headers["X-Request-Id"] == request_id           # M03 必回显


def test_m03_chat_requires_auth_with_the_spec_envelope(m03_app):
    request_id = str(uuid.uuid4())
    response = TestClient(m03_app.app).post(
        "/v1/chat/completions",
        headers={"X-Request-Id": request_id},
        json={"model": "m1", "messages": [{"role": "user", "content": "hi"}]})
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == 40101 and "detail" not in body
    assert response.headers["X-Request-Id"] == request_id


def test_m03_models_with_auth_returns_the_spec_list(m03_app):
    _wire_fakes()
    request_id = str(uuid.uuid4())
    response = TestClient(m03_app.app).get(
        "/v1/models",
        headers={"Authorization": "Bearer djb-unit-test-key", "X-Request-Id": request_id})
    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "list" and body["data"][0]["id"] == "m1"
    # 命中的是 M03 的模型目录（FakeCatalog），不是 legacy 的 pricing 表
    assert all(item["id"] != "djb/chat-lite" for item in body["data"])
    assert response.headers["X-Request-Id"] == request_id           # legacy 没有这个头


# ─────────────────────────────────────────────────────── 3) M03 开启：完整对话链路
def test_m03_chat_completion_round_trip(m03_app, m03_database, monkeypatch):
    from app.gateway import router as gateway_router

    @contextmanager
    def _connection():
        conn = m03_database.connect()
        try:
            yield conn
        finally:
            conn.close()

    monkeypatch.setattr(gateway_router, "_connection", _connection)
    fake_usage = _wire_fakes()

    request_id = str(uuid.uuid4())
    response = TestClient(m03_app.app).post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer djb-unit-test-key", "X-Request-Id": request_id},
        json={"model": "m1", "messages": [{"role": "user", "content": "hi"}]})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["object"] == "chat.completion"
    assert body["id"] == request_id and body["model"] == "m1"
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "hello"}
    assert body["usage"] == {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    assert response.headers["X-Request-Id"] == request_id
    assert "djb_receipt_id" not in body                             # 不是 legacy 收据口径
    assert fake_usage.drafts and fake_usage.drafts[0].amount_minor == 250

    with m03_database.connect() as conn:
        row = conn.execute("SELECT status, usage_source, tokens_in, tokens_out, node_id"
                           " FROM api_request_log WHERE request_id = %s",
                           (request_id,)).fetchone()
        events = conn.execute("SELECT type FROM m03_outbox WHERE aggregate_id = %s",
                              (request_id,)).fetchall()
    assert row == ("completed", "actual", 3, 2, "n_001")
    assert [item[0] for item in events] == ["request.completed"]


# ─────────────────────────────────────────────────────── 4) 通道 / fail-closed
def test_default_m03_node_client_is_echo(m03_app):
    assert isinstance(m03_app.M03_WIRING.node, EchoNodeClient)


def test_node_channel_env_installs_the_channel_node_client(m03_app_with_channel):
    wiring = m03_app_with_channel.M03_WIRING
    assert wiring is not None and wiring.channel_queue is not None
    assert isinstance(wiring.node, gateway_channel.ChannelNodeClient)
    assert isinstance(wiring.node, providers.NodeClient)
    assert wiring.channel_client is wiring.node
    # 特性开关仍默认关：只认显式 env，不因 env 把线上开关打开
    assert gateway_channel.enabled() is False


def test_missing_dsn_fails_closed_on_import():
    saved_dsn = os.environ.pop("DJB_DSN", None)
    os.environ["DJB_GATEWAY_M03"] = "1"
    try:
        with pytest.raises(RuntimeError) as info:
            importlib.reload(api_module)
        message = str(info.value)
    finally:
        if saved_dsn is not None:
            os.environ["DJB_DSN"] = saved_dsn
        _reload_default()
    assert "DJB_GATEWAY_M03" in message and "DJB_DSN" in message
    assert "legacy" in message                     # 明确说明不会静默降级
