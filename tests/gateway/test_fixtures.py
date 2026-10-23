# SPDX-License-Identifier: Apache-2.0
"""契约 fixtures（04-api-contracts §5：contracts/fixtures/M03/*.json）。

fixtures 只校验 schema 与状态码，不断言文案（文案由产品验收单独覆盖）。
本任务（T1+T2）覆盖 success / 429 两条；``boundary_stream_first_byte`` 属 T3（SSE），
这里断言「当前明确拒绝 + 契约期望已登记为未做项」，避免悄悄改成 200 却发不出 SSE。
"""
from __future__ import annotations

import json
import pathlib
import uuid

import pytest

from app.gateway import config_source, facts, providers
from gatewaykit import FakeAuth, FakeCatalog, FakeNode, FakeRoute, FakeUsage

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "contracts" / "fixtures" / "M03"


@pytest.fixture(scope="module")
def api_schema(db, schema_prefix) -> str:               # noqa: ARG001
    from gatewaykit import apply_migrations, create_schema, drop_schema

    name = f"{schema_prefix}_fix_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def client(api_schema: str):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.gateway import router as router_module
    from gatewaykit import connect

    app = FastAPI()
    app.include_router(router_module.router)

    def _connection():
        return connect(api_schema, autocommit=False)

    original = router_module._connection
    router_module._connection = _connection
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        router_module._connection = original


@pytest.fixture
def wired_stream(wired_all):
    """流式用例：额外接上 stream client（首字节即到达）。"""
    from gatewaykit import FakeStream

    providers.set_stream_client(FakeStream(chunks=["hi"], tokens_in=3, tokens_out=1))
    return wired_all


@pytest.fixture
def wired_all():
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode())
    providers.set_usage_provider(FakeUsage())
    providers.set_model_catalog_provider(FakeCatalog())
    return True


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fixture_files_exist():
    names = {path.name for path in FIXTURES.glob("*.json")}
    assert {"success_chat_completion.json", "error_rate_limited.json",
            "boundary_stream_first_byte.json"} <= names


def test_success_chat_completion_fixture(client, wired_all):
    fixture = _fixture("success_chat_completion.json")
    response = client.post("/v1/chat/completions", json=fixture["input"],
                           headers={facts.AUTH_HEADER: "Bearer djb_live_abcdefgh",
                                    facts.REQUEST_ID_HEADER: str(uuid.uuid4())})
    assert response.status_code == fixture["expect"]["http"] == 200
    payload = response.json()
    assert payload["object"] == "chat.completion"
    assert payload["choices"][0]["message"]["role"] == "assistant"
    if fixture["expect"].get("has_usage"):
        assert set(payload["usage"]) >= {"prompt_tokens", "completion_tokens", "total_tokens"}
    assert response.headers[facts.REQUEST_ID_HEADER]


def test_error_rate_limited_fixture(client, wired_all):
    """fixture 的 ``burst: 1000`` 是「高强度突发」的示意值；测试里收窄为 ``limit + 1`` 次，
    只断言契约面（429 + Retry-After），不跑 1000 次（04-api-contracts §5「不断言文案」）。"""
    fixture = _fixture("error_rate_limited.json")
    model = fixture["input"]["model"]
    limit = 2
    config_source.set_provider(lambda: {"gateway.rate_limit_qps": limit})
    headers = {facts.AUTH_HEADER: "Bearer djb_live_abcdefgh"}
    for index in range(limit):
        response = client.post(
            "/v1/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": f"hi-{index}"}]},
            headers=headers)
        assert response.status_code == 200, response.text
    limited = client.post("/v1/chat/completions",
                          json={"model": model,
                                "messages": [{"role": "user", "content": "over-limit"}]},
                          headers=headers)
    assert limited.status_code == fixture["expect"]["http"] == 429
    if fixture["expect"].get("retry_after"):
        assert limited.headers.get(facts.RETRY_AFTER_HEADER)
        assert limited.json()["error"]["code"] == 42901


def test_stream_fixture_is_satisfied_by_sse(client, wired_stream):
    """T3 起 ``boundary_stream_first_byte`` 必须真的返回 SSE（不再靠 400 占位）。"""
    fixture = _fixture("boundary_stream_first_byte.json")
    assert fixture["expect"]["http"] == 200
    assert fixture["expect"]["content_type"] == "text/event-stream"
    with client.stream("POST", "/v1/chat/completions",
                       json={"model": fixture["input"].get("model", "m1"),
                             "stream": True,
                             "messages": [{"role": "user", "content": "hi"}]},
                       headers={facts.AUTH_HEADER: "Bearer djb_live_abcdefgh"}) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())
    assert body.rstrip().endswith(f"data: {facts.SSE_DONE}")


def test_fixtures_have_no_secrets_or_body_text():
    for path in FIXTURES.glob("*.json"):
        text = path.read_text(encoding="utf-8").lower()
        assert "password" not in text and "secret" not in text and "sk-" not in text
