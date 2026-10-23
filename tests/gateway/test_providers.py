# SPDX-License-Identifier: Apache-2.0
"""注入点契约（M03 / WIRING.md）：默认 fail-closed、返回体 coerce、错误翻译。"""
from __future__ import annotations

import uuid

import pytest

from app.gateway import errors, models, providers
from gatewaykit import FakeCatalog, FakeNode, FakeRoute, FakeUsage, NOW, principal_dict


def _route_request() -> models.RouteRequest:
    return models.RouteRequest(model="m1", kind="realtime", tenant_id=str(uuid.uuid4()),
                               account_id=str(uuid.uuid4()), request_id=str(uuid.uuid4()),
                               trace_id="t1")


def _node_call() -> models.NodeCall:
    return models.NodeCall(node_id="n_1", upstream_id="u_1", access="A1", model="m1",
                           messages=({"role": "user", "content": "hi"},),
                           request_id="r1", trace_id="t1", attempt_no=1)


# ─────────────────────────────────────────────────────── 鉴权
def test_authenticate_passes_arguments_through():
    seen: dict = {}

    def provider(raw_key, *, now, client_ip, trace_id):
        seen.update({"key": raw_key, "now": now, "ip": client_ip, "trace": trace_id})
        return principal_dict(api_key_id=9, qps=5)

    providers.set_auth_provider(provider)
    principal = providers.authenticate("djb_live_abcdefgh", now=NOW, client_ip="10.0.0.1",
                                       trace_id="t-1")
    assert seen == {"key": "djb_live_abcdefgh", "now": NOW, "ip": "10.0.0.1", "trace": "t-1"}
    assert principal.api_key_id == 9


def test_async_provider_is_rejected_on_the_sync_path():
    async def provider(raw_key, *, now, client_ip, trace_id):     # noqa: ARG001
        return principal_dict()

    providers.set_auth_provider(provider)
    with pytest.raises(errors.GatewayError) as info:
        providers.authenticate("djb_live_abcdefgh", now=NOW)
    assert info.value.http_status == 503


# ─────────────────────────────────────────────────────── 路由
def test_route_coerces_mapping_with_amount_price():
    providers.set_route_provider(FakeRoute(node_id="n_9", price_minor=125, node_qps=4))
    decision = providers.route(_route_request())
    assert decision.node_id == "n_9"
    assert decision.price_minor == 125
    assert decision.node_qps == 4
    assert decision.chosen.upstream_id == "up_001"


def test_route_coerces_object_style_decision():
    class Chosen:
        node_id = "n_obj"
        upstream_id = "u_obj"
        access = "B"
        model = "m1"

    class Decision:
        decision_id = "d-1"
        chosen = Chosen()
        quote_version = "q1"
        eta_seconds = 3
        node_qps = 7

    providers.set_route_provider(lambda request: Decision())     # noqa: ARG005
    decision = providers.route(_route_request())
    assert (decision.decision_id, decision.node_id, decision.node_qps) == ("d-1", "n_obj", 7)


def test_route_without_chosen_is_treated_as_no_node():
    providers.set_route_provider(lambda request: {"decision_id": "d"})  # noqa: ARG005
    with pytest.raises(errors.GatewayError) as info:
        providers.route(_route_request())
    assert (info.value.http_status, info.value.code) == (503, 50901)


def test_route_provider_no_route_exception_maps_to_50901():
    def provider(request):                                       # noqa: ARG001
        raise providers.NoRoute("没有可用节点")

    providers.set_route_provider(provider)
    with pytest.raises(errors.GatewayError) as info:
        providers.route(_route_request())
    assert info.value.code == 50901 and info.value.retry_after_s


def test_route_provider_returning_none_is_fail_closed():
    providers.set_route_provider(lambda request: None)           # noqa: ARG005
    with pytest.raises(errors.GatewayError):
        providers.route(_route_request())


def test_route_not_wired_is_503():
    with pytest.raises(errors.GatewayError) as info:
        providers.route(_route_request())
    assert (info.value.http_status, info.value.code) == (503, 45001)


# ─────────────────────────────────────────────────────── 上游节点
def test_send_coerces_openai_style_mapping():
    def client(call):
        return {"choices": [{"message": {"content": "hi"}, "finish_reason": "length"}],
                "model": "m1", "usage": {"prompt_tokens": 4, "completion_tokens": 6},
                "id": "up-1"}

    providers.set_node_client(type("C", (), {"complete": staticmethod(client)})())
    result = providers.send(_node_call())
    assert result.content == "hi"
    assert result.finish_reason == "length"
    assert (result.tokens_in, result.tokens_out) == (4, 6)
    assert result.upstream_request_id == "up-1"


def test_send_maps_unexpected_exceptions_to_upstream_failure():
    class Boom:
        def complete(self, call):
            raise ValueError("bad frame")

    providers.set_node_client(Boom())
    with pytest.raises(providers.UpstreamFailure):
        providers.send(_node_call())


def test_send_none_result_is_upstream_failure():
    providers.set_node_client(type("C", (), {"complete": staticmethod(lambda call: None)})())
    with pytest.raises(providers.UpstreamFailure):
        providers.send(_node_call())


def test_send_not_wired_is_503():
    with pytest.raises(errors.GatewayError) as info:
        providers.send(_node_call())
    assert info.value.http_status == 503


# ─────────────────────────────────────────────────────── 计量 / 目录
def test_record_usage_without_provider_returns_empty_receipt():
    draft = models.UsageDraft(request_id="r1", attempt_no=1, account_id="a", tenant_id="t",
                              api_key_id=1, node_id="n", model="m1", access="A1",
                              tokens_in=1, tokens_out=1, usage_source="actual",
                              amount_minor=10, policy_version="pv", trace_id="t1",
                              occurred_at=NOW)
    receipt = providers.record_usage(draft)
    assert receipt.usage_id is None


def test_record_usage_coerces_mapping():
    providers.set_usage_provider(FakeUsage())
    draft = models.UsageDraft(request_id="abcdefgh-1", attempt_no=1, account_id="a",
                              tenant_id="t", api_key_id=1, node_id="n", model="m1",
                              access="A1", tokens_in=1, tokens_out=1, usage_source="actual",
                              amount_minor=10, policy_version="pv", trace_id="t1",
                              occurred_at=NOW)
    receipt = providers.record_usage(draft)
    assert receipt.usage_id == "u_abcdefgh" and receipt.amount_minor == 10


def test_list_models_rejects_non_sequence():
    providers.set_model_catalog_provider(type("C", (), {
        "list_models": staticmethod(lambda: {"not": "a list"})})())
    with pytest.raises(errors.GatewayError) as info:
        providers.list_models()
    assert info.value.http_status == 503


def test_list_models_accepts_objects():
    item = type("Model", (), {"id": "m9", "owned_by": "djb"})()
    providers.set_model_catalog_provider(type("C", (), {
        "list_models": staticmethod(lambda: [item])})())
    assert providers.list_models() == [{"id": "m9", "owned_by": "djb"}]


def test_list_models_not_wired_is_503():
    with pytest.raises(errors.GatewayError):
        providers.list_models()


# ─────────────────────────────────────────────────────── 错误翻译
def test_translate_error_passes_gateway_errors_through():
    original = errors.GatewayError("conflict", "x")
    assert providers.translate_error(original) is original


@pytest.mark.parametrize("code,status,expected", [
    ("40101", 401, "key_invalid"),
    ("40304", 403, "account_readonly"),
    ("40903", 409, "key_invalid"),
    ("40907", 409, "service_unavailable"),
])
def test_translate_identity_codes(code, status, expected):
    exc = RuntimeError("m01")
    exc.code, exc.status_code, exc.reason = code, status, "whatever"
    translated = providers.translate_error(exc)
    assert translated.key == expected
    assert translated.reason == "whatever"


@pytest.mark.parametrize("http,expected", [(400, "bad_request"), (401, "key_invalid"),
                                           (402, "insufficient_balance"),
                                           (403, "key_policy_denied"), (409, "conflict"),
                                           (429, "rate_limited"), (426, "service_unavailable")])
def test_translate_other_cross_module_codes_by_http(http, expected):
    exc = RuntimeError("other module")
    exc.code, exc.status_code = "49999", http
    assert providers.translate_error(exc).key == expected


def test_translate_5xx_is_service_unavailable_with_retry_after():
    exc = RuntimeError("upstream down")
    exc.status_code = 503
    translated = providers.translate_error(exc)
    assert translated.key == "service_unavailable" and translated.retry_after_s


def test_translate_timeout_error():
    assert providers.translate_error(TimeoutError("slow")).key == "upstream_timeout"


def test_translate_unknown_error_is_fail_closed():
    assert providers.translate_error(ValueError("weird")).key == "service_unavailable"


# ─────────────────────────────────────────────────────── 接线状态
def test_current_reports_boolean_flags_only():
    providers.set_auth_provider(lambda *a, **k: principal_dict())
    state = providers.current()
    assert state["auth"] is True and all(isinstance(value, bool) for value in state.values())


def test_reset_providers_returns_to_fail_closed():
    providers.set_node_client(FakeNode())
    providers.set_model_catalog_provider(FakeCatalog())
    providers.reset_providers()
    assert all(value is False for value in providers.current().values())
