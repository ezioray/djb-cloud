# SPDX-License-Identifier: AGPL-3.0-or-later
"""请求体校验（M03 §8.2 上限 / spec ``ChatCompletionRequest`` / INV-M03-07 容错读取）。"""
from __future__ import annotations

import json

import pytest

from app.gateway import errors, facts, validation


def _body(**overrides):
    body = {"model": "m1", "messages": [{"role": "user", "content": "hi"}]}
    body.update(overrides)
    return body


# ─────────────────────────────────────────────────────── 读体 / 限长
def test_read_body_parses_json():
    assert validation.read_body(b'{"model":"m1"}') == {"model": "m1"}


def test_empty_body_is_40001():
    with pytest.raises(errors.GatewayError) as info:
        validation.read_body(b"")
    assert info.value.code == 40001


def test_malformed_json_is_40001():
    with pytest.raises(errors.GatewayError) as info:
        validation.read_body(b"{not json")
    assert (info.value.http_status, info.value.code) == (400, 40001)


def test_non_object_body_is_40001():
    with pytest.raises(errors.GatewayError):
        validation.read_body(b"[1,2,3]")


def test_oversized_body_is_413_with_40013():
    payload = json.dumps({"model": "m1", "messages": [{"role": "user", "content": "x" * 200}]})
    with pytest.raises(errors.GatewayError) as info:
        validation.read_body(payload.encode(), max_bytes=100)
    assert (info.value.http_status, info.value.code) == (413, 40013)
    assert info.value.details["max_bytes"] == 100


def test_declared_content_length_over_limit_is_413_even_before_reading():
    with pytest.raises(errors.GatewayError) as info:
        validation.read_body(b"{}", declared_length=facts.CHAT_BODY_MAX_BYTES + 1)
    assert info.value.code == 40013


def test_parse_content_length_handles_garbage():
    assert validation.parse_content_length("42") == 42
    assert validation.parse_content_length("-1") is None
    assert validation.parse_content_length("abc") is None
    assert validation.parse_content_length(None) is None


def test_utf8_error_is_40001():
    with pytest.raises(errors.GatewayError) as info:
        validation.read_body(b"\xff\xfe{}")
    assert info.value.code == 40001


# ─────────────────────────────────────────────────────── 字段校验
def test_valid_chat_normalizes_fields():
    result = validation.validate_chat(_body(max_tokens=16, temperature=0.5, stop=["\n"],
                                            user="u-1"))
    assert result.model == "m1"
    assert result.messages == ({"role": "user", "content": "hi"},)
    assert result.max_tokens == 16
    assert result.temperature == 0.5
    assert result.stop == ("\n",)
    assert result.user == "u-1"
    assert result.stream is False
    assert result.extra_keys == ()


def test_unknown_top_level_fields_are_ignored_and_reported():
    result = validation.validate_chat(_body(tools=[{"type": "function"}], seed=7))
    assert result.extra_keys == ("seed", "tools")          # 记录但不失败（容错读取）


def test_unknown_message_fields_are_dropped():
    body = _body(messages=[{"role": "user", "content": "hi", "extra": "x"}])
    result = validation.validate_chat(body)
    assert result.messages[0] == {"role": "user", "content": "hi"}


def test_message_name_is_kept():
    body = _body(messages=[{"role": "user", "content": "hi", "name": "alice"}])
    assert validation.validate_chat(body).messages[0]["name"] == "alice"


@pytest.mark.parametrize("body", [
    {},
    {"model": "", "messages": [{"role": "user", "content": "hi"}]},
    {"model": "m1"},
    {"model": "m1", "messages": []},
    {"model": "m1", "messages": "hi"},
    {"model": "m1", "messages": [{"role": "robot", "content": "hi"}]},
    {"model": "m1", "messages": [{"content": "hi"}]},
    {"model": "m1", "messages": [{"role": "user", "content": None}]},
    {"model": "m1", "messages": [{"role": "user", "content": "hi"}], "stream": "yes"},
    {"model": "m1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 0},
    {"model": "m1", "messages": [{"role": "user", "content": "hi"}], "temperature": 3},
    {"model": "m1", "messages": [{"role": "user", "content": "hi"}], "stop": [1, 2]},
    {"model": "m1", "messages": [{"role": "user", "content": "hi"}], "user": ""},
])
def test_invalid_bodies_are_40001(body):
    with pytest.raises(errors.GatewayError) as info:
        validation.validate_chat(body)
    assert (info.value.http_status, info.value.code) == (400, 40001)


def test_messages_over_max_items_is_40001():
    messages = [{"role": "user", "content": "hi"}] * (facts.MESSAGES_MAX_ITEMS + 1)
    with pytest.raises(errors.GatewayError) as info:
        validation.validate_chat({"model": "m1", "messages": messages})
    assert info.value.details["max_items"] == facts.MESSAGES_MAX_ITEMS


def test_messages_at_max_items_is_accepted():
    messages = [{"role": "user", "content": "hi"}] * facts.MESSAGES_MAX_ITEMS
    assert len(validation.validate_chat({"model": "m1", "messages": messages}).messages) == \
        facts.MESSAGES_MAX_ITEMS


def test_single_message_over_content_limit_is_40001():
    body = {"model": "m1",
            "messages": [{"role": "user", "content": "x" * (facts.MESSAGE_CONTENT_MAX_BYTES + 1)}]}
    with pytest.raises(errors.GatewayError) as info:
        validation.validate_chat(body)
    assert info.value.code == 40001
    assert info.value.details["max_bytes"] == facts.MESSAGE_CONTENT_MAX_BYTES


def test_stop_may_be_a_single_string():
    assert validation.validate_chat(_body(stop="\n\n")).stop == ("\n\n",)


def test_empty_content_is_allowed_but_role_is_not():
    assert validation.validate_chat(_body(messages=[{"role": "assistant", "content": ""}]))


def test_request_tokens_hint_is_an_upper_bound_only():
    result = validation.validate_chat(_body(messages=[
        {"role": "user", "content": "x" * 400}]))
    assert result.request_tokens_hint() == 100


def test_request_tokens_hint_none_when_empty():
    result = validation.validate_chat(_body(messages=[{"role": "user", "content": ""}]))
    assert result.request_tokens_hint() is None
