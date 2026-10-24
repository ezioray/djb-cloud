# SPDX-License-Identifier: AGPL-3.0-or-later
"""请求体校验（spec ``ChatCompletionRequest`` / ``ChatMessage`` / M03 §8.2 上限）。

口径：

* **自己校验，不依赖框架 422**：不合法一律 400 / ``40001``（00-conventions §5；
  M04/M05 同款），错误信封里只给字段名与粗粒度原因。
* **请求体超上限 → 413 / ``40013``**（spec 1.2.0 的 HTTP 413 专用码；chat 建议 ≤1 MiB）。
* **容错读取（INV-M03-07）**：未知字段、未知 enum 值**不得导致失败**——
  ``ChatMessage`` 的额外字段与请求体的未知键会被**忽略并丢弃**（不落库、不回显）；
  ``role`` 是封闭枚举（spec），出现未知值按参数错误处理，这是有意的「严格点」。
* **不持久化正文**：本模块只做内存校验，返回值给上游用；任何日志不得出现 content。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from . import errors, facts

__all__ = ["ValidatedChat", "read_body", "validate_chat", "parse_content_length"]


@dataclass(frozen=True)
class ValidatedChat:
    """校验后的实时请求（**只含**网关需要的字段，未知字段已丢弃）。"""

    model: str
    messages: tuple[dict[str, str], ...]
    stream: bool = False
    max_tokens: int | None = None
    temperature: float | None = None
    stop: tuple[str, ...] = ()
    user: str | None = None
    raw_size: int = 0
    extra_keys: tuple[str, ...] = field(default=())

    def request_tokens_hint(self) -> int | None:
        """粗略的输入 token 上界（只用于向 M04 声明 ``requested_tokens``，不是计费值）。"""
        chars = sum(len(item.get("content") or "") for item in self.messages)
        return max(1, chars // 4) if chars else None


def parse_content_length(raw: str | None) -> int | None:
    """``Content-Length`` 头（非法 → None，交给实际读取长度判定）。"""
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def read_body(raw: bytes, *, declared_length: int | None = None,
              max_bytes: int = facts.CHAT_BODY_MAX_BYTES) -> dict[str, Any]:
    """读 + 限长 + 解析 JSON；超限 → 413 / ``40013``，非法 JSON → 400 / ``40001``。"""
    size = len(raw)
    if declared_length is not None and declared_length > max_bytes:
        raise errors.GatewayError(
            "payload_too_large", f"请求体超过上限（{max_bytes} 字节）",
            details={"max_bytes": max_bytes})
    if size > max_bytes:
        raise errors.GatewayError(
            "payload_too_large", f"请求体超过上限（{max_bytes} 字节）",
            details={"max_bytes": max_bytes})
    if not raw:
        raise errors.GatewayError("bad_request", "请求体不能为空", details={"field": "body"})
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise errors.GatewayError("bad_request", "请求体必须是 UTF-8 编码的 JSON",
                                  details={"field": "body"}) from exc
    except json.JSONDecodeError as exc:
        raise errors.GatewayError("bad_request", "请求体不是合法 JSON",
                                  details={"field": "body"}) from exc
    if not isinstance(parsed, dict):
        raise errors.GatewayError("bad_request", "请求体必须是 JSON 对象",
                                  details={"field": "body"})
    return parsed


def _require_text(value: Any, *, field_name: str, max_length: int | None = None,
                  allow_empty: bool = False, strip: bool = True) -> str:
    if not isinstance(value, str):
        raise errors.GatewayError("bad_request", f"{field_name} 必须是字符串",
                                  details={"field": field_name})
    # 正文类字段**不做 strip**（原样透传给上游），只做存在性 / 长度校验
    text = value.strip() if strip else value
    if not allow_empty and not text.strip():
        raise errors.GatewayError("bad_request", f"{field_name} 不能为空",
                                  details={"field": field_name})
    if max_length is not None and len(text) > max_length:
        raise errors.GatewayError("bad_request", f"{field_name} 超过 {max_length} 字符",
                                  details={"field": field_name})
    return text


def _validate_messages(value: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise errors.GatewayError("bad_request", "messages 必须是数组",
                                  details={"field": "messages"})
    items = list(value)
    if not items:
        raise errors.GatewayError("bad_request", "messages 至少 1 条",
                                  details={"field": "messages"})
    if len(items) > facts.MESSAGES_MAX_ITEMS:
        raise errors.GatewayError(
            "bad_request", f"messages 最多 {facts.MESSAGES_MAX_ITEMS} 条",
            details={"field": "messages", "max_items": facts.MESSAGES_MAX_ITEMS})
    out: list[dict[str, str]] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise errors.GatewayError("bad_request", f"messages[{index}] 必须是对象",
                                      details={"field": f"messages[{index}]"})
        role = item.get("role")
        if role not in facts.MESSAGE_ROLES:
            raise errors.GatewayError(
                "bad_request", f"messages[{index}].role 必须是 {facts.MESSAGE_ROLES} 之一",
                details={"field": f"messages[{index}].role"})
        content = item.get("content")
        content = _require_text(content, field_name=f"messages[{index}].content",
                                allow_empty=True, strip=False)
        if len(content.encode("utf-8")) > facts.MESSAGE_CONTENT_MAX_BYTES:
            raise errors.GatewayError(
                "bad_request",
                f"messages[{index}].content 超过 {facts.MESSAGE_CONTENT_MAX_BYTES} 字节",
                details={"field": f"messages[{index}].content",
                         "max_bytes": facts.MESSAGE_CONTENT_MAX_BYTES})
        normalized = {"role": str(role), "content": content}
        # 容错读取：name 是 spec 允许的可选字段，其余未知键一律丢弃（不落库、不回显）
        if isinstance(item.get("name"), str) and item["name"].strip():
            normalized["name"] = item["name"].strip()[:128]
        out.append(normalized)
    return tuple(out)


def validate_chat(body: Mapping[str, Any], *, raw_size: int = 0) -> ValidatedChat:
    """校验 ``/v1/chat/completions`` 请求体 → :class:`ValidatedChat`。"""
    if not isinstance(body, Mapping):
        raise errors.GatewayError("bad_request", "请求体必须是 JSON 对象")
    model = _require_text(body.get("model"), field_name="model",
                          max_length=facts.MODEL_SLUG_MAX_LENGTH)
    messages = _validate_messages(body.get("messages"))

    stream = body.get("stream", False)
    if stream is None:
        stream = False
    if not isinstance(stream, bool):
        raise errors.GatewayError("bad_request", "stream 必须是布尔值",
                                  details={"field": "stream"})

    max_tokens = body.get("max_tokens")
    if max_tokens is not None:
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
            raise errors.GatewayError("bad_request", "max_tokens 必须是 ≥1 的整数",
                                      details={"field": "max_tokens"})

    temperature = body.get("temperature")
    if temperature is not None:
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
            raise errors.GatewayError("bad_request", "temperature 必须是数字",
                                      details={"field": "temperature"})
        if not 0 <= float(temperature) <= 2:
            raise errors.GatewayError("bad_request", "temperature 必须在 0–2 之间",
                                      details={"field": "temperature"})
        temperature = float(temperature)

    stop = body.get("stop")
    stop_items: tuple[str, ...] = ()
    if stop is not None:
        if isinstance(stop, str):
            stop_items = (stop,)
        elif isinstance(stop, Sequence) and not isinstance(stop, bytes):
            values = list(stop)
            if not all(isinstance(item, str) for item in values):
                raise errors.GatewayError("bad_request", "stop 必须是字符串数组",
                                          details={"field": "stop"})
            stop_items = tuple(values)
        else:
            raise errors.GatewayError("bad_request", "stop 必须是字符串或字符串数组",
                                      details={"field": "stop"})

    user = body.get("user")
    if user is not None:
        user = _require_text(user, field_name="user", max_length=facts.USER_FIELD_MAX_LENGTH)

    known = {"model", "messages", "stream", "max_tokens", "temperature", "stop", "user"}
    extras = tuple(sorted(key for key in body.keys() if key not in known))
    return ValidatedChat(model=model, messages=messages, stream=stream,
                         max_tokens=None if max_tokens is None else int(max_tokens),
                         temperature=temperature, stop=stop_items, user=user,
                         raw_size=int(raw_size), extra_keys=extras)
