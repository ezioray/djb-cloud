# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 证明段的可注入 provider（C12）。

本模块只解决一件事：**服务端 tokenizer 从哪来**。

* 真实 tokenizer 属于 M03（网关）的能力，由 Lead 在 wiring 里注入：
  ``set_token_counter(fn, version="...")``；
* 未注入时 **fail-closed**：``token_counter()`` 抛 :class:`TokenizerUnavailable`
  （503 / 50001 / ``reason=tokenizer_unavailable``），绝不退化成「客户端说了算」；
* 注入的 counter 签名固定 ``(prompt, model) -> int``；返回值必须是正整数，
  否则同样视为不可用（不猜、不静默当作 0）。

为什么不用 50903：spec 里 50903 = 502 upstream_error（上游调用失败）。「服务端自身 tokenizer
未接线」不是上游错误，故沿用仓库既有 503 + 50001 口径，用 reason 区分（见 errors.py）。
"""
from __future__ import annotations

from typing import Any, Callable

from .errors import BadRequest, TokenizerUnavailable

__all__ = [
    "TokenCounter", "set_token_counter", "reset_token_counter", "is_wired",
    "token_counter", "tokenizer_version", "count_prompt_tokens",
]

TokenCounter = Callable[[str, str], int]

_counter: TokenCounter | None = None
_version: str | None = None


def set_token_counter(counter: TokenCounter | None, *, version: str | None = None) -> None:
    """注入服务端 tokenizer 计数器（Lead wiring 调用）。传 ``None`` 恢复 fail-closed。"""
    global _counter, _version
    if counter is not None and not callable(counter):
        raise TypeError("token_counter 必须是 callable(prompt, model) -> int")
    _counter = counter
    _version = (str(version).strip()[:64] or None) if version else None


def reset_token_counter() -> None:
    set_token_counter(None)


def is_wired() -> bool:
    return _counter is not None


def token_counter() -> TokenCounter:
    if _counter is None:
        raise TokenizerUnavailable(
            "服务端 tokenizer provider 未接线（M03 wiring 未注入）：L1–L3 定级 fail-closed；"
            "读接口不受影响")
    return _counter


def tokenizer_version() -> str | None:
    return _version


def count_prompt_tokens(prompt: str, model: str) -> int:
    """用注入的 counter 计数；非法返回值 → 503（不猜、不当 0、不放过）。"""
    counter = token_counter()
    try:
        value: Any = counter(prompt, model)
    except Exception as exc:                          # noqa: BLE001 - provider 内部错误一律 fail-closed
        raise TokenizerUnavailable("tokenizer 计数失败：provider 异常（fail-closed）") from exc
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenizerUnavailable("tokenizer 返回非整数计数（fail-closed）")
    if value <= 0:
        raise TokenizerUnavailable("tokenizer 返回非正计数（fail-closed）")
    return int(value)
