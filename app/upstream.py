# SPDX-License-Identifier: Apache-2.0
"""stub 上游：不调外部模型，确定性回复（用于打通链路；生产替换为真实路由）。

计费口径：prompt/completion token 用**字符数/4**估算（stub 专用近似），
真实上游必须回传权威 usage（spec `Usage`）。
"""
from __future__ import annotations


def count_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def complete(model: str, messages: list[dict], max_tokens: int | None = None) -> dict:
    last = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last = str(m.get("content") or "")
            break
    text = f"[stub:{model}] 收到 {len(messages)} 条消息。回声：{last[:120]}"
    if max_tokens:
        text = text[: max_tokens * 4]
    return {"text": text, "prompt_tokens": sum(count_tokens(str(m.get("content") or "")) for m in messages),
            "completion_tokens": count_tokens(text)}
