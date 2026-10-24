# SPDX-License-Identifier: Apache-2.0
"""本地 token 计数（C9a 消费侧双计）：**纯函数 + 无第三方硬依赖**。

背景（``ops/audit/reports/PROBE-TOKEN-AUDIT-20261024T0017Z.md`` §2.2 / §5 C9）：
网关此前只在上游缺 ``usage`` 时用 ``len(text) // 4`` 估算，中文按**字符数**算会低估约 4 倍；
有上游 ``usage`` 时完全不复核。本模块提供本地计数器，用于：

1. 上游缺用量时的**兜底估算**（替代 ``len // 4``，``usage_source=estimated``）；
2. 上游给了用量时的**双计复核**（``usage_source=dual``，差异 >1% 告警；
   响应 / 计费数值仍以上游为准——见 :mod:`app.gateway.chat` / :mod:`app.gateway.stream`）。

计数口径（近似，无需与某个特定分词器逐 token 对齐）：

* **CJK / 全角 / 其它非 ASCII**：≈1 token/字（中文 1 字 ≈ 1 token）；
* **ASCII 字母 / 数字 / 空白**：≈4 字符/token（连续段向上取整）；
* **ASCII 符号 / 标点**：≈2 字符/token（连续段向上取整）；
* **chat template 近似**：每条消息 +4、回复预备 +3、每个 tool +4（都是 OpenAI 系
  chat 模板的公开经验值，只做量级对齐，不是精确模板）。

可选 ``tiktoken``：**仅当**环境已装且模型属 OpenAI 系时使用（``try/except`` 降级）；
不写入依赖、不是硬依赖——没装就走上面的字符口径。因此本模块在最小安装下也是确定的：
同一个字符串永远得到同一个数字（:func:`count_text_tokens` 是纯函数）。

注意加载方式：本模块**没有** ``import tiktoken`` 声明，而是 ``importlib.import_module``
按需加载。原因：``tests/gateway/test_architecture.py`` 的架构门禁只允许 ``app/gateway/**``
出现标准库 / ``psycopg`` / ``fastapi`` / ``pydantic`` / ``starlette`` 的静态 import
（00-conventions §1「不自举依赖」），而 ``tiktoken`` 属于**可选**依赖——写静态 import 会被
门禁判为新增运行时依赖。按需加载等价于「装了就用、没装就降级」，且不改变依赖面。
"""
from __future__ import annotations

import functools
import importlib
import json
import math
from typing import Any, Iterable, Mapping

__all__ = [
    "ASCII_WORD_CHARS_PER_TOKEN", "ASCII_SYMBOL_CHARS_PER_TOKEN", "MESSAGE_OVERHEAD_TOKENS",
    "REPLY_PRIMING_TOKENS", "TOOL_OVERHEAD_TOKENS",
    "count_text_tokens", "count_prompt_tokens", "count_completion_tokens",
    "delta_ratio", "is_mismatch", "mismatch_event", "dual_mismatch_events",
    "uses_exact_encoder",
]

#: ASCII 字母 / 数字 / 空白：≈4 字符 1 token（M03 §5 的公开经验口径）
ASCII_WORD_CHARS_PER_TOKEN: int = 4
#: ASCII 符号 / 标点：≈2 字符 1 token（符号更碎）
ASCII_SYMBOL_CHARS_PER_TOKEN: int = 2
#: 每条消息的模板开销（role / 分隔符 / BOS-EOU 等）
MESSAGE_OVERHEAD_TOKENS: int = 4
#: 回复预备（assistant 起手）
REPLY_PRIMING_TOKENS: int = 3
#: 每个 tool 定义的模板开销
TOOL_OVERHEAD_TOKENS: int = 4

#: 能用 ``tiktoken`` 精确计数的模型族前缀（其余一律走字符口径）
_OPENAI_MODEL_PREFIXES: tuple[str, ...] = (
    "gpt-", "chatgpt", "o1", "o3", "o4", "text-", "davinci", "curie", "babbage", "ada",
)

#: 字符分类（只用于把连续段聚在一起，口径见模块 docstring）
_WORD, _SYMBOL, _WIDE = 0, 1, 2


def _char_class(char: str) -> int:
    """``0`` ASCII 词字符（字母/数字/空白）· ``1`` ASCII 符号 · ``2`` 非 ASCII（CJK/全角/其它）。"""
    if char.isascii():
        return _WORD if (char.isalnum() or char.isspace()) else _SYMBOL
    return _WIDE


def _run_tokens(text: str, kind: int) -> int:
    """一个同类别连续段的 token 数（向上取整；空段为 0）。"""
    size = len(text)
    if not size:
        return 0
    if kind == _WIDE:
        return size                                     # 1 token/字
    if kind == _SYMBOL:
        return math.ceil(size / ASCII_SYMBOL_CHARS_PER_TOKEN)
    return math.ceil(size / ASCII_WORD_CHARS_PER_TOKEN)


def count_text_tokens(text: str | None) -> int:
    """纯函数：按字符类别分段计数（确定性，无随机、无外部状态）。"""
    if not text:
        return 0
    tokens = 0
    run: list[str] = []
    kind = _WORD
    for char in text:
        current = _char_class(char)
        if current == _WIDE:                            # 宽字符单独 1 token，先结清前面的段
            tokens += _run_tokens("".join(run), kind)
            run, kind = [], _WORD
            tokens += 1
            continue
        if current != kind:
            tokens += _run_tokens("".join(run), kind)
            run, kind = [], current
        run.append(char)
    tokens += _run_tokens("".join(run), kind)
    return tokens


# --------------------------------------------------------------------------- 可选精确编码器
def _is_openai_family(model: str | None) -> bool:
    text = (model or "").strip().lower()
    return bool(text) and text.startswith(_OPENAI_MODEL_PREFIXES)


@functools.lru_cache(maxsize=32)
def _exact_encoding(model: str | None) -> Any:
    """OpenAI 系模型的可选 ``tiktoken`` 编码器；不可用 → ``None``（降级到字符口径）。

    ``tiktoken`` **不是**运行时依赖：没装 / 版本不匹配 / 模型不认，一律安静降级。
    """
    if not _is_openai_family(model):
        return None
    try:
        # 可选依赖：按需加载（不写静态 import，见模块 docstring 的架构门禁说明）
        tiktoken = importlib.import_module("tiktoken")
    except Exception:                                  # pragma: no cover - 环境相关
        return None
    assert model is not None
    try:
        return tiktoken.encoding_for_model(model)
    except Exception:                                  # pragma: no cover - 环境相关
        try:
            return tiktoken.get_encoding("cl100k_base")
        except Exception:                              # pragma: no cover - 环境相关
            return None


def uses_exact_encoder(model: str | None) -> bool:
    """该模型当前是否会走 ``tiktoken``（便于运维判定「本地计数是精确还是近似」）。"""
    return _exact_encoding(model) is not None


def _count(text: str | None, model: str | None) -> int:
    """单段文本计数：优先可选编码器，失败/缺席 → 字符口径（绝不抛异常）。"""
    if not text:
        return 0
    encoding = _exact_encoding(model)
    if encoding is not None:
        try:
            return len(encoding.encode(text, disallowed_special=()))
        except Exception:                              # pragma: no cover - 防御
            pass
    return count_text_tokens(text)


# --------------------------------------------------------------------------- 请求 / 回复
def _content_text(content: Any) -> str:
    """取消息正文里的**文本**部分（多模态只算 text，图片等占位不计——不读正文进日志）。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, Mapping):
        text = content.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(content, Iterable) and not isinstance(content, (bytes, bytearray)):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return str(content)


def _tool_text(tool: Any) -> str:
    """tool 定义的规范化文本（排序键，保证同一份定义计数确定）。"""
    try:
        return json.dumps(tool, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):                    # pragma: no cover - 防御
        return str(tool)


def count_prompt_tokens(model: str | None, messages: Iterable[Any],
                        tools: Iterable[Any] | None = None) -> int:
    """近似 prompt 用量：``回复预备 + Σ(每条消息 4 + role/content/name) + Σ(每个 tool 4 + 文本)``。"""
    total = REPLY_PRIMING_TOKENS
    for message in messages or ():
        if isinstance(message, Mapping):
            role = message.get("role")
            name = message.get("name")
            content = message.get("content")
        else:                                          # pragma: no cover - 防御
            role = getattr(message, "role", None)
            name = getattr(message, "name", None)
            content = getattr(message, "content", None)
        total += MESSAGE_OVERHEAD_TOKENS
        total += _count(role if isinstance(role, str) else "", model)
        total += _count(_content_text(content), model)
        total += _count(name if isinstance(name, str) else "", model)
    for tool in tools or ():
        total += TOOL_OVERHEAD_TOKENS
        total += _count(_tool_text(tool), model)
    return total


def count_completion_tokens(model: str | None, text: str | None) -> int:
    """近似 completion 用量（空串 → 0；不做 ``max(1, …)``，兜底取整由调用方负责）。"""
    return _count(text, model)


# --------------------------------------------------------------------------- 双计比对
def delta_ratio(local: int, upstream: int) -> float:
    """相对差异：``|local - upstream| / upstream``（``upstream=0`` 时以 ``local`` 为基准）。

    两端都为 0（空请求 / 空回复）→ ``0.0``，即视为一致。
    """
    local, upstream = int(local), int(upstream)
    diff = abs(local - upstream)
    if diff == 0:
        return 0.0
    baseline = upstream if upstream > 0 else local
    return diff / baseline if baseline else 0.0


def is_mismatch(local: int, upstream: int, threshold: float) -> bool:
    """差异是否**超过**阈值（严格大于：正好 1% 不算超）。"""
    return delta_ratio(local, upstream) > float(threshold)


def mismatch_event(*, request_id: str, model: str | None, source: str, local: int,
                   upstream: int, threshold: float) -> dict[str, Any] | None:
    """构造 ``gateway.token_mismatch`` 告警字段；阈值内返回 ``None``。

    ``source`` 说明是哪一路对不上（``prompt`` / ``completion``）。**只含数字与标识**：
    不含 prompt / response 正文（硬约束：不落正文）。
    """
    if not is_mismatch(local, upstream, threshold):
        return None
    return {
        "event": "gateway.token_mismatch",
        "request_id": request_id,
        "model": model,
        "source": source,
        "local": int(local),
        "upstream": int(upstream),
        "delta_pct": round(delta_ratio(local, upstream) * 100, 2),
        "threshold_pct": round(float(threshold) * 100, 2),
    }


def dual_mismatch_events(*, request_id: str, model: str | None, local_in: int, upstream_in: int,
                         local_out: int, upstream_out: int,
                         threshold: float) -> list[dict[str, Any]]:
    """双计比对：prompt / completion 两路各自超阈值才产出告警字段（纯函数，便于测试）。"""
    events: list[dict[str, Any]] = []
    for source, local, upstream in (("prompt", local_in, upstream_in),
                                    ("completion", local_out, upstream_out)):
        event = mismatch_event(request_id=request_id, model=model, source=source, local=local,
                               upstream=upstream, threshold=threshold)
        if event is not None:
            events.append(event)
    return events
