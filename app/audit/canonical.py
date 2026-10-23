# SPDX-License-Identifier: Apache-2.0
"""审计链哈希：canonical JSON + HMAC-SHA256（**唯一算式实现**，append 与 verify 都走这里）。

算式（M16 §6.3 / 任务卡；换实现必须红 —— ``tests/infra/test_canonical.py`` 钉死向量）::

    payload   = entry 去掉 hash 后的 17 个字段（键集固定，见 facts.ENTRY_FIELDS）
    canonical = JSON(payload) 的**规范形**：
                  · 键按字典序排序（sort_keys）
                  · 紧凑分隔符（`,` 与 `:`，无空格）
                  · UTF-8 直出（ensure_ascii=False，中文不转义）
                  · 浮点 NaN / Infinity 直接拒绝（allow_nan=False）
                  · ts 固定成 ``YYYY-MM-DDTHH:MM:SS.ffffffZ``（6 位微秒，UTC）
    message   = prev_hash + "\\n" + canonical           （UTF-8 字节）
    hash      = HMAC-SHA256(key, message) 的小写 hex

首条 ``prev_hash = "GENESIS"``；``prev_hash`` 同时出现在消息前缀与 canonical 里（它是条目字段），
两处都由前一行的 ``hash`` 决定——任何一处被改都会重算不一致。

为什么 canonical 要"定长 ts + 固定键集"：数据库 jsonb 会重排键、timestamptz 回读是 datetime，
如果哈希依赖序列化细节，append 与 verify 就会因为"同一个事实、不同的字符串"互相打架。
规范形把这件事钉死：**同一个事实永远只有一种字节表示**。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts


def canonical_ts(value: Any) -> Any:
    """把 ts 归一成定长 UTC ISO 字符串（无法解析时原样返回，交给 verify 报字段问题）。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return clock.iso_micros(value)
    if isinstance(value, str):
        text = value.strip()
        normalised = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            return clock.iso_micros(datetime.fromisoformat(normalised))
        except ValueError:
            return text
    return value


def canonical_json(value: Any) -> str:
    """规范 JSON：键排序 + 紧凑分隔符 + UTF-8 直出（+ 拒绝 NaN/Inf）。"""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def entry_payload(entry: Mapping[str, Any]) -> dict[str, Any]:
    """取出参与哈希的 17 个字段并归一（不修改入参）。"""
    payload: dict[str, Any] = {}
    for field in facts.ENTRY_FIELDS:
        value = entry.get(field)
        if field == "seq":
            payload[field] = int(value) if value is not None else None
        elif field == "entry_id":
            payload[field] = str(value) if value is not None else None
        elif field == "ts":
            payload[field] = canonical_ts(value)
        elif field == "approval_chain":
            payload[field] = list(value or [])
        else:
            payload[field] = value
    return payload


def chain_message(prev_hash: str, payload_json: str) -> bytes:
    """``prev_hash + "\n" + canonical_json`` 的 UTF-8 字节。"""
    return f"{prev_hash}{facts.MESSAGE_SEPARATOR}{payload_json}".encode("utf-8")


def compute_hash_payload(key: bytes, prev_hash: str, payload: Mapping[str, Any]) -> str:
    """对**已归一**的 payload 计算链哈希（store 用它，避免重复归一）。"""
    return hmac.new(key, chain_message(prev_hash, canonical_json(payload)),
                    hashlib.sha256).hexdigest()


def compute_hash(key: bytes, prev_hash: str, entry: Mapping[str, Any]) -> str:
    """对一个条目计算链哈希（verify 用）。"""
    return compute_hash_payload(key, prev_hash, entry_payload(entry))


def matches(key: bytes, entry: Mapping[str, Any]) -> bool:
    """条目声明的 hash 是否可重算（常量时间比较）。"""
    expected = compute_hash(key, str(entry.get("prev_hash")), entry)
    return hmac.compare_digest(expected, str(entry.get("hash") or ""))


__all__ = [
    "canonical_ts",
    "canonical_json",
    "entry_payload",
    "chain_message",
    "compute_hash",
    "compute_hash_payload",
    "matches",
]
