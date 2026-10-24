# SPDX-License-Identifier: AGPL-3.0-or-later
"""规范化 JSON 与内容摘要（INV-01 / INV-08）。

INV-01：``content_digest = sha256(canonical_json({key, value, schema_ref, unit}))``，可复算。
INV-08：``policy_version = snapshot_digest 前 12 位``，配置变化必须换版本。

三条纪律：
  1. **规范形式唯一**：``sort_keys=True`` + 紧凑分隔符 + UTF-8 + 不允许 NaN/Infinity。
     同一份内容在任何机器、任何进程、任何 Python 版本上得到同一个 digest；
  2. **不接受非 JSON 类型**：Decimal / datetime / bytes / set 一律抛 :class:`TypeError`，
     不做「看起来合理」的隐式转换——digest 一旦能漂移，复算就失去意义；
  3. **只吃规范值**：值先过 :mod:`app.config_center.units` 规范化再算 digest；本模块不猜单位。

digest 用十六进制小写（64 字符），与数据库 CHECK ``^[0-9a-f]{64}$`` 对齐；
与 ``spec/openapi.yaml`` 的 ConfigItem / ConfigPublishAck 字段类型（字符串）一致。
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

__all__ = [
    "canonical_json",
    "sha256_hex",
    "version_digest",
    "request_digest",
    "snapshot_digest",
    "policy_version",
    "version_payload",
]

POLICY_VERSION_LEN = 12


def canonical_json(obj: Any) -> str:
    """规范化 JSON 文本（键排序、紧凑分隔、UTF-8、拒绝 NaN/Infinity 与非 JSON 类型）。"""
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise TypeError(f"值不是可规范化的 JSON：{exc}") from exc


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def version_payload(*, key: str, value: Any, schema_ref: str, unit: str) -> dict[str, Any]:
    """INV-01 的规范化载荷：字段集合与顺序固定为 4 个，多一个少一个都不算同一份内容。"""
    for name, item in (("key", key), ("schema_ref", schema_ref), ("unit", unit)):
        if not isinstance(item, str) or not item:
            raise TypeError(f"version 载荷的 {name} 必须是非空字符串：{item!r}")
    return {"key": key, "value": value, "schema_ref": schema_ref, "unit": unit}


def version_digest(*, key: str, value: Any, schema_ref: str, unit: str) -> str:
    """版本内容摘要（INV-01）：内容相同则 digest 相同（识别「改回去」与「抄错」）。"""
    return sha256_hex(canonical_json(version_payload(
        key=key, value=value, schema_ref=schema_ref, unit=unit)))


def request_digest(*, key: str, scope: str, scope_id: str, value: Any) -> str:
    """写请求载荷指纹（幂等键的「同键同载荷 / 同键不同载荷」判定，§3 唯一约束与幂等）。"""
    return sha256_hex(canonical_json({
        "key": key,
        "scope": scope,
        "scope_id": scope_id,
        "value": value,
    }))


def snapshot_digest(entries: Iterable[Mapping[str, Any]]) -> str:
    """快照摘要（INV-08）：entries 覆盖全部 active key，顺序不影响结果。

    每个 entry 至少含 ``key`` / ``scope`` / ``scope_id`` / ``version`` / ``content_digest``；
    多出的字段（例如 ``value_type``）不参与 digest，避免「加字段 = 换 policy_version」，
    让 INV-08 的「配置变化必须换版本」只在**值**变化时触发。
    """
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        try:
            item = {
                "key": entry["key"],
                "scope": entry["scope"],
                "scope_id": entry["scope_id"],
                "version": int(entry["version"]),
                "content_digest": entry["content_digest"],
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise TypeError(f"快照 entry 字段不全或类型错：{entry!r}（{exc}）") from exc
        if (not isinstance(item["content_digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["content_digest"])):
            raise TypeError(f"快照 entry 的 content_digest 非法：{item['content_digest']!r}")
        normalized.append(item)
    if not normalized:
        raise ValueError("快照 entries 不能为空（INV-08：必须覆盖全部 active key）")
    normalized.sort(key=lambda item: (item["key"], item["scope"], item["scope_id"]))
    keys = [(item["key"], item["scope"], item["scope_id"]) for item in normalized]
    if len(set(keys)) != len(keys):
        raise ValueError(f"快照 entries 有重复 key/scope：{len(keys) - len(set(keys))} 条")
    return sha256_hex(canonical_json({"entries": normalized}))


def policy_version(digest: str) -> str:
    """policy_version = snapshot_digest 前 12 位（INV-08）。"""
    if not isinstance(digest, str) or len(digest) < POLICY_VERSION_LEN:
        raise ValueError(f"digest 非法：{digest!r}")
    return digest[:POLICY_VERSION_LEN]
