# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 注册表：内置初始版本 + payload 规范化 + 差异 + wire 视图（**纯函数，不碰 DB**）。

为什么内置：S2 还没有厂商适配器（§12 S3 才做自动采集），服务端必须先有一份**可复算**的
初始注册表，客户端/门户才能拿到同一份清单。内置条目的 tokenizer 用
``family / version / hash`` 三元组表示——**hash 是 family+version 的 sha256 占位**，
不是厂商 tokenizer 权重，也不含任何密钥（§2「不做」/ §10）。
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from . import facts
from .errors import BadRequest

__all__ = [
    "BUILTIN_MODELS", "canonical_json", "payload_hash_of", "normalize_models",
    "build_payload", "diff_models", "node_models", "catalog_payload", "bundle_summary",
    "tokenizer_hash_of",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def tokenizer_hash_of(family: str, version: str) -> str:
    """占位指纹：``sha256("family|version")``（可复算、非厂商权重、无密钥）。"""
    return hashlib.sha256(f"{family}|{version}".encode("utf-8")).hexdigest()


def _builtin(vendor: str, canonical: str, aliases: Sequence[str], context_window: int,
             family: str, version: str, effective_at: str) -> dict[str, Any]:
    return {
        "vendor": vendor,
        "canonical": canonical,
        "aliases": list(aliases),
        "context_window": int(context_window),
        "tokenizer_family": family,
        "tokenizer_version": version,
        "tokenizer_hash": tokenizer_hash_of(family, version),
        "effective_at": effective_at,
        "source": "sdk",
        "state": "active",
    }


#: 内置初始注册表（demo 厂商/模型；**不含任何真实凭据或厂商权重**）
BUILTIN_MODELS: tuple[dict[str, Any], ...] = (
    _builtin("openai", "gpt-4o-mini", ["gpt-4o-mini-2024-07-18"], 128_000,
             "o200k_base", "2024-07", "2024-07-18T00:00:00.000Z"),
    _builtin("openai", "gpt-4o", ["gpt-4o-2024-08-06"], 128_000,
             "o200k_base", "2024-08", "2024-08-06T00:00:00.000Z"),
    _builtin("anthropic", "claude-3-5-sonnet", ["claude-3-5-sonnet-20241022"], 200_000,
             "claude", "2024-10", "2024-10-22T00:00:00.000Z"),
    _builtin("deepseek", "deepseek-chat", ["deepseek-v3", "deepseek-chat-v3"], 64_000,
             "deepseek", "2024-12", "2024-12-26T00:00:00.000Z"),
    _builtin("qwen", "qwen2.5-72b-instruct", ["qwen-max", "qwen2.5-max"], 32_768,
             "qwen", "2024-09", "2024-09-19T00:00:00.000Z"),
    _builtin("glm", "glm-4-plus", [], 128_000,
             "glm", "2024-08", "2024-08-29T00:00:00.000Z"),
)
"""内置 6 条（4 家厂商 + 1 条无别名）。**只描述元数据**：tokenizer_hash 是占位指纹。"""


# ───────────────────────────────────────────────────────── 校验
def _require_text(value: Any, *, field: str, max_len: int = facts.MAX_FIELD_LEN) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRequest(f"{field} 必填", field=field)
    text = value.strip()
    if len(text) > max_len:
        raise BadRequest(f"{field} 超长（≤{max_len}）", field=field)
    return text


def _require_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequest(f"{field} 必须是整数", field=field)
    if not minimum <= value <= maximum:
        raise BadRequest(f"{field} 必须在 {minimum}–{maximum} 之间", field=field)
    return int(value)


def _require_hex64(value: Any, *, field: str) -> str:
    text = _require_text(value, field=field, max_len=facts.TOKENIZER_HASH_LEN)
    if not _HEX64.match(text):
        raise BadRequest(f"{field} 必须是 64 位十六进制（sha256）", field=field)
    return text


def _normalize_moment(value: Any, *, field: str) -> str:
    """ISO8601 → UTC，毫秒精度，``Z`` 结尾（payload_hash 可复算的第一前提）。"""
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise BadRequest(f"{field} 必须是 ISO8601 时间", field=field) from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
    else:
        raise BadRequest(f"{field} 必须是 ISO8601 时间", field=field)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalize_aliases(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise BadRequest(f"{field} 必须是字符串数组", field=field)
    if len(value) > facts.MAX_ALIASES:
        raise BadRequest(f"{field} 最多 {facts.MAX_ALIASES} 个", field=field)
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_require_text(item, field=f"{field}[{index}]"))
    return sorted(dict.fromkeys(result))


def normalize_models(models: Any) -> list[dict[str, Any]]:
    """校验并归一化一组模型版本；按 ``(vendor, canonical, effective_at)`` 排序。"""
    if not isinstance(models, (list, tuple)) or not models:
        raise BadRequest("models 必须是非空数组", field="models")
    if len(models) > facts.MAX_MODELS:
        raise BadRequest(f"models 最多 {facts.MAX_MODELS} 条", field="models")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, item in enumerate(models):
        if not isinstance(item, Mapping):
            raise BadRequest(f"models[{index}] 必须是对象", field=f"models[{index}]")
        state = item.get("state") or "active"
        if state not in facts.MODEL_STATES:
            raise BadRequest(f"models[{index}].state 必须是 "
                             f"{'/'.join(facts.MODEL_STATES)} 之一",
                             field=f"models[{index}].state")
        source = item.get("source") or "sdk"
        if source not in facts.MODEL_SOURCES:
            raise BadRequest(f"models[{index}].source 必须是 "
                             f"{'/'.join(facts.MODEL_SOURCES)} 之一",
                             field=f"models[{index}].source")
        entry = {
            "vendor": _require_text(item.get("vendor"), field=f"models[{index}].vendor"),
            "canonical": _require_text(item.get("canonical"),
                                       field=f"models[{index}].canonical"),
            "aliases": _normalize_aliases(item.get("aliases"), field=f"models[{index}].aliases"),
            "context_window": _require_int(item.get("context_window"),
                                           field=f"models[{index}].context_window",
                                           minimum=1, maximum=100_000_000),
            "tokenizer_family": _require_text(item.get("tokenizer_family"),
                                              field=f"models[{index}].tokenizer_family"),
            "tokenizer_version": _require_text(item.get("tokenizer_version"),
                                               field=f"models[{index}].tokenizer_version"),
            "tokenizer_hash": _require_hex64(item.get("tokenizer_hash"),
                                             field=f"models[{index}].tokenizer_hash"),
            "effective_at": _normalize_moment(item.get("effective_at"),
                                              field=f"models[{index}].effective_at"),
            "source": source,
            "state": state,
        }
        key = (entry["vendor"], entry["canonical"], entry["effective_at"])
        if key in seen:
            raise BadRequest(f"models[{index}] 与前面的条目重复（vendor+canonical+effective_at）",
                             field=f"models[{index}].effective_at")
        seen.add(key)
        result.append(entry)
    return sorted(result, key=lambda entry: (entry["vendor"], entry["canonical"],
                                             entry["effective_at"]))


# ───────────────────────────────────────────────────────── payload / hash
def canonical_json(payload: Any) -> bytes:
    """canonical JSON：键排序 + 紧凑分隔 + 不转义非 ASCII（payload_hash 可复算）。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def payload_hash_of(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def build_payload(models: Iterable[Mapping[str, Any]], *, version: int,
                  expires_at: str) -> dict[str, Any]:
    """bundle payload = **恰好** ``{version, expires_at, models}``（M18b 客户端同口径）。

    * ``models`` 每项只取 8 个字段（:func:`node_model`），顺序不影响 hash（``sort_keys``）；
    * 只有这三个键参与 ``payload_hash``——加键就会让客户端复算出来的 hash 不一致，
      因此**不要**在这里塞 ``format`` / 时间戳之外的东西（要加就先改客户端与 spec）。
    """
    normalized = normalize_models(list(models))
    return {"version": int(version), "expires_at": expires_at,
            "models": [node_model(entry) for entry in normalized]}


def node_model(entry: Mapping[str, Any]) -> dict[str, Any]:
    """wire 形状（lead 1.2.12）：8 个字段，一个不多一个不少。"""
    return {
        "vendor": entry["vendor"],
        "canonical": entry["canonical"],
        "aliases": list(entry.get("aliases") or []),
        "context_window": int(entry["context_window"]),
        "tokenizer_family": entry["tokenizer_family"],
        "tokenizer_version": entry["tokenizer_version"],
        "tokenizer_hash": entry["tokenizer_hash"],
        "effective_at": entry["effective_at"],
    }


def node_models(models: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [node_model(entry) for entry in models]


# ───────────────────────────────────────────────────────── 差异
def diff_models(previous: Iterable[Mapping[str, Any]],
                current: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """按 ``(vendor, canonical)`` 比对，返回 ``{added, removed, changed}``（后台列表用）。"""
    before = {(item["vendor"], item["canonical"]): item for item in previous}
    after = {(item["vendor"], item["canonical"]): item for item in current}
    added = sorted(f"{vendor}/{canonical}" for vendor, canonical in after.keys() - before.keys())
    removed = sorted(f"{vendor}/{canonical}" for vendor, canonical in before.keys() - after.keys())
    changed = sorted(
        f"{vendor}/{canonical}" for vendor, canonical in before.keys() & after.keys()
        if node_model(before[(vendor, canonical)]) != node_model(after[(vendor, canonical)]))
    return {"added": added, "removed": removed, "changed": changed}


# ───────────────────────────────────────────────────────── wire（node / admin）
def catalog_payload(bundle: Mapping[str, Any] | None, *, since: int | None) -> dict[str, Any]:
    """node catalog 200 响应（**lead 1.2.12 形状，一个不多一个不少**）：

    ``{version, payload_hash, signature, expires_at, not_modified, models}``。

    ``bundle`` 为空（未发布 / 开关关闭）→ 内置回退：``version=0`` + ``not_modified=true``
    + ``models=[]``（客户端保留本地内置表，不伪造版本）。
    ``since`` >= 当前版本 → ``not_modified=true`` 且不回传 models（省带宽）。
    """
    if bundle is None:
        return {"version": 0, "payload_hash": None, "signature": None, "expires_at": None,
                "not_modified": True, "models": []}
    version = int(bundle["version"])
    not_modified = since is not None and int(since) >= version
    payload = dict(bundle.get("payload") or {})
    return {
        "version": version,
        "payload_hash": bundle["payload_hash"],
        "signature": bundle.get("signature"),
        "expires_at": _iso(bundle.get("expires_at")),
        "not_modified": bool(not_modified),
        "models": [] if not_modified else list(payload.get("models") or []),
    }


def _iso(moment: Any) -> str | None:
    """DB timestamptz → UTC ISO-Z 毫秒（wire 只出现这一种时间形态）。"""
    if moment is None:
        return None
    from .clock import iso

    return iso(moment)


def bundle_summary(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """后台列表项（只暴露元数据；payload 另按需给 hash/模型数）。"""
    payload = dict(bundle.get("payload") or {})
    return {
        "bundle_id": str(bundle["id"]),
        "version": int(bundle["version"]),
        "state": bundle["state"],
        "source": bundle["source"],
        "payload_hash": bundle["payload_hash"],
        "signature": bundle.get("signature"),
        "published_at": _iso(bundle.get("published_at")),
        "expires_at": _iso(bundle.get("expires_at")),
        "created_at": _iso(bundle.get("created_at")),
        "models_count": len(payload.get("models") or []),
    }
