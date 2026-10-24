# SPDX-License-Identifier: AGPL-3.0-or-later
"""凭证哈希链：规范化 → 计算 → 校验（journal_entry.prev_hash / hash）。

链的定义（T2 落账与 T4 复算共用这一份实现，不允许各写一套）::

    hash = sha256( canonical_json({"prev": <上一凭证 hash 的十六进制 | "GENESIS">,
                                   "journal": <payload>}) )

    payload = {unit_type, event_type, source_type, source_id, event_seq,
               policy_version, fx_rate_id, lines: [
                   {line_no, account_id, coa_code, dc, amount_minor, qty_minor,
                    unit_scale, fund_class} ...]}

设计取舍：
  · ``journal_id`` / ``ts`` 不进 payload：前者是随机 UUID、后者是墙钟，都不属于"账务内容"，
    排除后「同样内容 + 同一 prev」必然得到同一 hash —— 一旦出现重复即等于链分叉，
    会被 ``journal_entry_hash_uq``（600 迁移）直接拒绝；
  · ``prev`` 用十六进制字符串、链首用 "GENESIS"（与 001 旧链的写法保持一致，便于对账）；
  · 规范化 JSON：键排序、无多余空格、UTF-8（``ensure_ascii=False``），跨语言可复现。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

from .constants import HASH_ALGO, HASH_LEN

GENESIS = "GENESIS"

_PAYLOAD_VERSION = 1


def line_payload(line: Any, line_no: int | None = None) -> dict:
    """取一行的可哈希字段（getattr 兼容 dataclass / Mapping / 数据库行）。

    写入时的 JournalLine 不带 line_no（行号由网关按顺序分配），所以允许传入序号兜底；
    读回校验时行自带 line_no，直接用它 —— 两种来源必须落在同一个规范形式上。
    """
    get = line.get if isinstance(line, Mapping) else lambda key, d=None: getattr(line, key, d)
    number = get("line_no", None)
    if number is None:
        if line_no is None:
            raise ValueError("line_payload 需要 line_no（行对象没带，调用方也没给序号）")
        number = line_no
    return {
        "line_no": int(number),
        "account_id": str(get("account_id")),
        "coa_code": str(get("coa_code")),
        "dc": str(get("dc")),
        "amount_minor": int(get("amount_minor")),
        "qty_minor": None if get("qty_minor") is None else int(get("qty_minor")),
        "unit_scale": int(get("unit_scale")),
        "fund_class": str(get("fund_class")),
    }


def canonical_payload(*, unit_type: str, event_type: str, source_type: str, source_id: str,
                      event_seq: int, policy_version: str, fx_rate_id: int,
                      lines: Iterable[Any]) -> dict:
    return {
        "v": _PAYLOAD_VERSION,
        "unit_type": unit_type,
        "event_type": event_type,
        "source_type": source_type,
        "source_id": source_id,
        "event_seq": int(event_seq),
        "policy_version": policy_version,
        "fx_rate_id": int(fx_rate_id),
        "lines": [line_payload(line, index) for index, line in enumerate(lines, start=1)],
    }


def canonical_bytes(payload: Mapping) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def journal_hash(prev_hash: bytes | None, payload: Mapping) -> bytes:
    """链上哈希：sha256(canonical({"prev": …, "journal": payload}))，返回 32 字节。"""
    if prev_hash is not None and len(bytes(prev_hash)) != HASH_LEN:
        raise ValueError(f"prev_hash 必须是 {HASH_LEN} 字节或 None")
    body = {"prev": GENESIS if prev_hash is None else bytes(prev_hash).hex(), "journal": payload}
    return hashlib.new(HASH_ALGO, canonical_bytes(body)).digest()


def verify_chain(conn) -> dict:
    """全量校验新账本的 hash 链（只读；T4 复算会在此之上展开余额与 Merkle）。

    返回 ``{"journals", "chain_bad", "hash_bad", "diff"}``：
      · ``chain_bad`` = prev_hash 与上一条 hash 不一致的 seq（断链 / 乱序）
      · ``hash_bad``  = 重算 hash 与库内 hash 不一致的 seq（内容被改过）
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT seq, journal_id, prev_hash, hash, unit_type, event_type, source_type,
                      source_id, event_seq, policy_version, fx_rate_id
                 FROM journal_entry ORDER BY seq""")
        journals = cur.fetchall()
        cur.execute(
            """SELECT journal_id, line_no, account_id, coa_code, dc, amount_minor, qty_minor,
                      unit_scale, fund_class
                 FROM journal_line ORDER BY journal_id, line_no""")
        lines_by_journal: dict[str, list[dict]] = {}
        for row in cur.fetchall():
            journal_id, line_no, account_id, coa_code, dc, amount_minor, qty_minor, unit_scale, fund_class = row
            lines_by_journal.setdefault(str(journal_id), []).append({
                "line_no": line_no, "account_id": account_id, "coa_code": coa_code, "dc": dc,
                "amount_minor": amount_minor, "qty_minor": qty_minor,
                "unit_scale": unit_scale, "fund_class": fund_class,
            })

    prev: bytes | None = None
    chain_bad: list[int] = []
    hash_bad: list[int] = []
    for (seq, journal_id, prev_hash, digest, unit_type, event_type, source_type, source_id,
         event_seq, policy_version, fx_rate_id) in journals:
        stored_prev = None if prev_hash is None else bytes(prev_hash)
        if stored_prev != prev:
            chain_bad.append(seq)
        payload = canonical_payload(
            unit_type=unit_type, event_type=event_type, source_type=source_type,
            source_id=source_id, event_seq=event_seq, policy_version=policy_version,
            fx_rate_id=fx_rate_id, lines=lines_by_journal.get(str(journal_id), []))
        if journal_hash(stored_prev, payload) != bytes(digest):
            hash_bad.append(seq)
        prev = bytes(digest)

    return {"journals": len(journals), "chain_bad": chain_bad, "hash_bad": hash_bad,
            "diff": len(chain_bad) + len(hash_bad)}


def hash_hex(value: bytes | None) -> str | None:
    return None if value is None else bytes(value).hex()
