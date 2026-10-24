# SPDX-License-Identifier: AGPL-3.0-or-later
"""链校验 + 日根封盘（``POST /internal/ops/audit/verify``，等价于 ``ops/audit/verify.mjs --seal``）。

行为（M16 §6.3 / spec-1.2.2 ``AuditVerifyResponse``）：

* 逐条重算 hash、校验 prev_hash / alg / 字段完整 / 审批链非自批 / ``pending_approval`` 超时；
* 断链时返回 ``ok=false`` + ``broken_seq`` + ``problems``，**不修链、不重算覆盖**（M16 §7「不修链重算」）；
* 密钥不可用 → ``ok=false``（不静默通过，也不抛 5xx 让调用方误以为"暂时性故障"）；
* ``seal=true`` 则按 **UTC 日**算 Merkle 根并幂等写 ``audit_anchors``：
  同日重复调用返回同一 ``merkle_root``；**链不干净时拒绝封盘**（不把可疑链固化成锚点）；
* 已封盘根与重算不一致 → 报问题（链在封盘后被改动），不覆盖既有锚点。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from . import chain, clock, errors, facts, keys, merkle, models, store


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return clock.as_utc(value)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        normalised = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            return clock.as_utc(datetime.fromisoformat(normalised))
        except ValueError:
            return None
    return None


def verify_chain(c: Any, *, key_provider: Any, period: str | None = None, seal: bool = False,
                 expected_alg: str | None = None, now: Any = None,
                 pending_timeout: Any = facts.PENDING_TIMEOUT,
                 evidence_ref: str | None = None) -> dict[str, Any]:
    """校验整条链（可选封盘），返回 spec ``AuditVerifyResponse`` 的字段集合。"""
    moment = clock.as_utc(now or clock.utcnow())
    day = models.parse_period(period, default_day=clock.day_of(moment))
    expected = expected_alg or facts.ALG
    if expected != facts.ALG:
        raise errors.InvalidArgument(
            f"expected_alg 只支持 {facts.ALG}（算法固定，不接受降级）", field="expected_alg")

    key = keys.read_key(key_provider)
    entries = store.fetch_all(c)
    report = chain.verify_entries(entries, key=key, expected_alg=expected, now=moment,
                                  pending_timeout=pending_timeout)

    day_entries = []
    for entry in entries:
        created = _as_datetime(entry.get("ts"))
        if created is not None and clock.day_of(created) == day:
            day_entries.append(entry)
    root = merkle.merkle_root([str(entry["hash"]) for entry in day_entries])

    problems = report.all_problems()
    seal_problems: list[str] = []
    sealed = False
    anchor: Mapping[str, Any] | None = None
    if seal:
        if not report.ok:
            seal_problems.append("链校验未通过：拒绝封盘（不把可疑链固化成锚点，先按 P0 处置）")
        else:
            first_seq = day_entries[0]["seq"] if day_entries else None
            last_seq = day_entries[-1]["seq"] if day_entries else None
            anchor, created = store.insert_anchor(
                c, period=day, merkle_root=root, sealed_at=moment, alg=expected,
                evidence_ref=evidence_ref, entry_count=len(day_entries),
                first_seq=first_seq, last_seq=last_seq)
            if anchor["merkle_root"] != root:
                seal_problems.append(
                    f"period {day} 已封盘的 Merkle 根与重算不一致"
                    f"（锚点 {anchor['merkle_root'][:12]}… ≠ 重算 {root[:12]}…）："
                    "链在封盘后被改动，按 P0 处置，不覆盖锚点")
            else:
                sealed = True
            if not created:
                # 幂等：同日重复封盘返回首次根（sealed=True 表示"当前已封盘"）
                sealed = anchor["merkle_root"] == root

    return {
        "ok": report.ok and not seal_problems,
        "period": day,
        "entries": report.entries,
        "alg": expected,
        "checked_at": clock.iso_micros(moment),
        "merkle_root": root,
        "sealed": sealed,
        "broken_seq": report.broken_seq,
        "expired_pending": report.expired_pending,
        "problems": [*problems, *seal_problems],
        "period_entries": len(day_entries),
        "anchor": None if anchor is None else {
            "period": anchor["period"],
            "merkle_root": anchor["merkle_root"],
            "sealed_at": clock.iso_micros(anchor["sealed_at"]),
            "entry_count": anchor["entry_count"],
        },
    }


__all__ = ["verify_chain"]
