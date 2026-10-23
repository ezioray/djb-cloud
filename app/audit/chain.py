# SPDX-License-Identifier: Apache-2.0
"""链校验内核（**纯函数**，无 DB / 无网络；append 与 verify 共用同一策略与算式）。

逐条重算，判定 6 件事（M16 §6.3 / INV-M16-01/02）：

1. ``alg`` 一致：每条都必须是 ``hmac-sha256``（声明被改成 sha256 = 算法降级）；
2. ``hash`` 可重算：``hmac_sha256(key, prev_hash + LF + canonical_json(entry))`` 与行内一致；
3. ``prev_hash`` 不掉链：第一条必须是 ``GENESIS``，之后每条指向上一条的 ``hash``；
4. 字段完整：信封字段齐备 + 高危动作的 6 个字段齐备（:mod:`app.audit.policy`）；
5. 审批链非自批：至少两人、``propose ≠ approve``、``approve ≠ execute``；
6. ``pending_approval`` 超时（默认 4h）：超时只报问题，**不自动放行**。

发现断链时只返回 ``broken_seq``（第一条断的位置）与 ``problems``，**绝不修链、绝不重算覆盖**。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from . import canonical, clock, facts, policy


@dataclass
class ChainReport:
    """校验结论（verify 响应的内部形态；``ok`` 决定是否允许封盘）。"""

    entries: int = 0
    key_available: bool = True
    problems: list[str] = field(default_factory=list)        # 链完整性 / 结构
    field_gaps: list[str] = field(default_factory=list)      # 字段完整性
    approval_problems: list[str] = field(default_factory=list)
    expired_pending: int = 0
    broken_seq: int | None = None

    @property
    def ok(self) -> bool:
        return (self.key_available and not self.problems and not self.field_gaps
                and not self.approval_problems and self.expired_pending == 0)

    def all_problems(self) -> list[str]:
        """展平成 spec ``AuditVerifyResponse.problems``（人类可读，不含密钥 / 正文）。"""
        return [*self.problems, *self.field_gaps, *self.approval_problems]


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


def _mark_broken(report: ChainReport, seq: Any) -> None:
    """记录**第一处**断链位置（后续问题照样收集，便于一次看全）。"""
    if report.broken_seq is None and isinstance(seq, int):
        report.broken_seq = seq


def verify_entries(entries: Iterable[Mapping[str, Any]], *, key: bytes | None,
                   expected_alg: str = facts.ALG, now: datetime | None = None,
                   pending_timeout: timedelta = facts.PENDING_TIMEOUT) -> ChainReport:
    """逐条校验整条链（``entries`` 必须按 seq 升序）."""
    report = ChainReport(key_available=key is not None)
    moment = clock.as_utc(now or clock.utcnow())
    if key is None:
        report.problems.append(
            "审计链 HMAC 密钥不可用（DJB_AUDIT_HMAC_KEY_FILE 未配置 / 不可读）："
            "fail-closed，无法校验，不视为通过")

    prev_hash = facts.GENESIS
    for entry in entries:
        report.entries += 1
        seq = entry.get("seq")
        declared_alg = entry.get("alg")

        # 1) 算法一致（先判算法：声明不是 hmac-sha256 就不能用 hmac 重算）
        if declared_alg != expected_alg:
            report.problems.append(
                f"seq={seq} 算法不一致：声明 {declared_alg!r}，期望 {expected_alg!r}（疑似降级重标）")
            _mark_broken(report, seq)
        elif key is not None:
            try:
                recomputed = canonical.compute_hash(key, str(entry.get("prev_hash")), entry)
            except (TypeError, ValueError) as exc:
                report.problems.append(f"seq={seq} 无法重算哈希（字段不可序列化：{exc}）")
                _mark_broken(report, seq)
            else:
                if recomputed != entry.get("hash"):
                    report.problems.append(
                        f"seq={seq} 行内哈希不匹配（内容被改动 / 密钥不符）")
                    _mark_broken(report, seq)

        # 2) 前向引用
        if entry.get("prev_hash") != prev_hash:
            report.problems.append(
                f"seq={seq} prev_hash 断链（期望 {str(prev_hash)[:12]}…，实际 "
                f"{str(entry.get('prev_hash'))[:12]}…）")
            _mark_broken(report, seq)
        prev_hash = entry.get("hash")

        # 3) 字段完整 + 高危字段 + 审批链
        for gap in policy.base_gaps(entry):
            report.field_gaps.append(f"seq={seq} {gap}")
        for gap in policy.high_risk_gaps(entry):
            report.field_gaps.append(f"seq={seq} {gap}")
        for problem in policy.approval_problems(entry):
            report.approval_problems.append(f"seq={seq} {problem}")

        # 4) 时间可解析 + pending 超时
        created = _as_datetime(entry.get("ts"))
        if created is None:
            report.field_gaps.append(f"seq={seq} ts 不可解析：{entry.get('ts')!r}")
        elif entry.get("status") == "pending_approval":
            deadline = created + pending_timeout
            if moment > deadline:
                report.expired_pending += 1
                report.problems.append(
                    f"seq={seq} pending_approval 已超时（{entry.get('action')}，"
                    f"截至 {deadline.isoformat()}）→ 必须置 expired，不得自动放行")
    return report


__all__ = ["ChainReport", "verify_entries"]
