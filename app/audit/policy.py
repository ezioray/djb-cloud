# SPDX-License-Identifier: AGPL-3.0-or-later
"""审计策略（append 与 verify **共用一份**，避免两侧集合漂移 —— 对应 ops/audit/policy.mjs）。

判定口径（M16 INV-M16-02 / §6.3）：

1. **高危动作** = 动作名命中 ``HIGH_RISK_ACTION``，**或**携带 ``reason_code``（有理由码就是高危），
   **或**带 ``approval_chain``（走审批就是高危），**或**状态不是 ``recorded``（审批类）。
   这是"更严"的方向：宁可多要求字段，也不放过一条缺证据的高危事实。
2. 高危必须有 ``reason_code`` / ``ticket`` / ``actor_type`` / ``role`` / ``before`` / ``after``。
3. 审批链至少两人、``propose ≠ approve``、``approve ≠ execute``；复核类动作
   （``approve.`` / ``authorize.`` / ``execute.`` / ``release.``）必须有 propose + approve。

同一个函数既被 :mod:`app.audit.store` 用来**拒绝写入**，也被 :mod:`app.audit.chain`
用来**校验历史**——所以"写得进去的，就一定能验得过去"。
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from . import facts

#: 字段缺失判定里视为"空"的旗标占位（与 ops/audit/policy.mjs 的 'true' 规则一致）
_EMPTY_VALUES: tuple[Any, ...] = (None, "", "true")

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def action_is_high_risk(action: Any) -> bool:
    """只看动作名的判定（与 policy.mjs ``isHighRisk`` 一致）。"""
    return bool(facts.HIGH_RISK_ACTION.match(str(action or "")))


def is_high_risk(entry: Mapping[str, Any]) -> bool:
    """条目级高危判定：动作名 / reason_code / 审批链 / 非 recorded 状态，任一命中即高危。"""
    if action_is_high_risk(entry.get("action")):
        return True
    if entry.get("reason_code") not in (None, ""):
        return True
    if entry.get("approval_chain"):
        return True
    status = entry.get("status")
    return status not in (None, facts.DEFAULT_STATUS)


def high_risk_gaps(entry: Mapping[str, Any]) -> list[str]:
    """高危条目的必填字段缺口（返回人类可读清单，空列表 = 齐全）。"""
    if not is_high_risk(entry):
        return []
    gaps: list[str] = []
    for field in facts.HIGH_RISK_REQUIRED:
        value = entry.get(field)
        if field in ("before", "after"):
            if value is None:
                gaps.append(f"缺字段 {field}（高危动作必须有 {field} 快照）")
            elif not isinstance(value, dict):
                gaps.append(f"字段 {field} 必须是 JSON 对象")
        elif value in _EMPTY_VALUES:
            gaps.append(f"缺有效字段 {field}")
    return gaps


def _chain_decisions(entry: Mapping[str, Any]) -> tuple[list[str], dict[str, set[str]]]:
    """解析审批链：返回（结构问题清单，decision → 参与人集合）。"""
    problems: list[str] = []
    actors: dict[str, set[str]] = {decision: set() for decision in facts.DECISIONS}
    chain = entry.get("approval_chain")
    if chain in (None, []):
        return problems, actors
    if not isinstance(chain, list):
        return ["approval_chain 必须是数组"], actors
    for index, item in enumerate(chain):
        if not isinstance(item, Mapping):
            problems.append(f"approval_chain[{index}] 必须是对象")
            continue
        actor = item.get("actor")
        decision = item.get("decision")
        if not isinstance(actor, str) or not actor.strip():
            problems.append(f"approval_chain[{index}] 缺 actor")
            continue
        if decision not in facts.DECISIONS:
            problems.append(f"approval_chain[{index}] decision 非法：{decision!r}")
            continue
        actors[decision].add(actor.strip())
    return problems, actors


def approval_problems(entry: Mapping[str, Any]) -> list[str]:
    """审批链问题清单（自批自核 / 人数不足 / 复核类动作缺审批）——append 拒写，verify 报警。"""
    problems, actors = _chain_decisions(entry)
    chain = entry.get("approval_chain") or []
    people: set[str] = set()
    for decision_actors in actors.values():
        people |= decision_actors

    if chain:
        if len(people) < 2:
            problems.append(f"审批链至少两人（当前 {len(people)} 人）：propose / approve 必须不同人")

    for actor in sorted(actors["propose"] & actors["approve"]):
        problems.append(f"自批自核：actor {actor} 既 propose 又 approve")
    for actor in sorted(actors["approve"] & actors["execute"]):
        problems.append(f"复核与执行同人：actor {actor} 既 approve 又 execute")

    action = str(entry.get("action") or "")
    if facts.APPROVAL_ACTION.match(action):
        if not chain:
            problems.append(f"复核类动作 {action} 必须有 approval_chain（propose + approve，两人以上）")
        else:
            if not actors["propose"]:
                problems.append(f"复核类动作 {action} 的审批链缺 propose")
            if not actors["approve"]:
                problems.append(f"复核类动作 {action} 的审批链缺 approve")
    return problems


def base_gaps(entry: Mapping[str, Any]) -> list[str]:
    """所有条目都必须齐备的信封字段（spec AuditEntry.required + 链形状）。"""
    gaps: list[str] = []
    for field in ("actor", "actor_type", "role", "action", "target", "status", "alg",
                  "prev_hash", "hash"):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            gaps.append(f"缺有效字段 {field}")
    if entry.get("seq") is None:
        gaps.append("缺字段 seq")
    if not entry.get("entry_id"):
        gaps.append("缺字段 entry_id")
    if entry.get("ts") is None:
        gaps.append("缺字段 ts")

    if entry.get("actor_type") is not None and entry.get("actor_type") not in facts.ACTOR_TYPES:
        gaps.append(f"actor_type 非法：{entry.get('actor_type')!r}")
    if entry.get("status") is not None and entry.get("status") not in facts.STATUSES:
        gaps.append(f"status 非法：{entry.get('status')!r}")
    # 算法一致性由 chain.verify_entries 统一判定（避免两处重复报同一个问题）

    prev_hash = entry.get("prev_hash")
    if isinstance(prev_hash, str) and prev_hash != facts.GENESIS and not _HASH_RE.match(prev_hash):
        gaps.append("prev_hash 形状非法（应为 GENESIS 或 64 位小写 hex）")
    hash_value = entry.get("hash")
    if isinstance(hash_value, str) and hash_value and not _HASH_RE.match(hash_value):
        gaps.append("hash 形状非法（应为 64 位小写 hex）")
    return gaps


def entry_problems(entry: Mapping[str, Any]) -> list[str]:
    """verify 用：单条条目的全部策略问题（信封 + 高危字段 + 审批链）。"""
    problems = base_gaps(entry)
    problems.extend(high_risk_gaps(entry))
    problems.extend(approval_problems(entry))
    return problems


def validate_new_entry(draft: Mapping[str, Any]) -> None:
    """append 用：策略不通过就不写链。高危字段缺失 → 40001；自批 / 人数不足 → 40901。"""
    from . import errors                          # 局部导入：errors 不反向依赖 policy

    gaps = high_risk_gaps(draft)
    if gaps:
        raise errors.InvalidArgument(
            "高危动作字段不全，拒绝写入：" + "；".join(gaps),
            reason="high_risk_fields_missing", gaps=gaps)

    problems = approval_problems(draft)
    if problems:
        raise errors.Conflict("审批链不合法，拒绝写入：" + "；".join(problems),
                              reason="approval_chain_invalid", problems=problems)


__all__ = [
    "action_is_high_risk",
    "is_high_risk",
    "high_risk_gaps",
    "approval_problems",
    "base_gaps",
    "entry_problems",
    "validate_new_entry",
]
