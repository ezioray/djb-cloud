# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 审计钩子（INV-08：审计唯一权威在 M16，M14 只追加读、不建第二条链）。

``sink`` 在**业务事务内**调用：sink 抛错 = 业务回滚（fail-closed，不会出现
「导出了但没审计」）。未接线时返回 ``False``（S1 现状写进证据），但事件 outbox
与业务状态仍落库，追溯链不丢。记录只放 id / 动作 / 理由，不放 PII / 签名 / 正文。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock

__all__ = ["AuditRecord", "AuditSink", "emit"]

AuditSink = Callable[[Mapping[str, Any]], Any]


@dataclass(frozen=True)
class AuditRecord:
    action: str
    object_type: str
    object_id: str
    actor: str
    reason: str
    occurred_at: datetime
    details: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "producer": "M14",
            "action": self.action,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "actor": self.actor,
            "reason": self.reason,
            "occurred_at": clock.iso(self.occurred_at),
        }
        payload.update({key: value for key, value in self.details.items()
                        if value is not None})
        return payload


def emit(sink: AuditSink | None, record: AuditRecord) -> bool:
    if sink is None:
        return False
    sink(record.as_dict())
    return True
