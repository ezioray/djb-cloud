# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08 管理面审计钩子（M16 audit_log 的注入点；本模块不拥有审计表）。

约定（与 M11 同款）：

* sink 在**业务事务内**调用：sink 抛错 = 业务回滚（fail-closed，不会「动了钱没审计」）；
* 记录只放 id / 动作 / 理由 / 主体标识 / 金额，不放密钥 / 完整报文 / PII；
* 未接线时返回 False（S1 现状，写进证据），业务事实仍在 outbox / 业务表里。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock

__all__ = ["AuditRecord", "emit", "AuditSink"]

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
            "producer": "M08",
            "action": self.action,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "actor": self.actor,
            "reason": self.reason,
            "occurred_at": clock.iso(self.occurred_at),
        }
        payload.update({key: value for key, value in self.details.items() if value is not None})
        return payload


def emit(sink: AuditSink | None, record: AuditRecord) -> bool:
    if sink is None:
        return False
    sink(record.as_dict())
    return True
