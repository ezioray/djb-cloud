# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 处置审计钩子（INV-07：处置动作必须同时写审计并留 decision 理由）。

本模块**不拥有** audit_log（M16）：S1 只定义记录形状与注入点，合并期由 Lead 注入
``audit_sink``（M16 ``audit.append`` 适配器）。约定：

* ``sink`` 在**业务事务内**调用——sink 抛错 = 业务回滚（fail-closed，不会出现「处置了但没审计」）；
* 记录只放 id / 动作 / 理由 / 主体标识，不放阈值、不放 PII、不放请求正文；
* 未接线 sink 时返回 ``False``（S1 现状，写进证据遗留项），但 decision 理由与 outbox
  提案事件始终落库，审计追溯链不丢。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock

__all__ = ["AuditRecord", "emit"]

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
            "producer": "M11",
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
    """调用注入的审计 sink；未接线返回 False（不静默丢理由——理由已在 decision 里）。"""
    if sink is None:
        return False
    sink(record.as_dict())
    return True
