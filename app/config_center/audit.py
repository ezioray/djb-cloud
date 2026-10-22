# SPDX-License-Identifier: Apache-2.0
"""M16 审计接入（T5）：只定义接口 + 本地测试 sink，**不持有任何审计链凭据**。

M10 §1「不做」：不拥有 audit_log / audit_anchors，不直接写审计表，只调审计 API。
因此本模块提供：

* :class:`AuditEvent` —— 配置动作的审计事实（动作 / 主体 / 键 / 版本 / 结果 / 前后值 / trace）；
* :class:`AuditSink` 协议 —— 生产实现由 M16 注入（HMAC append 的 HTTP 客户端）；
* :class:`NullAuditSink` / :class:`InMemoryAuditSink` —— 默认空实现与测试用记录器；
* :func:`emit` —— 统一调用点：sink 抛错一律转 :class:`AuditUnavailable`（发布失败并回滚）。

**安全边界**：本仓库不写审计链、不读审计密钥、不实现 HMAC；测试 sink 只在内存里记事件。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, runtime_checkable

from .errors import AuditUnavailable

__all__ = [
    "ACTIONS",
    "AuditEvent",
    "AuditSink",
    "NullAuditSink",
    "InMemoryAuditSink",
    "emit",
    "build_event",
]

#: 本模块会写审计的动作（加值属 MINOR；M16 按 action 建索引）
ACTIONS: tuple[str, ...] = (
    "config.draft.created",
    "config.publish.requested",
    "config.publish.approved",
    "config.publish.rejected",
    "config.published",
    "config.rolled_back",
    "config.rollback.requested",
    "config.kill_switch",
    "config.closed",
    "config.cancelled",
    "config.promoted",
    "config.drift.detected",
    "config.drift.resolved",
)


@dataclass(frozen=True)
class AuditEvent:
    """一条配置审计事实（不含明文敏感值：before/after 由调用方脱敏）。"""

    action: str
    actor: str
    key: str
    scope: str = "global"
    scope_id: str = ""
    version: int | None = None
    request_id: str | None = None
    outcome: str = "success"
    reason: str | None = None
    before: Any = None
    after: Any = None
    trace_id: str | None = None
    occurred_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        if self.action not in ACTIONS:
            raise ValueError(f"未登记的审计动作：{self.action!r}")
        moment = self.occurred_at or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise ValueError("occurred_at 必须带时区")
        return {
            "action": self.action,
            "actor": self.actor,
            "key": self.key,
            "scope": self.scope,
            "scope_id": self.scope_id,
            "version": self.version,
            "request_id": self.request_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "before": self.before,
            "after": self.after,
            "trace_id": self.trace_id,
            "occurred_at": moment.astimezone(timezone.utc).isoformat(),
            "metadata": dict(self.metadata),
        }


@runtime_checkable
class AuditSink(Protocol):
    """审计写入端（生产 = M16 audit API 的 HMAC append 客户端）。"""

    def append(self, event: AuditEvent) -> str | None:
        """返回审计引用（audit_id / hash），失败抛异常。"""


class NullAuditSink:
    """默认空实现：不落审计（本地/未注入 M16 时的安全缺省）。"""

    def append(self, event: AuditEvent) -> str | None:
        return None


class InMemoryAuditSink:
    """测试 / 本地演练用的记录器（内存，不写生产链）。"""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, event: AuditEvent) -> str | None:
        payload = event.as_payload()
        self.events.append(payload)
        return f"mem:{len(self.events)}"

    def query(self, key: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = [row for row in self.events if key is None or row["key"] == key]
        return rows[-limit:][::-1]


def emit(sink: AuditSink | None, event: AuditEvent) -> str | None:
    """统一调用点：审计失败 = 业务失败（M10 §7），转 409/40919 让外层回滚。"""
    if sink is None:
        return None
    try:
        return sink.append(event)
    except Exception as exc:                      # noqa: BLE001 - 任何 sink 失败都算审计失败
        raise AuditUnavailable(f"审计写入失败（M16）：{type(exc).__name__}: {exc}") from exc


def build_event(action: str, *, actor: str, key: str, **kwargs: Any) -> AuditEvent:
    return AuditEvent(action=action, actor=actor, key=key, **kwargs)
