# SPDX-License-Identifier: Apache-2.0
"""M14 admin-data 常量与枚举（M14 §3 / §5 / §8.2 · 02-events §3 · 03-facts §8）。

本文件只放**枚举、状态机、文件失效期、批量上限、事件 payload 白名单**；
不复制任何其它模块的业务阈值（风控阈值仍只在 M10 私有配置；账本 / 金额规则在 M06）。

状态机（M14 §3，一处定义、policy / store / 测试共用）::

    export     pending → approved → running → done
                     ↘ failed / expired           （终止：failed / expired，过期不自动续期）
    retention  queued → running → done；failed 可幂等重放（queued）

``cancelled`` **不是**已登记枚举值（M14 §5 state 只有 6 值）：取消以
``failed + failure_reason='cancelled_by_requester'`` 表达，见 CR-M14-01（证据文件）。
"""
from __future__ import annotations

from typing import Final

# ── 枚举（M14 §3 / §5）
EXPORT_STATES: Final[tuple[str, ...]] = (
    "pending", "approved", "running", "done", "failed", "expired",
)
EXPORT_TERMINAL_STATES: Final[frozenset[str]] = frozenset({"done", "failed", "expired"})
#: 取消只对未执行生效（M14 §4.1 / INV-04）
EXPORT_CANCELLABLE_STATES: Final[frozenset[str]] = frozenset({"pending", "approved"})
#: M14 §3：pending → approved → running → done；终止 failed / expired
EXPORT_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "pending": frozenset({"approved", "failed", "expired"}),
    "approved": frozenset({"running", "failed", "expired"}),
    "running": frozenset({"done", "failed"}),
    "done": frozenset({"expired"}),
    "failed": frozenset(),
    "expired": frozenset(),
}

RETENTION_STATES: Final[tuple[str, ...]] = ("queued", "running", "done", "failed")
RETENTION_TERMINAL_STATES: Final[frozenset[str]] = frozenset({"done"})
RETENTION_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "queued": frozenset({"running", "failed"}),
    "running": frozenset({"done", "failed"}),
    "failed": frozenset({"queued"}),        # INV-07：失败可幂等重放
    "done": frozenset(),
}

#: data_export_requests.scope.object / retention_jobs.object（M14 §5 同一枚举）
RETENTION_OBJECTS: Final[tuple[str, ...]] = (
    "usage", "receipts", "tickets", "logs", "backups", "analytics",
)
EXPORT_OBJECTS: Final[tuple[str, ...]] = RETENTION_OBJECTS
EXPORT_FORMATS: Final[tuple[str, ...]] = ("json", "csv")
#: 导出范围白名单键（S3：拒绝未知字段，不把任意过滤条件透传 Owner）
EXPORT_SCOPE_FIELDS: Final[frozenset[str]] = frozenset({"object", "from", "to", "tenant_id"})

#: 后台十一域（§7.9；admin_saved_views.domain）
DOMAINS: Final[tuple[str, ...]] = (
    "supply", "account", "content", "risk", "ledger", "recon", "reports",
    "ticket", "config", "treasury", "audit",
)
SAVED_VIEW_STATES: Final[tuple[str, ...]] = ("active", "deleted")

# ── 批量五步（M14 §8.2：≤200 条 / 10 分钟撤销 / >50 条或涉资金冻结双人）
BATCH_STEPS: Final[tuple[str, ...]] = ("preview", "execute", "undo")
BATCH_STATES: Final[tuple[str, ...]] = ("previewed", "executed", "undone", "failed")
BATCH_ACTIONS: Final[tuple[str, ...]] = (
    "notify", "tag", "freeze", "unfreeze", "retire", "limit_adjust",
    "payout_proposal", "refund_proposal",
)
#: 涉资金 / 冻结的动作：一律双人复核（M14 §8.2）
DUAL_REVIEW_ACTIONS: Final[frozenset[str]] = frozenset({
    "freeze", "payout_proposal", "refund_proposal",
})
BATCH_MAX_ITEMS: Final[int] = 200
BATCH_DUAL_REVIEW_ITEMS: Final[int] = 50
BATCH_UNDO_WINDOW_S: Final[int] = 600
BATCH_SAMPLE_SIZE: Final[int] = 10
#: 只读沙箱 / break-glass 会话上限（M14 §8.2 / INV-09）
SANDBOX_MAX_S: Final[int] = 4 * 3600

# ── 导出（M14 §8.1 / §8.2）
EXPORT_MAX_ROWS_DEFAULT: Final[int] = 200_000
EXPORT_MAX_ROWS_MIN: Final[int] = 1_000
EXPORT_MAX_ROWS_MAX: Final[int] = 1_000_000
EXPORT_LINK_TTL_MAX_S: Final[int] = 15 * 60          # INV-04：签名链接 ≤15 分钟
EXPORT_LINK_TTL_DEFAULT_S: Final[int] = 15 * 60
EXPORT_FILE_TTL_D: Final[int] = 7                    # 文件 7 天失效（到期删除）
EXPORT_LARGE_ROWS: Final[int] = 1_000                # >1,000 行 → 双人复核
EXPORT_DAILY_LARGE_LIMIT: Final[int] = 1            # 同一人 24h ≤1 次大导出
EXPORT_DAILY_WINDOW_S: Final[int] = 24 * 3600
WATERMARK_PREFIX: Final[str] = "DJB-M14"
MAX_WATERMARK_LEN: Final[int] = 128

# ── 保留（M14 §8.2 / INV-06：备份 ≤35 天、日志元数据 30 天、埋点 ≤14 个月、工单 24 个月）
#: 天数为**上限内**的保守值（14 个月取 420 天、24 个月取 720 天，均不超过规格上限）
RETENTION_POLICY_DAYS: Final[dict[str, int]] = {
    "usage": 720,
    "receipts": 720,
    "tickets": 720,
    "logs": 30,
    "backups": 35,
    "analytics": 420,
}
RETENTION_POLICY_MIN_DAYS: Final[int] = 1
RETENTION_POLICY_MAX_DAYS: Final[int] = 3_650
#: INV-05：删除请求 30 天办结；删除后 40 天抽样 0 命中
RETENTION_SLA_DAYS: Final[int] = 30
RETENTION_SAMPLE_DAYS: Final[int] = 40
#: 保留对象 → Owner + 约定的只读视图名（未接线时报告 unknown，绝不由 M14 直删业务表）
RETENTION_SOURCES: Final[dict[str, tuple[str, str, str]]] = {
    "usage": ("M05", "v_m05_usage_records", "created_at"),
    "receipts": ("M05", "v_m05_receipts", "created_at"),
    "tickets": ("M14", "v_m14_tickets", "created_at"),      # CR-1：工单域待 Lead 裁决
    "logs": ("M16", "v_m16_log_metadata", "ts"),
    "backups": ("M16", "v_m16_backups", "created_at"),
    "analytics": ("M05", "v_m05_tracking_events", "occurred_at"),
}

# ── 健康总览（§22.21：网关 / 调度 / 账本 / 对账 / 钱包 / 配置 / 通知七块）
HEALTH_BLOCKS: Final[tuple[str, ...]] = (
    "gateway", "scheduling", "ledger", "recon", "wallet", "config", "notification",
)
HEALTH_STATUSES: Final[tuple[str, ...]] = ("green", "yellow", "red")
HEALTH_RANK: Final[dict[str, int]] = {"green": 0, "yellow": 1, "red": 2}
#: 每块"最近变更"在 audit_log 里匹配的动作前缀（M16 审计链是唯一权威）
HEALTH_CHANGE_PATTERNS: Final[dict[str, tuple[str, ...]]] = {
    "gateway": ("gateway.",),
    "scheduling": ("schedule.", "scheduling.", "routing."),
    "ledger": ("ledger.",),
    "recon": ("recon.",),
    "wallet": ("wallet.", "treasury."),
    "config": ("config.",),
    "notification": ("notify.", "notification."),
}
#: 健康探针默认阈值（S1 运维默认，不是业务事实；Owner 接线后可覆盖）
HEALTH_LEDGER_STALE_H: Final[int] = 24
HEALTH_LEDGER_RED_H: Final[int] = 72
HEALTH_WALLET_STUCK_MIN: Final[int] = 30
HEALTH_WALLET_RED_COUNT: Final[int] = 10

# ── 变更日历（窗口 / 回滚方案 / 影响面）读取 audit_log 的动作前缀
CHANGE_ACTION_PATTERNS: Final[tuple[str, ...]] = (
    "deploy.", "config.publish", "config.rollback", "backup.", "upgrade.", "release.",
)

# ── 分页 / 幂等（00-conventions §5/§6）
MIN_PAGE_SIZE: Final[int] = 1
MAX_PAGE_SIZE: Final[int] = 200
DEFAULT_PAGE_SIZE: Final[int] = 50
MIN_IDEMPOTENCY_LEN: Final[int] = 16
MAX_IDEMPOTENCY_LEN: Final[int] = 128
MAX_REASON_LEN: Final[int] = 512
MAX_BODY_BYTES: Final[int] = 64 * 1024
MAX_ACTOR_LEN: Final[int] = 128
MAX_TARGET_LEN: Final[int] = 256

# ── 事件（02-events §3 已登记；未登记事件不得上线）
EVENT_EXPORT_COMPLETED: Final[str] = "data.export.completed"
EVENT_RETENTION_EXECUTED: Final[str] = "retention.executed"
PRODUCED_EVENTS: Final[tuple[str, ...]] = (EVENT_EXPORT_COMPLETED, EVENT_RETENTION_EXECUTED)
PRODUCER: Final[str] = "M14"
EVENT_VERSION: Final[int] = 1
EVENT_PAYLOAD_FIELDS: Final[dict[str, frozenset[str]]] = {
    EVENT_EXPORT_COMPLETED: frozenset({"export_id", "requester", "rows"}),
    EVENT_RETENTION_EXECUTED: frozenset({"job_id", "object", "deleted_count"}),
}
#: 消费事件（M14 §4.2）；S1 只做 schema 校验与幂等入口，健康数据仍以只读视图直取
CONSUMED_EVENTS: Final[tuple[str, ...]] = (
    "audit.appended", "deploy.completed", "backup.completed", "recon.completed",
    "exception.opened", "notification.delivered", "notification.failed",
)
CONSUMED_PAYLOAD_FIELDS: Final[dict[str, frozenset[str]]] = {
    "audit.appended": frozenset({"audit_id", "actor", "action", "hash"}),
    "deploy.completed": frozenset({"run_id", "env", "status"}),
    "backup.completed": frozenset({"run_id", "env", "status"}),
    "recon.completed": frozenset({"run_id", "period", "p0", "p1", "p2"}),
    "exception.opened": frozenset({"exception_id", "severity", "amount_minor"}),
    "notification.delivered": frozenset({"notification_id", "channel", "attempt"}),
    "notification.failed": frozenset({"notification_id", "channel", "attempt"}),
}
ENVELOPE_REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "event_id", "type", "version", "occurred_at", "producer", "aggregate_type",
    "aggregate_id", "trace_id", "idempotency_key", "payload",
)

# ── 审计动作（append-only；写入口只在 audit.py，权威链在 M16）
AUDIT_EXPORT_REQUESTED: Final[str] = "data.export.requested"
AUDIT_EXPORT_APPROVED: Final[str] = "data.export.approved"
AUDIT_EXPORT_CANCELLED: Final[str] = "data.export.cancelled"
AUDIT_EXPORT_STARTED: Final[str] = "data.export.started"
AUDIT_EXPORT_COMPLETED: Final[str] = "data.export.completed"
AUDIT_EXPORT_FAILED: Final[str] = "data.export.failed"
AUDIT_EXPORT_EXPIRED: Final[str] = "data.export.expired"
AUDIT_EXPORT_LINK_MINTED: Final[str] = "data.export.link_minted"
AUDIT_EXPORT_LINK_CONSUMED: Final[str] = "data.export.link_consumed"
AUDIT_RETENTION_CREATED: Final[str] = "retention.job.created"
AUDIT_RETENTION_COMPLETED: Final[str] = "retention.job.completed"
AUDIT_RETENTION_FAILED: Final[str] = "retention.job.failed"
AUDIT_RETENTION_REPLAYED: Final[str] = "retention.job.replayed"
AUDIT_BATCH_PREVIEWED: Final[str] = "ops.batch.previewed"
AUDIT_BATCH_EXECUTED: Final[str] = "ops.batch.executed"
AUDIT_BATCH_UNDONE: Final[str] = "ops.batch.undone"
AUDIT_SANDBOX_OPENED: Final[str] = "ops.sandbox.opened"

#: 后台角色 → 权限点（§7.10 三段式；真实角色绑定在 M01，这里只是 S1 本地/测试映射）
ROLE_SCOPES: Final[dict[str, tuple[str, ...]]] = {
    "SUPER": ("*",),
    "OPS": ("data.read", "data.write", "data.approve", "ops.read", "ops.write"),
    "AUDIT": ("data.read", "ops.read"),
    "VIEWER": ("data.read", "ops.read"),
    "FIN": (),
    "RISK": (),
    "CS": (),
    "SVC": (),
}
#: 管理面权限点（M14 §4.1；三段式：数据读 / 数据写 / 审批 / 运维读 / 运维写）
SCOPES: Final[tuple[str, ...]] = ("data.read", "data.write", "data.approve", "ops.read", "ops.write")
