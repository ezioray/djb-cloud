# SPDX-License-Identifier: AGPL-3.0-or-later
"""运维中心 + 配置中心服务层（§22.21 / §21.12 / §21.4 / RPT-0002 §3）。

本模块是 §21.12.2 那 8 条管理面操作在**服务层**的唯一实现入口，外加运维中心
（§22.21）的 5 个只读视图。它**不注册任何 HTTP 路由**：接线点写在
``docs/DEV-0004-ops-center.md`` §6，由后续票据在改完 spec 后挂载
（§21.12.2 原文：配置域端点先改 spec 再实现）。

一、契约纪律（验收 ①）
======================
``@operation("<operationId>")`` 是硬门：不在 ``app.admin.OPERATIONS``（= spec 里
已定稿的 8 条）里的名字，**导入期就抛错**。测试拿 ``spec/openapi.yaml`` 反查两边集合，
少一条 / 多一条都红。运维中心的只读视图没有 operationId，登记在 ``PENDING_SPEC_VIEWS``
里——它们要么已被 spec 的既有端点覆盖，要么必须"先改 spec 再接线"。

二、四条硬规则的落点
====================
② 自批自核 403           ``approve_config_publish``：（发起人=复核人）→ ``Forbidden`` 403。
                          注：产品文档 §21.12.4 把 SoD 归到 409/40902，而 spec 的
                          ``approveConfigPublish`` 描述与本单验收都写 403 —— 以 spec 为准，
                          差异登记在 docs §8。
③ 敏感项不明文          三层：① 表上有 ``CHECK (NOT sensitive OR value IS NULL)``，
                          压根没有存明文的位置；② 渲染只给 ``secret_ref`` + 摘要素要；
                          ③ 审计与链锚参数里 value 一律 ``<<sensitive>>``。
④ P0 step-up + 双人      ``approvals_required``：P0=2（两名不同复核人，均 ≠ 发起人，
                          且至少一名来自 FIN/AUDIT）；发布与每次复核**各需一次** step-up
                          （``step_up_ref`` 不得复用，§21.4.3）。``expired`` 不自动放行：
                          ``approve`` 遇 ``expired`` 直接 409，必须新建发布单。
⑤ 幂等 24h + 审计同事务  每个写操作在**同一事务**里做：变更 → 审计链追加 → 幂等行落库。
                          任一失败全回滚（测试有注入用例证明）。响应回带
                          ``audit.seq`` / ``audit.hash`` 作为同事务的证据。
                          幂等键 24h；未带键时按 spec 退化为 300s 请求体指纹去重。

三、状态机（§21.4.2）
=====================
::

    pending_approval --通过(人数够)--> scheduled --到点--> active
            |                              ^
            +--拒绝--> rejected            +--(无 effective_at)--> approved --> active
            +--4h 超时--> expired（不自动放行）
    active --回滚--> rolled_back（以历史版本为内容生成**新**发布单）
    emergency(kill switch) --> active（只收紧，单人可做，到期自动回退 + 留痕）

四、不做什么
============
* 不碰账本、不签名、不发钱：本模块只写配置与审计（``app/ledger.py`` 等不在写范围）。
* 不建迁移：表结构由本模块的 ``ensure_schema()`` 在**独立 schema**（默认 ``ops_center``，
  可用 ``DJB_ADMIN_SCHEMA`` 覆盖）里幂等自举，属于"临时 schema"脚手架；正式迁移另开票据
  （本单验收明确"不要新增迁移"，见 docs §9 遗留）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any, Iterable, Mapping

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .. import db
from . import (
    APPROVER_ROLES_P0,
    OPERATIONS,
    BadRequest,
    BreakGlassReadOnly,
    Conflict,
    FeatureDisabled,
    Forbidden,
    NotFound,
    OpsCenterError,
    StepUpRequired,
    require_writes_enabled,
)

__all__ = [
    # 契约
    "operation",
    "PENDING_SPEC_VIEWS",
    "SYSTEM_TRANSITIONS",
    # 基础设施
    "AdminPrincipal",
    "KeyPolicy",
    "KEY_POLICIES",
    "ensure_schema",
    "schema_name",
    "verify_audit_chain",
    "build_chain_anchor_argv",
    # 8 个 spec 操作
    "list_config_items",
    "list_config_drifts",
    "get_config_item",
    "create_config_draft",
    "publish_config_item",
    "approve_config_publish",
    "rollback_config_item",
    "kill_switch_config_item",
    # 运维只读视图
    "health_overview",
    "slo_burn_rate",
    "list_alerts",
    "search_audit",
    "change_calendar",
    "freeze_window_active",
    # 系统驱动
    "expire_stale_requests",
    "expire_kill_switches",
    "advance_publish_requests",
    "report_runtime",
]

UTC = timezone.utc
CST = timezone(timedelta(hours=8))          # 发布窗口按 UTC+8 判定（OPS-02）

# --------------------------------------------------------------------------- 时间与阈值
STEP_UP_TTL = timedelta(minutes=5)            # §21.4.3 二次认证 ≤5 分钟
APPROVAL_TIMEOUT = timedelta(hours=4)         # §21.4.2 pending_approval 4h → expired
IDEMPOTENCY_TTL = timedelta(hours=24)         # 验收 ⑤：写操作幂等 24h
IDEMPOTENCY_TTL_FINGERPRINT = timedelta(seconds=300)   # spec：缺键时 300s 指纹去重
KILL_SWITCH_MAX_TTL = 86400                   # §21.12 ConfigKillSwitchRequest.ttl_seconds ≤86400
SECRET_REVEAL_TTL_SECONDS = 300               # §21.12.5 #6：明文查看 5 分钟后重新脱敏

#: 风险级 → 复核人数（§21.4.3 双人复核；§21.4.5 例② 支付地址类为双签）
APPROVALS_REQUIRED: dict[str, int] = {"P0": 2, "P1": 1, "P2": 1}
#: 风险级 → 冷却期（§21.4.3 P0 24h；OPS-12 P1 60min；P2 无）
PUBLISH_COOLDOWN: dict[str, timedelta] = {
    "P0": timedelta(hours=24),
    "P1": timedelta(minutes=60),
    "P2": timedelta(0),
}
#: 风险级 → 漂移纠正 SLA（OPS-20：A≠B 24h 内纠正；B≠C 5 分钟内收敛）
DRIFT_SLA_SECONDS = {"desired_vs_effective": 86400, "effective_vs_running": 300}

REQUEST_STATES = (
    "pending_approval", "approved", "scheduled", "rolling_out", "active",
    "rejected", "expired", "cancelled", "rolled_back", "failed",
)
REQUEST_TERMINAL = frozenset({"rejected", "expired", "cancelled", "rolled_back", "failed"})
REQUEST_IN_FLIGHT = ("pending_approval", "approved", "scheduled", "rolling_out")
ITEM_STATES = ("draft", "active", "rolled_back", "retired")

DEFAULT_SCOPE = "global"          # spec 的 4 个请求体都没有 scope 字段 → 一期只有 global
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

#: 发布窗口（OPS-02）：工作日 10:00–17:00（UTC+8）。回滚 / kill switch 不在此限（止损免窗口）。
PUBLISH_WINDOW = (time(10, 0), time(17, 0))
#: 冻结窗口（§22.21 变更日历）：月末 2 天 + ``ops_freeze_window`` 里的重大活动期。
MONTH_END_FREEZE_DAYS = 2

#: 健康总览七块（§22.21 健康总览）
COMPONENTS = ("gateway", "scheduler", "ledger", "reconcile", "wallet", "config", "notify")
COMPONENT_LABELS = {
    "gateway": "网关", "scheduler": "调度", "ledger": "账本", "reconcile": "对账",
    "wallet": "钱包", "config": "配置", "notify": "通知",
}
STATUS_RANK = {"green": 0, "yellow": 1, "unknown": 1, "red": 2}

#: SLO 目标（燃烧率看板）。target 是可用性承诺，burn = (1-实际)/(1-目标)。
SLO_TARGETS: dict[str, dict] = {
    "api.availability": {"target": 0.999, "description": "网关 5xx 率"},
    "config.convergence": {"target": 0.99, "description": "发布后 5 分钟内收敛比例"},
    "payout.success_rate": {"target": 0.995, "description": "出款成功率"},
}
BURN_WARN, BURN_HIGH, BURN_CRITICAL = 1.0, 6.0, 14.4      # 多窗口燃烧率惯例阈值


# --------------------------------------------------------------------------- 配置键注册表
@dataclass(frozen=True)
class KeyPolicy:
    """配置键的静态策略（§21.4.4 步 0"注册 key"；数值来自 v4 §21.14.4 / §21.15）。

    风险级、敏感标记、量纲、收紧方向**都不由调用方给**，只由这张表决定——否则
    调用方可以把一个秘密声明成非敏感，或用 kill switch 反过来放宽。
    """

    risk: str
    value_type: str
    domain: str
    description: str = ""
    unit: str | None = None
    sensitive: bool = False
    direction: str = "none"          # kill switch 收紧方向：reduce / raise / none
    minimum: float | int | None = None
    maximum: float | int | None = None
    max_delta: float | int | None = None
    enum: tuple[str, ...] | None = None
    kill_switch_value: Any = None    # kill switch 的保守预设值（None = 无预设，不允许急停）
    frozen: bool = False             # 禁止在管理后台修改（如 risk.* 私有域）

    def tighten_ok(self, preset: Any, current: Any) -> bool:
        """preset 是否比 current 更保守。current 为空视为"无生效值"，允许落地基线。"""
        if current is None:
            return True
        if self.direction == "reduce":
            return preset < current
        if self.direction == "raise":
            return preset > current
        return False


KEY_POLICIES: dict[str, KeyPolicy] = {
    # —— 计费与价格（§21.15：费率变更 = P0 + 双人 + 公示 ≥7 天）——
    "billing.service_fee_bps": KeyPolicy(
        risk="P0", value_type="integer", domain="billing", unit="bps",
        description="服务费率（1500 = 15%，上限 2000）",
        direction="reduce", minimum=0, maximum=2000, max_delta=500,
        kill_switch_value=1500,
    ),
    "billing.slow_task_discount_pct": KeyPolicy(
        risk="P1", value_type="integer", domain="billing", unit="pct",
        description="慢任务折扣百分比（40；组网 50）",
        direction="reduce", minimum=0, maximum=100, max_delta=20,
    ),
    "billing.channel_fee_bps": KeyPolicy(
        risk="P1", value_type="integer", domain="billing", unit="bps",
        description="渠道费率", direction="reduce", minimum=0, maximum=2000, max_delta=500,
    ),
    # —— 调度与预留池（§21.4.4 例①）——
    "pool.reserved_default": KeyPolicy(
        risk="P0", value_type="integer", domain="scheduling", unit="pct",
        description="预留池基线（默认 30%，区间 10–50，max-delta 10pp）",
        direction="reduce", minimum=10, maximum=50, max_delta=10,
        kill_switch_value=30,
    ),
    "routing.policy_version": KeyPolicy(
        risk="P0", value_type="string", domain="scheduling",
        description="调度策略包版本（随 snapshot_digest 变化）", direction="none",
    ),
    "quota.per_user_daily_requests": KeyPolicy(
        risk="P1", value_type="integer", domain="scheduling", unit="count",
        description="单用户单日请求上限", direction="reduce",
        minimum=1, maximum=10_000_000, kill_switch_value=1,
    ),
    # —— 支付与 treasury（§21.4.5 例②）——
    "treasury.hot_wallet_cap": KeyPolicy(
        risk="P0", value_type="integer", domain="treasury", unit="usd_minor",
        description="热钱包单池上限（minor unit）",
        direction="reduce", minimum=0, maximum=10**12, kill_switch_value=0,
    ),
    "treasury.gas_fee_mode": KeyPolicy(
        risk="P0", value_type="string", domain="treasury",
        description="gas 承担方", direction="none", enum=("platform", "provider"),
    ),
    "treasury.platform_share_bps": KeyPolicy(
        risk="P0", value_type="integer", domain="treasury", unit="bps",
        description="平台分润比例", direction="reduce",
        minimum=0, maximum=10000, max_delta=500, kill_switch_value=0,
    ),
    "treasury.deposit_address_ref": KeyPolicy(
        risk="P0", value_type="string", domain="treasury", sensitive=True,
        description="收款地址引用（只存秘密引用，不存地址本身）", direction="none",
    ),
    # —— 风控（私有域：只记版本号，值由私有仓部署期注入）——
    "risk.rule_version": KeyPolicy(
        risk="P0", value_type="string", domain="risk", sensitive=True,
        description="风控规则包版本（只存引用）", direction="none", frozen=True,
    ),
    # —— 通知（P2 可裁剪复核）——
    "notify.report.daily_send_at": KeyPolicy(
        risk="P2", value_type="string", domain="notify",
        description="日报发送时刻（HH:MM，UTC+8）", direction="none",
    ),
    "notify.p0.email_enabled": KeyPolicy(
        risk="P1", value_type="boolean", domain="notify",
        description="P0 通知邮件渠道（不可退订，§21.12.1）", direction="none",
    ),
}

KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")     # 同 spec path 参数
SENSITIVE_HINTS = re.compile(r"(ref|secret|key|token|password|signing)$")


# --------------------------------------------------------------------------- 契约装饰器
def operation(operation_id: str):
    """声明函数实现哪条 spec 操作。名字不在 ``OPERATIONS`` 里 → 导入期报错（不新造端点）。"""
    if operation_id not in OPERATIONS:
        raise ValueError(
            f"{operation_id} 不在 spec 已定稿的 8 个配置操作里；"
            "新增端点必须先改 spec（§21.12.2），不允许先写代码后补 spec"
        )

    def deco(fn):
        fn.operation_id = operation_id
        fn.spec = OPERATIONS[operation_id]
        return fn

    return deco


#: 运维中心只读视图：**没有** operationId。接线前必须先改 spec（§21.12.2 红线）。
PENDING_SPEC_VIEWS = (
    "health_overview", "slo_burn_rate", "list_alerts",
    "search_audit", "change_calendar", "freeze_window_active",
)

#: 系统驱动状态迁移：不是管理面操作，不占 operationId；actor 必须是 ``system:*``。
SYSTEM_TRANSITIONS = ("expire_stale_requests", "expire_kill_switches",
                      "advance_publish_requests", "report_runtime")


# --------------------------------------------------------------------------- 主体与鉴权
@dataclass(frozen=True)
class AdminPrincipal:
    """管理面调用主体。由网关/会话层构造后传入，本模块只做判定不做认证。"""

    actor: str
    roles: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset()
    step_up_at: datetime | None = None
    step_up_ref: str | None = None
    break_glass: bool = False
    request_id: str | None = None

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def has_role(self, *roles: str) -> bool:
        return bool(self.roles & set(roles))


def _require_perm(principal: AdminPrincipal, permission: str, *, as_not_found: bool = False) -> None:
    if principal.has(permission):
        return
    if as_not_found:
        # §21.12.4：无权访问该配置项 → 越权统一 404，不泄露对象存在性
        raise NotFound(f"无权访问该配置项（需要 {permission}）")
    raise Forbidden(f"缺少权限点 {permission}")


def _require_step_up(principal: AdminPrincipal, now: datetime) -> None:
    """step-up ≤5 分钟；P0 由调用方再校验"发布与复核各一次"（step_up_ref 不复用）。"""
    if not principal.step_up_ref or principal.step_up_at is None:
        raise StepUpRequired("该操作需要 step-up 二次认证（X-Admin-Step-Up，≤5 分钟有效）")
    age = now - principal.step_up_at
    if age > STEP_UP_TTL or age < -STEP_UP_TTL:
        raise StepUpRequired(
            f"step-up 已失效（{int(age.total_seconds())}s，上限 {int(STEP_UP_TTL.total_seconds())}s），请重新认证"
        )


# --------------------------------------------------------------------------- schema / 连接
_SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_bootstrapped: set[str] = set()
AUDIT_LOCK_ID = 4_004_000_042          # pg_advisory_xact_lock 的固定键（审计链串行化）


def schema_name() -> str:
    """本模块的表所在的 schema（默认 ``ops_center``；测试用 ``DJB_ADMIN_SCHEMA`` 隔开）。"""
    raw = os.environ.get("DJB_ADMIN_SCHEMA") or "ops_center"
    if not _SCHEMA_RE.match(raw):
        raise ValueError(f"DJB_ADMIN_SCHEMA 非法（^[a-z_][a-z0-9_]{{0,62}}$）: {raw!r}")
    return raw


DDL = """
CREATE TABLE IF NOT EXISTS config_item (
    key           text        NOT NULL,
    scope         text        NOT NULL,
    version       integer     NOT NULL CHECK (version >= 1),
    state         text        NOT NULL CHECK (state IN ('draft','active','rolled_back','retired')),
    value_type    text        NOT NULL CHECK (value_type IN ('string','integer','number','boolean','json')),
    value         jsonb,
    secret_ref    text,
    sensitive     boolean     NOT NULL DEFAULT false,
    risk_level    text        NOT NULL CHECK (risk_level IN ('P0','P1','P2')),
    domain        text,
    unit          text,
    direction     text        NOT NULL DEFAULT 'none' CHECK (direction IN ('reduce','raise','none')),
    description   text,
    digest        text        NOT NULL,
    created_at    timestamptz NOT NULL,
    created_by    text        NOT NULL,
    reason        text,
    ticket        text,
    effective_at  timestamptz,
    superseded_by integer,
    PRIMARY KEY (key, scope, version),
    -- ③ 敏感项绝不明文：表上根本没有"敏感项还能带明文"的合法状态
    CHECK (NOT sensitive OR value IS NULL),
    CHECK (NOT sensitive OR secret_ref IS NOT NULL),
    CHECK (sensitive OR value IS NOT NULL)
);

CREATE OR REPLACE FUNCTION config_item_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'config_item 不可删除：历史版本只追加（§21.4.2 回滚以历史版本为内容新建发布）';
    END IF;
    IF OLD.state <> 'draft' AND (
           NEW.value      IS DISTINCT FROM OLD.value
        OR NEW.secret_ref IS DISTINCT FROM OLD.secret_ref
        OR NEW.digest     IS DISTINCT FROM OLD.digest
        OR NEW.version    IS DISTINCT FROM OLD.version
    ) THEN
        RAISE EXCEPTION 'config_item 版本不可变：% @v% 已生效（state=%）', OLD.key, OLD.version, OLD.state;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS config_item_guard_trg ON config_item;
CREATE TRIGGER config_item_guard_trg BEFORE UPDATE OR DELETE ON config_item
    FOR EACH ROW EXECUTE FUNCTION config_item_guard();

CREATE TABLE IF NOT EXISTS config_publish_request (
    request_id          text        PRIMARY KEY,
    key                 text        NOT NULL,
    scope               text        NOT NULL,
    kind                text        NOT NULL CHECK (kind IN ('publish','rollback','kill_switch')),
    state               text        NOT NULL,
    target_version      integer     NOT NULL,
    previous_version    integer,
    requested_by        text        NOT NULL,
    requested_at        timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    approvals_required  integer     NOT NULL CHECK (approvals_required >= 1),
    approvals_received  integer     NOT NULL DEFAULT 0 CHECK (approvals_received >= 0),
    approval_chain      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    publish_step_up_ref text,
    effective_at        timestamptz,
    gray_plan           jsonb,
    kill_switch_ttl     integer,
    reason              text        NOT NULL,
    ticket              text,
    cooldown_until      timestamptz,
    reject_reason       text,
    updated_at          timestamptz NOT NULL,
    CHECK (state IN ('pending_approval','approved','scheduled','rolling_out','active',
                     'rejected','expired','cancelled','rolled_back','failed'))
);

CREATE INDEX IF NOT EXISTS config_publish_request_key_idx
    ON config_publish_request (key, scope, state);

CREATE TABLE IF NOT EXISTS config_runtime (
    key               text        NOT NULL,
    scope             text        NOT NULL,
    instance          text        NOT NULL,
    effective_version integer,
    running_version   integer,
    reported_at       timestamptz NOT NULL,
    PRIMARY KEY (key, scope, instance)
);

CREATE TABLE IF NOT EXISTS config_audit (
    seq          bigserial   PRIMARY KEY,
    at           timestamptz NOT NULL,
    actor        text        NOT NULL,
    actor_roles  text        NOT NULL DEFAULT '',
    action       text        NOT NULL,
    op_id        text,
    key          text,
    scope        text,
    version      integer,
    request_id   text,
    outcome      text        NOT NULL,
    http_status  integer     NOT NULL,
    reason       text,
    reason_code  text,
    idem_hash    text,
    before       jsonb,
    after        jsonb,
    prev_hash    text,
    hash         text        NOT NULL
);

CREATE INDEX IF NOT EXISTS config_audit_key_idx ON config_audit (key, scope, seq);
CREATE INDEX IF NOT EXISTS config_audit_actor_idx ON config_audit (actor, seq);

CREATE OR REPLACE FUNCTION config_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'config_audit 只追加：不允许 %（审计链不可改写，§21.8.2）', TG_OP;
END $$;

DROP TRIGGER IF EXISTS config_audit_guard_trg ON config_audit;
CREATE TRIGGER config_audit_guard_trg BEFORE UPDATE OR DELETE ON config_audit
    FOR EACH ROW EXECUTE FUNCTION config_audit_guard();

CREATE TABLE IF NOT EXISTS config_idempotency (
    key_hash       text        NOT NULL,
    operation_id   text        NOT NULL,
    actor          text        NOT NULL,
    request_digest text        NOT NULL,
    response       jsonb       NOT NULL,
    status         integer     NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (key_hash, operation_id, actor)
);

CREATE TABLE IF NOT EXISTS ops_component_state (
    component       text        PRIMARY KEY,
    status          text        NOT NULL CHECK (status IN ('green','yellow','red')),
    detail          text,
    last_change_at  timestamptz,
    last_change_ref text,
    updated_at      timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS ops_slo_window (
    slo          text        NOT NULL,
    window_start timestamptz NOT NULL,
    window_end   timestamptz NOT NULL,
    good         bigint      NOT NULL CHECK (good >= 0),
    total        bigint      NOT NULL CHECK (total > 0),
    PRIMARY KEY (slo, window_start)
);

CREATE TABLE IF NOT EXISTS ops_alert (
    alert_id         text        PRIMARY KEY,
    fingerprint      text        NOT NULL,
    severity         text        NOT NULL,
    title            text        NOT NULL,
    opened_at        timestamptz NOT NULL,
    last_seen        timestamptz NOT NULL,
    occurrences      integer     NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    state            text        NOT NULL DEFAULT 'firing'
                                 CHECK (state IN ('firing','acked','resolved','suppressed')),
    suppressed_until timestamptz,
    owner            text
);

CREATE TABLE IF NOT EXISTS ops_freeze_window (
    window_id text        PRIMARY KEY,
    reason    text        NOT NULL,
    starts_at timestamptz NOT NULL,
    ends_at   timestamptz NOT NULL
);
"""


def _check_schema(name: str) -> str:
    if not _SCHEMA_RE.match(name):
        raise ValueError(f"schema 名非法: {name!r}")
    return name


def ensure_schema(name: str | None = None) -> str:
    """幂等自举表结构（独立 schema，不碰 public，不新增迁移文件）。"""
    schema = _check_schema(name or schema_name())
    if schema in _bootstrapped:
        return schema
    with db.conn() as c:
        c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        with c.cursor() as cur:
            cur.execute(f'SET LOCAL search_path TO "{schema}", public')
            cur.execute(DDL)
    _bootstrapped.add(schema)
    return schema


@contextmanager
def _tx(name: str | None = None):
    """开一个事务：``SET LOCAL search_path`` 后把游标交给调用方；退出即提交/回滚。"""
    schema = _check_schema(name or schema_name())
    if schema not in _bootstrapped:
        ensure_schema(schema)
    with db.conn() as c:
        c.row_factory = dict_row
        with c.cursor() as cur:
            cur.execute(f'SET LOCAL search_path TO "{schema}", public')
            yield cur


# --------------------------------------------------------------------------- 小工具
def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime,)):
        return obj.astimezone(UTC).isoformat(timespec="microseconds")
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def canon(obj: Any) -> str:
    """规范化 JSON：稳定排序 + 紧凑分隔符（审计哈希与幂等指纹共用）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=_json_default)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _b64(obj: Any) -> str:
    raw = canon(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(cursor: str, *, field: str = "cursor") -> Any:
    try:
        pad = "=" * (-len(cursor) % 4)
        return json.loads(base64.urlsafe_b64decode(cursor + pad).decode("utf-8"))
    except Exception:
        raise BadRequest(f"游标非法（{field}）", details=[{"field": field}]) from None


def _limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise BadRequest("limit 必须是整数", details=[{"field": "limit"}])
    if limit < 1 or limit > MAX_LIMIT:
        raise BadRequest(f"limit 越界（1..{MAX_LIMIT}）", details=[{"field": "limit"}])
    return limit


def _normalize(dt: datetime | None) -> datetime | None:
    return _as_utc(dt) if dt is not None else None


def _parse_dt(raw: Any, *, field: str) -> datetime | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        return _as_utc(raw)
    try:
        return _as_utc(datetime.fromisoformat(str(raw).replace("Z", "+00:00")))
    except ValueError:
        raise BadRequest(f"{field} 不是合法 RFC3339 时间", details=[{"field": field}]) from None


def _reject_unknown_fields(body: Mapping[str, Any], allowed: Iterable[str], *, where: str) -> None:
    """spec 的请求体是 ``additionalProperties: false``：多给字段直接 400（OPS-08 复用 40001）。"""
    extra = sorted(set(body) - set(allowed))
    if extra:
        raise BadRequest(
            f"{where} 含未定义字段: {', '.join(extra)}",
            details=[{"field": e} for e in extra],
        )


def _require_reason(body: Mapping[str, Any], *, min_length: int = 4) -> str:
    reason = body.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < min_length:
        raise BadRequest(f"reason 必填且至少 {min_length} 个字符", details=[{"field": "reason"}])
    return reason.strip()


def _require_key(key: str) -> KeyPolicy:
    if not isinstance(key, str) or not KEY_PATTERN.match(key):
        raise BadRequest("key 不合法（^[a-z][a-z0-9_.-]{2,127}$）", details=[{"field": "key"}])
    try:
        return KEY_POLICIES[key]
    except KeyError:
        raise BadRequest(
            f"配置项未注册: {key}（§21.4.4 步 0：先注册 key 再建草稿）",
            details=[{"field": "key"}],
        ) from None


def _page(rows: list[dict], limit: int, next_cursor_of) -> dict:
    has_more = len(rows) > limit
    kept = rows[:limit]
    return {
        "page": {
            "has_more": has_more,
            "cursor": None,
            "next_cursor": next_cursor_of(kept[-1]) if (has_more and kept) else None,
        }
    }


def _ok(operation_id: str, payload: dict) -> dict:
    """响应统一回带 operationId —— 验收 ① 的"走 spec 的 8 个 operationId"在响应上可核。"""
    payload.setdefault("meta", {})["operation_id"] = operation_id
    return payload


# --------------------------------------------------------------------------- 审计链
AUDIT_FIELDS = ("at", "actor", "actor_roles", "action", "op_id", "key", "scope", "version",
                "request_id", "outcome", "http_status", "reason", "reason_code", "idem_hash",
                "before", "after")


def _audit_payload(row: Mapping[str, Any]) -> dict:
    payload = {}
    for f in AUDIT_FIELDS:
        v = row.get(f)
        if f == "at":
            v = _as_utc(v).astimezone(UTC).isoformat(timespec="microseconds")
        elif f == "actor_roles":
            v = v or ""
        payload[f] = v
    return payload


def _append_audit(cur, *, actor: str, actions: str, outcome: str, http_status: int,
                  now: datetime, op_id: str | None = None, roles: Iterable[str] = (),
                  key: str | None = None, scope: str | None = None, version: int | None = None,
                  request_id: str | None = None, reason: str | None = None,
                  reason_code: str | None = None, idem_hash: str | None = None,
                  before: Any = None, after: Any = None) -> dict:
    """追加一条审计（哈希链）。必须在业务变更的**同一事务**里调用（验收 ⑤）。

    ``pg_advisory_xact_lock`` 串行化链尾读取，避免并发写出同 prev 的分叉
    （教训来自 BUG-0002：先读后写不加锁必然分叉）。
    """
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_ID,))
    cur.execute("SELECT hash FROM config_audit ORDER BY seq DESC LIMIT 1")
    row = cur.fetchone()
    prev = row["hash"] if row else None
    row = {
        "at": _as_utc(now), "actor": actor, "actor_roles": ",".join(sorted(roles)),
        "action": actions, "op_id": op_id, "key": key, "scope": scope, "version": version,
        "request_id": request_id, "outcome": outcome, "http_status": http_status,
        "reason": reason, "reason_code": reason_code, "idem_hash": idem_hash,
        "before": before, "after": after,
    }
    payload = _audit_payload(row)
    digest = _sha256((prev or "") + "\n" + canon(payload))
    cur.execute(
        """INSERT INTO config_audit
             (at, actor, actor_roles, action, op_id, key, scope, version, request_id,
              outcome, http_status, reason, reason_code, idem_hash, before, after,
              prev_hash, hash)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           RETURNING seq, hash""",
        (row["at"], row["actor"], row["actor_roles"], row["action"], row["op_id"], row["key"],
         row["scope"], row["version"], row["request_id"], row["outcome"], row["http_status"],
         row["reason"], row["reason_code"], row["idem_hash"],
         Jsonb(row["before"]) if row["before"] is not None else None,
         Jsonb(row["after"]) if row["after"] is not None else None,
         prev, digest),
    )
    out = cur.fetchone()
    return {"seq": out["seq"], "hash": digest, "prev_hash": prev}


def verify_audit_chain(*, name: str | None = None) -> dict:
    """全链复算：逐条重算 hash 并核对 prev_hash 串接。返回 ``{entries, bad, ok}``。"""
    with _tx(name) as cur:
        cur.execute("SELECT * FROM config_audit ORDER BY seq")
        rows = cur.fetchall()
    bad: list[int] = []
    prev = None
    for row in rows:
        expected = _sha256((prev or "") + "\n" + canon(_audit_payload(row)))
        if row["prev_hash"] != prev or row["hash"] != expected:
            bad.append(row["seq"])
        prev = row["hash"]
    return {"entries": len(rows), "bad": bad, "ok": not bad}


def build_chain_anchor_argv(entry: Mapping[str, Any], *, task: str = "DEV-0004",
                            evidence: str | None = None) -> list[str]:
    """把一条审计条目翻译成 ``node ops/audit/append.mjs`` 的参数（**接线点，不执行**）。

    返回 argv 供调用方（部署期脚本 / 定时锚定任务）执行；本模块不 subprocess，
    以免把服务进程和外部 CLI 绑死。``--before/--after`` 里的敏感项一律打码。
    """

    def _safe(value: Any) -> str:
        if isinstance(value, Mapping) and value.get("sensitive"):
            return "<<sensitive>>"
        return canon(value)

    argv = [
        "node", "ops/audit/append.mjs",
        "--actor", str(entry.get("actor") or "unknown"),
        "--role", str(entry.get("actor_roles") or "ADMIN").split(",")[0] or "ADMIN",
        "--actor-type", "human" if not str(entry.get("actor", "")).startswith("system:") else "agent",
        "--action", str(entry.get("action") or "config.change"),
        "--target", f"{entry.get('key') or '-'}@v{entry.get('version') or '-'}",
        "--task", task,
        "--reason-code", str(entry.get("reason_code") or "R-OK"),
        "--reason", str(entry.get("reason") or ""),
        "--before", _safe(entry.get("before")),
        "--after", _safe(entry.get("after")),
        "--status", "approved" if entry.get("outcome") == "ok" else "rejected",
    ]
    if entry.get("request_id"):
        argv += ["--ticket", str(entry["request_id"])]
    if evidence:
        argv += ["--evidence", evidence]
    return argv


def _audit_denial(principal: AdminPrincipal, operation_id: str, exc: OpsCenterError,
                  *, now: datetime, key: str | None = None, scope: str | None = None,
                  request_id: str | None = None) -> None:
    """拒绝也要留痕（§21.13.1 ⑥ 越权尝试计入指标）。

    业务事务已回滚，所以这里**另开**一个事务写——拒绝记录本身不参与回滚。
    任何失败都吞掉：审计写不进去不能把原始 403/424 变成 500。
    """
    if isinstance(exc, FeatureDisabled):
        return
    try:
        with _tx() as cur:
            _append_audit(
                cur, actor=principal.actor, actions=f"denied.{operation_id}",
                outcome="denied", http_status=exc.http_status, now=now,
                op_id=operation_id, roles=principal.roles, key=key, scope=scope,
                request_id=request_id or principal.request_id, reason=exc.message,
                reason_code=_reason_code_for(exc),
                before=None, after={"code": exc.code},
            )
    except Exception:                                    # pragma: no cover - 兜底
        pass


def _reason_code_for(exc: OpsCenterError) -> str:
    mapping = {
        "forbidden_self_approval": "R-SOD",
        "forbidden_duplicate_approver": "R-SOD",
        "forbidden_step_up_reuse": "R-STEPUP",
        "forbidden_p0_approver_role": "R-SOD",
    }
    return mapping.get(getattr(exc, "reason_code", ""), "R-DENIED")


# --------------------------------------------------------------------------- 幂等
def _request_digest(operation_id: str, actor: str, payload: Any) -> str:
    return _sha256(canon({"op": operation_id, "actor": actor, "payload": payload}))


def _run_write(*, principal: AdminPrincipal, operation_id: str, idempotency_key: str | None,
               request_payload: Any, fn, now: datetime, enabled: bool | None,
               key: str | None = None, scope: str | None = None) -> dict:
    """写操作统一包装：开关 → 权限 → 幂等 → 业务变更 → 审计 → 幂等行（同一事务）。"""
    require_writes_enabled(override=enabled)
    if principal.break_glass:
        raise BreakGlassReadOnly("break-glass 只读模式（≤4h）下禁止写配置，请走审批后正常会话")
    _require_perm(principal, OPERATIONS[operation_id]["permission"])

    ttl = IDEMPOTENCY_TTL if idempotency_key else IDEMPOTENCY_TTL_FINGERPRINT
    digest = _request_digest(operation_id, principal.actor, request_payload)
    key_hash = _sha256(idempotency_key) if idempotency_key else "fp:" + digest[:32]

    try:
        with _tx() as cur:
            cur.execute(
                """SELECT * FROM config_idempotency
                    WHERE key_hash=%s AND operation_id=%s AND actor=%s""",
                (key_hash, operation_id, principal.actor),
            )
            cache = cur.fetchone()
            if cache and _as_utc(cache["expires_at"]) > now:
                if cache["request_digest"] != digest:
                    raise Conflict("幂等键冲突：同一键被用于不同请求体（24h 内）")
                replay = dict(cache["response"])
                replay["idempotent_replay"] = True
                return replay

            outcome = fn(cur)
            audit = _append_audit(
                cur, actor=principal.actor, actions=outcome.audit_action,
                outcome="ok", http_status=outcome.http_status, now=now,
                op_id=operation_id, roles=principal.roles,
                key=outcome.key or key, scope=outcome.scope or scope,
                version=outcome.version, request_id=outcome.request_id or principal.request_id,
                reason=outcome.reason, reason_code=outcome.reason_code or "R-OK",
                idem_hash=key_hash, before=outcome.before, after=outcome.after,
            )
            response = dict(outcome.response)
            response["audit"] = {"seq": audit["seq"], "hash": audit["hash"][:16],
                                 "prev_hash": (audit["prev_hash"] or "")[:16]}
            response["idempotent_replay"] = False
            cur.execute(
                """INSERT INTO config_idempotency
                     (key_hash, operation_id, actor, request_digest, response, status,
                      created_at, expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (key_hash, operation_id, actor) DO UPDATE
                     SET request_digest=EXCLUDED.request_digest,
                         response=EXCLUDED.response,
                         status=EXCLUDED.status,
                         created_at=EXCLUDED.created_at,
                         expires_at=EXCLUDED.expires_at""",
                (key_hash, operation_id, principal.actor, digest, Jsonb(response),
                 outcome.http_status, now, now + ttl),
            )
            return response
    except OpsCenterError as exc:
        _audit_denial(principal, operation_id, exc, now=now, key=key, scope=scope)
        raise


@dataclass
class WriteOutcome:
    response: dict
    audit_action: str
    http_status: int = 200
    key: str | None = None
    scope: str | None = None
    version: int | None = None
    request_id: str | None = None
    reason: str | None = None
    reason_code: str | None = None
    before: Any = None
    after: Any = None


# --------------------------------------------------------------------------- 渲染
def _mask_summary(digest: str) -> str:
    """敏感项的"脱敏摘要"：只证明"这一版是哪一版"，不含任何明文片段。"""
    return f"<sensitive sha256:{digest[:12]}>"


def render_config_item(row: Mapping[str, Any]) -> dict:
    """ConfigItem 渲染。敏感项 ``value`` 恒为 None，只给 ``secret_ref`` + 脱敏摘要。"""
    item: dict[str, Any] = {
        "key": row["key"],
        "scope": row["scope"],
        "version": row["version"],
        "value_type": row["value_type"],
        "state": row["state"],
        "description": row.get("description"),
        "updated_at": _as_utc(row["created_at"]).isoformat(),
        "updated_by": row["created_by"],
        "risk_level": row["risk_level"],
        "unit": row.get("unit"),
        "domain": row.get("domain"),
        "digest": row["digest"],
    }
    if row["sensitive"]:
        item["value"] = None
        item["secret_ref"] = row["secret_ref"]
        item["sensitive"] = True
        item["masked_summary"] = _mask_summary(row["digest"])
    else:
        item["value"] = row["value"]
        item["secret_ref"] = None
        item["sensitive"] = False
    return item


def _audit_view(row: Mapping[str, Any], *, sensitive: bool = False) -> dict:
    """审计 before/after：敏感项整体打码（审计不是拿明文的后门）。"""
    if sensitive:
        return {"sensitive": True, "value": "<<sensitive>>",
                "secret_ref": row.get("secret_ref")}
    return {"value": row.get("value"), "state": row.get("state")}


# --------------------------------------------------------------------------- 8 个操作
@operation("listConfigItems")
def list_config_items(principal: AdminPrincipal, *, prefix: str | None = None,
                      scope: str | None = None, cursor: str | None = None,
                      limit: int | None = None, name: str | None = None) -> dict:
    """配置项检索（不返回敏感值）。只读，不受开关影响。"""
    _require_perm(principal, "config.item.read")
    limit = _limit(limit)
    if prefix is not None and not isinstance(prefix, str):
        raise BadRequest("prefix 必须是字符串", details=[{"field": "prefix"}])
    if scope is not None and not isinstance(scope, str):
        raise BadRequest("scope 必须是字符串", details=[{"field": "scope"}])

    after = _unb64(cursor) if cursor else {"key": "", "scope": ""}
    with _tx(name) as cur:
        cur.execute(
            """WITH latest AS (
                   SELECT DISTINCT ON (key, scope) *
                     FROM config_item
                    WHERE (%s::text IS NULL OR key LIKE %s)
                      AND (%s::text IS NULL OR scope = %s)
                    ORDER BY key, scope, version DESC
               )
               SELECT * FROM latest
                WHERE (key, scope) > (%s, %s)
                ORDER BY key, scope
                LIMIT %s""",
            (prefix, f"{prefix}%" if prefix is not None else None,
             scope, scope,
             after.get("key", ""), after.get("scope", ""), limit + 1),
        )
        rows = cur.fetchall()
    page = _page(rows, limit, lambda r: _b64({"key": r["key"], "scope": r["scope"]}))
    return _ok("listConfigItems", {"data": [render_config_item(r) for r in rows[:limit]], **page})


@operation("getConfigItem")
def get_config_item(principal: AdminPrincipal, key: str, *, version: int | None = None,
                    scope: str | None = None, disclose: bool = False,
                    now: datetime | None = None, name: str | None = None) -> dict:
    """读单个配置项。``version`` 缺省读当前生效版本；``disclose`` 是敏感项查看入口。

    明文查看（§21.12.5 #6）：另需 ``config.item.secret.read``，**写审计**，并在响应里
    给 ``reveal_ttl_seconds=300``（前端 5 分钟后重新脱敏）。服务层本身不持有明文——
    敏感值只在 KMS/密钥库里，这里只回 ``secret_ref``。
    """
    now = _normalize(now) or _utcnow()
    policy = KEY_POLICIES.get(key)
    if policy is None and not (isinstance(key, str) and KEY_PATTERN.match(key)):
        raise BadRequest("key 不合法（^[a-z][a-z0-9_.-]{2,127}$）", details=[{"field": "key"}])
    scope = scope or "global"
    with _tx(name) as cur:
        if version is None:
            cur.execute(
                """SELECT * FROM config_item WHERE key=%s AND scope=%s
                    ORDER BY (state='active') DESC, version DESC LIMIT 1""",
                (key, scope),
            )
        else:
            cur.execute("SELECT * FROM config_item WHERE key=%s AND scope=%s AND version=%s",
                        (key, scope, version))
        row = cur.fetchone()
        if not row:
            # 越权统一 404（§21.12.4 40401），同时避免泄露"这个 key 存在但没有该版本"
            raise NotFound(f"配置项不存在: {key} @ {scope}" + (f" v{version}" if version else ""))
        _require_perm(principal, "config.item.read", as_not_found=True)
        item = render_config_item(row)
        if disclose:
            if not row["sensitive"]:
                raise BadRequest("该配置项不是敏感项，直接读 value 即可", details=[{"field": "disclose"}])
            _require_perm(principal, "config.item.secret.read")
            _append_audit(
                cur, actor=principal.actor, actions="config.secret.view", outcome="ok",
                http_status=200, now=now, op_id="getConfigItem", roles=principal.roles,
                key=key, scope=scope, version=row["version"],
                request_id=principal.request_id, reason="敏感项查看入口",
                reason_code="R-SECRET-VIEW",
                after={"sensitive": True, "value": "<<sensitive>>",
                       "masked_summary": item["masked_summary"]},
            )
            item["reveal"] = {
                "secret_ref": row["secret_ref"],
                "reveal_ttl_seconds": SECRET_REVEAL_TTL_SECONDS,
                "plaintext_available_here": False,
                "notice": "服务层不持有明文：请按 secret_ref 由 KMS 授权取用；5 分钟后前端重新脱敏",
            }
    return _ok("getConfigItem", item)


@operation("listConfigDrifts")
def list_config_drifts(principal: AdminPrincipal, *, cursor: str | None = None,
                       limit: int | None = None, now: datetime | None = None,
                       name: str | None = None) -> dict:
    """三源漂移（desired / effective / running）。目标恒为 0，非 0 即告警（OPS-20）。"""
    _require_perm(principal, "config.item.read")
    limit = _limit(limit)
    now = _normalize(now) or _utcnow()
    after = int(_unb64(cursor)["after"]) if cursor else 0
    with _tx(name) as cur:
        cur.execute(
            """WITH active AS (
                   SELECT DISTINCT ON (key, scope) key, scope,
                          version AS desired_version, created_at AS activated_at
                     FROM config_item
                    WHERE state = 'active'
                    ORDER BY key, scope, version DESC
               ), runtime AS (
                   SELECT key, scope,
                          MIN(effective_version) AS effective_version,
                          MIN(running_version)   AS running_version,
                          MAX(reported_at)       AS reported_at
                     FROM config_runtime
                    GROUP BY key, scope
               )
               SELECT a.key, a.scope, a.desired_version, a.activated_at,
                      r.effective_version, r.running_version, r.reported_at
                 FROM active a LEFT JOIN runtime r USING (key, scope)
                ORDER BY a.key, a.scope""")
        rows = cur.fetchall()

    drifts: list[dict] = []
    for row in rows:
        desired, effective, running = (row["desired_version"], row["effective_version"],
                                      row["running_version"])
        activated_at = _as_utc(row["activated_at"])
        reported_at = _as_utc(row["reported_at"]) if row["reported_at"] else activated_at
        if effective is None:
            drifts.append(_drift_row(row, "desired_vs_effective", now, activated_at,
                                     "从未回执生效版本（配置包未下发或实例全离线）"))
            continue
        if desired != effective:
            drifts.append(_drift_row(row, "desired_vs_effective", now, activated_at,
                                     f"desired v{desired} ≠ effective v{effective}"))
        if running is None:
            drifts.append(_drift_row(row, "effective_vs_running", now, reported_at,
                                     "未收到 running 版本回执"))
        elif effective != running:
            drifts.append(_drift_row(row, "effective_vs_running", now, reported_at,
                                     f"effective v{effective} ≠ running v{running}"))

    indexed = list(enumerate(drifts))[after: after + limit + 1]
    has_more = len(indexed) > limit
    kept = indexed[:limit]
    page = {"page": {"has_more": has_more, "cursor": None,
                     "next_cursor": _b64({"after": kept[-1][0] + 1})
                     if has_more and kept else None}}
    return _ok("listConfigDrifts", {"data": [d for _, d in kept], **page,
                                    "summary": {"total": len(drifts),
                                                "target": 0,
                                                "breached": sum(1 for d in drifts if d["sla_breached"])}})


def _drift_row(row: Mapping[str, Any], kind: str, now: datetime, since: datetime,
               detail: str) -> dict:
    sla = DRIFT_SLA_SECONDS[kind]
    age = max(0, int((now - since).total_seconds()))
    return {
        "key": row["key"],
        "scope": row["scope"],
        "desired_version": row["desired_version"],
        "effective_version": row["effective_version"],
        "running_version": row["running_version"],
        "kind": kind,
        "detail": detail,
        "detected_at": now.isoformat(),
        "age_seconds": age,
        "sla_seconds": sla,
        "sla_breached": age > sla,
    }


@operation("createConfigDraft")
def create_config_draft(principal: AdminPrincipal, key: str, body: Mapping[str, Any], *,
                        idempotency_key: str | None = None, now: datetime | None = None,
                        enabled: bool | None = None, name: str | None = None) -> dict:
    """建配置草稿（不生效）。schema + 量纲 + 幅度 + 权限点都在这一步拦（§21.4.1 ①）。"""
    now = _normalize(now) or _utcnow()
    policy = _require_key(key)
    body = dict(body or {})
    _reject_unknown_fields(body, ("value", "secret_ref", "value_type", "reason", "ticket",
                                  "effective_at"), where="ConfigDraftRequest")
    scope = DEFAULT_SCOPE
    reason = _require_reason(body)
    if policy.frozen:
        raise Forbidden(f"{key} 属私有域（frozen），不允许在管理后台改值（§21.9）")

    draft, delta_note = _validate_draft_value(policy, key, body, now=now, name=name)

    def fn(cur) -> WriteOutcome:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"config_item:{key}:{scope}",))
        cur.execute("SELECT COALESCE(MAX(version), 0) AS v FROM config_item WHERE key=%s AND scope=%s",
                    (key, scope))
        version = cur.fetchone()["v"] + 1
        digest = _sha256(canon({"key": key, "scope": scope, "version": version,
                                "value_type": policy.value_type,
                                "value": draft["value"],
                                "secret_ref": draft["secret_ref"]}))
        cur.execute(
            """INSERT INTO config_item
                 (key, scope, version, state, value_type, value, secret_ref, sensitive,
                  risk_level, domain, unit, direction, description, digest, created_at,
                  created_by, reason, ticket, effective_at)
               VALUES (%s,%s,%s,'draft',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING *""",
            (key, scope, version, policy.value_type,
             Jsonb(draft["value"]) if not policy.sensitive else None,
             draft["secret_ref"], policy.sensitive, policy.risk, policy.domain,
             policy.unit, policy.direction, policy.description, digest, now,
             principal.actor, reason, body.get("ticket"),
             _parse_dt(body.get("effective_at"), field="effective_at")),
        )
        row = cur.fetchone()
        after = _audit_view(row, sensitive=policy.sensitive)
        after["delta_note"] = delta_note
        return WriteOutcome(
            response=render_config_item(row), audit_action="config.draft.create",
            http_status=201, key=key, scope=scope, version=version, reason=reason,
            reason_code="R-CONFIG-DRAFT", after=after,
        )

    response = _run_write(principal=principal, operation_id="createConfigDraft",
                          idempotency_key=idempotency_key,
                          request_payload={"key": key, "scope": scope, **body},
                          fn=fn, now=now, enabled=enabled, key=key, scope=scope)
    return _ok("createConfigDraft", response)


def _validate_draft_value(policy: KeyPolicy, key: str, body: Mapping[str, Any], *,
                          now: datetime, name: str | None) -> tuple[dict, str | None]:
    """草稿值校验：类型 / 范围 / 枚举 / 敏感项只能给 secret_ref / max-delta。"""
    value_type = body.get("value_type")
    if value_type != policy.value_type:
        raise BadRequest(
            f"value_type 不匹配：{key} 声明为 {policy.value_type}，请求为 {value_type!r}",
            details=[{"field": "value_type"}],
        )

    has_value = "value" in body and body["value"] is not None
    has_ref = bool(body.get("secret_ref"))

    if policy.sensitive:
        if has_value:
            raise BadRequest(
                f"{key} 是敏感项：只能给 secret_ref，不允许提交明文 value（§21.12 敏感项只回引用）",
                details=[{"field": "value"}],
            )
        if not has_ref:
            raise BadRequest("敏感项必须提供 secret_ref", details=[{"field": "secret_ref"}])
        return {"value": None, "secret_ref": str(body["secret_ref"])}, None

    if has_ref:
        raise BadRequest(f"{key} 不是敏感项：请提供 value，不要给 secret_ref",
                         details=[{"field": "secret_ref"}])
    if not has_value:
        raise BadRequest("缺少 value", details=[{"field": "value"}])

    value = body["value"]
    expected = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
                "json": (dict, list)}
    want = expected[policy.value_type]
    if policy.value_type == "integer" and isinstance(value, bool):
        raise BadRequest("integer 类型不接受布尔", details=[{"field": "value"}])
    if not isinstance(value, want):
        raise BadRequest(f"value 类型错误：期望 {policy.value_type}",
                         details=[{"field": "value"}])
    if policy.enum is not None and value not in policy.enum:
        raise BadRequest(f"value 必须是 {list(policy.enum)} 之一", details=[{"field": "value"}])
    if policy.minimum is not None and value < policy.minimum:
        raise BadRequest(f"value 低于下限 {policy.minimum}", details=[{"field": "value"}])
    if policy.maximum is not None and value > policy.maximum:
        raise BadRequest(f"value 高于上限 {policy.maximum}", details=[{"field": "value"}])

    note = None
    if policy.max_delta is not None:
        current = _current_active_value(key, name=name)
        if current is not None:
            delta = abs(value - current)
            if delta > policy.max_delta:
                raise BadRequest(
                    f"变化幅度 {delta}{policy.unit or ''} 超过 max-delta {policy.max_delta}"
                    f"（当前 {current}，§21.13.1 ② 量级门禁）",
                    details=[{"field": "value", "max_delta": policy.max_delta,
                              "current": current}],
                )
            note = f"delta={delta}{policy.unit or ''} (max {policy.max_delta})"
    return {"value": value, "secret_ref": None}, note


def _current_active_value(key: str, *, name: str | None) -> Any:
    with _tx(name) as cur:
        cur.execute("""SELECT value FROM config_item WHERE key=%s AND state='active'
                        ORDER BY version DESC LIMIT 1""", (key,))
        row = cur.fetchone()
    return row["value"] if row else None


@operation("publishConfigItem")
def publish_config_item(principal: AdminPrincipal, key: str, body: Mapping[str, Any], *,
                        step_up_ref: str | None = None, step_up_at: datetime | None = None,
                        idempotency_key: str | None = None, now: datetime | None = None,
                        enabled: bool | None = None, name: str | None = None) -> dict:
    """发起发布单（生成 ``pending_approval``）。P0 需 step-up；窗口 / 冻结 / 冷却 / 锁都在这里。"""
    now = _normalize(now) or _utcnow()
    principal = _with_step_up(principal, step_up_ref, step_up_at)
    policy = _require_key(key)
    body = dict(body or {})
    _reject_unknown_fields(body, ("version", "effective_at", "reason", "ticket", "gray_plan"),
                           where="ConfigPublishRequest")
    scope = DEFAULT_SCOPE
    reason = _require_reason(body)
    version = body.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise BadRequest("version 必填且 ≥1", details=[{"field": "version"}])
    gray_plan = body.get("gray_plan")
    if gray_plan is not None:
        _validate_gray_plan(gray_plan)
    if policy.risk == "P0" and not body.get("ticket"):
        raise BadRequest("P0 配置必须带 ticket（变更单 / 影响面分析单，§21.4.1 P0 额外三件）",
                         details=[{"field": "ticket"}])

    def fn(cur) -> WriteOutcome:
        _require_step_up(principal, now)
        _assert_change_window(cur, now)
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"config_publish:{key}:{scope}",))
        cur.execute("""SELECT * FROM config_item WHERE key=%s AND scope=%s AND version=%s""",
                    (key, scope, version))
        target = cur.fetchone()
        if not target:
            raise NotFound(f"草稿不存在: {key} v{version} @ {scope}")
        if target["state"] != "draft":
            raise Conflict(f"v{version} 已是 {target['state']}：发布只能指向草稿（历史版本不可改）")
        cur.execute("""SELECT request_id FROM config_publish_request
                        WHERE key=%s AND scope=%s AND state = ANY(%s)""",
                    (key, scope, list(REQUEST_IN_FLIGHT)))
        locked = cur.fetchone()
        if locked:
            raise Conflict(f"该配置项已被发布单 {locked['request_id']} 锁定（同 key 并发发布 40901 语义）",
                           code=40901)
        prev = _current_active_version(cur, key, scope)
        _assert_cooldown(cur, key, scope, policy, now)

        effective_at = _parse_dt(body.get("effective_at"), field="effective_at")
        if policy.risk == "P0":
            floor = now + PUBLISH_COOLDOWN["P0"]
            if effective_at is None:
                effective_at = floor
            elif effective_at < floor:
                raise Conflict(
                    f"P0 冷却期 24h：effective_at 不得早于 {floor.isoformat()}（§21.4.3）",
                    code=40902)
        request_id = str(uuid.uuid4())
        approvals = APPROVALS_REQUIRED[policy.risk]
        cur.execute(
            """INSERT INTO config_publish_request
                 (request_id, key, scope, kind, state, target_version, previous_version,
                  requested_by, requested_at, expires_at, approvals_required,
                  approvals_received, approval_chain, publish_step_up_ref, effective_at,
                  gray_plan, reason, ticket, cooldown_until, updated_at)
               VALUES (%s,%s,%s,'publish','pending_approval',%s,%s,%s,%s,%s,%s,0,'[]'::jsonb,
                       %s,%s,%s,%s,%s,%s,%s)""",
            (request_id, key, scope, version, prev, principal.actor, now,
             now + APPROVAL_TIMEOUT, approvals, principal.step_up_ref, effective_at,
             Jsonb(gray_plan) if gray_plan is not None else None, reason, body.get("ticket"),
             now + PUBLISH_COOLDOWN[policy.risk], now),
        )
        ack = _ack(request_id, "pending_approval", version, effective_at, approvals, 0)
        return WriteOutcome(
            response=ack, audit_action="config.publish.request", http_status=202,
            key=key, scope=scope, version=version, request_id=request_id, reason=reason,
            reason_code="R-CONFIG-PUBLISH",
            before={"active_version": prev},
            after={"request_id": request_id, "state": "pending_approval",
                   "target_version": version, "risk": policy.risk,
                   "approvals_required": approvals,
                   "effective_at": effective_at.isoformat() if effective_at else None},
        )

    response = _run_write(principal=principal, operation_id="publishConfigItem",
                          idempotency_key=idempotency_key,
                          request_payload={"key": key, "scope": scope, **body},
                          fn=fn, now=now, enabled=enabled, key=key, scope=scope)
    return _ok("publishConfigItem", response)


def _with_step_up(principal: AdminPrincipal, ref: str | None,
                  at: datetime | None) -> AdminPrincipal:
    """网关把 X-Admin-Step-Up 解析成 (ref, at) 后并入主体；本模块只校验新鲜度。"""
    if ref is None and at is None:
        return principal
    return AdminPrincipal(
        actor=principal.actor, roles=principal.roles, permissions=principal.permissions,
        step_up_at=_normalize(at) or principal.step_up_at,
        step_up_ref=ref or principal.step_up_ref, break_glass=principal.break_glass,
        request_id=principal.request_id,
    )


def _validate_gray_plan(gray_plan: Any) -> None:
    if not isinstance(gray_plan, dict):
        raise BadRequest("gray_plan 必须是对象", details=[{"field": "gray_plan"}])
    _reject_unknown_fields(gray_plan, ("buckets", "observation_seconds"), where="gray_plan")
    buckets = gray_plan.get("buckets")
    if buckets is not None:
        if not isinstance(buckets, list) or not buckets:
            raise BadRequest("gray_plan.buckets 必须是非空数组",
                             details=[{"field": "gray_plan.buckets"}])
        for b in buckets:
            if not isinstance(b, int) or isinstance(b, bool) or not 0 <= b <= 100:
                raise BadRequest("gray_plan.buckets 元素必须是 0..100 的整数",
                                 details=[{"field": "gray_plan.buckets"}])
        if buckets != sorted(buckets):
            raise BadRequest("gray_plan.buckets 必须递增（1% → 5% → 25% → 100%，不自动全量）",
                             details=[{"field": "gray_plan.buckets"}])
    obs = gray_plan.get("observation_seconds")
    if obs is not None and (not isinstance(obs, int) or isinstance(obs, bool) or obs < 60):
        raise BadRequest("gray_plan.observation_seconds 必须 ≥60",
                         details=[{"field": "gray_plan.observation_seconds"}])


def _current_active_version(cur, key: str, scope: str) -> int | None:
    cur.execute("""SELECT MAX(version) AS v FROM config_item
                    WHERE key=%s AND scope=%s AND state='active'""", (key, scope))
    row = cur.fetchone()
    return row["v"] if row else None


def _assert_cooldown(cur, key: str, scope: str, policy: KeyPolicy, now: datetime) -> None:
    """同 key 冷却期内不得**再次发布**（回滚/急停不受限，止损优先，§21.4.3）。"""
    cooldown = PUBLISH_COOLDOWN[policy.risk]
    if cooldown <= timedelta(0):
        return
    cur.execute("""SELECT requested_at FROM config_publish_request
                    WHERE key=%s AND scope=%s AND kind='publish' AND state IN ('active','scheduled',
                          'rolling_out','approved')
                    ORDER BY requested_at DESC LIMIT 1""", (key, scope))
    row = cur.fetchone()
    if not row:
        return
    ready_at = _as_utc(row["requested_at"]) + cooldown
    if now < ready_at:
        raise Conflict(
            f"{policy.risk} 冷却期未到：{key} 上次发布 {_as_utc(row['requested_at']).isoformat()}，"
            f"可再发时间 {ready_at.isoformat()}（冷却期内只能回滚）",
            code=40902,
        )


def _is_business_window(at: datetime) -> bool:
    local = at.astimezone(CST)
    if local.weekday() >= 5:              # 周六日
        return False
    return PUBLISH_WINDOW[0] <= local.time() <= PUBLISH_WINDOW[1]


def _month_end_freeze(at: datetime) -> bool:
    local = at.astimezone(CST).date()
    next_month = (local.replace(day=28) + timedelta(days=4)).replace(day=1)
    month_end = next_month - timedelta(days=1)
    return (month_end - local).days < MONTH_END_FREEZE_DAYS


def freeze_window_active(principal: AdminPrincipal, *, at: datetime | None = None,
                         name: str | None = None) -> dict:
    """当前是否处于冻结窗口（月末 2 天 / 重大活动期）。变更日历的只读入口。"""
    _require_perm(principal, "config.item.read")
    at = _normalize(at) or _utcnow()
    with _tx(name) as cur:
        row = _freeze_row(cur, at)
    return {
        "frozen": bool(row),
        "at": at.isoformat(),
        "window": row,
        "meta": {"operation_id": None, "spec_status": "pending",
                 "note": "变更日历视图；接线前先改 spec（§21.12.2）"},
    }


def _freeze_row(cur, at: datetime) -> dict | None:
    cur.execute("""SELECT window_id, reason, starts_at, ends_at FROM ops_freeze_window
                    WHERE starts_at <= %s AND ends_at >= %s ORDER BY starts_at LIMIT 1""",
                (at, at))
    row = cur.fetchone()
    if row:
        return {"window_id": row["window_id"], "reason": row["reason"],
                "starts_at": _as_utc(row["starts_at"]).isoformat(),
                "ends_at": _as_utc(row["ends_at"]).isoformat()}
    if _month_end_freeze(at):
        return {"window_id": "month_end", "reason": "月末 2 天冻结（§22.21 变更日历）",
                "starts_at": None, "ends_at": None}
    return None


def _assert_change_window(cur, now: datetime) -> None:
    """窗口外变更 100% 被拒（§22.21 变更日历）。回滚 / kill switch 不走这里。"""
    frozen = _freeze_row(cur, now)
    if frozen:
        raise Conflict(f"冻结窗口内禁止发布：{frozen['reason']}", code=40902)
    if not _is_business_window(now):
        raise Conflict(
            "发布窗口为工作日 10:00–17:00（UTC+8）；止损动作请走 rollback / kill-switch（免窗口）",
            code=40902,
        )


def _ack(request_id: str, state: str, version: int, effective_at: datetime | None,
         approvals_required: int, approvals_received: int) -> dict:
    return {
        "request_id": request_id,
        "state": state,
        "version": version,
        "effective_at": effective_at.isoformat() if effective_at else None,
        "approvals_required": approvals_required,
        "approvals_received": approvals_received,
    }


@operation("approveConfigPublish")
def approve_config_publish(principal: AdminPrincipal, request_id: str,
                           body: Mapping[str, Any], *, step_up_ref: str | None = None,
                           step_up_at: datetime | None = None,
                           idempotency_key: str | None = None, now: datetime | None = None,
                           enabled: bool | None = None, name: str | None = None) -> dict:
    """复核发布单。自批自核 403；``expired`` 不自动放行；P0 需 FIN/AUDIT + 独立 step-up。"""
    now = _normalize(now) or _utcnow()
    principal = _with_step_up(principal, step_up_ref, step_up_at)
    # 先把超时的 pending_approval 打成 expired（独立事务提交）：这样"过期不放行"
    # 不会因为本次复核抛 409 而被一起回滚掉。
    expire_stale_requests(now=now, name=name)
    body = dict(body or {})
    _reject_unknown_fields(body, ("decision", "reason"), where="ConfigApprovalRequest")
    decision = body.get("decision")
    if decision not in ("approve", "reject"):
        raise BadRequest("decision 必须是 approve / reject", details=[{"field": "decision"}])
    reason = _require_reason(body)

    def fn(cur) -> WriteOutcome:
        _require_step_up(principal, now)
        cur.execute("SELECT * FROM config_publish_request WHERE request_id=%s FOR UPDATE",
                    (request_id,))
        req = cur.fetchone()
        if not req:
            raise NotFound(f"发布单不存在: {request_id}")

        if req["state"] == "expired":
            raise Conflict(
                "发布单已 expired：4h 未复核即作废，**不自动放行**，请重新建草稿并发起新单（§21.4.2）",
                code=40902,
            )
        if req["state"] != "pending_approval":
            raise Conflict(f"发布单当前状态 {req['state']} 不可复核", code=40902)

        if principal.actor == req["requested_by"]:
            exc = Forbidden("自批自核被拒绝：复核人不得等于发起人（SoD，§21.4.3）")
            exc.reason_code = "forbidden_self_approval"
            raise exc

        chain = list(req["approval_chain"] or [])
        if any(entry.get("actor") == principal.actor for entry in chain):
            exc = Forbidden("同一人不得重复复核同一发布单（双人复核需两名不同复核人）")
            exc.reason_code = "forbidden_duplicate_approver"
            raise exc

        policy = KEY_POLICIES.get(req["key"])
        risk = policy.risk if policy else "P1"
        if risk == "P0":
            if not principal.has_role(*APPROVER_ROLES_P0):
                exc = Forbidden("P0 配置的复核人必须来自 FIN 或 AUDIT（§21.4.3 双人复核）")
                exc.reason_code = "forbidden_p0_approver_role"
                raise exc
            if principal.step_up_ref and principal.step_up_ref == req["publish_step_up_ref"]:
                exc = Forbidden(
                    "step-up 不得复用：发布与复核各需一次独立二次认证（§21.4.3）")
                exc.reason_code = "forbidden_step_up_reuse"
                raise exc

        if decision == "reject":
            cur.execute("""UPDATE config_publish_request
                              SET state='rejected', reject_reason=%s, updated_at=%s,
                                  approvals_received=%s, approval_chain=%s
                            WHERE request_id=%s""",
                        (reason, now, len(chain), Jsonb(chain), request_id))
            ack = _ack(request_id, "rejected", req["target_version"], req["effective_at"],
                       req["approvals_required"], len(chain))
            return WriteOutcome(
                response=ack, audit_action="config.publish.reject", http_status=200,
                key=req["key"], scope=req["scope"], version=req["target_version"],
                request_id=request_id, reason=reason, reason_code="R-CONFIG-REJECT",
                before={"state": "pending_approval"},
                after={"state": "rejected", "reason": reason},
            )

        chain.append({
            "actor": principal.actor, "roles": sorted(principal.roles),
            "step_up_ref": principal.step_up_ref, "at": now.isoformat(),
            "decision": "approve", "reason": reason,
        })
        received = len(chain)
        if received >= req["approvals_required"]:
            effective_at = _normalize(req["effective_at"])
            state = "scheduled" if (effective_at and effective_at > now) else "approved"
        else:
            state = "pending_approval"
        cur.execute("""UPDATE config_publish_request
                          SET state=%s, approvals_received=%s, approval_chain=%s, updated_at=%s
                        WHERE request_id=%s""",
                    (state, received, Jsonb(chain), now, request_id))
        ack = _ack(request_id, state, req["target_version"], req["effective_at"],
                   req["approvals_required"], received)
        return WriteOutcome(
            response=ack, audit_action="config.publish.approve", http_status=200,
            key=req["key"], scope=req["scope"], version=req["target_version"],
            request_id=request_id, reason=reason, reason_code="R-CONFIG-APPROVE",
            before={"state": "pending_approval", "approvals_received": received - 1},
            after={"state": state, "approvals_received": received,
                   "approver": principal.actor},
        )

    response = _run_write(principal=principal, operation_id="approveConfigPublish",
                          idempotency_key=idempotency_key,
                          request_payload={"request_id": request_id, **body},
                          fn=fn, now=now, enabled=enabled)
    return _ok("approveConfigPublish", response)


@operation("rollbackConfigItem")
def rollback_config_item(principal: AdminPrincipal, key: str, body: Mapping[str, Any], *,
                         step_up_ref: str | None = None, step_up_at: datetime | None = None,
                         idempotency_key: str | None = None, now: datetime | None = None,
                         enabled: bool | None = None, name: str | None = None) -> dict:
    """回滚 = 以历史版本为内容生成**新的**发布单；历史版本本身不可修改（§21.4.2）。

    止损动作：**免发布窗口、免冷却期**（冷却期内只能回滚 → 这里必须放行）。
    """
    now = _normalize(now) or _utcnow()
    principal = _with_step_up(principal, step_up_ref, step_up_at)
    policy = _require_key(key)
    body = dict(body or {})
    _reject_unknown_fields(body, ("target_version", "reason", "ticket"),
                           where="ConfigRollbackRequest")
    scope = DEFAULT_SCOPE
    reason = _require_reason(body)
    target_version = body.get("target_version")
    if not isinstance(target_version, int) or isinstance(target_version, bool) or target_version < 1:
        raise BadRequest("target_version 必填且 ≥1", details=[{"field": "target_version"}])

    def fn(cur) -> WriteOutcome:
        _require_step_up(principal, now)
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"config_publish:{key}:{scope}",))
        cur.execute("SELECT * FROM config_item WHERE key=%s AND scope=%s AND version=%s",
                    (key, scope, target_version))
        target = cur.fetchone()
        if not target:
            raise NotFound(f"目标版本不存在: {key} v{target_version} @ {scope}")
        if target["state"] == "draft":
            raise Conflict("回滚目标不能是草稿：只能指向已生效过的不可变版本（§21.4.2）")
        cur.execute("""SELECT request_id FROM config_publish_request
                        WHERE key=%s AND scope=%s AND state = ANY(%s)""",
                    (key, scope, list(REQUEST_IN_FLIGHT)))
        locked = cur.fetchone()
        if locked:
            raise Conflict(f"该配置项已被发布单 {locked['request_id']} 锁定", code=40901)

        current = _current_active_version(cur, key, scope)
        if current == target_version:
            raise Conflict(f"v{target_version} 已是当前生效版本，无需回滚")
        request_id = str(uuid.uuid4())
        approvals = APPROVALS_REQUIRED[policy.risk]
        cur.execute(
            """INSERT INTO config_publish_request
                 (request_id, key, scope, kind, state, target_version, previous_version,
                  requested_by, requested_at, expires_at, approvals_required,
                  approvals_received, approval_chain, publish_step_up_ref, effective_at,
                  reason, ticket, updated_at)
               VALUES (%s,%s,%s,'rollback','pending_approval',%s,%s,%s,%s,%s,%s,0,
                       '[]'::jsonb,%s,%s,%s,%s,%s)""",
            (request_id, key, scope, target_version, current, principal.actor, now,
             now + APPROVAL_TIMEOUT, approvals, principal.step_up_ref, now, reason,
             body.get("ticket"), now),
        )
        ack = _ack(request_id, "pending_approval", target_version, now, approvals, 0)
        return WriteOutcome(
            response=ack, audit_action="config.rollback.request", http_status=200,
            key=key, scope=scope, version=target_version, request_id=request_id,
            reason=reason, reason_code="R-CONFIG-ROLLBACK",
            before={"active_version": current},
            after={"request_id": request_id, "state": "pending_approval",
                   "target_version": target_version, "kind": "rollback"},
        )

    response = _run_write(principal=principal, operation_id="rollbackConfigItem",
                          idempotency_key=idempotency_key,
                          request_payload={"key": key, "scope": scope, **body},
                          fn=fn, now=now, enabled=enabled, key=key, scope=scope)
    return _ok("rollbackConfigItem", response)


@operation("killSwitchConfigItem")
def kill_switch_config_item(principal: AdminPrincipal, key: str, body: Mapping[str, Any], *,
                            step_up_ref: str | None = None, step_up_at: datetime | None = None,
                            idempotency_key: str | None = None, now: datetime | None = None,
                            enabled: bool | None = None, name: str | None = None) -> dict:
    """紧急收紧开关：只能收紧、≤24h、到期自动回退上一生效版本（§21.12 killSwitchConfigItem）。

    收紧动作**单人可做**（§21.13.3 应急五步第 1 步"先恢复后归因"），事后进审计与补审；
    但 step-up 仍必需（spec 的 ``AdminStepUp`` 是 required）。
    """
    now = _normalize(now) or _utcnow()
    principal = _with_step_up(principal, step_up_ref, step_up_at)
    policy = _require_key(key)
    body = dict(body or {})
    _reject_unknown_fields(body, ("reason", "ttl_seconds", "tighten_only"),
                           where="ConfigKillSwitchRequest")
    scope = DEFAULT_SCOPE
    reason = _require_reason(body)
    ttl = body.get("ttl_seconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= KILL_SWITCH_MAX_TTL:
        raise BadRequest(f"ttl_seconds 必须是 1..{KILL_SWITCH_MAX_TTL} 的整数",
                         details=[{"field": "ttl_seconds"}])
    if body.get("tighten_only") is False:
        raise BadRequest("kill switch 只允许收紧：tighten_only 不得为 false",
                         details=[{"field": "tighten_only"}])
    if policy.kill_switch_value is None:
        raise BadRequest(f"{key} 没有保守预设值，不支持 kill switch（§21.12 只收紧）",
                         details=[{"field": "key"}])

    def fn(cur) -> WriteOutcome:
        _require_step_up(principal, now)
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"config_item:{key}:{scope}",))
        current = None
        cur.execute("""SELECT * FROM config_item WHERE key=%s AND scope=%s AND state='active'
                        ORDER BY version DESC LIMIT 1""", (key, scope))
        active = cur.fetchone()
        if active:
            current = active["value"]
        preset = policy.kill_switch_value
        if not policy.tighten_ok(preset, current):
            raise Conflict(
                f"拒绝：{key} 当前生效值 {current} 已经比保守预设 {preset} 更保守，"
                "kill switch 只收紧不放开（§21.12）",
                code=40902,
            )
        cur.execute("SELECT COALESCE(MAX(version),0) AS v FROM config_item WHERE key=%s AND scope=%s",
                    (key, scope))
        version = cur.fetchone()["v"] + 1
        digest = _sha256(canon({"key": key, "scope": scope, "version": version,
                                "value_type": policy.value_type, "value": preset}))
        cur.execute(
            """INSERT INTO config_item
                 (key, scope, version, state, value_type, value, secret_ref, sensitive,
                  risk_level, domain, unit, direction, description, digest, created_at,
                  created_by, reason, ticket, effective_at)
               VALUES (%s,%s,%s,'active',%s,%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s)
               RETURNING *""",
            (key, scope, version, policy.value_type, Jsonb(preset), policy.sensitive,
             policy.risk, policy.domain, policy.unit, policy.direction,
             f"{policy.description}（kill switch 保守预设）", digest, now,
             principal.actor, reason, now),
        )
        new_row = cur.fetchone()
        if active:
            cur.execute("""UPDATE config_item SET state='rolled_back', superseded_by=%s
                            WHERE key=%s AND scope=%s AND version=%s""",
                        (version, key, scope, active["version"]))
        request_id = str(uuid.uuid4())
        cur.execute(
            """INSERT INTO config_publish_request
                 (request_id, key, scope, kind, state, target_version, previous_version,
                  requested_by, requested_at, expires_at, approvals_required,
                  approvals_received, approval_chain, publish_step_up_ref, effective_at,
                  kill_switch_ttl, reason, updated_at)
               VALUES (%s,%s,%s,'kill_switch','active',%s,%s,%s,%s,%s,1,0,'[]'::jsonb,
                       %s,%s,%s,%s,%s)""",
            (request_id, key, scope, version,
             active["version"] if active else None, principal.actor, now,
             now + timedelta(seconds=ttl), principal.step_up_ref, now, ttl, reason, now),
        )
        ack = _ack(request_id, "active", version, now, 1, 0)
        ack["ttl_seconds"] = ttl
        ack["tighten_only"] = True
        ack["revert_to_version"] = active["version"] if active else None
        return WriteOutcome(
            response=ack, audit_action="config.kill_switch.apply", http_status=200,
            key=key, scope=scope, version=version, request_id=request_id, reason=reason,
            reason_code="R-CONFIG-EMERGENCY",
            before={"active_version": active["version"] if active else None,
                    "value": current},
            after={"active_version": version, "value": preset, "ttl_seconds": ttl,
                   "mode": "emergency", "post_review_required": True},
        )

    response = _run_write(principal=principal, operation_id="killSwitchConfigItem",
                          idempotency_key=idempotency_key,
                          request_payload={"key": key, "scope": scope, **body},
                          fn=fn, now=now, enabled=enabled, key=key, scope=scope)
    return _ok("killSwitchConfigItem", response)


# --------------------------------------------------------------------------- 系统驱动
def _expire_one(cur, req: Mapping[str, Any], now: datetime) -> bool:
    """``pending_approval`` 超 4h → ``expired``（解锁 key，但**绝不自动放行**）。"""
    if req["state"] != "pending_approval":
        return False
    if now < _as_utc(req["expires_at"]):
        return False
    cur.execute("""UPDATE config_publish_request
                      SET state='expired', updated_at=%s, reject_reason=%s
                    WHERE request_id=%s""",
                (now, "4h 未复核自动过期（不自动放行，§21.4.2）", req["request_id"]))
    _append_audit(
        cur, actor="system:scheduler", actions="config.request.expire", outcome="ok",
        http_status=200, now=now, roles=("SYSTEM",), key=req["key"], scope=req["scope"],
        version=req["target_version"], request_id=req["request_id"],
        reason="4h 未复核自动过期，不自动放行", reason_code="R-CONFIG-EXPIRE",
        before={"state": "pending_approval"}, after={"state": "expired"},
    )
    return True


def expire_stale_requests(now: datetime | None = None, *, name: str | None = None) -> dict:
    """把超时的 ``pending_approval`` 打成 ``expired``（系统任务，非管理面操作）。"""
    now = _normalize(now) or _utcnow()
    expired: list[str] = []
    with _tx(name) as cur:
        cur.execute("""SELECT * FROM config_publish_request
                        WHERE state='pending_approval' AND expires_at <= %s FOR UPDATE""", (now,))
        for req in cur.fetchall():
            if _expire_one(cur, req, now):
                expired.append(req["request_id"])
    return {"expired": expired, "count": len(expired)}


def expire_kill_switches(now: datetime | None = None, *, name: str | None = None) -> dict:
    """kill switch 到期：回到上一生效版本并留痕（§21.12 "到期自动回到上一生效版本"）。"""
    now = _normalize(now) or _utcnow()
    reverted: list[str] = []
    with _tx(name) as cur:
        cur.execute("""SELECT * FROM config_publish_request
                        WHERE kind='kill_switch' AND state='active'
                          AND requested_at + make_interval(secs => kill_switch_ttl) <= %s
                        FOR UPDATE""", (now,))
        for req in cur.fetchall():
            prev = req["previous_version"]
            cur.execute("""UPDATE config_item SET state='rolled_back'
                            WHERE key=%s AND scope=%s AND version=%s AND state='active'""",
                        (req["key"], req["scope"], req["target_version"]))
            if prev is not None:
                cur.execute("""UPDATE config_item SET state='active'
                                WHERE key=%s AND scope=%s AND version=%s""",
                            (req["key"], req["scope"], prev))
            cur.execute("""UPDATE config_publish_request SET state='rolled_back', updated_at=%s
                            WHERE request_id=%s""", (now, req["request_id"]))
            _append_audit(
                cur, actor="system:scheduler", actions="config.kill_switch.expire",
                outcome="ok", http_status=200, now=now, roles=("SYSTEM",),
                key=req["key"], scope=req["scope"], version=req["target_version"],
                request_id=req["request_id"],
                reason=f"kill switch TTL {req['kill_switch_ttl']}s 到期，回到上一生效版本",
                reason_code="R-CONFIG-KILL-EXPIRE",
                before={"active_version": req["target_version"]},
                after={"active_version": prev},
            )
            reverted.append(req["request_id"])
    return {"reverted": reverted, "count": len(reverted)}


def advance_publish_requests(now: datetime | None = None, *, name: str | None = None) -> dict:
    """推进发布单：``approved`` → ``scheduled``/``active``；``scheduled`` 到点 → ``active``。

    生效时把目标草稿转 ``active``、旧 active 转 ``rolled_back``（只改状态，不动值）。
    """
    now = _normalize(now) or _utcnow()
    activated: list[str] = []
    with _tx(name) as cur:
        cur.execute("""SELECT * FROM config_publish_request
                        WHERE state IN ('approved','scheduled') FOR UPDATE""")
        for req in cur.fetchall():
            effective_at = _normalize(req["effective_at"])
            if req["state"] == "approved" and effective_at and effective_at > now:
                cur.execute("""UPDATE config_publish_request SET state='scheduled', updated_at=%s
                                WHERE request_id=%s""", (now, req["request_id"]))
                continue
            if effective_at and effective_at > now:
                continue
            _activate_one(cur, req, now)
            activated.append(req["request_id"])
    return {"activated": activated, "count": len(activated)}


def _activate_one(cur, req: Mapping[str, Any], now: datetime) -> None:
    target_version = req["target_version"]
    cur.execute("""SELECT * FROM config_item WHERE key=%s AND scope=%s AND version=%s""",
                (req["key"], req["scope"], target_version))
    target = cur.fetchone()
    if not target:
        cur.execute("""UPDATE config_publish_request SET state='failed', updated_at=%s
                        WHERE request_id=%s""", (now, req["request_id"]))
        _append_audit(cur, actor="system:scheduler", actions="config.publish.activate",
                      outcome="denied", http_status=409, now=now, roles=("SYSTEM",),
                      key=req["key"], scope=req["scope"], version=target_version,
                      request_id=req["request_id"], reason="目标版本已不存在",
                      reason_code="R-CONFIG-FAILED", after={"state": "failed"})
        return
    cur.execute("""UPDATE config_item SET state='rolled_back'
                    WHERE key=%s AND scope=%s AND state='active' AND version <> %s""",
                (req["key"], req["scope"], target_version))
    cur.execute("""UPDATE config_item SET state='active', effective_at=%s
                    WHERE key=%s AND scope=%s AND version=%s""",
                (now, req["key"], req["scope"], target_version))
    cur.execute("""UPDATE config_publish_request SET state='active', updated_at=%s
                    WHERE request_id=%s""", (now, req["request_id"]))
    _append_audit(
        cur, actor="system:scheduler", actions="config.publish.activate", outcome="ok",
        http_status=200, now=now, roles=("SYSTEM",), key=req["key"], scope=req["scope"],
        version=target_version, request_id=req["request_id"],
        reason=f"{req['kind']} 发布单生效", reason_code="R-CONFIG-ACTIVATE",
        before={"active_version": req["previous_version"]},
        after={"active_version": target_version, "kind": req["kind"]},
    )


def report_runtime(key: str, scope: str, instance: str, *, effective_version: int | None = None,
                   running_version: int | None = None, now: datetime | None = None,
                   name: str | None = None) -> dict:
    """消费端回执（漂移检测的 B/C 两源）。心跳写入，不算管理面写操作。"""
    now = _normalize(now) or _utcnow()
    if not instance:
        raise BadRequest("instance 必填", details=[{"field": "instance"}])
    with _tx(name) as cur:
        cur.execute(
            """INSERT INTO config_runtime
                 (key, scope, instance, effective_version, running_version, reported_at)
               VALUES (%s,%s,%s,%s,%s,%s)
               ON CONFLICT (key, scope, instance) DO UPDATE
                 SET effective_version=EXCLUDED.effective_version,
                     running_version=EXCLUDED.running_version,
                     reported_at=EXCLUDED.reported_at""",
            (key, scope, instance, effective_version, running_version, now))
    return {"ok": True, "key": key, "scope": scope, "instance": instance}


# --------------------------------------------------------------------------- 运维只读视图
def health_overview(principal: AdminPrincipal, *, now: datetime | None = None,
                    name: str | None = None) -> dict:
    """健康总览七块（网关/调度/账本/对账/钱包/配置/通知）：红黄绿 + 最近一次变更。

    ``配置`` 一块由漂移实况覆盖：有未纠正漂移至少黄，SLA 超时直接红——避免
    "面板全绿但配置早飘了"。
    """
    _require_perm(principal, "config.item.read")
    now = _normalize(now) or _utcnow()
    drifts = list_config_drifts(principal, now=now, name=name)["data"]
    with _tx(name) as cur:
        cur.execute("SELECT * FROM ops_component_state")
        rows = {r["component"]: r for r in cur.fetchall()}
        cur.execute("""SELECT COUNT(*) AS n FROM config_publish_request
                        WHERE state IN ('pending_approval','approved','scheduled','rolling_out')""")
        in_flight = cur.fetchone()["n"]

    blocks: list[dict] = []
    for component in COMPONENTS:
        row = rows.get(component)
        status = row["status"] if row else "unknown"
        detail = row["detail"] if row else "无心跳"
        block = {
            "component": component,
            "label": COMPONENT_LABELS[component],
            "status": status,
            "detail": detail,
            "last_change_at": (_as_utc(row["last_change_at"]).isoformat()
                               if row and row["last_change_at"] else None),
            "last_change_ref": row["last_change_ref"] if row else None,
        }
        if component == "config":
            own = [d for d in drifts if not d["sla_breached"]]
            breached = [d for d in drifts if d["sla_breached"]]
            if breached:
                block.update(status="red",
                             detail=f"{len(breached)} 项漂移超时未纠正（共 {len(drifts)} 项）")
            elif own:
                block.update(status="yellow",
                             detail=f"{len(own)} 项三源漂移待纠正（目标 0）")
            elif status == "unknown":
                block.update(status="green", detail="无漂移，配置已收敛")
            block["drift_count"] = len(drifts)
        blocks.append(block)

    overall = max(blocks, key=lambda b: STATUS_RANK.get(b["status"], 1))["status"]
    return {
        "overall": overall,
        "checked_at": now.isoformat(),
        "blocks": blocks,
        "counts": {"red": sum(1 for b in blocks if b["status"] == "red"),
                   "yellow": sum(1 for b in blocks if b["status"] == "yellow"),
                   "green": sum(1 for b in blocks if b["status"] == "green"),
                   "publish_in_flight": in_flight},
        "meta": {"operation_id": None, "spec_status": "pending",
                 "note": "运维中心只读视图；接线前先改 spec（§21.12.2）"},
    }


def slo_burn_rate(principal: AdminPrincipal, *, now: datetime | None = None,
                  name: str | None = None) -> dict:
    """SLO 燃烧率（多窗口惯例阈值：≥14.4 紧急 / ≥6 高 / ≥1 观察）。"""
    _require_perm(principal, "config.item.read")
    now = _normalize(now) or _utcnow()
    with _tx(name) as cur:
        cur.execute("""SELECT * FROM ops_slo_window ORDER BY slo, window_start DESC""")
        rows = cur.fetchall()
    latest: dict[str, dict] = {}
    for row in rows:
        latest.setdefault(row["slo"], row)
    series: list[dict] = []
    for slo, row in sorted(latest.items()):
        target = SLO_TARGETS.get(slo, {}).get("target")
        achieved = row["good"] / row["total"] if row["total"] else 1.0
        if target is None or target >= 1:
            burn = None
            severity = "unknown"
        else:
            burn = round((1 - achieved) / (1 - target), 3)
            severity = ("critical" if burn >= BURN_CRITICAL else
                        "high" if burn >= BURN_HIGH else
                        "watch" if burn >= BURN_WARN else "ok")
        series.append({
            "slo": slo,
            "description": SLO_TARGETS.get(slo, {}).get("description"),
            "target": target,
            "window_start": _as_utc(row["window_start"]).isoformat(),
            "window_end": _as_utc(row["window_end"]).isoformat(),
            "good": row["good"],
            "total": row["total"],
            "achieved": round(achieved, 6),
            "burn_rate": burn,
            "severity": severity,
        })
    worst = "ok"
    for sev in ("critical", "high", "watch"):
        if any(s["severity"] == sev for s in series):
            worst = sev
            break
    return {"overall": worst, "series": series, "checked_at": now.isoformat(),
            "meta": {"operation_id": None, "spec_status": "pending"}}


def list_alerts(principal: AdminPrincipal, *, now: datetime | None = None,
                include_resolved: bool = False, name: str | None = None) -> dict:
    """告警去重 / 抑制 / 升级视图。目标：重复告警合并率 ≥80%（§22.21 值班与告警）。"""
    _require_perm(principal, "config.item.read")
    now = _normalize(now) or _utcnow()
    with _tx(name) as cur:
        sql = "SELECT * FROM ops_alert"
        if not include_resolved:
            sql += " WHERE state <> 'resolved'"
        cur.execute(sql + " ORDER BY opened_at")
        rows = cur.fetchall()

    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["fingerprint"], []).append(row)
    merged: list[dict] = []
    for fingerprint, items in groups.items():
        items.sort(key=lambda r: _as_utc(r["opened_at"]))
        first, last = items[0], items[-1]
        suppressed = any(
            r["state"] == "suppressed" or (r["suppressed_until"] and _as_utc(r["suppressed_until"]) > now)
            for r in items
        )
        merged.append({
            "fingerprint": fingerprint,
            "alert_ids": [r["alert_id"] for r in items],
            "severity": max((r["severity"] for r in items), key=lambda s: {"P2": 0, "P1": 1, "P0": 2}.get(s, 0)),
            "title": first["title"],
            "opened_at": _as_utc(first["opened_at"]).isoformat(),
            "last_seen": _as_utc(max(_as_utc(r["last_seen"]) for r in items)).isoformat(),
            "occurrences": sum(r["occurrences"] for r in items),
            "merged": len(items),
            "state": "suppressed" if suppressed else last["state"],
            "suppressed": suppressed,
            "owner": last.get("owner"),
        })
    merged.sort(key=lambda a: ({"P0": 0, "P1": 1, "P2": 2}.get(a["severity"], 3), a["opened_at"]))
    total = sum(a["occurrences"] for a in merged)
    groups_n = len(merged)
    ratio = round(1 - groups_n / total, 4) if total else 0.0
    return {
        "data": merged,
        "metrics": {
            "raw_occurrences": total,
            "groups": groups_n,
            "dedupe_ratio": ratio,
            "target_ratio": 0.8,
            "meets_target": ratio >= 0.8,
            "suppressed_groups": sum(1 for a in merged if a["suppressed"]),
            "p0_open": sum(1 for a in merged if a["severity"] == "P0" and a["state"] != "resolved"),
        },
        "checked_at": now.isoformat(),
        "meta": {"operation_id": None, "spec_status": "pending"},
    }


def search_audit(principal: AdminPrincipal, *, key: str | None = None,
                 actor: str | None = None, action: str | None = None,
                 since: datetime | None = None, until: datetime | None = None,
                 cursor: str | None = None, limit: int | None = None,
                 name: str | None = None) -> dict:
    """审计检索入口（AUDIT 只读）。导出走 ``config.audit.export`` 权限，本函数不导出文件。"""
    _require_perm(principal, "config.item.read")
    limit = _limit(limit)
    after = int(_unb64(cursor)["after"]) if cursor else 0
    since = _normalize(since)
    until = _normalize(until)
    with _tx(name) as cur:
        cur.execute(
            """SELECT * FROM config_audit
                WHERE seq > %s
                  AND (%s::text IS NULL OR key = %s)
                  AND (%s::text IS NULL OR actor = %s)
                  AND (%s::text IS NULL OR action LIKE %s)
                  AND (%s::timestamptz IS NULL OR at >= %s)
                  AND (%s::timestamptz IS NULL OR at <= %s)
                ORDER BY seq
                LIMIT %s""",
            (after, key, key, actor, actor, action, f"{action}%" if action else None,
             since, since, until, until, limit + 1))
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) AS n FROM config_audit")
        total = cur.fetchone()["n"]
    page = _page(rows, limit, lambda r: _b64({"after": r["seq"]}))
    return {
        "data": [
            {
                "seq": r["seq"], "at": _as_utc(r["at"]).isoformat(), "actor": r["actor"],
                "roles": r["actor_roles"], "action": r["action"], "op_id": r["op_id"],
                "key": r["key"], "scope": r["scope"], "version": r["version"],
                "request_id": r["request_id"], "outcome": r["outcome"],
                "http_status": r["http_status"], "reason": r["reason"],
                "reason_code": r["reason_code"], "before": r["before"], "after": r["after"],
                "hash": r["hash"][:16], "prev_hash": (r["prev_hash"] or "")[:16],
            }
            for r in rows[:limit]
        ],
        "page": page["page"],
        "totals": {"entries": total, "export_requires": "config.audit.export"},
        "meta": {"operation_id": None, "spec_status": "pending"},
    }


def change_calendar(principal: AdminPrincipal, *, since: datetime | None = None,
                    until: datetime | None = None, name: str | None = None) -> dict:
    """变更日历：进行中与历史发布单 + 冻结窗口，一条时间线看"谁在什么时候改了什么"。"""
    _require_perm(principal, "config.item.read")
    since = _normalize(since)
    until = _normalize(until)
    with _tx(name) as cur:
        cur.execute(
            """SELECT * FROM config_publish_request
                WHERE (%s::timestamptz IS NULL OR requested_at >= %s)
                  AND (%s::timestamptz IS NULL OR requested_at <= %s)
                ORDER BY requested_at""", (since, since, until, until))
        requests = cur.fetchall()
        cur.execute("SELECT * FROM ops_freeze_window ORDER BY starts_at")
        freezes = cur.fetchall()
    return {
        "requests": [
            {
                "request_id": r["request_id"], "key": r["key"], "scope": r["scope"],
                "kind": r["kind"], "state": r["state"], "target_version": r["target_version"],
                "previous_version": r["previous_version"], "requested_by": r["requested_by"],
                "requested_at": _as_utc(r["requested_at"]).isoformat(),
                "effective_at": (_as_utc(r["effective_at"]).isoformat()
                                 if r["effective_at"] else None),
                "approvals": f"{r['approvals_received']}/{r['approvals_required']}",
                "reason": r["reason"], "ticket": r["ticket"],
            }
            for r in requests
        ],
        "freeze_windows": [
            {"window_id": f["window_id"], "reason": f["reason"],
             "starts_at": _as_utc(f["starts_at"]).isoformat(),
             "ends_at": _as_utc(f["ends_at"]).isoformat()}
            for f in freezes
        ],
        "publish_window": {"weekdays": "Mon-Fri", "local": "UTC+8",
                           "from": PUBLISH_WINDOW[0].isoformat(),
                           "to": PUBLISH_WINDOW[1].isoformat(),
                           "exempt": ["rollback", "kill_switch"]},
        "meta": {"operation_id": None, "spec_status": "pending"},
    }
