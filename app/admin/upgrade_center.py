# SPDX-License-Identifier: AGPL-3.0-or-later
"""技术升级中心服务层（§22.22 · §18.7.1 · §22.9 · 〔决策K8〕）。

本模块把「技术升级」做成**可以判定、可以停、可以回滚、可以复算**的服务层：
版本清单与回滚点（读 spec）、灰度阶梯推进（按桶 + 命中阈值自动停）、
回滚到上一版（记录时间与证据）、兼容矩阵 N/N-1/N-2（未知即 unknown）。

它**不注册任何 HTTP 路由**（本单红线：不新增未进 spec 的端点），也不发布任何东西：
发布动作只能由发布窗闸门 + 变更单驱动，接线点写在 ``docs/DEV-0005-upgrade-center.md`` §6。

一、验收对照（本文件逐条可测）
==============================
① 版本清单 / 回滚点    ``version_inventory()`` 解析 ``spec/CHANGELOG-协议.md``，
                       并把 ``spec/openapi.yaml`` 的 ``info.version`` 一起摆出来做对齐判定
                       （``alignment``）。**不一致就报不一致**，不取整、不糊过去。
② 灰度按桶推进         阶梯取自 §22.22（``internal → 1% → 10% → 50% → 全量``）与
                       §22.9（客户端 ``5% → 25% → 100%``，每桶 ≥24h）；``evaluate_stage()``
                       给 advance / hold / stop 三态；命中阈值 → 落库 + 审计 → 40907。
③ 回滚到上一版         ``rollback()`` 写 ``upgrade_rollback``：回滚时刻、from/to 版本、
                       回滚点的**记录时间**（上一版的 spec 记录时间，或 run 的部署时间）、
                       耗时与是否在预算内、以及证据 JSON。
④ 兼容矩阵             ``compat_matrix()`` 固定三行 N / N-1 / N-2；缺证据一律 ``unknown``，
                       只有三行全 ``pass`` 才允许对外说「通过」。
⑤ 错误码               只使用 §6.3 / §6.3b 已登记码（``ERROR_CODES_USED``），
                       每个码都标了出处；不新造，``test_upgrade_center.py`` 逐条反查。
⑥ 特性开关             ``upgrade_center``：owner=release-manager · expire_at=2026-12-31 ·
                       默认关闭；关闭后只保留**只读版本列表**，写入口 404（不是 403）。

二、三态判定为什么是「未知即 unknown」
======================================
灰度看的是「这一桶有没有变坏」。**缺指标不等于没事**，所以在 ``evaluate_stage()`` 里：
指标缺失 → ``hold``（不推进，也不当作通过），指标越线 → ``stop``（停桶 + 留证），
全部通过才 ``advance``。同理兼容矩阵缺证据 → ``unknown``，汇总永远不会因此变成 ``pass``。

三、不做什么
============
* **不发布**：本模块没有「发版」能力，只有闸门与记录；发布由 release-manager 在
  批准窗口内执行（本单红线：研发不得直接发布）。
* 不碰账本、不签名、不发钱：模块不 import ``app.ledger`` 等，不产生任何资金分录。
* 不改 ``spec/openapi.yaml``：只读解析；版本号不一致时如实报 ``mismatch``。
* 不建迁移：表结构由 ``ensure_schema()`` 在**独立 schema**（默认 ``upgrade_center``，
  可用 ``DJB_UPGRADE_SCHEMA`` 覆盖）里幂等自举，属临时脚手架；正式迁移另开票据。
"""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .. import db
from . import (
    FEATURE_FLAGS,
    REQUIRED_FLAG_FIELDS,
    BadRequest,
    BreakGlassReadOnly,
    Conflict,
    FeatureDisabled,
    Forbidden,
    NotFound,
    OpsCenterError,
    StepUpRequired,
    flag_enabled as _admin_flag_enabled,
    flag_expired as _admin_flag_expired,
    flag_spec as _admin_flag_spec,
)

__all__ = [
    # 开关
    "FLAG_NAME",
    "UPGRADE_CENTER_FLAG_SPEC",
    "register_feature_flag",
    "flag_spec",
    "flag_enabled",
    "flag_expired",
    "writes_enabled",
    "require_writes_enabled",
    # 契约常量
    "PERMISSIONS",
    "ERROR_CODES_USED",
    "ERROR_CODE_SOURCES",
    "UPGRADE_KINDS",
    "UPGRADE_STATES",
    "STAGE_DECISIONS",
    "COMPAT_SLOTS",
    "COMPAT_STATUSES",
    "COMPAT_OVERALL_STATUSES",
    "APP_RELEASE_LADDER",
    "CLIENT_UPDATE_LADDER",
    "LADDERS",
    "LADDER_BY_KIND",
    "DEFAULT_THRESHOLDS",
    "ROLLBACK_BUDGET_SECONDS",
    "PUBLISH_WINDOW",
    "MONTH_END_FREEZE_DAYS",
    "P0_POST_TICKET_HOURS",
    "CLIENT_SHELL_POLICY",
    "CLIENT_SURFACES",
    # 数据类
    "ReleaseEntry",
    "RollbackPoint",
    "VersionInventory",
    "CompatRow",
    "Stage",
    "Threshold",
    "ThresholdHit",
    "CanaryVerdict",
    "ReleaseWindow",
    "UpgradePrincipal",
    # spec 读取与判定（纯函数，无库依赖）
    "spec_dir",
    "changelog_path",
    "openapi_path",
    "load_changelog",
    "openapi_info_version",
    "align_versions",
    "version_inventory",
    "previous_release",
    "require_version_supported",
    "VersionIncompatible",
    "compat_matrix",
    "compat_overall",
    "client_shell_matrix",
    "client_surface_matrix",
    "ladder_for",
    "stage_index",
    "next_stage",
    "bucket_of",
    "in_rollout",
    "evaluate_stage",
    "release_window",
    "release_gate",
    # 基础设施
    "ensure_schema",
    "schema_name",
    "verify_audit_chain",
    "build_chain_anchor_argv",
    # 写入口
    "create_run",
    "advance",
    "stop_run",
    "rollback",
    # 读入口（关闭开关后仍可用）
    "list_runs",
    "get_run",
    "render_run",
    "list_rollbacks",
    "render_version_list",
]

UTC = timezone.utc
CST = timezone(timedelta(hours=8))          # 发布窗口按 UTC+8 判定（§22.22）

# --------------------------------------------------------------------------- 开关
FLAG_NAME = "upgrade_center"

#: §B.5 / §21.6.4：三字段必填、默认关闭、到期 fail-closed。
UPGRADE_CENTER_FLAG_SPEC: dict[str, Any] = {
    "default": False,
    "owner": "release-manager",
    "expire_at": "2026-12-31",
    "rollback_rule": (
        "关闭后只保留只读版本列表（版本清单 / 回滚点 / 兼容矩阵三块只读），"
        "create_run / advance / stop_run / rollback / release_gate 一律 404，不暴露可写能力；"
        "已完成的升级记录、回滚记录与审计链只追加、不删不改；"
        "发布动作改走变更单 + 发布经理人工流程（本模块本来就不发布）"
    ),
    "summary": "技术升级中心（发布列车灰度推进 + 回滚点 + 兼容矩阵；不注册 HTTP 路由）",
}


def register_feature_flag(registry: dict | None = None) -> dict:
    """把 ``upgrade_center`` 登记进管理域开关表（幂等）。

    管理域开关表在 ``app.admin.FEATURE_FLAGS``（运维中心那一份）里；本单的写范围不含
    ``app/admin/__init__.py``，所以用**运行期登记**而不是改文件。冲突（同名字段不同）
    直接报错——一个开关只允许有一个定义。
    """
    registry = FEATURE_FLAGS if registry is None else registry
    existing = registry.get(FLAG_NAME)
    if existing is not None and dict(existing) != dict(UPGRADE_CENTER_FLAG_SPEC):
        raise RuntimeError(
            f"特性开关 {FLAG_NAME} 已有不同定义，拒绝覆盖（同一开关只能有一个定义，"
            f"冲突需 lead 裁决）：现有={dict(existing)!r}"
        )
    registry[FLAG_NAME] = dict(UPGRADE_CENTER_FLAG_SPEC)
    return registry[FLAG_NAME]


register_feature_flag()


def flag_spec() -> dict:
    """本模块开关定义（三字段缺失即报错，不允许「裸开关」上线）。"""
    return _admin_flag_spec(FLAG_NAME)


def flag_expired(*, today: date | None = None) -> bool:
    return _admin_flag_expired(FLAG_NAME, today=today)


def flag_enabled(*, override: bool | None = None, today: date | None = None) -> bool:
    return _admin_flag_enabled(FLAG_NAME, override=override, today=today)


def writes_enabled(*, override: bool | None = None, today: date | None = None) -> bool:
    """写入口是否开启（读路径永远可用）。"""
    return flag_enabled(override=override, today=today)


def require_writes_enabled(*, override: bool | None = None, today: date | None = None) -> None:
    """写入口闸门：关闭态抛 404（rollback_rule 要求「只保留只读版本列表」）。"""
    if not writes_enabled(override=override, today=today):
        raise FeatureDisabled(
            "技术升级中心写入口已关闭（upgrade_center=false）；"
            "版本清单 / 回滚点 / 兼容矩阵只读视图仍可用，开写需按 §21.6.4 重新评审开关"
        )


# --------------------------------------------------------------------------- 契约常量
#: 权限点（§7.10 只加权限点、不加角色）。归口 release-manager。
PERMISSIONS = frozenset({
    "upgrade.version.read",     # 版本清单 / 回滚点 / 兼容矩阵（只读）
    "upgrade.run.read",         # 升级单与灰度轨迹（只读）
    "upgrade.run.promote",      # 建单 + 推进灰度（发布窗闸门在此）
    "upgrade.run.stop",         # 停桶（可停任意桶，免窗口）
    "upgrade.run.rollback",     # 回滚到上一版（免窗口）
})

#: 本模块使用、且**已在 §6.3 / §6.3b 登记**的错误码。不新造（验收⑤）。
ERROR_CODES_USED: dict[int, str] = {
    40001: "输入校验失败（超长 / 超限 / 缺字段）",
    40301: "管理接口签名失败 / 无权限",
    40401: "对象不存在；越权访问统一 404；开关关闭时的写入口",
    40901: "对象被待复核动作锁定",
    40902: "触发职责分离（SoD）或冷却期硬拒绝",
    40907: "灰度观测窗未满 / 健康门槛未过，禁止推进",
    42301: "break-glass 只读模式下拒绝写操作",
    42401: "需要 step-up 二次认证（≤5 分钟）",
    42601: "协议版本不兼容（§18.3）",
}

#: 每个码的出处（人工可核对；测试按这张表反查 §6.3/§6.3b 原文）。
ERROR_CODE_SOURCES: dict[int, str] = {
    40001: "产品文档 §6.3b 行 1",
    40301: "产品文档 §6.3b 行 3 / §6.3 40101-40103 同族",
    40401: "产品文档 §6.3b 行 4（越权统一 404）",
    40901: "产品文档 §6.3b 行 5",
    40902: "产品文档 §6.3b 行 6",
    40907: "产品文档 §6.3b 行 13（灰度观测窗未满 / 健康门槛未过，禁止推进）",
    42301: "产品文档 §6.3b 行 7",
    42401: "产品文档 §6.3b 行 8",
    42601: "产品文档 §6.3b 行 10（协议版本不兼容）与 spec `Error`",
}

class VersionIncompatible(OpsCenterError):
    """协议版本不兼容（§6.3b ``42601`` / §18.3）：低于 N-2 明确拒绝，不静默降级。

    只是复用已登记错误码的新异常类，**没有新造码值**。
    """

    http_status = 426
    code = 42601
    type = "protocol_error"


#: 升级类型。S1 只覆盖应用发布与客户端灰度（§22.22 一期口径：升级中心 S1 只做发布列车与回滚）。
UPGRADE_KINDS = ("app", "client")
UNSUPPORTED_KINDS = ("config", "schema", "protocol", "contract", "dependency", "region")

#: 升级单状态机。没有 ``draft``：建单即进入首桶，避免「建了单却没人负责」的悬空对象。
UPGRADE_STATES = ("running", "stopped", "completed", "rolled_back", "failed")
STAGE_DECISIONS = ("start", "advance", "hold", "stop", "complete", "rollback")

#: 兼容矩阵槽位（§22.22 协议/API 行：N / N-1 / N-2；旧版本至少支持 2 个 MAJOR）。
COMPAT_SLOTS = ("N", "N-1", "N-2")
COMPAT_STATUSES = ("pass", "fail", "unknown", "not_applicable")
COMPAT_OVERALL_STATUSES = ("pass", "fail", "unknown", "not_applicable", "partial")

#: 客户端外壳支持策略（§22.9：外壳 N/N-1，N-2 不保证可安装）。声明式，不算证据。
CLIENT_SHELL_POLICY = (
    {"offset": 0, "shell": "N", "rule": "可用；完整功能", "source": "§22.9 支持策略"},
    {"offset": 1, "shell": "N-1", "rule": "可用；外壳可退回一版", "source": "§22.9 支持策略"},
    {"offset": 2, "shell": "N-2",
     "rule": "不保证可安装；只读 + 保守模式 + 不接新单 + 明确升级提示", "source": "§22.9 支持策略"},
)

#: 客户端交付面（〔决策K8〕：S1 CLI+daemon / S2 托盘 / S3 GUI）。声明式，不算证据。
CLIENT_SURFACES = (
    {"stage": "S1", "surface": "Linux CLI + daemon", "rule": "核心能力全集，无 GUI 依赖",
     "source": "§15.2 · §22.9.1 · 〔决策K8〕"},
    {"stage": "S2", "surface": "三平台最小托盘",
     "rule": "安装引导 / 状态 / 暂停恢复 / 今日收益；设置与组网留到 S3",
     "source": "§22.9.1 · 〔决策K8〕"},
    {"stage": "S3", "surface": "完整 GUI",
     "rule": "设置 / 组网 / 一键部署 / 诊断", "source": "§22.9.1 · 〔决策K8〕"},
)

#: 发布列车（§22.22）：工作日 10:00–17:00（UTC+8）；月末 2 天与重大活动期冻结。
PUBLISH_WINDOW = (time(10, 0), time(17, 0))
MONTH_END_FREEZE_DAYS = 2
#: P0 通道：窗口外可发，但必须带 P0 变更单，并在 24h 内补齐变更单（§22.22 发布列车）。
P0_POST_TICKET_HOURS = 24

#: 回滚预算（§22.22：应用 ≤5 分钟；§22.9：客户端灰度回滚 ≤30 分钟）。
ROLLBACK_BUDGET_SECONDS: dict[str, int] = {"app": 300, "client": 1800}


# --------------------------------------------------------------------------- 灰度阶梯
@dataclass(frozen=True)
class Stage:
    """灰度阶梯的一档。``percent == 0`` 表示显式名单桶（内部），不按哈希分流。"""

    key: str
    label: str
    percent: float
    required_dwell: timedelta | None
    source: str

    @property
    def is_allowlist(self) -> bool:
        return self.percent <= 0

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "percent": self.percent,
            "required_dwell_seconds": (
                None if self.required_dwell is None else int(self.required_dwell.total_seconds())
            ),
            "source": self.source,
        }


_APP_SOURCE = "§22.22 应用发布：内部 → 1% → 10% → 50% → 全量"
_CLIENT_SOURCE = "§22.9 自动更新：5% → 25% → 100%，每桶观测 ≥24h"

#: 应用发布阶梯（§22.22）。**spec 未规定每桶最短时长**，所以 ``required_dwell`` 为 None：
#: 该桶要观测多久由变更单明确（缺省不放行），不替产品发明数字。
APP_RELEASE_LADDER: tuple[Stage, ...] = (
    Stage("internal", "内部", 0.0, None, _APP_SOURCE + "；内部为显式名单桶"),
    Stage("pct_1", "1%", 1.0, None, _APP_SOURCE),
    Stage("pct_10", "10%", 10.0, None, _APP_SOURCE),
    Stage("pct_50", "50%", 50.0, None, _APP_SOURCE),
    Stage("full", "全量", 100.0, None, _APP_SOURCE),
)

#: 客户端更新阶梯（§22.9）。每桶 ≥24h 写进了产品文档，所以这里有硬性 dwell。
CLIENT_UPDATE_LADDER: tuple[Stage, ...] = (
    Stage("pct_5", "5%", 5.0, timedelta(hours=24), _CLIENT_SOURCE),
    Stage("pct_25", "25%", 25.0, timedelta(hours=24), _CLIENT_SOURCE),
    Stage("full", "全量", 100.0, timedelta(hours=24), _CLIENT_SOURCE),
)

LADDERS: dict[str, tuple[Stage, ...]] = {
    "app": APP_RELEASE_LADDER,
    "client": CLIENT_UPDATE_LADDER,
}
#: 升级类型 → 阶梯名（S1 只这两类；其余类型先改 spec/产品口径再进来）。
LADDER_BY_KIND: dict[str, str] = {"app": "app", "client": "client"}


def ladder_for(kind: str) -> tuple[Stage, ...]:
    try:
        return LADDERS[LADDER_BY_KIND[kind]]
    except KeyError:
        raise BadRequest(
            f"升级类型 {kind!r} 不在本单灰度范围（S1 只做应用发布与客户端灰度，§22.22）；"
            f"允许值={sorted(LADDER_BY_KIND)}",
            details=[{"field": "kind", "allowed": sorted(LADDER_BY_KIND)}],
        ) from None


def stage_index(kind: str, stage_key: str) -> int:
    keys = [s.key for s in ladder_for(kind)]
    try:
        return keys.index(stage_key)
    except ValueError:
        raise BadRequest(
            f"灰度桶 {stage_key!r} 不在 {kind} 阶梯内；允许值={keys}",
            details=[{"field": "stage", "allowed": keys}],
        ) from None


def next_stage(kind: str, stage_key: str) -> Stage | None:
    ladder = ladder_for(kind)
    idx = stage_index(kind, stage_key)
    return ladder[idx + 1] if idx + 1 < len(ladder) else None


# --------------------------------------------------------------------------- 灰度阈值
@dataclass(frozen=True)
class Threshold:
    """一条放行阈值。``limit`` 一律来自产品文档，出处写在 ``source`` 里可核对。"""

    key: str
    comparator: str          # "<=" | ">=" | "=="
    limit: float
    unit: str
    source: str
    description: str = ""

    def check(self, observed: float) -> bool:
        if self.comparator == "<=":
            return observed <= self.limit
        if self.comparator == ">=":
            return observed >= self.limit
        if self.comparator == "==":
            return observed == self.limit
        raise ValueError(f"未知比较符 {self.comparator!r}")

    def as_dict(self) -> dict:
        return {
            "key": self.key, "comparator": self.comparator, "limit": self.limit,
            "unit": self.unit, "source": self.source, "description": self.description,
        }


#: 默认放行阈值。每一条都能在产品文档里找到依据，没有凭感觉定的数字。
DEFAULT_THRESHOLDS: tuple[Threshold, ...] = (
    Threshold("error_rate_pct", "<=", 2.0, "pct",
              "§22.22 应用发布·验证列「错误率」；§23.2.5 失败率 >2% → P1",
              "灰度桶内错误率"),
    Threshold("smoke_pass_pct", ">=", 100.0, "pct",
              "§22.22 升级完成判据②；§22.9 验收③ 矩阵冒烟 100%",
              "冒烟通过率"),
    Threshold("install_success_pct", ">=", 95.0, "pct",
              "§22.9 验收① 三平台安装成功率 ≥95%",
              "客户端安装成功率"),
    Threshold("ledger_recompute_diff_minor", "==", 0.0, "usd_minor",
              "§22.22 schema 行 + 升级完成判据③ 账本全量复算差异 0",
              "账本复算差异（最小单位）"),
    Threshold("reserve_coverage_delta_pct", ">=", 0.0, "pct",
              "§22.22 升级完成判据④ 储备覆盖率不变",
              "储备覆盖率变化（pp）"),
)


@dataclass(frozen=True)
class ThresholdHit:
    """一条阈值的判定结果（带出处，便于审计复述）。"""

    threshold: Threshold
    observed: float

    @property
    def key(self) -> str:
        return self.threshold.key

    @property
    def passed(self) -> bool:
        return self.threshold.check(self.observed)

    def as_dict(self) -> dict:
        return {
            "key": self.threshold.key,
            "comparator": self.threshold.comparator,
            "limit": self.threshold.limit,
            "observed": self.observed,
            "unit": self.threshold.unit,
            "passed": self.passed,
            "source": self.threshold.source,
        }


@dataclass(frozen=True)
class CanaryVerdict:
    """一桶的判定结果：``advance`` / ``hold`` / ``stop``。"""

    decision: str
    hits: tuple[ThresholdHit, ...]
    unknown: tuple[str, ...]
    reason: str

    @property
    def failed(self) -> tuple[ThresholdHit, ...]:
        return tuple(h for h in self.hits if not h.passed)

    def as_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "unknown": list(self.unknown),
            "hits": [h.as_dict() for h in self.hits],
            "failed": [h.key for h in self.failed],
        }


def _coerce_metric(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return None if out != out else out          # NaN → 未知，不当作 0


def evaluate_stage(metrics: Mapping[str, Any] | None,
                   thresholds: Sequence[Threshold] = DEFAULT_THRESHOLDS) -> CanaryVerdict:
    """按阈值判一桶：缺指标 → hold（不装作通过）；越线 → stop；全过 → advance。"""
    metrics = metrics or {}
    hits: list[ThresholdHit] = []
    unknown: list[str] = []
    for th in thresholds:
        observed = _coerce_metric(metrics.get(th.key))
        if observed is None:
            unknown.append(th.key)
            continue
        hits.append(ThresholdHit(th, observed))

    if unknown:
        return CanaryVerdict(
            decision="hold",
            hits=tuple(hits),
            unknown=tuple(unknown),
            reason=f"指标缺失，不能判定为通过：{', '.join(unknown)}（未知即 unknown，不推进）",
        )
    failed = [h for h in hits if not h.passed]
    if failed:
        parts = [f"{h.key}={h.observed}{h.threshold.unit} 违反 {h.threshold.comparator}"
                 f"{h.threshold.limit}" for h in failed]
        return CanaryVerdict(
            decision="stop",
            hits=tuple(hits),
            unknown=(),
            reason="红线触发，自动停桶：" + "；".join(parts),
        )
    return CanaryVerdict(decision="advance", hits=tuple(hits), unknown=(),
                         reason="全部阈值通过")


# --------------------------------------------------------------------------- 流量分桶
_DEFAULT_SALT = "djb-canary-v1"


def bucket_of(subject: str, *, salt: str = _DEFAULT_SALT) -> int:
    """把主体稳定映射到 0..9999 的桶（同一 salt 下结果恒定，跨进程一致）。"""
    if not isinstance(subject, str) or not subject:
        raise BadRequest("分桶主体必须是非空字符串", details=[{"field": "subject"}])
    digest = hashlib.sha256(f"{salt}\x1f{subject}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 10_000


def in_rollout(subject: str, stage: Stage, *, allowlist: Iterable[str] = (),
               salt: str = _DEFAULT_SALT) -> bool:
    """该主体是否落在这一桶里。``internal`` 桶按显式名单，其余按哈希百分比。"""
    if stage.is_allowlist:
        return subject in set(allowlist)
    return bucket_of(subject, salt=salt) < int(round(stage.percent * 100))


# --------------------------------------------------------------------------- spec 读取
class SpecSourceMissing(RuntimeError):
    """spec 目录缺失 / 缺文件（部署期配置问题，不是请求错误，不占错误码）。"""


SPEC_DIR_ENV = "DJB_SPEC_DIR"
CHANGELOG_NAME = "CHANGELOG-协议.md"
OPENAPI_NAME = "openapi.yaml"


def _repo_root() -> Path:
    """``app/admin/upgrade_center.py`` → 仓库根（worktree 下同样成立）。"""
    return Path(__file__).resolve().parents[2]


def _spec_candidates() -> tuple[Path, ...]:
    """候选 spec 目录：``$DJB_SPEC_DIR`` 优先，然后从仓库根逐级向上找 ``spec/``。

    逐级向上是为了同时覆盖两种布局：主检出（``<ws>/repos/djb-cloud`` → ``<ws>/spec``）
    与隔离 worktree（``<ws>/worktrees/<id>`` → ``<ws>/spec``）。
    """
    cands: list[Path] = []
    env = os.environ.get(SPEC_DIR_ENV)
    if env:
        cands.append(Path(env))
    root = _repo_root()
    walk = root
    for _ in range(4):
        cands.append(walk / "spec")
        if walk.parent == walk:
            break
        walk = walk.parent
    return tuple(cands)


def spec_dir() -> Path:
    """spec 目录解析顺序：``$DJB_SPEC_DIR`` → 仓库内 ``spec/`` → 工作区 ``spec/``。"""
    for cand in _spec_candidates():
        if (cand / CHANGELOG_NAME).is_file() and (cand / OPENAPI_NAME).is_file():
            return cand
    tried = ", ".join(str(c) for c in _spec_candidates())
    raise SpecSourceMissing(
        f"找不到 spec 目录（需同时含 {CHANGELOG_NAME} 与 {OPENAPI_NAME}）；已尝试：{tried}；"
        f"可用 $DJB_SPEC_DIR 指定"
    )


def changelog_path() -> Path:
    return spec_dir() / CHANGELOG_NAME


def openapi_path() -> Path:
    return spec_dir() / OPENAPI_NAME


@dataclass(frozen=True)
class ReleaseEntry:
    """``spec/CHANGELOG-协议.md`` 的一条版本记录（解析结果，不改原文）。"""

    version: str
    released_at: date
    kind: str
    type_note: str
    change_items: tuple[str, ...]
    impact_items: tuple[str, ...]
    compat_notes: tuple[str, ...]
    breaking: tuple[str, ...]
    reviewers: str
    line: int

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "released_at": self.released_at.isoformat(),
            "kind": self.kind,
            "type_note": self.type_note,
            "change_items": list(self.change_items),
            "impact_items": list(self.impact_items),
            "compat_notes": list(self.compat_notes),
            "breaking": list(self.breaking),
            "reviewers": self.reviewers,
            "evidence": f"{CHANGELOG_NAME}#L{self.line}",
        }


_RELEASE_HEAD_RE = re.compile(
    r"^##\s+(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)\s*·\s*"
    r"(?P<date>\d{4}-\d{2}-\d{2})\s*·\s*(?P<kind>MAJOR|MINOR|PATCH)\s*$"
)
#: 段标题 ``**兼容矩阵**`` 可能不带冒号（只有内容行才带），所以冒号整段可选。
_SECTION_HEAD_RE = re.compile(
    r"^\*\*(?P<name>[^*]+?)\*\*(?:\s*[：:]\s*(?P<inline>.*))?$"
)
_BULLET_RE = re.compile(r"^[-*]\s+(?P<text>\S.*?)\s*$")
_NUMBERED_RE = re.compile(r"^\d+[.)]\s+(?P<text>\S.*?)\s*$")


def _classify_section(name: str) -> str | None:
    if "变更" in name:
        return "change"
    if "影响面" in name:
        return "impact"
    if "兼容矩阵" in name or "兼容" in name:
        return "compat"
    if "复核" in name:
        return "reviewer"
    if "类型" in name:
        return "type"
    return None


def load_changelog(path: Path | str | None = None) -> tuple[ReleaseEntry, ...]:
    """解析协议变更记录，返回**文件顺序**（通常新→旧）的版本记录。"""
    path = Path(path) if path is not None else changelog_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SpecSourceMissing(f"协议变更记录不存在：{path}") from None

    entries: list[ReleaseEntry] = []
    current: dict[str, Any] | None = None
    section: str | None = None

    def flush() -> None:
        if current is None:
            return
        entries.append(ReleaseEntry(
            version=current["version"],
            released_at=current["date"],
            kind=current["kind"],
            type_note=current["type"],
            change_items=tuple(current["change"]),
            impact_items=tuple(current["impact"]),
            compat_notes=tuple(current["compat"]),
            breaking=tuple(c for c in current["compat"] if "破坏性" in c
                           or "breaking" in c.lower()),
            reviewers=current["reviewer"],
            line=current["line"],
        ))

    for lineno, raw in enumerate(text.splitlines(), start=1):
        head = _RELEASE_HEAD_RE.match(raw)
        if head:
            flush()
            current = {
                "version": head["version"],
                "date": date.fromisoformat(head["date"]),
                "kind": head["kind"],
                "type": "", "change": [], "impact": [], "compat": [],
                "reviewer": "", "line": lineno,
            }
            section = None
            continue
        if current is None:
            continue
        section_head = _SECTION_HEAD_RE.match(raw)
        if section_head:
            section = _classify_section(section_head["name"])
            inline = (section_head["inline"] or "").strip()
            if section == "reviewer" and inline:
                current["reviewer"] = inline
            if section == "type" and inline:
                current["type"] = inline
            continue
        bullet = _BULLET_RE.match(raw) or _NUMBERED_RE.match(raw)
        if bullet and section in ("change", "impact", "compat"):
            current[section].append(bullet["text"])
    flush()

    if not entries:
        raise SpecSourceMissing(f"{path} 里没有解析出任何版本记录（格式应为 `## X.Y.Z · YYYY-MM-DD · MINOR`）")
    return tuple(entries)


def openapi_info_version(path: Path | str | None = None) -> str:
    """读 ``spec/openapi.yaml`` 的 ``info.version``（只读；本模块不改 spec）。"""
    path = Path(path) if path is not None else openapi_path()
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SpecSourceMissing(f"spec 文件不存在：{path}") from None
    except yaml.YAMLError as exc:
        raise SpecSourceMissing(f"spec 不是合法 YAML：{path}（{exc}）") from None
    version = ((doc or {}).get("info") or {}).get("version")
    if not version:
        raise SpecSourceMissing(f"{path} 缺 info.version")
    return str(version)


_VERSION_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:-(?P<pre>.+))?$")


def _split_version(version: str) -> tuple[int, int, int, str] | None:
    m = _VERSION_RE.match(str(version).strip())
    if not m:
        return None
    return int(m["major"]), int(m["minor"]), int(m["patch"]), (m["pre"] or "")


def _version_key(version: str) -> tuple[int, int, int]:
    parsed = _split_version(version)
    return (parsed[0], parsed[1], parsed[2]) if parsed else (0, 0, 0)


def align_versions(spec_version: str, info_version: str) -> tuple[str, str, bool]:
    """对齐 ``CHANGELOG`` 最新版本与 ``openapi.info.version``。

    返回 ``(status, detail, needs_attention)``；status ∈ aligned / aligned_core_prerelease /
    mismatch / unknown。**判断不了就说 unknown**，不把 ``-skeleton`` 之类当成同一版。
    """
    if str(spec_version).strip() == str(info_version).strip():
        return "aligned", f"CHANGELOG 最新版本与 openapi info.version 同为 {spec_version}", False
    left = _split_version(spec_version)
    right = _split_version(info_version)
    if left is None or right is None:
        return ("unknown",
                f"版本号无法解析：CHANGELOG={spec_version!r} · openapi={info_version!r}；"
                "无法判定对齐，按 unknown 处理（不假装通过）",
                True)
    if left[:3] == right[:3]:
        return ("aligned_core_prerelease",
                f"核心版本一致（{left[0]}.{left[1]}.{left[2]}），openapi info.version 带预发布后缀 "
                f"{right[3]!r}；spec 尚未把 info.version 提升到已发布版本",
                False)
    return ("mismatch",
            f"版本不一致：CHANGELOG 最新 {spec_version}（核心 {left[0]}.{left[1]}.{left[2]}）≠ "
            f"openapi info.version {info_version}（核心 {right[0]}.{right[1]}.{right[2]}）；"
            "按 spec 唯一真源口径，应由 arch-protocol 在同一次 PR 里把 info.version 同步到 "
            f"{spec_version}（本单只读 spec，不改）",
            True)


@dataclass(frozen=True)
class RollbackPoint:
    """可回滚到的一个版本。``recorded_at`` 即该版本的**记录时间**（验收③）。"""

    version: str
    recorded_at: datetime
    kind: str
    evidence: str
    is_current: bool
    age_seconds: float

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "recorded_at": self.recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
            "kind": self.kind,
            "is_current": self.is_current,
            "age_seconds": round(self.age_seconds, 3),
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class CompatRow:
    """兼容矩阵的一行（N / N-1 / N-2）。``status`` 与 ``evidence`` 一起看。"""

    slot: str
    offset: int
    version: str | None
    status: str
    evidence: str
    evidence_level: str          # green / yellow / none
    note: str

    def as_dict(self) -> dict:
        return {
            "slot": self.slot,
            "offset": self.offset,
            "version": self.version,
            "status": self.status,
            "evidence": self.evidence,
            "evidence_level": self.evidence_level,
            "note": self.note,
        }


@dataclass(frozen=True)
class VersionInventory:
    """版本清单（只读视图的主体）。"""

    spec_version: str
    openapi_version: str
    alignment: str
    alignment_detail: str
    needs_attention: bool
    releases: tuple[ReleaseEntry, ...]
    rollback_points: tuple[RollbackPoint, ...]
    compat: tuple[CompatRow, ...]
    compat_overall: str
    generated_at: datetime
    sources: Mapping[str, str]

    def as_dict(self) -> dict:
        return {
            "spec_version": self.spec_version,
            "openapi_version": self.openapi_version,
            "alignment": {
                "status": self.alignment,
                "detail": self.alignment_detail,
                "needs_attention": self.needs_attention,
            },
            "releases": [r.as_dict() for r in self.releases],
            "rollback_points": [p.as_dict() for p in self.rollback_points],
            "compat": {
                "overall": self.compat_overall,
                "rows": [r.as_dict() for r in self.compat],
            },
            "generated_at": self.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
            "sources": dict(self.sources),
        }


_SLOT_TOKEN_RE = re.compile(r"N-2|N-1|N(?![-0-9])")


def _slots_in(text: str) -> list[str]:
    seen: list[str] = []
    for token in _SLOT_TOKEN_RE.findall(text):
        if token not in seen:
            seen.append(token)
    return seen


def _status_from_note(note: str) -> str | None:
    """从一条兼容矩阵说明里判状态。判不出来返回 None（上层按 unknown 处理）。"""
    if "不适用" in note:
        return "not_applicable"
    if "失败" in note or "不通过" in note or "fail" in note.lower():
        return "fail"
    if "通过" in note or "pass" in note.lower():
        return "pass"
    return None


def compat_matrix(releases: Sequence[ReleaseEntry] | None = None,
                  *, spec_version: str | None = None,
                  changelog_name: str = CHANGELOG_NAME) -> tuple[CompatRow, ...]:
    """N / N-1 / N-2 三行。**没有证据就是 unknown**，不会替任何一档担保。"""
    releases = tuple(releases) if releases is not None else load_changelog()
    current = spec_version or releases[0].version
    version_by_offset: dict[int, str | None] = {0: current}
    for offset in (1, 2):
        version_by_offset[offset] = (
            releases[offset].version if len(releases) > offset else None
        )

    # 只有最新那条记录的「兼容矩阵」段能说明当前版本的支持面。
    latest = next((r for r in releases if r.version == current), releases[0])
    derived: dict[str, tuple[str, str, str]] = {}
    for note in latest.compat_notes:
        # 一条说明里可能混写多档（``N：通过；N-2：失败``），必须按分句判，
        # 否则「失败」会把整条里的 N / N-1 一起拉黑。
        for clause in re.split(r"[；;。，,]", note):
            clause = clause.strip()
            status = _status_from_note(clause)
            if status is None:
                continue
            for slot in _slots_in(clause):
                # 先出现的说明优先（文件里更具体的写在前）
                derived.setdefault(slot, (status, f"{changelog_name}#L{latest.line}", clause))

    rows: list[CompatRow] = []
    for offset, slot in enumerate(COMPAT_SLOTS):
        version = version_by_offset[offset]
        if slot in derived:
            status, evidence, note = derived[slot]
            level = "green" if status in ("pass", "not_applicable") else "yellow"
        else:
            status, evidence = "unknown", "none"
            level = "none"
            note = (f"CHANGELOG 未对 {slot} 给出结论；"
                    f"按「未知即 unknown」处理，不得当作通过")
            if version is None:
                note = f"无 {slot} 版本记录（存量版本不足），且 CHANGELOG 未给结论"
        if version is None and status == "pass":
            # 没有版本却声称通过 = 自相矛盾，降级为 unknown 并要求补证据。
            status, level = "unknown", "none"
            note = f"{slot} 无对应版本记录，不能声称通过；需补齐版本与冒烟证据"
        rows.append(CompatRow(slot=slot, offset=offset, version=version, status=status,
                              evidence=evidence, evidence_level=level, note=note))
    return tuple(rows)


def compat_overall(rows: Sequence[CompatRow]) -> str:
    """汇总口径：**只有三行全 pass 才算 pass**；不适用单独成一档，绝不并入 pass。"""
    statuses = [r.status for r in rows]
    if not statuses:
        return "unknown"
    if any(s == "fail" for s in statuses):
        return "fail"
    if any(s == "unknown" for s in statuses):
        return "unknown"
    if all(s == "pass" for s in statuses):
        return "pass"
    if all(s == "not_applicable" for s in statuses):
        return "not_applicable"
    return "partial"


def previous_release(version: str,
                     releases: Sequence[ReleaseEntry] | None = None) -> ReleaseEntry | None:
    """返回比 ``version`` 更旧的下一条版本记录（没有则 None，不编造）。"""
    releases = tuple(releases) if releases is not None else load_changelog()
    ordered = sorted(releases, key=lambda r: (_version_key(r.version), r.released_at), reverse=True)
    for idx, entry in enumerate(ordered):
        if entry.version == version:
            return ordered[idx + 1] if idx + 1 < len(ordered) else None
    older = [r for r in ordered if _version_key(r.version) < _version_key(version)]
    return older[0] if older else None


def require_version_supported(client_version: str,
                              releases: Sequence[ReleaseEntry] | None = None) -> dict:
    """调用方版本必须落在 N / N-1 / N-2 内（§22.22 协议行 / §18.3）。

    * 在支持面内 → ``stage=supported``
    * 版本比最低支持版本还新但不在清单里（未发布构建）→ ``stage=unknown``，**不当作通过**
    * 低于 N-2 → ``42601`` 明确拒绝，并给出支持矩阵（不静默降级，§22.9 验收⑤）
    """
    releases = tuple(releases) if releases is not None else load_changelog()
    ordered = sorted(releases, key=lambda r: (_version_key(r.version), r.released_at),
                     reverse=True)
    supported = [r.version for r in ordered[:3]]
    if _split_version(client_version) is None:
        raise BadRequest("版本号必须形如 X.Y.Z（可带 -pre 后缀）",
                         details=[{"field": "client_version"}])
    if client_version in supported:
        return {"client_version": client_version, "stage": "supported",
                "supported": supported, "note": "落在 N / N-1 / N-2 内"}
    floor = min(supported, key=_version_key) if supported else None
    if floor is not None and _version_key(client_version) >= _version_key(floor):
        return {"client_version": client_version, "stage": "unknown", "supported": supported,
                "note": "版本不在已发布清单内（可能是未发布构建），按 unknown 处理，不假装通过"}
    raise VersionIncompatible(
        f"协议版本 {client_version} 低于最低支持版本 {floor}（支持 N/N-1/N-2：{supported}）；"
        "请升级客户端，低于最低版本的请求被明确拒绝并给出原因（§22.9）",
        details=[{"field": "client_version", "supported": supported}])


def version_inventory(*, now: datetime | None = None,
                      changelog: Path | str | None = None,
                      openapi: Path | str | None = None) -> VersionInventory:
    """版本清单 + 回滚点 + 兼容矩阵（验收①④的共同数据源；只读）。"""
    now = _as_utc(now or datetime.now(UTC))
    releases = tuple(sorted(load_changelog(changelog),
                            key=lambda r: (_version_key(r.version), r.released_at),
                            reverse=True))
    info_version = openapi_info_version(openapi)
    spec_version = releases[0].version
    alignment, alignment_detail, needs_attention = align_versions(spec_version, info_version)

    changelog_name = Path(changelog).name if changelog else CHANGELOG_NAME
    points: list[RollbackPoint] = []
    for entry in releases:
        recorded = datetime.combine(entry.released_at, time(0, 0), tzinfo=UTC)
        points.append(RollbackPoint(
            version=entry.version,
            recorded_at=recorded,
            kind=entry.kind,
            evidence=f"{changelog_name}#L{entry.line}",
            is_current=(entry.version == spec_version),
            age_seconds=max(0.0, (now - recorded).total_seconds()),
        ))

    rows = compat_matrix(releases, spec_version=spec_version, changelog_name=changelog_name)
    return VersionInventory(
        spec_version=spec_version,
        openapi_version=info_version,
        alignment=alignment,
        alignment_detail=alignment_detail,
        needs_attention=needs_attention,
        releases=releases,
        rollback_points=tuple(points),
        compat=rows,
        compat_overall=compat_overall(rows),
        generated_at=now,
        sources={
            "changelog": str(changelog) if changelog else str(changelog_path()),
            "openapi": str(openapi) if openapi else str(openapi_path()),
        },
    )


def render_version_list(*, now: datetime | None = None) -> dict:
    """**只读版本列表**：开关关闭后唯一保留的视图（rollback_rule 的落地形态）。"""
    return version_inventory(now=now).as_dict()


def client_shell_matrix(releases: Sequence[ReleaseEntry] | None = None) -> list[dict]:
    """客户端外壳支持策略（§22.9）。声明式规则，不是兼容证据。"""
    releases = tuple(releases) if releases is not None else load_changelog()
    out: list[dict] = []
    for row in CLIENT_SHELL_POLICY:
        offset = row["offset"]
        version = releases[offset].version if len(releases) > offset else None
        out.append({**row, "version": version, "evidence_level": "yellow"})
    return out


def client_surface_matrix() -> list[dict]:
    """客户端交付面（〔决策K8〕）。声明式路线，不是兼容证据。"""
    return [dict(r) for r in CLIENT_SURFACES]


# --------------------------------------------------------------------------- 发布窗
@dataclass(frozen=True)
class ReleaseWindow:
    """发布窗判定结果（§22.22 发布列车）。"""

    open: bool
    reason: str
    code: int | None
    local: datetime
    is_workday: bool
    in_hours: bool
    is_month_end_freeze: bool
    is_declared_freeze: bool

    def as_dict(self) -> dict:
        return {
            "open": self.open,
            "reason": self.reason,
            "code": self.code,
            "cst": self.local.isoformat(timespec="minutes"),
            "weekday": self.local.strftime("%a"),
            "is_workday": self.is_workday,
            "in_hours": self.in_hours,
            "is_month_end_freeze": self.is_month_end_freeze,
            "is_declared_freeze": self.is_declared_freeze,
            "window": [PUBLISH_WINDOW[0].strftime("%H:%M"), PUBLISH_WINDOW[1].strftime("%H:%M")],
        }


def release_window(now: datetime | None = None, *,
                   declared_freeze: bool = False) -> ReleaseWindow:
    """工作日 10:00–17:00（UTC+8）内的发布窗；月末 2 天与声明冻结期关闭。

    窗口外/冻结期 → ``code=40902``（§6.3b「冷却期硬拒绝」）。回滚与停桶**不看窗口**
    （止损免窗口，§22.22 配置行 + 运维中心同款口径）。
    """
    now = _as_utc(now or datetime.now(UTC))
    local = now.astimezone(CST)
    is_workday = local.weekday() < 5
    in_hours = PUBLISH_WINDOW[0] <= local.time() < PUBLISH_WINDOW[1]
    last_day = calendar.monthrange(local.year, local.month)[1]
    month_end = (local.day > last_day - MONTH_END_FREEZE_DAYS) and not declared_freeze

    if declared_freeze:
        return ReleaseWindow(False, "变更日历声明的冻结期（重大活动 / 月末锁定），禁止发布",
                             40902, local, is_workday, in_hours, False, True)
    if month_end:
        return ReleaseWindow(False, f"月末 {MONTH_END_FREEZE_DAYS} 天冻结窗口（§22.22 发布列车）",
                             40902, local, is_workday, in_hours, True, False)
    if not is_workday:
        return ReleaseWindow(False, "非工作日（§22.22：工作日 10:00–17:00 UTC+8 发布）",
                             40902, local, is_workday, in_hours, False, False)
    if not in_hours:
        return ReleaseWindow(
            False,
            f"窗口外（当前 {local.strftime('%H:%M')} UTC+8，窗口 "
            f"{PUBLISH_WINDOW[0].strftime('%H:%M')}–{PUBLISH_WINDOW[1].strftime('%H:%M')}）",
            40902, local, is_workday, in_hours, False, False)
    return ReleaseWindow(True, "在发布窗口内", None, local, True, True, False, False)


def release_gate(*, now: datetime | None = None, kind: str = "app",
                 compat: Sequence[CompatRow] | None = None,
                 alignment: str | None = None,
                 declared_freeze: bool = False) -> dict:
    """发布闸门（只判定，不执行发布）。

    * 兼容矩阵：``pass`` / ``not_applicable`` 放行；``unknown`` / ``fail`` / ``partial`` 阻断
      （§22.22 协议行「兼容性矩阵 100% 通过」）。
    * spec 版本对齐：不一致只记 warning —— 版本号没同步 ≠ 兼容性失败，但必须被看见。
    * 发布窗：窗口外 / 冻结期阻断（40902）。
    """
    rows = tuple(compat) if compat is not None else compat_matrix()
    overall = compat_overall(rows)
    window = release_window(now, declared_freeze=declared_freeze)
    blocked_by: list[dict] = []
    warnings: list[str] = []

    if overall in ("unknown", "fail", "partial"):
        blocked_by.append({
            "gate": "compat_matrix", "status": overall, "code": 40907,
            "detail": f"兼容矩阵汇总为 {overall}，未达到「100% 通过」（§22.22 协议行）",
            "rows": [r.as_dict() for r in rows if r.status in ("unknown", "fail")],
        })
    elif overall == "not_applicable":
        warnings.append("兼容矩阵：N/N-1/N-2 不适用（协议未发布 / 无存量客户端）")

    if alignment and alignment not in ("aligned",):
        warnings.append(f"spec 版本对齐：{alignment}（不影响兼容判断，但需 arch-protocol 同步）")

    if not window.open:
        blocked_by.append({"gate": "release_window", "status": "closed", "code": window.code,
                           "detail": window.reason})

    if kind not in LADDER_BY_KIND:
        blocked_by.append({"gate": "kind", "status": "unsupported", "code": 40001,
                           "detail": f"升级类型 {kind!r} 不在本单灰度范围"})

    return {
        "ok": not blocked_by,
        "kind": kind,
        "compat_overall": overall,
        "window": window.as_dict(),
        "blocked_by": blocked_by,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- 基础设施
_SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SCHEMA_ENV = "DJB_UPGRADE_SCHEMA"
DEFAULT_SCHEMA = "upgrade_center"
AUDIT_LOCK_ID = 0x444A_4205          # 与运维中心分开：本模块有自己的审计链

_bootstrapped: set[str] = set()

DDL = """
CREATE TABLE IF NOT EXISTS upgrade_run (
    upgrade_id                text        PRIMARY KEY,
    kind                      text        NOT NULL,
    ladder                    text        NOT NULL,
    from_version              text        NOT NULL,
    to_version                text        NOT NULL,
    change_ticket             text        NOT NULL,
    impact                    text        NOT NULL,
    rollback_plan             text        NOT NULL,
    acceptance_owner          text        NOT NULL,
    observation_seconds       integer     NOT NULL CHECK (observation_seconds > 0),
    stage                     text        NOT NULL,
    state                     text        NOT NULL,
    stage_entered_at          timestamptz NOT NULL,
    created_at                timestamptz NOT NULL,
    created_by                text        NOT NULL,
    updated_at                timestamptz NOT NULL,
    p0_exception              boolean     NOT NULL DEFAULT false,
    post_ticket_due_at        timestamptz,
    spec_alignment            text        NOT NULL DEFAULT 'unknown',
    compat_overall            text        NOT NULL DEFAULT 'unknown',
    CHECK (state IN ('running','stopped','completed','rolled_back','failed'))
);

CREATE TABLE IF NOT EXISTS upgrade_stage_event (
    seq          bigserial   PRIMARY KEY,
    upgrade_id   text        NOT NULL,
    at           timestamptz NOT NULL,
    actor        text        NOT NULL,
    actor_roles  text        NOT NULL DEFAULT '',
    action       text        NOT NULL,
    from_stage   text,
    to_stage     text        NOT NULL,
    decision     text        NOT NULL,
    reason       text,
    reason_code  text,
    metrics      jsonb,
    hits         jsonb,
    verdict      jsonb,
    CHECK (decision IN ('start','advance','hold','stop','complete','rollback'))
);

CREATE INDEX IF NOT EXISTS upgrade_stage_event_run_idx
    ON upgrade_stage_event (upgrade_id, seq);

CREATE TABLE IF NOT EXISTS upgrade_rollback (
    seq                    bigserial   PRIMARY KEY,
    upgrade_id             text        NOT NULL,
    at                     timestamptz NOT NULL,
    actor                  text        NOT NULL,
    from_version           text        NOT NULL,
    to_version             text        NOT NULL,
    rollback_point_version text        NOT NULL,
    rollback_point_at      timestamptz NOT NULL,
    rollback_point_source  text        NOT NULL,
    duration_seconds       numeric(12,3) NOT NULL,
    budget_seconds         integer     NOT NULL,
    within_budget          boolean     NOT NULL,
    evidence               jsonb       NOT NULL,
    reason                 text,
    reason_code            text
);

CREATE INDEX IF NOT EXISTS upgrade_rollback_run_idx ON upgrade_rollback (upgrade_id, seq);

CREATE TABLE IF NOT EXISTS upgrade_audit (
    seq          bigserial   PRIMARY KEY,
    at           timestamptz NOT NULL,
    actor        text        NOT NULL,
    actor_roles  text        NOT NULL DEFAULT '',
    action       text        NOT NULL,
    upgrade_id   text,
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

CREATE INDEX IF NOT EXISTS upgrade_audit_run_idx ON upgrade_audit (upgrade_id, seq);

CREATE OR REPLACE FUNCTION upgrade_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'upgrade_audit 只追加：不允许 %（审计链不可改写）', TG_OP;
END $$;

DROP TRIGGER IF EXISTS upgrade_audit_guard_trg ON upgrade_audit;
CREATE TRIGGER upgrade_audit_guard_trg BEFORE UPDATE OR DELETE ON upgrade_audit
    FOR EACH ROW EXECUTE FUNCTION upgrade_audit_guard();

CREATE OR REPLACE FUNCTION upgrade_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '升级证据只追加：% 不允许 %（灰度轨迹与回滚记录不可改写）', TG_TABLE_NAME, TG_OP;
END $$;

DROP TRIGGER IF EXISTS upgrade_stage_event_guard_trg ON upgrade_stage_event;
CREATE TRIGGER upgrade_stage_event_guard_trg BEFORE UPDATE OR DELETE ON upgrade_stage_event
    FOR EACH ROW EXECUTE FUNCTION upgrade_evidence_guard();

DROP TRIGGER IF EXISTS upgrade_rollback_guard_trg ON upgrade_rollback;
CREATE TRIGGER upgrade_rollback_guard_trg BEFORE UPDATE OR DELETE ON upgrade_rollback
    FOR EACH ROW EXECUTE FUNCTION upgrade_evidence_guard();

CREATE TABLE IF NOT EXISTS upgrade_idempotency (
    key_hash       text        NOT NULL,
    operation      text        NOT NULL,
    actor          text        NOT NULL,
    request_digest text        NOT NULL,
    response       jsonb       NOT NULL,
    status         integer     NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (key_hash, operation, actor)
);
"""

#: 审计哈希链的字段顺序（与运维中心同款算法：hash = sha256(prev + "\\n" + canon(payload))）。
AUDIT_FIELDS = ("at", "actor", "actor_roles", "action", "upgrade_id", "outcome",
                "http_status", "reason", "reason_code", "idem_hash", "before", "after")


def schema_name() -> str:
    return os.environ.get(SCHEMA_ENV) or DEFAULT_SCHEMA


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
    if isinstance(obj, datetime):
        return obj.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(obj, (date, time)):
        return obj.isoformat()
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def canon(obj: Any) -> str:
    """规范化 JSON：稳定排序 + 紧凑分隔符（审计哈希与幂等指纹共用）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=_json_default)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return _as_utc(value).astimezone(UTC).isoformat(timespec="seconds")


def _audit_payload(row: Mapping[str, Any]) -> dict:
    payload = {}
    for field in AUDIT_FIELDS:
        value = row.get(field)
        if field == "at":
            value = _as_utc(value).astimezone(UTC).isoformat(timespec="microseconds")
        elif field == "actor_roles":
            value = value or ""
        payload[field] = value
    return payload


def _append_audit(cur, *, actor: str, actions: str, outcome: str, http_status: int,
                  now: datetime, roles: Iterable[str] = (), upgrade_id: str | None = None,
                  reason: str | None = None, reason_code: str | None = None,
                  idem_hash: str | None = None, before: Any = None,
                  after: Any = None) -> dict:
    """追加一条审计（哈希链），必须与业务变更同一事务。

    ``pg_advisory_xact_lock`` 串行化链尾读取：先读后写不加锁必然并发分叉
    （BUG-0002 的老教训）。
    """
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_ID,))
    cur.execute("SELECT hash FROM upgrade_audit ORDER BY seq DESC LIMIT 1")
    prev = cur.fetchone()
    prev_hash = prev["hash"] if prev else None
    row = {
        "at": _as_utc(now), "actor": actor, "actor_roles": ",".join(sorted(roles)),
        "action": actions, "upgrade_id": upgrade_id, "outcome": outcome,
        "http_status": http_status, "reason": reason, "reason_code": reason_code,
        "idem_hash": idem_hash, "before": before, "after": after,
    }
    digest = _sha256((prev_hash or "") + "\n" + canon(_audit_payload(row)))
    cur.execute(
        """INSERT INTO upgrade_audit
             (at, actor, actor_roles, action, upgrade_id, outcome, http_status,
              reason, reason_code, idem_hash, before, after, prev_hash, hash)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           RETURNING seq""",
        (row["at"], row["actor"], row["actor_roles"], row["action"], row["upgrade_id"],
         row["outcome"], row["http_status"], row["reason"], row["reason_code"],
         row["idem_hash"],
         Jsonb(row["before"]) if row["before"] is not None else None,
         Jsonb(row["after"]) if row["after"] is not None else None,
         prev_hash, digest),
    )
    return {"seq": cur.fetchone()["seq"], "hash": digest, "prev_hash": prev_hash}


def verify_audit_chain(*, name: str | None = None) -> dict:
    """全链复算：逐条重算 hash 并核对 prev_hash 串接。"""
    with _tx(name) as cur:
        cur.execute("SELECT * FROM upgrade_audit ORDER BY seq")
        rows = cur.fetchall()
    bad: list[int] = []
    prev = None
    for row in rows:
        expected = _sha256((prev or "") + "\n" + canon(_audit_payload(row)))
        if row["prev_hash"] != prev or row["hash"] != expected:
            bad.append(row["seq"])
        prev = row["hash"]
    return {"entries": len(rows), "bad": bad, "ok": not bad}


def build_chain_anchor_argv(entry: Mapping[str, Any], *, task: str = "DEV-0005",
                            evidence: str | None = None) -> list[str]:
    """把一条审计条目翻成 ``node ops/audit/append.mjs`` 的参数（**接线点，不执行**）。"""
    argv = [
        "node", "ops/audit/append.mjs",
        "--actor", str(entry.get("actor") or "unknown"),
        "--role", str(entry.get("actor_roles") or "RELEASE").split(",")[0] or "RELEASE",
        "--actor-type", "system" if str(entry.get("actor", "")).startswith("system:") else "agent",
        "--action", str(entry.get("action") or "upgrade.change"),
        "--target", f"{entry.get('upgrade_id') or '-'}",
        "--task", task,
        "--reason-code", str(entry.get("reason_code") or "R-OK"),
        "--reason", str(entry.get("reason") or ""),
        "--status", "approved" if entry.get("outcome") in ("ok", "stopped") else "rejected",
    ]
    if entry.get("evidence_ref") or evidence:
        argv += ["--evidence", str(evidence or entry.get("evidence_ref"))]
    return argv


class _StageHalt(Conflict):
    """内部信号：灰度闸门拦停（40907）。先落库再抛，保证「命中阈值自动停并留证」。"""

    def __init__(self, message: str, *, decision: str, run: Mapping[str, Any],
                 metrics: Mapping[str, Any], verdict: CanaryVerdict, from_stage: str,
                 to_stage: str, reason_code: str, action: str = "upgrade.advance"):
        super().__init__(message, code=40907, details=[{
            "decision": decision,
            "upgrade_id": run.get("upgrade_id"),
            "from_stage": from_stage,
            "to_stage": to_stage,
            "reason_code": reason_code,
            "verdict": verdict.as_dict(),
        }])
        self.decision = decision
        self.run = dict(run)
        self.metrics = dict(metrics or {})
        self.verdict = verdict
        self.from_stage = from_stage
        self.to_stage = to_stage
        self.reason_code = reason_code
        self.action = action


def _audit_denial(principal: "UpgradePrincipal", operation: str, exc: OpsCenterError,
                  *, now: datetime, upgrade_id: str | None = None) -> None:
    """拒绝也要留痕。业务事务已回滚，这里另开事务写；写不进去不能把原错误变成 500。"""
    if isinstance(exc, FeatureDisabled):
        return
    try:
        with _tx() as cur:
            _append_audit(cur, actor=principal.actor, actions=f"denied.{operation}",
                          outcome="denied", http_status=exc.http_status, now=now,
                          roles=principal.roles, upgrade_id=upgrade_id,
                          reason=exc.message, reason_code="R-DENIED",
                          after={"code": exc.code})
    except Exception:                                    # pragma: no cover - 兜底
        pass


# --------------------------------------------------------------------------- 主体
@dataclass(frozen=True)
class UpgradePrincipal:
    """升级中心调用主体。由网关/会话层构造后传入；本模块只做判定不做认证。"""

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


def _as_principal(obj: Any) -> UpgradePrincipal:
    """接受本模块主体，或任何同形状对象（如 ``app.admin.ops_center.AdminPrincipal``）。"""
    if isinstance(obj, UpgradePrincipal):
        return obj
    return UpgradePrincipal(
        actor=getattr(obj, "actor", None) or "unknown",
        roles=frozenset(getattr(obj, "roles", frozenset()) or ()),
        permissions=frozenset(getattr(obj, "permissions", frozenset()) or ()),
        step_up_at=getattr(obj, "step_up_at", None),
        step_up_ref=getattr(obj, "step_up_ref", None),
        break_glass=bool(getattr(obj, "break_glass", False)),
        request_id=getattr(obj, "request_id", None),
    )


def _require_perm(principal: UpgradePrincipal, permission: str) -> None:
    if not principal.has(permission):
        raise Forbidden(f"缺少权限点 {permission}（升级中心归口 release-manager）",
                        details=[{"permission": permission}])


def _require_text(value: Any, field: str, *, min_length: int = 1) -> str:
    text = str(value or "").strip()
    if len(text) < min_length:
        raise BadRequest(f"{field} 必填且长度 ≥{min_length}",
                         details=[{"field": field, "actual_length": len(text)}])
    return text


def _require_step_up(principal: UpgradePrincipal, now: datetime) -> None:
    """高风险管理动作（推桶 / 回滚）要 step-up ≤5 分钟（§21.4.3 / 42401）。

    停桶与建单**不要求** step-up：止损链路不该被二次认证卡住（§22.22「决策回滚 ≤5 分钟」）。
    """
    if principal.step_up_at is None:
        raise StepUpRequired("该操作需要 step-up 二次认证（≤5 分钟）")
    if _as_utc(principal.step_up_at) + timedelta(minutes=5) < _as_utc(now):
        raise StepUpRequired("step-up 已过期（>5 分钟），请重新认证")


# --------------------------------------------------------------------------- 幂等
IDEMPOTENCY_TTL = timedelta(hours=24)
IDEMPOTENCY_TTL_FINGERPRINT = timedelta(seconds=300)


def _request_digest(operation: str, actor: str, payload: Any) -> str:
    return _sha256(canon({"op": operation, "actor": actor, "payload": payload}))


def _idem_key_hash(key: str | None, digest: str) -> str:
    return _sha256(key) if key else "fp:" + digest[:32]


def _idem_lookup(cur, *, key_hash: str, operation: str, actor: str, digest: str,
                 now: datetime) -> dict | None:
    cur.execute(
        """SELECT * FROM upgrade_idempotency
            WHERE key_hash=%s AND operation=%s AND actor=%s""",
        (key_hash, operation, actor),
    )
    cached = cur.fetchone()
    if cached and _as_utc(cached["expires_at"]) > now:
        if cached["request_digest"] != digest:
            raise Conflict("幂等键冲突：同一键被用于不同请求体（24h 内）", code=40901)
        replay = dict(cached["response"])
        replay["idempotent_replay"] = True
        return replay
    return None


def _idem_store(cur, *, key_hash: str, operation: str, actor: str, digest: str,
                response: Mapping[str, Any], status: int, now: datetime,
                ttl: timedelta) -> None:
    cur.execute(
        """INSERT INTO upgrade_idempotency
             (key_hash, operation, actor, request_digest, response, status, created_at, expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (key_hash, operation, actor) DO UPDATE
             SET request_digest=EXCLUDED.request_digest, response=EXCLUDED.response,
                 status=EXCLUDED.status, created_at=EXCLUDED.created_at,
                 expires_at=EXCLUDED.expires_at""",
        (key_hash, operation, actor, digest, Jsonb(dict(response)), status,
         now, now + ttl),
    )


# --------------------------------------------------------------------------- 渲染
def render_run(row: Mapping[str, Any]) -> dict:
    return {
        "upgrade_id": row["upgrade_id"],
        "kind": row["kind"],
        "ladder": row["ladder"],
        "from_version": row["from_version"],
        "to_version": row["to_version"],
        "change_ticket": row["change_ticket"],
        "impact": row["impact"],
        "rollback_plan": row["rollback_plan"],
        "acceptance_owner": row["acceptance_owner"],
        "observation_seconds": row["observation_seconds"],
        "stage": row["stage"],
        "state": row["state"],
        "stage_entered_at": _iso(row["stage_entered_at"]),
        "created_at": _iso(row["created_at"]),
        "created_by": row["created_by"],
        "updated_at": _iso(row["updated_at"]),
        "p0_exception": row["p0_exception"],
        "post_ticket_due_at": _iso(row["post_ticket_due_at"]),
        "spec_alignment": row["spec_alignment"],
        "compat_overall": row["compat_overall"],
    }


def _load_run(cur, upgrade_id: str) -> dict:
    cur.execute("SELECT * FROM upgrade_run WHERE upgrade_id=%s", (upgrade_id,))
    row = cur.fetchone()
    if not row:
        raise NotFound(f"升级单不存在：{upgrade_id}")
    return dict(row)


# --------------------------------------------------------------------------- 写入口
def create_run(principal: Any, body: Mapping[str, Any], *, now: datetime | None = None,
               idempotency_key: str | None = None, enabled: bool | None = None,
               inventory: VersionInventory | None = None) -> dict:
    """建升级单（= 进入首桶）。没有 upgrade_id 不得发布（§18.7.1），所以这里是唯一入口。

    建单即校验：变更单 / 影响面 / 回滚方案 / 验收人四件齐（§22.22 升级完成判据①），
    并把当时的 spec 对齐与兼容矩阵状态**钉进单里**（事后能复盘当时凭什么放行）。
    """
    require_writes_enabled(override=enabled)
    principal = _as_principal(principal)
    now = _as_utc(now or _utcnow())
    operation = "createRun"
    try:
        _require_perm(principal, "upgrade.run.promote")
        if principal.break_glass:
            raise BreakGlassReadOnly("break-glass 只读模式（≤4h）下禁止建升级单")

        kind = _require_text(body.get("kind"), "kind")
        if kind not in LADDER_BY_KIND:
            raise BadRequest(
                f"升级类型 {kind!r} 不在本单灰度范围；允许值={sorted(LADDER_BY_KIND)}",
                details=[{"field": "kind", "allowed": sorted(LADDER_BY_KIND)}])
        to_version = _require_text(body.get("to_version"), "to_version")
        from_version = _require_text(body.get("from_version"), "from_version")
        if _split_version(to_version) is None or _split_version(from_version) is None:
            raise BadRequest("版本号必须形如 X.Y.Z（可带 -pre 后缀）",
                             details=[{"field": "to_version"}, {"field": "from_version"}])
        if _version_key(to_version) == _version_key(from_version):
            raise BadRequest("from_version 与 to_version 相同，无升级动作")
        if _version_key(to_version) < _version_key(from_version):
            raise BadRequest("to_version 必须高于 from_version（降级走 rollback，不走建单）")

        body_impact = _require_text(body.get("impact"), "impact", min_length=4)
        rollback_plan = _require_text(body.get("rollback_plan"), "rollback_plan", min_length=4)
        acceptance_owner = _require_text(body.get("acceptance_owner"), "acceptance_owner")
        change_ticket = _require_text(body.get("change_ticket"), "change_ticket", min_length=4)
        observation_seconds = int(body.get("observation_seconds") or 0)
        if observation_seconds <= 0:
            raise BadRequest("observation_seconds 必须 >0（§18.7.1 升级后 24h 观察窗由变更单声明）",
                             details=[{"field": "observation_seconds"}])

        ladder = ladder_for(kind)
        inventory = inventory if inventory is not None else version_inventory(now=now)

        payload = {
            "kind": kind, "from_version": from_version, "to_version": to_version,
            "change_ticket": change_ticket, "impact": body_impact,
            "rollback_plan": rollback_plan, "acceptance_owner": acceptance_owner,
            "observation_seconds": observation_seconds,
        }
        digest = _request_digest(operation, principal.actor, payload)
        key_hash = _idem_key_hash(idempotency_key, digest)
        ttl = IDEMPOTENCY_TTL if idempotency_key else IDEMPOTENCY_TTL_FINGERPRINT

        with _tx() as cur:
            replay = _idem_lookup(cur, key_hash=key_hash, operation=operation,
                                  actor=principal.actor, digest=digest, now=now)
            if replay is not None:
                return replay

            upgrade_id = str(body.get("upgrade_id") or f"UPG-{now:%Y%m%d}-{os.urandom(3).hex()}")
            cur.execute("SELECT 1 FROM upgrade_run WHERE upgrade_id=%s", (upgrade_id,))
            if cur.fetchone():
                raise Conflict(f"升级单已存在：{upgrade_id}", code=40901)

            first = ladder[0]
            cur.execute(
                """INSERT INTO upgrade_run
                     (upgrade_id, kind, ladder, from_version, to_version, change_ticket,
                      impact, rollback_plan, acceptance_owner, observation_seconds,
                      stage, state, stage_entered_at, created_at, created_by, updated_at,
                      p0_exception, post_ticket_due_at, spec_alignment, compat_overall)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'running',%s,%s,%s,%s,
                           false,NULL,%s,%s)""",
                (upgrade_id, kind, LADDER_BY_KIND[kind], from_version, to_version, change_ticket,
                 body_impact, rollback_plan, acceptance_owner, observation_seconds,
                 first.key, now, now, principal.actor, now,
                 inventory.alignment, inventory.compat_overall),
            )
            cur.execute(
                """INSERT INTO upgrade_stage_event
                     (upgrade_id, at, actor, actor_roles, action, from_stage, to_stage,
                      decision, reason, reason_code)
                   VALUES (%s,%s,%s,%s,'upgrade.create',NULL,%s,'start',%s,'R-OK')""",
                (upgrade_id, now, principal.actor, ",".join(sorted(principal.roles)),
                 first.key, f"建单进入首桶 {first.key}（{first.label}）"),
            )
            audit = _append_audit(
                cur, actor=principal.actor, actions="upgrade.create", outcome="ok",
                http_status=201, now=now, roles=principal.roles, upgrade_id=upgrade_id,
                reason=f"{from_version} → {to_version} 首桶 {first.key}", reason_code="R-OK",
                idem_hash=key_hash, after=payload,
            )
            row = _load_run(cur, upgrade_id)
            response = {
                "upgrade_id": upgrade_id,
                "run": render_run(row),
                "stage": first.as_dict(),
                "ladder": [s.as_dict() for s in ladder],
                "spec": {
                    "alignment": inventory.alignment,
                    "alignment_detail": inventory.alignment_detail,
                    "compat_overall": inventory.compat_overall,
                    "spec_version": inventory.spec_version,
                    "openapi_version": inventory.openapi_version,
                },
                "gate": release_gate(now=now, kind=kind, compat=inventory.compat,
                                     alignment=inventory.alignment),
                "audit": {"seq": audit["seq"], "hash": audit["hash"][:16],
                          "prev_hash": (audit["prev_hash"] or "")[:16]},
                "idempotent_replay": False,
            }
            _idem_store(cur, key_hash=key_hash, operation=operation, actor=principal.actor,
                        digest=digest, response=response, status=201, now=now, ttl=ttl)
            return response
    except OpsCenterError as exc:
        _audit_denial(principal, operation, exc, now=now,
                      upgrade_id=str(body.get("upgrade_id") or "") or None)
        raise


def advance(principal: Any, upgrade_id: str, *, metrics: Mapping[str, Any],
            dwell: timedelta | None = None, observation_completed: bool = False,
            observation_seconds: float | None = None, p0_emergency: bool = False,
            now: datetime | None = None, idempotency_key: str | None = None,
            enabled: bool | None = None, thresholds: Sequence[Threshold] = DEFAULT_THRESHOLDS,
            declared_freeze: bool = False) -> dict:
    """把升级单推进到下一桶（发布窗闸门 + 阈值闸门 + 观测窗闸门）。

    三态：``advance`` 推进；``hold`` 不推进也不判通过（缺指标 / 观测窗未满）；
    ``stop`` 自动停桶 + 落库 + 审计 + 抛 40907。**停与不推进都会留证**。
    """
    require_writes_enabled(override=enabled)
    principal = _as_principal(principal)
    now = _as_utc(now or _utcnow())
    operation = "advanceUpgrade"
    try:
        _require_perm(principal, "upgrade.run.promote")
        if principal.break_glass:
            raise BreakGlassReadOnly("break-glass 只读模式（≤4h）下禁止推进灰度")
        _require_step_up(principal, now)

        payload = {"upgrade_id": upgrade_id, "metrics": dict(metrics or {}),
                   "dwell_seconds": None if dwell is None else int(dwell.total_seconds()),
                   "observation_completed": bool(observation_completed),
                   "observation_seconds": observation_seconds,
                   "p0_emergency": bool(p0_emergency)}
        digest = _request_digest(operation, principal.actor, payload)
        key_hash = _idem_key_hash(idempotency_key, digest)
        ttl = IDEMPOTENCY_TTL if idempotency_key else IDEMPOTENCY_TTL_FINGERPRINT

        with _tx() as cur:
            replay = _idem_lookup(cur, key_hash=key_hash, operation=operation,
                                  actor=principal.actor, digest=digest, now=now)
            if replay is not None:
                return replay
            run = _load_run(cur, upgrade_id)
            if run["state"] != "running":
                raise Conflict(f"升级单当前状态 {run['state']} 不允许推进（只有 running 可推进）",
                               code=40902)

            kind = run["kind"]
            ladder = ladder_for(kind)
            current = ladder[stage_index(kind, run["stage"])]
            target = next_stage(kind, run["stage"])

            # —— 到顶：完成判定（24h 观察窗 + 账本复算 0 + 储备覆盖率不变）——
            if target is None:
                verdict = evaluate_stage(metrics, thresholds)
                if verdict.decision != "advance":
                    raise _StageHalt(verdict.reason, decision=verdict.decision, run=run,
                                     metrics=metrics, verdict=verdict,
                                     from_stage=current.key, to_stage=current.key,
                                     reason_code="R-GATE-STOP" if verdict.decision == "stop"
                                     else "R-GATE-UNKNOWN", action="upgrade.complete")
                required = float(run["observation_seconds"])
                got = float(observation_seconds or 0)
                if not observation_completed or got < required:
                    raise _StageHalt(
                        f"观测窗未满，禁止判定完成（需 {required:.0f}s，实测 {got:.0f}s，"
                        f"completed={observation_completed}）",
                        decision="hold", run=run, metrics=metrics, verdict=verdict,
                        from_stage=current.key, to_stage=current.key,
                        reason_code="R-WINDOW", action="upgrade.complete")
                cur.execute(
                    """UPDATE upgrade_run SET state='completed', updated_at=%s
                        WHERE upgrade_id=%s""", (now, upgrade_id))
                cur.execute(
                    """INSERT INTO upgrade_stage_event
                         (upgrade_id, at, actor, actor_roles, action, from_stage, to_stage,
                          decision, reason, reason_code, metrics, hits, verdict)
                       VALUES (%s,%s,%s,%s,'upgrade.complete',%s,%s,'complete',%s,'R-OK',
                               %s,%s,%s)""",
                    (upgrade_id, now, principal.actor, ",".join(sorted(principal.roles)),
                     current.key, current.key,
                     f"观测窗 {got:.0f}s ≥ {required:.0f}s，判定完成",
                     Jsonb(dict(metrics or {})), Jsonb([h.as_dict() for h in verdict.hits]),
                     Jsonb(verdict.as_dict())))
                audit = _append_audit(
                    cur, actor=principal.actor, actions="upgrade.complete", outcome="ok",
                    http_status=200, now=now, roles=principal.roles, upgrade_id=upgrade_id,
                    reason="升级完成判据通过", reason_code="R-OK", idem_hash=key_hash,
                    after={"stage": current.key, "observation_seconds": got})
                response = {
                    "upgrade_id": upgrade_id, "decision": "complete",
                    "stage": current.as_dict(), "next": None,
                    "verdict": verdict.as_dict(),
                    "run": render_run(_load_run(cur, upgrade_id)),
                    "audit": {"seq": audit["seq"], "hash": audit["hash"][:16],
                              "prev_hash": (audit["prev_hash"] or "")[:16]},
                    "idempotent_replay": False,
                }
                _idem_store(cur, key_hash=key_hash, operation=operation,
                            actor=principal.actor, digest=digest, response=response,
                            status=200, now=now, ttl=ttl)
                return response

            # —— 观测窗（客户端阶梯有硬性 24h；应用阶梯由变更单声明）——
            required_dwell = target.required_dwell if target.required_dwell is not None else dwell
            if required_dwell is None:
                verdict = evaluate_stage(metrics, thresholds)
                raise _StageHalt(
                    f"该桶（{target.key}）产品口径未规定最短观测时长，须在变更单中明确"
                    f"（§22.22 应用发布阶梯），当前未提供 → 不推进",
                    decision="hold", run=run, metrics=metrics, verdict=verdict,
                    from_stage=current.key, to_stage=target.key, reason_code="R-WINDOW")
            elapsed = (now - _as_utc(run["stage_entered_at"])).total_seconds()
            want = required_dwell.total_seconds()
            if elapsed < want:
                verdict = evaluate_stage(metrics, thresholds)
                raise _StageHalt(
                    f"观测窗未满：{current.key} 需 ≥{want:.0f}s，已 {elapsed:.0f}s（40907）",
                    decision="hold", run=run, metrics=metrics, verdict=verdict,
                    from_stage=current.key, to_stage=target.key, reason_code="R-WINDOW")

            # —— 阈值闸门（含「未知不通过」）：红线优先于窗口，命中即停 ——
            verdict = evaluate_stage(metrics, thresholds)
            if verdict.decision == "stop":
                raise _StageHalt(f"{current.key} → {target.key} 被拦停：{verdict.reason}",
                                 decision="stop", run=run, metrics=metrics, verdict=verdict,
                                 from_stage=current.key, to_stage=target.key,
                                 reason_code="R-GATE-STOP")

            # —— 发布窗闸门（P0 通道免窗口，但要补变更单）——
            window = release_window(now, declared_freeze=declared_freeze)
            p0 = bool(p0_emergency)
            if not window.open and p0 and not str(run["change_ticket"]).upper().startswith("P0-"):
                raise BadRequest("P0 通道要求变更单号以 P0- 开头（§22.22 发布列车）",
                                 details=[{"field": "change_ticket",
                                           "actual": run["change_ticket"]}])
            if verdict.decision == "hold":
                raise _StageHalt(f"{current.key} → {target.key} 暂不推进：{verdict.reason}",
                                 decision="hold", run=run, metrics=metrics, verdict=verdict,
                                 from_stage=current.key, to_stage=target.key,
                                 reason_code="R-GATE-UNKNOWN")
            if not window.open and not p0:
                raise _StageHalt(
                    f"发布窗关闭：{window.reason}（40902）；紧急修复走 P0 通道",
                    decision="hold", run=run, metrics=metrics, verdict=verdict,
                    from_stage=current.key, to_stage=target.key, reason_code="R-WINDOW")

            post_due = now + timedelta(hours=P0_POST_TICKET_HOURS) if (p0 and not window.open) else None
            cur.execute(
                """UPDATE upgrade_run
                      SET stage=%s, stage_entered_at=%s, updated_at=%s,
                          p0_exception=%s, post_ticket_due_at=COALESCE(%s, post_ticket_due_at)
                    WHERE upgrade_id=%s""",
                (target.key, now, now, bool(p0 and not window.open), post_due, upgrade_id))
            cur.execute(
                """INSERT INTO upgrade_stage_event
                     (upgrade_id, at, actor, actor_roles, action, from_stage, to_stage,
                      decision, reason, reason_code, metrics, hits, verdict)
                   VALUES (%s,%s,%s,%s,'upgrade.advance',%s,%s,'advance',%s,'R-OK',%s,%s,%s)""",
                (upgrade_id, now, principal.actor, ",".join(sorted(principal.roles)),
                 current.key, target.key,
                 f"{current.key} → {target.key}（{target.percent}%）；{verdict.reason}",
                 Jsonb(dict(metrics or {})), Jsonb([h.as_dict() for h in verdict.hits]),
                 Jsonb(verdict.as_dict())))
            audit = _append_audit(
                cur, actor=principal.actor, actions="upgrade.advance", outcome="ok",
                http_status=200, now=now, roles=principal.roles, upgrade_id=upgrade_id,
                reason=f"{current.key} → {target.key}", reason_code="R-OK", idem_hash=key_hash,
                before={"stage": current.key}, after={"stage": target.key,
                                                      "metrics": dict(metrics or {}),
                                                      "p0_exception": bool(p0 and not window.open)})
            response = {
                "upgrade_id": upgrade_id,
                "decision": "advance",
                "stage": current.as_dict(),
                "next": target.as_dict(),
                "verdict": verdict.as_dict(),
                "window": window.as_dict(),
                "p0_exception": bool(p0 and not window.open),
                "post_ticket_due_at": _iso(post_due),
                "run": render_run(_load_run(cur, upgrade_id)),
                "audit": {"seq": audit["seq"], "hash": audit["hash"][:16],
                          "prev_hash": (audit["prev_hash"] or "")[:16]},
                "idempotent_replay": False,
            }
            _idem_store(cur, key_hash=key_hash, operation=operation, actor=principal.actor,
                        digest=digest, response=response, status=200, now=now, ttl=ttl)
            return response
    except _StageHalt as halt:
        _persist_halt(principal, halt, now=now)
        raise Conflict(halt.message, code=40907, details=halt.details) from None
    except OpsCenterError as exc:
        _audit_denial(principal, operation, exc, now=now, upgrade_id=upgrade_id)
        raise


def _persist_halt(principal: UpgradePrincipal, halt: _StageHalt, *, now: datetime) -> None:
    """拦停/暂不推进也要落库（独立事务：业务事务已回滚，这条证据不能跟着回滚）。"""
    run = halt.run
    try:
        with _tx() as cur:
            if halt.decision == "stop":
                cur.execute(
                    """UPDATE upgrade_run SET state='stopped', updated_at=%s
                        WHERE upgrade_id=%s AND state='running'""",
                    (now, run["upgrade_id"]))
            cur.execute(
                """INSERT INTO upgrade_stage_event
                     (upgrade_id, at, actor, actor_roles, action, from_stage, to_stage,
                      decision, reason, reason_code, metrics, hits, verdict)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (run["upgrade_id"], now, principal.actor,
                 ",".join(sorted(principal.roles)), halt.action,
                 halt.from_stage, halt.to_stage, halt.decision, halt.verdict.reason,
                 halt.reason_code, Jsonb(dict(halt.metrics)),
                 Jsonb([h.as_dict() for h in halt.verdict.hits]),
                 Jsonb(halt.verdict.as_dict())))
            _append_audit(
                cur, actor=principal.actor, actions=f"upgrade.{halt.decision}",
                outcome="stopped" if halt.decision == "stop" else "held",
                http_status=409, now=now, roles=principal.roles,
                upgrade_id=run["upgrade_id"], reason=halt.verdict.reason,
                reason_code=halt.reason_code,
                after={"from_stage": halt.from_stage, "to_stage": halt.to_stage,
                       "verdict": halt.verdict.as_dict()})
    except Exception:                                    # pragma: no cover - 兜底
        pass


def stop_run(principal: Any, upgrade_id: str, *, reason: str,
             now: datetime | None = None, idempotency_key: str | None = None,
             enabled: bool | None = None) -> dict:
    """停桶（任意桶可停，免发布窗；§22.22 客户端「可停任意桶」）。"""
    require_writes_enabled(override=enabled)
    principal = _as_principal(principal)
    now = _as_utc(now or _utcnow())
    operation = "stopUpgrade"
    try:
        _require_perm(principal, "upgrade.run.stop")
        if principal.break_glass:
            raise BreakGlassReadOnly("break-glass 只读模式（≤4h）下禁止停桶")
        reason = _require_text(reason, "reason", min_length=4)

        digest = _request_digest(operation, principal.actor,
                                 {"upgrade_id": upgrade_id, "reason": reason})
        key_hash = _idem_key_hash(idempotency_key, digest)
        ttl = IDEMPOTENCY_TTL if idempotency_key else IDEMPOTENCY_TTL_FINGERPRINT
        with _tx() as cur:
            replay = _idem_lookup(cur, key_hash=key_hash, operation=operation,
                                  actor=principal.actor, digest=digest, now=now)
            if replay is not None:
                return replay
            run = _load_run(cur, upgrade_id)
            if run["state"] != "running":
                raise Conflict(f"升级单当前状态 {run['state']} 不允许停桶", code=40902)
            cur.execute(
                """UPDATE upgrade_run SET state='stopped', updated_at=%s WHERE upgrade_id=%s""",
                (now, upgrade_id))
            cur.execute(
                """INSERT INTO upgrade_stage_event
                     (upgrade_id, at, actor, actor_roles, action, from_stage, to_stage,
                      decision, reason, reason_code)
                   VALUES (%s,%s,%s,%s,'upgrade.stop',%s,%s,'stop',%s,'R-MANUAL-STOP')""",
                (upgrade_id, now, principal.actor, ",".join(sorted(principal.roles)),
                 run["stage"], run["stage"], reason))
            audit = _append_audit(
                cur, actor=principal.actor, actions="upgrade.stop", outcome="stopped",
                http_status=200, now=now, roles=principal.roles, upgrade_id=upgrade_id,
                reason=reason, reason_code="R-MANUAL-STOP", idem_hash=key_hash,
                after={"stage": run["stage"], "state": "stopped"})
            response = {
                "upgrade_id": upgrade_id, "decision": "stop", "stage": run["stage"],
                "run": render_run(_load_run(cur, upgrade_id)),
                "audit": {"seq": audit["seq"], "hash": audit["hash"][:16],
                          "prev_hash": (audit["prev_hash"] or "")[:16]},
                "idempotent_replay": False,
            }
            _idem_store(cur, key_hash=key_hash, operation=operation, actor=principal.actor,
                        digest=digest, response=response, status=200, now=now, ttl=ttl)
            return response
    except OpsCenterError as exc:
        _audit_denial(principal, operation, exc, now=now, upgrade_id=upgrade_id)
        raise


def rollback(principal: Any, upgrade_id: str, *, reason: str,
             evidence: Mapping[str, Any] | None = None,
             rollback_started_at: datetime | None = None,
             now: datetime | None = None, idempotency_key: str | None = None,
             enabled: bool | None = None) -> dict:
    """回滚到上一版（免发布窗），并记录**时间 + 证据**（验收③）。

    ``rollback_point_at`` 取上一版在 spec 里的**记录时间**（CHANGELOG 发布日期）；
    若该版本不在 CHANGELOG 里，退化为本单的部署时间 ``created_at``，并把来源写进
    ``rollback_point_source``，不假装它来自 spec。
    """
    require_writes_enabled(override=enabled)
    principal = _as_principal(principal)
    now = _as_utc(now or _utcnow())
    operation = "rollbackUpgrade"
    try:
        _require_perm(principal, "upgrade.run.rollback")
        if principal.break_glass:
            raise BreakGlassReadOnly("break-glass 只读模式（≤4h）下禁止回滚")
        _require_step_up(principal, now)
        reason = _require_text(reason, "reason", min_length=4)
        if not evidence:
            raise BadRequest("回滚必须带证据（冒烟 / 黄金指标 / 账本复算差异 0 / 审计锚）",
                             details=[{"field": "evidence"}])

        digest = _request_digest(operation, principal.actor,
                                 {"upgrade_id": upgrade_id, "reason": reason,
                                  "evidence": dict(evidence)})
        key_hash = _idem_key_hash(idempotency_key, digest)
        ttl = IDEMPOTENCY_TTL if idempotency_key else IDEMPOTENCY_TTL_FINGERPRINT

        with _tx() as cur:
            replay = _idem_lookup(cur, key_hash=key_hash, operation=operation,
                                  actor=principal.actor, digest=digest, now=now)
            if replay is not None:
                return replay
            run = _load_run(cur, upgrade_id)
            if run["state"] not in ("running", "stopped", "completed"):
                raise Conflict(f"升级单当前状态 {run['state']} 不允许回滚", code=40902)

            kind = run["kind"]
            from_version = run["to_version"]
            to_version = run["from_version"]

            try:
                releases = load_changelog()
            except SpecSourceMissing:                    # pragma: no cover - 部署期缺 spec
                releases = ()
            entry = next((r for r in releases if r.version == to_version), None)
            if entry is not None:
                point_at = datetime.combine(entry.released_at, time(0, 0), tzinfo=UTC)
                point_source = f"{CHANGELOG_NAME}#L{entry.line}"
            else:
                point_at = _as_utc(run["created_at"])
                point_source = "run:created_at（该版本不在 CHANGELOG，用本单部署时间）"

            started = _as_utc(rollback_started_at) if rollback_started_at else now
            duration = max(0.0, (now - started).total_seconds())
            budget = ROLLBACK_BUDGET_SECONDS.get(kind, 0)
            within = budget > 0 and duration <= budget

            evidence_payload = dict(evidence)
            evidence_payload.setdefault("from_version", from_version)
            evidence_payload.setdefault("to_version", to_version)
            evidence_payload.setdefault("stage", run["stage"])
            evidence_payload.setdefault("rollback_started_at", _iso(started))

            cur.execute(
                """UPDATE upgrade_run SET state='rolled_back', updated_at=%s
                    WHERE upgrade_id=%s""", (now, upgrade_id))
            cur.execute(
                """INSERT INTO upgrade_rollback
                     (upgrade_id, at, actor, from_version, to_version,
                      rollback_point_version, rollback_point_at, rollback_point_source,
                      duration_seconds, budget_seconds, within_budget, evidence,
                      reason, reason_code)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'R-ROLLBACK')""",
                (upgrade_id, now, principal.actor, from_version, to_version, to_version,
                 point_at, point_source, round(duration, 3), budget, within,
                 Jsonb(evidence_payload), reason))
            cur.execute(
                """INSERT INTO upgrade_stage_event
                     (upgrade_id, at, actor, actor_roles, action, from_stage, to_stage,
                      decision, reason, reason_code)
                   VALUES (%s,%s,%s,%s,'upgrade.rollback',%s,%s,'rollback',%s,'R-ROLLBACK')""",
                (upgrade_id, now, principal.actor, ",".join(sorted(principal.roles)),
                 run["stage"], run["stage"], reason))
            audit = _append_audit(
                cur, actor=principal.actor, actions="upgrade.rollback", outcome="ok",
                http_status=200, now=now, roles=principal.roles, upgrade_id=upgrade_id,
                reason=reason, reason_code="R-ROLLBACK", idem_hash=key_hash,
                before={"version": from_version, "stage": run["stage"]},
                after={"version": to_version, "duration_seconds": round(duration, 3),
                       "within_budget": within, "evidence": evidence_payload})
            response = {
                "upgrade_id": upgrade_id,
                "decision": "rollback",
                "rolled_back_at": _iso(now),
                "from_version": from_version,
                "to_version": to_version,
                "rollback_point": {
                    "version": to_version,
                    "recorded_at": _iso(point_at),
                    "source": point_source,
                    "evidence_level": "green" if entry is not None else "yellow",
                },
                "duration_seconds": round(duration, 3),
                "budget_seconds": budget,
                "within_budget": within,
                "evidence": evidence_payload,
                "run": render_run(_load_run(cur, upgrade_id)),
                "audit": {"seq": audit["seq"], "hash": audit["hash"][:16],
                          "prev_hash": (audit["prev_hash"] or "")[:16]},
                "idempotent_replay": False,
            }
            _idem_store(cur, key_hash=key_hash, operation=operation, actor=principal.actor,
                        digest=digest, response=response, status=200, now=now, ttl=ttl)
            return response
    except OpsCenterError as exc:
        _audit_denial(principal, operation, exc, now=now, upgrade_id=upgrade_id)
        raise


# --------------------------------------------------------------------------- 读入口
def list_runs(principal: Any, *, state: str | None = None, kind: str | None = None,
              limit: int = 50, name: str | None = None) -> list[dict]:
    """升级单列表（只读；开关关闭时仍可用）。"""
    principal = _as_principal(principal)
    _require_perm(principal, "upgrade.run.read")
    clauses, params = [], []
    if state:
        if state not in UPGRADE_STATES:
            raise BadRequest(f"state 非法：{state}；允许值={list(UPGRADE_STATES)}")
        clauses.append("state = %s")
        params.append(state)
    if kind:
        if kind not in LADDER_BY_KIND:
            raise BadRequest(f"kind 非法：{kind}；允许值={sorted(LADDER_BY_KIND)}")
        clauses.append("kind = %s")
        params.append(kind)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit), 200)))
    with _tx(name) as cur:
        cur.execute(f"SELECT * FROM upgrade_run{where} ORDER BY created_at DESC LIMIT %s", params)
        return [render_run(dict(row)) for row in cur.fetchall()]


def get_run(principal: Any, upgrade_id: str, *, name: str | None = None) -> dict:
    """升级单详情 + 灰度轨迹 + 回滚记录（只读）。"""
    principal = _as_principal(principal)
    _require_perm(principal, "upgrade.run.read")
    with _tx(name) as cur:
        run = render_run(_load_run(cur, upgrade_id))
        cur.execute("SELECT * FROM upgrade_stage_event WHERE upgrade_id=%s ORDER BY seq",
                    (upgrade_id,))
        events = [{
            "seq": row["seq"], "at": _iso(row["at"]), "actor": row["actor"],
            "action": row["action"], "from_stage": row["from_stage"],
            "to_stage": row["to_stage"], "decision": row["decision"],
            "reason": row["reason"], "reason_code": row["reason_code"],
            "verdict": row["verdict"],
        } for row in cur.fetchall()]
        rollbacks = _rollback_rows(cur, upgrade_id)
    return {"run": run, "events": events, "rollbacks": rollbacks}


def _rollback_rows(cur, upgrade_id: str) -> list[dict]:
    cur.execute("SELECT * FROM upgrade_rollback WHERE upgrade_id=%s ORDER BY seq", (upgrade_id,))
    return [{
        "seq": row["seq"],
        "at": _iso(row["at"]),
        "actor": row["actor"],
        "from_version": row["from_version"],
        "to_version": row["to_version"],
        "rollback_point_at": _iso(row["rollback_point_at"]),
        "rollback_point_source": row["rollback_point_source"],
        "duration_seconds": float(row["duration_seconds"]),
        "budget_seconds": row["budget_seconds"],
        "within_budget": row["within_budget"],
        "evidence": row["evidence"],
        "reason": row["reason"],
        "reason_code": row["reason_code"],
    } for row in cur.fetchall()]


def list_rollbacks(principal: Any, upgrade_id: str, *, name: str | None = None) -> list[dict]:
    """回滚记录（验收③的证据面；只读）。"""
    principal = _as_principal(principal)
    _require_perm(principal, "upgrade.run.read")
    with _tx(name) as cur:
        return _rollback_rows(cur, upgrade_id)
