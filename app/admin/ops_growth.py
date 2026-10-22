# SPDX-License-Identifier: Apache-2.0
"""运营管理中心服务层（§22.23 · §6.6 · 〔决策K3〕〔决策K4〕· 配置中心 §21.12）。

本模块是「运营配置」在**服务层**的唯一入口：一块只读视图 + 三个受控写入口，
**所有写都经配置中心**（草稿 → 发布单 → 复核 → 到点生效），本模块自己不写任何业务表。
它不注册 HTTP 路由（本单红线），也不碰账本、不碰积分台账。

一、验收对照（本文件逐条可测）
==============================
① 写操作落到配置中心  ``_draft`` / ``_publish`` 一律委托 ``app.admin.ops_center`` 的
                      ``createConfigDraft`` / ``publishConfigItem``；模块内 **没有一条 SQL**。
                      生效语义固定为「下一批生效、不追溯」：``effective_at`` 只能落在
                      批次边界（UTC 00:00）且不早于该风险级的冷却期；响应回带
                      ``retroactive=False`` 与历史口径说明。
② 费率 >3000 bps 提示   ``preview_share_bps()`` 返回 ``confirmation.required``；
                      写入口在缺二次确认时抛 40902 并回带确认文案；确认人必须 **≠ 发起人**
                      且持有 ``growth.fee.confirm``（职责分离，不是点一下「我确认」）。
③ 增长类默认关闭      ``ops_growth`` 开关：owner=ops-lead · expire_at=2026-12-31 · 默认关；
                      关闭后只剩只读视图，写入口 404（不是 403）。
④ 变更全部进审计链    ``createConfigDraft`` / ``publishConfigItem`` / ``approveConfigPublish``
                      本身就在**同一事务**里往 ``config_audit`` 哈希链追加，失败即整体回滚；
                      本模块只把 ``audit.seq/hash`` 转递给调用方，不另建第二条链。
⑤ 命名红线            ``NAMING_POLICY`` + ``naming_scan()``：源码与文档里不出现 §18.12
                      第一段的任何禁用词（词表放在 CI 门禁与测试里，生产代码只做引用）；
                      能力位 ``client_cash_account=False``。

二、为什么写入口要「绕一圈」
============================
〔决策K3〕要求费率、gas、分润比例**全部可配置**，§21.4 又要求这类变更走「提议 → 第二人复核 →
决策人确认 → 冷却 → 发布」。把这两条合在一起，唯一正确的实现就是：运营侧只提供**受控入口**，
真正的版本化、冷却、复核、审计、灰度、回滚全部由配置中心负责。所以本模块的写函数
签名里带着 ``reason`` / ``ticket`` / ``confirm``，却没有一个字段能直接落到表里。

三、不做什么
============
* 不直接改积分策略（``app.points`` 的 ``update_policy`` 是"配置中心发布后的落地动作"，
  由消费方在发布生效时调用；本模块不越位）。
* 不新增迁移：只登记配置键（``register_config_keys``），表结构仍由配置中心自举。
* 不设客户现金账户（§6.6.3）：COP 只能抵扣服务费或兑换服务，模块里没有这类能力位。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from . import (
    FEATURE_FLAGS,
    BadRequest,
    Conflict,
    FeatureDisabled,
    Forbidden,
    NotFound,
    OpsCenterError,
    flag_enabled as _admin_flag_enabled,
    flag_expired as _admin_flag_expired,
    flag_spec as _admin_flag_spec,
)
from . import ops_center as config_center
from .ops_center import KEY_POLICIES, KeyPolicy

__all__ = [
    # 开关
    "FLAG_NAME",
    "OPS_GROWTH_FLAG_SPEC",
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
    "SECOND_CONFIRM_THRESHOLD_BPS",
    "CONFIRM_TTL",
    "BATCH_CUTOVER_UTC",
    "CONTROLS",
    "Control",
    "GROWTH_KEYS",
    "S1_SCOPE",
    "NAMING_POLICY",
    "naming_scan",
    "CLIENT_CAPABILITIES",
    # 配置键登记
    "register_config_keys",
    "registered_keys",
    # 生效语义
    "next_batch_cutover",
    "effective_at_for",
    "effect_semantics",
    # 预览（纯函数）
    "preview_share_bps",
    "preview_service_fee",
    "preview_gas_mode",
    "preview_points_transfer",
    "split_share_bps",
    # 只读视图
    "growth_overview",
    "campaign_allowlist",
    "recent_changes",
    "client_capabilities",
    "s1_scope",
    # 受控写入口
    "set_points_transfer_enabled",
    "set_platform_share_bps",
    "set_gas_mode",
    "FeeConfirmation",
    "SecondConfirmationRequired",
    # 生效推进（系统动作）
    "apply_due",
]

UTC = timezone.utc
CST = timezone(timedelta(hours=8))

# --------------------------------------------------------------------------- 开关
FLAG_NAME = "ops_growth"

#: §B.5 / §21.6.4：三字段必填、默认关闭、到期 fail-closed。
OPS_GROWTH_FLAG_SPEC: dict[str, Any] = {
    "default": False,
    "owner": "ops-lead",
    "expire_at": "2026-12-31",
    "rollback_rule": (
        "关闭后仅只读：运营配置只读视图（growth_overview / 费率与 gas 预览 / 活动白名单）"
        "照常可用，set_points_transfer_enabled / set_platform_share_bps / set_gas_mode "
        "与 apply_due 一律 404，不暴露可写能力；已发布的配置值与 config_audit 审计链"
        "只追加、不删除、不回滚；后续变更回到配置中心既有入口（运维中心 / 变更单人工流程）"
    ),
    "summary": "运营管理中心（运营配置只读视图 + 受控写入口；不注册 HTTP 路由）",
}


def register_feature_flag(registry: dict | None = None) -> dict:
    """把 ``ops_growth`` 登记进管理域开关表（幂等；同名不同定义直接报错）。"""
    registry = FEATURE_FLAGS if registry is None else registry
    existing = registry.get(FLAG_NAME)
    if existing is not None and dict(existing) != dict(OPS_GROWTH_FLAG_SPEC):
        raise RuntimeError(
            f"特性开关 {FLAG_NAME} 已有不同定义，拒绝覆盖（同一开关只能有一个定义，"
            f"冲突需 lead 裁决）：现有={dict(existing)!r}"
        )
    registry[FLAG_NAME] = dict(OPS_GROWTH_FLAG_SPEC)
    return registry[FLAG_NAME]


register_feature_flag()


def flag_spec() -> dict:
    return _admin_flag_spec(FLAG_NAME)


def flag_expired(*, today: date | None = None) -> bool:
    return _admin_flag_expired(FLAG_NAME, today=today)


def flag_enabled(*, override: bool | None = None, today: date | None = None) -> bool:
    return _admin_flag_enabled(FLAG_NAME, override=override, today=today)


def writes_enabled(*, override: bool | None = None, today: date | None = None) -> bool:
    return flag_enabled(override=override, today=today)


def require_writes_enabled(*, override: bool | None = None, today: date | None = None) -> None:
    """写入口闸门：关闭态抛 404（rollback_rule 要求「关闭后仅只读」）。"""
    if not writes_enabled(override=override, today=today):
        raise FeatureDisabled(
            "运营管理中心写入口已关闭（ops_growth=false）；"
            "只读视图（运营配置 / 费率与 gas 预览 / 活动白名单）仍可用，"
            "开写需按 §21.6.4 重新评审开关"
        )


# --------------------------------------------------------------------------- 契约常量
#: 权限点（§7.10 只加权限点、不加角色）。写入口同时要求配置中心自己的 ``config.item.*``。
PERMISSIONS = frozenset({
    "growth.read",           # 只读视图
    "growth.config.write",   # 受控写入口（草稿 + 发布）
    "growth.fee.confirm",    # 费率 / 分润比例 >3000 bps 的二次确认（必须 ≠ 发起人）
})

#: 只使用 §6.3 / §6.3b 已登记码（不新造）。委托配置中心时用的是对方同族码。
ERROR_CODES_USED: dict[int, str] = {
    40001: "输入校验失败（超长 / 超限 / 缺字段）",
    40301: "无权限 / 自批自核等职责分离拒绝",
    40401: "对象不存在；开关关闭时的写入口",
    40901: "对象被待复核动作锁定",
    40902: "触发职责分离（SoD）或冷却期硬拒绝（含二次确认未完成）",
    42301: "break-glass 只读模式下拒绝写操作",
    42401: "需要 step-up 二次认证（≤5 分钟）",
}

ERROR_CODE_SOURCES: dict[int, str] = {
    40001: "产品文档 §6.3b 行 1",
    40301: "产品文档 §6.3b 行 3",
    40401: "产品文档 §6.3b 行 4（越权统一 404）",
    40901: "产品文档 §6.3b 行 5",
    40902: "产品文档 §6.3b 行 6（SoD / 冷却期硬拒绝）",
    42301: "产品文档 §6.3b 行 7",
    42401: "产品文档 §6.3b 行 8",
}

#: 费率 / 分润比例超过该值需决策人二次确认（§19.8.7、§21.14.4、§19 配置范围）。
SECOND_CONFIRM_THRESHOLD_BPS = 3000
#: 二次确认有效期：确认人点头 10 分钟内有效，过期重来。
CONFIRM_TTL = timedelta(minutes=10)
#: 批次边界：UTC 00:00。配置在「下一批」生效，不追溯已发出的记录。
BATCH_CUTOVER_UTC = time(0, 0)
#: 分润比例的上下限：平台 + 共享方 = 10000（§19.8.7）。
SHARE_TOTAL_BPS = 10000


# --------------------------------------------------------------------------- 配置键
@dataclass(frozen=True)
class GrowthKey:
    """本模块**新增登记**的运营配置键（键的元数据仍走 ``ops_center.KeyPolicy``）。"""

    key: str
    policy: KeyPolicy
    default: Any
    source: str

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "default": self.default,
            "value_type": self.policy.value_type,
            "risk": self.policy.risk,
            "domain": self.policy.domain,
            "description": self.policy.description,
            "source": self.source,
        }


#: 新增登记的键：默认值一律「关闭 / 空」，没有一个是默认打开的。
GROWTH_KEYS: dict[str, GrowthKey] = {
    "points.transfer_enabled": GrowthKey(
        key="points.transfer_enabled",
        policy=KeyPolicy(
            risk="P1", value_type="boolean", domain="growth",
            description="COP 平台内转让开关（默认关闭；开启后也只在平台内双边记账）",
            direction="none",
        ),
        default=False,
        source="§6.6.3 持有物的性质②（默认不可转让；后台开关打开后仅限平台内）",
    ),
    "growth.campaign_allowlist": GrowthKey(
        key="growth.campaign_allowlist",
        policy=KeyPolicy(
            risk="P2", value_type="json", domain="growth",
            description="活动白名单（只读视图；本单不提供写入口）",
            direction="none",
        ),
        default=[],
        source="§22.23 运营审计行（每个活动有 owner / 预算 / 起止）",
    ),
}

_bootstrapped_keys: set[str] = set()


def register_config_keys(registry: dict[str, KeyPolicy] | None = None) -> tuple[str, ...]:
    """把 `GROWTH_KEYS` 登记进配置键注册表（幂等；同名不同定义直接报错）。

    ``ops_center.KEY_POLICIES`` 是「配置键注册表」，§21.4.4 步 0 就是「注册 key」。
    本单写范围不含 ``ops_center.py``，所以用运行期登记而不是改文件；收编时把这里的
    ``KeyPolicy`` 原样搬进 ``KEY_POLICIES`` 即可（键定义只有一份，不会漂）。
    """
    registry = KEY_POLICIES if registry is None else registry
    absent = object()
    for key, spec in GROWTH_KEYS.items():
        existing = registry.get(key, absent)
        if existing is not absent and existing != spec.policy:
            raise RuntimeError(
                f"配置键 {key} 已有不同定义，拒绝覆盖（同一键只能有一个定义，冲突需 lead 裁决）："
                f"现有={existing!r} / 本模块={spec.policy!r}"
            )
        registry[key] = spec.policy
        _bootstrapped_keys.add(key)
    return tuple(sorted(GROWTH_KEYS))


register_config_keys()


def registered_keys() -> tuple[str, ...]:
    """本模块新增登记的配置键（用于接线核对与测试断言）。"""
    return tuple(sorted(GROWTH_KEYS))


# --------------------------------------------------------------------------- 控件清单
@dataclass(frozen=True)
class Control:
    """一个运营控件：读的是哪条配置、能不能写、默认值多少、依据在哪。"""

    name: str
    key: str
    label: str
    writable: bool
    default: Any
    source: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "control": self.name, "key": self.key, "label": self.label,
            "writable": self.writable, "default": self.default,
            "source": self.source, "note": self.note,
        }


CONTROLS: tuple[Control, ...] = (
    Control("points_transfer", "points.transfer_enabled", "COP 平台内转让开关",
            True, False, "§6.6.3②",
            "开启后也只在平台内双边记账，不改变结算与账本口径"),
    Control("platform_share", "treasury.platform_share_bps", "平台分润比例（bps）",
            True, 1500, "§19.8.7〔决策K3〕",
            f"平台 + 共享方 = {SHARE_TOTAL_BPS}；>{SECOND_CONFIRM_THRESHOLD_BPS} bps 需二次确认"),
    Control("gas_mode", "treasury.gas_fee_mode", "gas 承担方",
            True, "platform", "§19.8.7〔决策K3〕", "默认平台内扣"),
    Control("service_fee", "billing.service_fee_bps", "服务费率（bps）",
            False, 1500, "§21.14.4 / §21.15",
            "本单只做预览；改值走配置中心既有入口（DEV-0004）"),
    Control("campaign_allowlist", "growth.campaign_allowlist", "活动白名单",
            False, [], "§22.23 运营审计",
            "只读：活动白名单由运营活动单维护，本单不提供写入口"),
)

CONTROLS_BY_NAME = {c.name: c for c in CONTROLS}
CONTROLS_BY_KEY = {c.key: c for c in CONTROLS}


# --------------------------------------------------------------------------- 生效语义
def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def next_batch_cutover(now: datetime | None = None) -> datetime:
    """下一个批次边界（UTC 00:00，**严格晚于** ``now``）。"""
    moment = _as_utc(now or datetime.now(UTC))
    day = moment.replace(hour=BATCH_CUTOVER_UTC.hour, minute=0, second=0, microsecond=0)
    cut = day + timedelta(days=1)
    while cut <= moment:
        cut += timedelta(days=1)
    return cut


def effective_at_for(now: datetime | None = None, risk: str = "P1") -> datetime:
    """生效时刻 = 「≥ 现在 + 该风险级冷却期」的最近批次边界。

    这样既满足配置中心的冷却期（P0 24h / P1 60min / P2 无），又保证**只在新批次生效**，
    不会在批次中途把一个半批次的数据口径改掉。
    """
    moment = _as_utc(now or datetime.now(UTC))
    cooldown = config_center.PUBLISH_COOLDOWN.get(risk, timedelta(0))
    return next_batch_cutover(moment + cooldown)


def effect_semantics(now: datetime | None = None, risk: str = "P1") -> dict:
    """「下一批生效、不追溯」的机器可读口径。"""
    moment = _as_utc(now or datetime.now(UTC))
    cooldown = config_center.PUBLISH_COOLDOWN.get(risk, timedelta(0))
    effective_from = effective_at_for(moment, risk)
    return {
        "applies_to": "next_batch",
        "effective_from": effective_from.isoformat(timespec="seconds"),
        "retroactive": False,
        "cooldown_seconds": int(cooldown.total_seconds()),
        "history_policy": (
            "已结算 / 已发放的记录保留原 policy_version，不回溯重算（§18.11："
            "配置变更只影响新决策、不改历史口径）"
        ),
        "cutover_utc": BATCH_CUTOVER_UTC.strftime("%H:%M"),
    }


# --------------------------------------------------------------------------- 预览
def split_share_bps(platform_bps: int) -> dict:
    """分润拆分：平台 + 共享方 = 10000（§19.8.7）。"""
    if not isinstance(platform_bps, int) or isinstance(platform_bps, bool):
        raise BadRequest("platform_bps 必须是整数（bps）", details=[{"field": "platform_bps"}])
    if not 0 <= platform_bps <= SHARE_TOTAL_BPS:
        raise BadRequest(f"platform_bps 必须在 0–{SHARE_TOTAL_BPS} 之间",
                         details=[{"field": "platform_bps"}])
    return {
        "platform_bps": platform_bps,
        "provider_bps": SHARE_TOTAL_BPS - platform_bps,
        "platform_pct": f"{platform_bps / 100:.2f}%",
        "provider_pct": f"{(SHARE_TOTAL_BPS - platform_bps) / 100:.2f}%",
    }


def _delta_block(policy: KeyPolicy, proposed: Any, current: Any) -> dict | None:
    """量级门禁预演（与配置中心 ``max_delta`` 同口径，提前告一次）。"""
    if policy.max_delta is None or current is None:
        return None
    if not isinstance(proposed, (int, float)) or not isinstance(current, (int, float)):
        return None
    delta = abs(proposed - current)
    if delta > policy.max_delta:
        return {
            "gate": "max_delta",
            "delta": delta,
            "max_delta": policy.max_delta,
            "current": current,
            "detail": (f"单次变化 {delta}{policy.unit or ''} 超过 max-delta "
                       f"{policy.max_delta}{policy.unit or ''}（§21.13.1② 量级门禁）"),
        }
    return None


def _confirmation_prompt(key: str, value: int, *, current: int | None) -> dict:
    """二次确认提示：写清为什么拦、谁该确认、确认什么。"""
    return {
        "required": True,
        "threshold_bps": SECOND_CONFIRM_THRESHOLD_BPS,
        "key": key,
        "proposed_bps": value,
        "current_bps": current,
        "confirm_permission": "growth.fee.confirm",
        "must_differ_from_requester": True,
        "ttl_seconds": int(CONFIRM_TTL.total_seconds()),
        "prompt": (
            f"平台分润比例将设为 {value} bps（{value / 100:.2f}%），"
            f"超过 {SECOND_CONFIRM_THRESHOLD_BPS} bps 门槛：需决策人二次确认后才能提交发布"
            f"（§19.8.7 / §21.14.4）。确认人必须与发起人不同，且持有 growth.fee.confirm。"
        ),
        "source": "§19.8.7 · §21.14.4 · §19 配置范围（>3000 bps 需决策人二次确认）",
    }


def preview_share_bps(platform_bps: int, *, current: int | None = None,
                      now: datetime | None = None, risk: str = "P0") -> dict:
    """分润比例预览（纯函数）：拆分 + 量级门禁 + >3000 bps 二次确认提示 + 生效语义。"""
    policy = KEY_POLICIES["treasury.platform_share_bps"]
    split = split_share_bps(platform_bps)
    blocked = _delta_block(policy, platform_bps, current)
    confirmation = (_confirmation_prompt("treasury.platform_share_bps", platform_bps,
                                         current=current)
                    if platform_bps > SECOND_CONFIRM_THRESHOLD_BPS
                    else {"required": False, "threshold_bps": SECOND_CONFIRM_THRESHOLD_BPS,
                          "proposed_bps": platform_bps, "current_bps": current})
    return {
        "key": "treasury.platform_share_bps",
        "risk": policy.risk,
        "allowed": blocked is None,
        "blocked_by": blocked,
        "split": split,
        "delta": None if current is None else platform_bps - current,
        "range": {"min": policy.minimum, "max": policy.maximum,
                  "max_delta": policy.max_delta},
        "confirmation": confirmation,
        "effect": effect_semantics(now, risk),
        "unit": policy.unit,
    }


def preview_service_fee(bps: int, *, current: int | None = None,
                        now: datetime | None = None) -> dict:
    """服务费率预览（纯函数）。

    ``billing.service_fee_bps`` 的上限是 2000 bps，所以 >3000 的门槛**天然触发不到**；
    这里显式写出来，免得有人以为「没提示 = 没门槛」。
    """
    policy = KEY_POLICIES["billing.service_fee_bps"]
    if not isinstance(bps, int) or isinstance(bps, bool):
        raise BadRequest("bps 必须是整数", details=[{"field": "bps"}])
    if policy.maximum is not None and bps > policy.maximum:
        raise BadRequest(f"服务费率上限 {policy.maximum} bps（{policy.maximum / 100:.0f}%，§21.15）",
                         details=[{"field": "bps", "max": policy.maximum}])
    if policy.minimum is not None and bps < policy.minimum:
        raise BadRequest(f"服务费率下限 {policy.minimum} bps", details=[{"field": "bps"}])
    blocked = _delta_block(policy, bps, current)
    return {
        "key": "billing.service_fee_bps",
        "risk": policy.risk,
        "allowed": blocked is None,
        "blocked_by": blocked,
        "proposed_bps": bps,
        "current_bps": current,
        "delta": None if current is None else bps - current,
        "range": {"min": policy.minimum, "max": policy.maximum,
                  "max_delta": policy.max_delta},
        "confirmation": {
            "required": False,
            "threshold_bps": SECOND_CONFIRM_THRESHOLD_BPS,
            "note": (f"上限 {policy.maximum} bps < 门槛 {SECOND_CONFIRM_THRESHOLD_BPS} bps，"
                     "该键不会触发二次确认；本单只做预览，改值走配置中心既有入口"),
        },
        "effect": effect_semantics(now, policy.risk),
    }


def preview_gas_mode(mode: str, *, current: str | None = None,
                     now: datetime | None = None) -> dict:
    """gas 承担方预览（纯函数）。``platform`` = 平台内扣（默认）。"""
    policy = KEY_POLICIES["treasury.gas_fee_mode"]
    allowed = tuple(policy.enum or ())
    if mode not in allowed:
        raise BadRequest(f"gas 承担方必须是 {list(allowed)} 之一",
                         details=[{"field": "mode", "allowed": list(allowed)}])
    return {
        "key": "treasury.gas_fee_mode",
        "risk": policy.risk,
        "allowed": True,
        "blocked_by": None,
        "proposed": mode,
        "current": current,
        "enum": list(allowed),
        "changes": current is not None and current != mode,
        "effect": effect_semantics(now, policy.risk),
        "note": "切换承担方不改变已发批次的分润结果（不追溯）",
    }


def preview_points_transfer(enabled: bool, *, current: bool | None = None,
                            now: datetime | None = None) -> dict:
    """转让开关预览（纯函数）：开/关都只影响新转让，已发生的转让保留。"""
    if not isinstance(enabled, bool):
        raise BadRequest("enabled 必须是布尔", details=[{"field": "enabled"}])
    policy = KEY_POLICIES["points.transfer_enabled"]
    return {
        "key": "points.transfer_enabled",
        "risk": policy.risk,
        "allowed": True,
        "blocked_by": None,
        "proposed": enabled,
        "current": current,
        "changes": current is not None and current != enabled,
        "capabilities": dict(CLIENT_CAPABILITIES),
        "effect": effect_semantics(now, policy.risk),
        "note": "开启后仅允许平台内转让；关闭即刻禁止新转让，已转让的不回溯扣回",
    }


def client_capabilities() -> dict:
    """客户侧能力位（与 ``app.points.capabilities`` 同口径，§6.6.3 / 〔决策K4〕）。"""
    return dict(CLIENT_CAPABILITIES)


#: 客户侧只有三样东西（§6.6.1）：服务预付款（USD）· 拉新奖励积分（COP）· 账单 / Invoice。
CLIENT_CAPABILITIES: dict[str, Any] = {
    "settlement_asset": "COP",
    "client_cash_account": False,
    "customer_cash_transfer": False,
    "custodial": False,
    "cop_spend_targets": ["service_fee_offset", "capacity_credit", "merchandise", "donation"],
    "cop_transfer_scope": "platform_internal_only",
    "source": "§6.6.1 · §6.6.3 · 〔决策K4〕",
}


# --------------------------------------------------------------------------- S1 范围
#: §22.0.1：运营中心 S1 只做积分与邀请；增长类（分群 / 促销 / 实验 / 渠道）后置。
S1_SCOPE: tuple[dict[str, Any], ...] = (
    {"module": "积分运营", "s1": True, "why": "§22.0.1 S1 只做积分与邀请；先资金与安全"},
    {"module": "拉新与邀请", "s1": True, "why": "§22.0.1 同上（4% / 12 个月，单层）"},
    {"module": "用户分群", "s1": False, "why": "增长类后置"},
    {"module": "优惠与促销", "s1": False, "why": "增长类后置；不作用于资金链路"},
    {"module": "内容与通知", "s1": False, "why": "增长类后置"},
    {"module": "实验平台", "s1": False, "why": "增长类后置；资金 / 费率 / 风控阈值不做实验"},
    {"module": "数据分析", "s1": False, "why": "增长类后置"},
    {"module": "客户成功", "s1": False, "why": "增长类后置"},
    {"module": "渠道与伙伴", "s1": False, "why": "增长类后置；返佣只走合同与账本"},
    {"module": "运营审计", "s1": True, "why": "S1 必须有：每个活动有 owner / 预算 / 起止（§22.23）"},
)


def s1_scope() -> list[dict]:
    return [dict(row) for row in S1_SCOPE]


# --------------------------------------------------------------------------- 命名红线
#: 命名红线（§18.12 第一段 · §6.6.3 · §9）：本模块只做**引用**，不复述禁用词本身。
#: 词表和 CI 门禁的 spec-lint 关键词表同源（spec/README §3：关键词表在 job 内），
#: 所以词表写在测试里，生产代码与文档一个字都不出现。
NAMING_POLICY: dict[str, str] = {
    "source": "§18.12 第一段（永久禁用）· §6.6.3（持有物的性质）· §9（COP 定位）",
    "rule": ("不得把 COP 描述成任何可交易 / 可兑换 / 可转出的价值载体；"
             "客户侧只有服务预付款、拉新奖励积分与账单三类东西（§6.6.1）"),
    "scanner": "naming_scan(terms, *texts)",
    "enforced_by": "tests/test_ops_growth.py::TestNaming（词表与 CI 门禁同源）",
}


def naming_scan(terms: Iterable[str], *texts: str) -> list[dict]:
    """通用禁用词扫描：返回命中位置（第几段 / 行号 / 词 / 上下文）。

    ``terms`` 由调用方给（测试 / CI），模块自身不内置任何禁用词。
    """
    wanted = [str(t) for t in terms if str(t)]
    out: list[dict] = []
    for index, text in enumerate(texts):
        for lineno, line in enumerate(str(text).splitlines(), start=1):
            for term in wanted:
                if term in line:
                    out.append({"text_index": index, "line": lineno, "term": term,
                                "context": line.strip()[:80]})
    return out


# --------------------------------------------------------------------------- 二次确认
class SecondConfirmationRequired(Conflict):
    """费率 / 分润比例超过门槛时的「二次确认提示」（40902：SoD 硬拒绝）。

    复用已登记码（§6.3b 行 6），不新造；``reason_code`` 让调用方能把这提示与
    「冷却期未到」区分开。
    """

    def __init__(self, prompt: Mapping[str, Any], *, message: str | None = None):
        super().__init__(message or str(prompt.get("prompt") or "需要二次确认"),
                         code=40902, details=[dict(prompt)])
        self.reason_code = "R-SECOND-CONFIRM"
        self.prompt = dict(prompt)


@dataclass(frozen=True)
class FeeConfirmation:
    """二次确认凭据：确认人主体 + 确认时刻 + 备注。确认人必须 ≠ 发起人。"""

    principal: Any
    at: datetime
    note: str = ""

    @property
    def actor(self) -> str:
        return str(getattr(self.principal, "actor", "") or "")


def _check_confirmation(principal: Any, prompt: Mapping[str, Any],
                        confirm: FeeConfirmation | None, *, now: datetime) -> dict:
    """校验二次确认；不满足就抛提示（40902），不吞不猜。"""
    if confirm is None:
        raise SecondConfirmationRequired(prompt)
    actor = str(getattr(principal, "actor", "") or "")
    if not confirm.actor or confirm.actor == actor:
        raise Forbidden(
            "二次确认必须有第二个人：确认人不得等于发起人（职责分离，§21.4.3）",
            details=[{"field": "confirm", "requester": actor}],
        )
    if not getattr(confirm.principal, "has", lambda _p: False)("growth.fee.confirm"):
        raise Forbidden(
            "二次确认人缺少权限点 growth.fee.confirm",
            details=[{"field": "confirm", "permission": "growth.fee.confirm"}],
        )
    at = _as_utc(confirm.at)
    if abs(_as_utc(now) - at) > CONFIRM_TTL:
        raise SecondConfirmationRequired(
            prompt, message=(f"二次确认已过期（确认于 {at.isoformat()}，有效期 "
                             f"{int(CONFIRM_TTL.total_seconds())}s），请重新确认"),
        )
    return {
        "confirmed_by": confirm.actor,
        "confirmed_at": at.isoformat(timespec="seconds"),
        "note": confirm.note,
        "threshold_bps": prompt.get("threshold_bps"),
        "must_differ_from_requester": True,
    }


# --------------------------------------------------------------------------- 只读视图
def _require_perm(principal: Any, permission: str) -> None:
    checker = getattr(principal, "has", None)
    if checker is None or not checker(permission):
        raise Forbidden(f"缺少权限点 {permission}", details=[{"permission": permission}])


def _policy_of(key: str) -> KeyPolicy:
    policy = KEY_POLICIES.get(key)
    if policy is None:
        raise NotFound(f"配置键未登记：{key}")
    return policy


def _effective(principal: Any, control: Control, *, now: datetime,
               name: str | None = None) -> dict:
    """读一条配置的当前状态（经配置中心；读不到就用声明的默认值，并标明来源）。"""
    try:
        item = config_center.get_config_item(principal, control.key, now=now, name=name)
    except config_center.NotFound:
        policy = _policy_of(control.key)
        return {
            "key": control.key, "state": "default", "value": control.default,
            "live_value": control.default, "pending_value": None,
            "version": None, "value_type": policy.value_type, "risk": policy.risk,
            "unit": policy.unit, "updated_at": None, "updated_by": None,
            "source": "声明默认值（配置中心暂无该键的版本）",
        }
    state = item.get("state")
    active = state == "active"
    return {
        "key": control.key, "state": state, "value": item.get("value"),
        # live_value = 现在真正生效的值；pending_value = 已提发布单但还没到点的值。
        # 两者分开，读视图才不会把「草稿」当成「已生效」（下一批生效、不追溯）。
        "live_value": item.get("value") if active else control.default,
        "pending_value": None if active else item.get("value"),
        "version": item.get("version"), "value_type": item.get("value_type"),
        "risk": item.get("risk_level"), "unit": item.get("unit"),
        "updated_at": item.get("updated_at"), "updated_by": item.get("updated_by"),
        "digest": item.get("digest"),
        "source": "配置中心",
    }


def growth_overview(principal: Any, *, now: datetime | None = None,
                    name: str | None = None) -> dict:
    """运营配置只读总览：控件清单 + 当前生效值 + 预览 + 能力位 + 命名红线。

    需要 ``growth.read`` + ``config.item.read``（读的是配置中心的权威值，不另开一份读模型）。
    """
    _require_perm(principal, "growth.read")
    moment = _as_utc(now or datetime.now(UTC))
    rows: list[dict] = []
    for control in CONTROLS:
        state = _effective(principal, control, now=moment, name=name)
        rows.append({**control.as_dict(), "state": state["state"], "value": state["value"],
                     "live_value": state["live_value"],
                     "pending_value": state["pending_value"],
                     "version": state["version"], "value_type": state["value_type"],
                     "risk": state["risk"], "unit": state["unit"],
                     "updated_at": state["updated_at"], "updated_by": state["updated_by"],
                     "value_source": state["source"]})

    by_key = {row["key"]: row for row in rows}
    current_share = by_key["treasury.platform_share_bps"]["live_value"]
    current_fee = by_key["billing.service_fee_bps"]["live_value"]
    current_gas = by_key["treasury.gas_fee_mode"]["live_value"]
    current_transfer = by_key["points.transfer_enabled"]["live_value"]
    return {
        "generated_at": moment.isoformat(timespec="seconds"),
        "flag": {"name": FLAG_NAME, "enabled": flag_enabled(),
                 "spec": {k: flag_spec()[k] for k in ("owner", "expire_at", "default")}},
        "controls": rows,
        "previews": {
            "platform_share": preview_share_bps(
                current_share if isinstance(current_share, int) else 1500,
                current=current_share if isinstance(current_share, int) else None,
                now=moment),
            "service_fee": preview_service_fee(
                current_fee if isinstance(current_fee, int) else 1500,
                current=current_fee if isinstance(current_fee, int) else None, now=moment),
            "gas_mode": preview_gas_mode(
                current_gas if current_gas in ("platform", "provider") else "platform",
                current=current_gas, now=moment),
            "points_transfer": preview_points_transfer(
                bool(current_transfer), current=current_transfer, now=moment),
        },
        "capabilities": client_capabilities(),
        "s1_scope": s1_scope(),
        "naming_policy": dict(NAMING_POLICY),
        "meta": {"read_only": True, "operation_id": None, "spec_status": "pending",
                 "note": "只读视图；接线前先改 spec（§21.12.2）"},
    }


def campaign_allowlist(principal: Any, *, now: datetime | None = None,
                       name: str | None = None) -> dict:
    """活动白名单（**只读**）：本单不提供写入口。"""
    _require_perm(principal, "growth.read")
    moment = _as_utc(now or datetime.now(UTC))
    control = CONTROLS_BY_NAME["campaign_allowlist"]
    state = _effective(principal, control, now=moment, name=name)
    entries = state["live_value"] if isinstance(state["live_value"], list) else []
    pending = state["pending_value"] if isinstance(state["pending_value"], list) else None
    return {
        "key": control.key,
        "entries": entries,
        "count": len(entries),
        "pending_entries": pending,
        "state": state["state"],
        "version": state["version"],
        "updated_at": state["updated_at"],
        "writable": False,
        "note": "只读视图：活动白名单由运营活动单维护（每活动有 owner / 预算 / 起止，§22.23）",
        "generated_at": moment.isoformat(timespec="seconds"),
    }


def recent_changes(principal: Any, *, key: str | None = None, limit: int = 10,
                   now: datetime | None = None, name: str | None = None) -> dict:
    """最近的运营配置变更（来自配置中心审计链，验收④的证据面；只读）。"""
    _require_perm(principal, "growth.read")
    wanted = [key] if key else [c.key for c in CONTROLS]
    entries: list[dict] = []
    for each in wanted:
        page = config_center.search_audit(principal, key=each, limit=limit, name=name)
        for row in (page.get("data") or []):
            entries.append({
                "key": row.get("key"), "at": row.get("at"), "actor": row.get("actor"),
                "action": row.get("action"), "outcome": row.get("outcome"),
                "version": row.get("version"), "reason_code": row.get("reason_code"),
                "reason": row.get("reason"), "seq": row.get("seq"),
            })
    entries.sort(key=lambda r: (r["at"] or "", r["seq"] or 0), reverse=True)
    return {
        "entries": entries[:limit],
        "count": len(entries[:limit]),
        "total_scanned": len(entries),
        "source": "配置中心 config_audit 哈希链（只追加）",
        "generated_at": _as_utc(now or datetime.now(UTC)).isoformat(timespec="seconds"),
    }


# --------------------------------------------------------------------------- 写入口
def _require_reason(reason: Any) -> str:
    text = str(reason or "").strip()
    if len(text) < 4:
        raise BadRequest("reason 必填且长度 ≥4（变更必须留下为什么）",
                         details=[{"field": "reason"}])
    return text


def _draft(principal: Any, key: str, value: Any, *, reason: str, ticket: str | None,
           effective_at: datetime, now: datetime, name: str | None) -> dict:
    """建配置草稿（**经配置中心**，本模块不写库）。"""
    policy = _policy_of(key)
    body: dict[str, Any] = {
        "value": value,
        "value_type": policy.value_type,
        "reason": reason,
        "effective_at": effective_at.isoformat(timespec="seconds"),
    }
    if ticket:
        body["ticket"] = ticket
    return config_center.create_config_draft(principal, key, body, now=now, name=name)


def _publish(principal: Any, key: str, version: int, *, reason: str, ticket: str | None,
             effective_at: datetime, now: datetime, name: str | None) -> dict:
    """发起发布单（**经配置中心**）：窗口 / 冻结 / 冷却 / 锁都由配置中心判定。"""
    body: dict[str, Any] = {
        "version": version,
        "reason": reason,
        "effective_at": effective_at.isoformat(timespec="seconds"),
    }
    if ticket:
        body["ticket"] = ticket
    return config_center.publish_config_item(principal, key, body, now=now, name=name)


def _write_result(*, control: Control, preview: Mapping[str, Any],
                  draft: Mapping[str, Any] | None, publish: Mapping[str, Any] | None,
                  confirmation: Mapping[str, Any] | None, effective_at: datetime,
                  now: datetime) -> dict:
    return {
        "control": control.name,
        "key": control.key,
        "state": "published" if publish else "drafted",
        "preview": dict(preview),
        "confirmation": dict(confirmation) if confirmation else {"required": False},
        "draft": draft,
        "publish": publish,
        "effect": {**effect_semantics(now, _policy_of(control.key).risk),
                   "effective_from": effective_at.isoformat(timespec="seconds")},
        "audit": {
            "draft": (draft or {}).get("audit"),
            "publish": (publish or {}).get("audit"),
            "chain": "config_audit（配置中心哈希链，与业务变更同事务）",
        },
    }


def set_points_transfer_enabled(principal: Any, enabled: bool, *, reason: str,
                                ticket: str | None = None, publish: bool = True,
                                now: datetime | None = None, current: bool | None = None,
                                effective_at: datetime | None = None,
                                name: str | None = None,
                                flag_override: bool | None = None) -> dict:
    """受控写入口：COP 平台内转让开关。

    写入路径固定为「配置中心草稿 →（可选）发布单」，**不直写积分策略表**；
    策略落地由消费方在发布生效时调用 ``app.points.update_policy``（接线点见文档 §6.2）。
    """
    require_writes_enabled(override=flag_override)
    _require_perm(principal, "growth.config.write")
    moment = _as_utc(now or datetime.now(UTC))
    control = CONTROLS_BY_NAME["points_transfer"]
    preview = preview_points_transfer(enabled, current=current, now=moment)
    eff = _as_utc(effective_at) if effective_at else effective_at_for(moment, preview["risk"])

    draft = _draft(principal, control.key, enabled, reason=_require_reason(reason),
                   ticket=ticket, effective_at=eff, now=moment, name=name)
    issued = None
    if publish:
        issued = _publish(principal, control.key, draft["version"], reason=_require_reason(reason),
                          ticket=ticket, effective_at=eff, now=moment, name=name)
    return _write_result(control=control, preview=preview, draft=draft, publish=issued,
                         confirmation=None, effective_at=eff, now=moment)


def set_platform_share_bps(principal: Any, platform_bps: int, *, reason: str,
                           ticket: str | None = None, confirm: FeeConfirmation | None = None,
                           publish: bool = True, now: datetime | None = None,
                           current: int | None = None,
                           effective_at: datetime | None = None,
                           name: str | None = None,
                           flag_override: bool | None = None) -> dict:
    """受控写入口：平台分润比例（bps）。**>3000 bps 必须先拿到第二人的确认**。"""
    require_writes_enabled(override=flag_override)
    _require_perm(principal, "growth.config.write")
    moment = _as_utc(now or datetime.now(UTC))
    control = CONTROLS_BY_NAME["platform_share"]
    preview = preview_share_bps(platform_bps, current=current, now=moment)
    if not preview["allowed"]:
        raise BadRequest(preview["blocked_by"]["detail"],
                         details=[preview["blocked_by"]])
    confirmation = None
    if preview["confirmation"]["required"]:
        confirmation = _check_confirmation(principal, preview["confirmation"], confirm,
                                           now=moment)
    if _policy_of(control.key).risk == "P0" and not ticket:
        raise BadRequest("分润比例属 P0 配置：必须带 ticket（变更单 / 影响面分析单，§21.4.1）",
                         details=[{"field": "ticket"}])

    eff = _as_utc(effective_at) if effective_at else effective_at_for(moment, preview["risk"])
    draft_reason = _require_reason(reason)
    if confirmation:
        draft_reason = (f"{draft_reason}｜二次确认：{confirmation['confirmed_by']} "
                        f"@{confirmation['confirmed_at']}")
    draft = _draft(principal, control.key, platform_bps, reason=draft_reason, ticket=ticket,
                   effective_at=eff, now=moment, name=name)
    issued = None
    if publish:
        issued = _publish(principal, control.key, draft["version"], reason=draft_reason,
                          ticket=ticket, effective_at=eff, now=moment, name=name)
    return _write_result(control=control, preview=preview, draft=draft, publish=issued,
                         confirmation=confirmation, effective_at=eff, now=moment)


def set_gas_mode(principal: Any, mode: str, *, reason: str, ticket: str | None = None,
                 publish: bool = True, now: datetime | None = None,
                 current: str | None = None, effective_at: datetime | None = None,
                 name: str | None = None, flag_override: bool | None = None) -> dict:
    """受控写入口：gas 承担方（``platform`` / ``provider``）。"""
    require_writes_enabled(override=flag_override)
    _require_perm(principal, "growth.config.write")
    moment = _as_utc(now or datetime.now(UTC))
    control = CONTROLS_BY_NAME["gas_mode"]
    preview = preview_gas_mode(mode, current=current, now=moment)
    if _policy_of(control.key).risk == "P0" and not ticket:
        raise BadRequest("gas 承担方属 P0 配置：必须带 ticket（§21.4.1）",
                         details=[{"field": "ticket"}])
    eff = _as_utc(effective_at) if effective_at else effective_at_for(moment, preview["risk"])
    draft = _draft(principal, control.key, mode, reason=_require_reason(reason), ticket=ticket,
                   effective_at=eff, now=moment, name=name)
    issued = None
    if publish:
        issued = _publish(principal, control.key, draft["version"], reason=_require_reason(reason),
                          ticket=ticket, effective_at=eff, now=moment, name=name)
    return _write_result(control=control, preview=preview, draft=draft, publish=issued,
                         confirmation=None, effective_at=eff, now=moment)


# --------------------------------------------------------------------------- 系统动作
def apply_due(*, now: datetime | None = None, name: str | None = None) -> dict:
    """推进到点的发布单（系统动作，**不是**管理面操作）。

    本模块不自己改配置状态，直接把配置中心 ``advance_publish_requests`` 的结论转出来；
    这也是「下一批生效」的落地时刻：到了 ``effective_at`` 才真正切到新值。
    """
    require_writes_enabled()
    moment = _as_utc(now or datetime.now(UTC))
    result = config_center.advance_publish_requests(now=moment, name=name)
    return {"at": moment.isoformat(timespec="seconds"), **result,
            "source": "config_center.advance_publish_requests"}
