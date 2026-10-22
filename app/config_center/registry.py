# SPDX-License-Identifier: Apache-2.0
"""十域配置键注册表（T1「schema 注册」；§21.1.1 / §21.3.1 / §21.3.5）。

一个 ``ConfigKey`` = 一条**契约**，不是一条数据：键名、类型、单位、范围、风险级、owner、
消费者声明、危险/敏感标记、过期要求、JSON Schema（含八个 ``x-djb-*`` 扩展关键字）。
运行值在 ``config_versions``（T2 存储），元数据在 ``config_items``（由 :func:`sync_items`
把本表落库）；本文件是**唯一声明源**——改键 = 改这里 + 过评审，不允许后台直接改库。

十个配置域严格按 §21.1.1（flag / billing / risk / quota+pool / routing / notify / content /
treasury / partner / exp），每个域至少注册一个键（03-facts「十域全覆盖」）。另外两个
**辅助命名空间**不是第十一、十二个域，而是：

* ``config.`` —— M10 自己管理自己的键（M10 §8.1 五键），01-ownership §4 把 ``config.`` 分给 M10；
* ``points.`` —— 01-ownership §4 把 ``points.`` 分给 M07，但默认值是 M10 的交付物
  （03-facts §9；CR-5 / CR-6 裁决「points.transfer_* 保留，默认 false，仅 admin」）。

默认值纪律（03-facts §13 / _boundary-checks §1.5）：
  · 有 facts 的一律**运行时从 facts 读**（``default_source="facts:..."``），不在代码里写数字；
  · 规格里明确但 facts 没有的（例如 ``billing.fee_cap_pct`` 的 ≤20 承诺上限）标
    ``spec:...``，并在证据文件 §风险 里登记「应补 facts」的 CR；
  · 开关类只有「安全默认关闭」一种缺省（``policy:switch-default-off``）；
  · 确实没有声明默认的（私有仓注入 / M10 生成 / 域 owner 未定）用 ``MISSING`` +
    ``default_source="unset:..."``，:func:`app.config_center.validators.check_publishable`
    在发布前拒绝（§21.2.3：default_value 缺失 = schema 校验失败）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable, Iterator

from . import facts as facts_mod
from . import units
from .errors import UnknownKey, ValidationFailed

__all__ = [
    "MISSING",
    "Missing",
    "Domain",
    "AuxNamespace",
    "ConfigKey",
    "Registry",
    "DOMAINS",
    "AUX_NAMESPACES",
    "FORBIDDEN_KEY_PATTERNS",
    "KEY_PATTERN",
    "RISK_LEVELS",
    "SCOPES",
    "load",
    "forbidden_reason",
]

#: 风险级（M10 §5 枚举；加值 = MINOR）
RISK_LEVELS: tuple[str, ...] = ("P0", "P1", "P2")
#: 作用域（M10 §5 枚举；S1 只有 global，region/tenant 由 S2 灰度/覆盖使用）
SCOPES: tuple[str, ...] = ("global", "region", "tenant")
#: key 全名格式（§21.1.3 / spec path 参数同一正则）
KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")


class Missing:
    """「没有声明默认值」的哨兵（区别于 ``None``：``None`` 是一个合法 JSON 值）。"""

    __slots__ = ()
    _instance: "Missing | None" = None

    def __new__(cls) -> "Missing":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:            # pragma: no cover - 仅调试可见
        return "<unset>"

    def __bool__(self) -> bool:
        return False


MISSING = Missing()


# ───────────────────────────────────────────────────────────── 域名与命名空间
@dataclass(frozen=True)
class Domain:
    """一个配置域（§21.1.1）：域名、命名空间前缀、发起 / 审批角色组、默认风险级。"""

    code: str
    title: str
    namespaces: tuple[str, ...]
    proposer_roles: tuple[str, ...]
    approver_roles: tuple[str, ...]
    default_risk: str
    public: bool
    source: str = "spec:§21.1.1"


@dataclass(frozen=True)
class AuxNamespace:
    """辅助命名空间：不是第十一域，只是由本模块承载默认值的另一个 owner 的命名空间。"""

    namespace: str
    title: str
    owner_roles: tuple[str, ...]
    default_risk: str
    source: str
    public: bool = True


#: 十个配置域（§21.1.1，顺序与产品表一致）
DOMAINS: tuple[Domain, ...] = (
    Domain("flag", "产品开关", ("flag",), ("OPS",), ("OPS", "SUPER"), "P1", True),
    Domain("billing", "计费与价格", ("billing",), ("FIN",), ("FIN", "SUPER"), "P0", True),
    Domain("risk", "风控与违规治理", ("risk",), ("RISK",), ("RISK", "AUDIT"), "P0", False),
    Domain("quota_pool", "配额与预留池", ("quota", "pool"), ("OPS",), ("OPS", "FIN"), "P0", True),
    Domain("routing", "路由与调度", ("routing",), ("OPS",), ("OPS", "FAIRNESS_REVIEW"), "P1", True),
    Domain("notify", "通知模板", ("notify",), ("OPS",), ("CS", "OPS"), "P2", True),
    Domain("content", "文案与词表", ("content",), ("OPS",), ("OPS", "AUDIT"), "P2", True),
    Domain("treasury", "支付与 treasury 限额", ("treasury",), ("FIN",), ("FIN", "SUPER"), "P0", False),
    Domain("partner", "伙伴与渠道", ("partner",), ("OPS",), ("OPS", "FIN"), "P1", False),
    Domain("exp", "实验", ("exp",), ("OPS",), ("OPS", "AUDIT"), "P2", True),
)

#: 辅助命名空间（config = M10 自管；points = M07 命名空间、M10 承载默认值）
AUX_NAMESPACES: tuple[AuxNamespace, ...] = (
    AuxNamespace("config", "配置中心自管键（M10 §8.1）", ("OPS",), "P0",
                 "01-ownership §4（M10）+ M10 §8.1", public=True),
    AuxNamespace("points", "COP 转让与兑换（M07 命名空间，默认值归 M10）", ("OPS",), "P0",
                 "01-ownership §4（M07）+ facts §9 + CR-5/CR-6", public=True),
)

#: 危险键黑名单（§21.3.5「不提供控制台编辑入口」）：正则 → (类别, 判据)。
#: 命中即 47004，**不看是否注册**——「关掉地基不是配置，是拆除」。
FORBIDDEN_KEY_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(^|\.)(audit_enabled|audit_disabled|skip_audit|audit_mutable)$"), "审计与账本行为",
     "关闭 / 改写审计"),
    (re.compile(r"(^|\.)(ledger_mutable|ledger_editable|journal_editable|merkle_enabled|merkle_disabled)$"),
     "审计与账本行为", "账本可改 / Merkle 锚定开关"),
    (re.compile(r"(^|\.)(mfa_required|mfa_enabled|mfa_disabled|skip_mfa)$"), "底线开关", "关闭 MFA"),
    (re.compile(r"(^|\.)(skip_approval|skip_dual_control|skip_step_up|approval_required)$"), "底线开关",
     "跳过双人复核 / step-up"),
    (re.compile(r"(^|\.)(private_key|secret_key|mnemonic|password|hmac_key|api_secret|signing_key)$"),
     "密钥与凭据", "配置 ≠ 密钥，只能存 secret_ref"),
    (re.compile(r"(^|\.)(image_tag|plugin_dir|entrypoint|container_image)$"), "代码加载路径",
     "属代码发布，不得用配置绕开制品签名"),
    (re.compile(r"^(slo|price_page)\."), "对外承诺数值", "公开承诺改动需公告与 RFC"),
)


def forbidden_reason(key: str) -> str | None:
    """key 命中危险键黑名单时返回「类别：判据」，否则 None。"""
    for pattern, category, reason in FORBIDDEN_KEY_PATTERNS:
        if pattern.search(key):
            return f"{category}：{reason}"
    return None


# ───────────────────────────────────────────────────────────── 键
@dataclass(frozen=True)
class ConfigKey:
    """一条键契约。字段与 §21.3.1 的 schema 关键字一一对应。"""

    key: str
    domain: str
    value_type: str
    unit: str
    default: Any
    default_source: str
    risk: str
    owner: str
    description: str = ""
    minimum: Any = None
    maximum: Any = None
    enum: tuple[str, ...] | None = None
    pattern: str | None = None
    max_length: int | None = None
    multiple_of: int | None = None
    max_delta: int | None = None            # x-djb-max-delta（单位随 unit，pct 即 pp）
    escalate_above: Any = None              # 超过则强制升级审批（P1 → P0 流程，§21.3.2）
    dangerous: bool = False                 # x-djb-dangerous：只读展示，API 403（INV-06）
    sensitive: bool = False                 # 值默认脱敏（§21.10.2）
    secret_ref_only: bool = False           # x-djb-secret-ref：只接受引用结构（INV-05）
    generated: bool = False                 # 由 M10 生成，不接受人工写（policy_version）
    legacy_alias_of: str | None = None      # 旧键只读兼容（03-facts §9 命名收口）
    expire_required: bool = False           # x-djb-expire-required：开关/实验必带 expire_at
    tighten_only: bool = False              # x-djb-tighten-only：只允许收紧
    kill_switch: bool = False               # x-djb-kill-switch：允许 kill switch 收紧
    direction: str = "none"                 # 收紧方向：reduce / raise / none
    consumers: tuple[str, ...] = ()         # x-djb-consumers：影响面分析来源
    allow_scope: tuple[str, ...] = ("global",)
    schema_version: int = 1

    # ── 派生视图 ────────────────────────────────────────────
    @property
    def namespace(self) -> str:
        return self.key.split(".", 1)[0]

    @property
    def schema_ref(self) -> str:
        """§21.3.1：schema 本身也版本化，``schema_ref = namespace.param@v3``。"""
        return f"{self.key}@v{self.schema_version}"

    @property
    def publishable(self) -> bool:
        """有声明默认值才允许发布（§21.2.3：default_value 缺失 = schema 校验失败）。"""
        return self.default is not MISSING

    def schema_body(self) -> dict[str, Any]:
        """JSON Schema 2020-12 + 八个 ``x-djb-*`` 扩展关键字（§21.3.1）。"""
        type_map = {
            "integer": "integer", "number": "number", "string": "string",
            "boolean": "boolean", "json": ["object", "array"],
        }
        body: dict[str, Any] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": self.schema_ref,
            "title": self.description or self.key,
            "type": type_map[self.value_type],
            "x-djb-unit": self.unit,
            "x-djb-consumers": list(self.consumers),
            "x-djb-tighten-only": self.tighten_only,
            "x-djb-kill-switch": self.kill_switch,
            "x-djb-secret-ref": self.secret_ref_only,
            "x-djb-public": _domain_public(self),
            "x-djb-expire-required": self.expire_required,
        }
        if self.publishable and self.default is not None:
            body["default"] = self.default
        if self.minimum is not None:
            body["minimum"] = self.minimum
        if self.maximum is not None:
            body["maximum"] = self.maximum
        if self.enum:
            body["enum"] = list(self.enum)
        if self.pattern:
            body["pattern"] = self.pattern
        if self.max_length is not None:
            body["maxLength"] = self.max_length
        if self.multiple_of is not None:
            body["multipleOf"] = self.multiple_of
        if self.max_delta is not None:
            body["x-djb-max-delta"] = {
                "abs": self.max_delta,
                "unit": "pp" if self.unit == "pct" else self.unit,
            }
        if self.escalate_above is not None:
            body["x-djb-escalate-above"] = self.escalate_above
        return body

    def as_metadata(self) -> dict[str, Any]:
        """落 ``config_items`` 用的元数据（JSON 可存；MISSING 转 None + 来源字符串）。"""
        return {
            "namespace": self.namespace,
            "key": self.key,
            "value_type": self.value_type,
            "unit": self.unit,
            "schema_ref": self.schema_ref,
            "schema_body": self.schema_body(),
            "risk_level": self.risk,
            "owner_role": self.owner,
            "allow_scope": list(self.allow_scope),
            "consumers": list(self.consumers),
            "dangerous": self.dangerous,
            "sensitive": self.sensitive,
            "secret_ref_only": self.secret_ref_only,
            "default_value": None if self.default is MISSING else self.default,
            "default_source": self.default_source,
            "expire_required": self.expire_required,
        }


def _domain_public(item: "ConfigKey") -> bool:
    for domain in DOMAINS:
        if domain.code == item.domain:
            return domain.public
    for aux in AUX_NAMESPACES:
        if aux.namespace == item.domain:
            return aux.public
    return False


# ───────────────────────────────────────────────────────────── 注册表
@dataclass(frozen=True)
class Registry:
    """不可变注册表：十域 + 辅助命名空间 + 全部键。"""

    domains: tuple[Domain, ...]
    aux: tuple[AuxNamespace, ...]
    keys: tuple[ConfigKey, ...]
    _index: dict[str, ConfigKey] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_index", {item.key: item for item in self.keys})

    # ── 查询 ────────────────────────────────────────────────
    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._index

    def __iter__(self) -> Iterator[ConfigKey]:
        return iter(self.keys)

    def __len__(self) -> int:
        return len(self.keys)

    def get(self, key: str) -> ConfigKey | None:
        return self._index.get(key)

    def require(self, key: str) -> ConfigKey:
        item = self._index.get(key)
        if item is None:
            raise UnknownKey(f"未注册的配置键：{key!r}（§21.3.4 第①道：未知键一律拒绝）", key=key)
        return item

    def by_domain(self, code: str) -> tuple[ConfigKey, ...]:
        return tuple(item for item in self.keys if item.domain == code)

    def namespaces(self) -> tuple[str, ...]:
        return tuple(domain_ns for domain in self.domains for domain_ns in domain.namespaces) + tuple(
            aux.namespace for aux in self.aux)

    def domain_of(self, key: str) -> Domain | AuxNamespace:
        namespace = key.split(".", 1)[0]
        for domain in self.domains:
            if namespace in domain.namespaces:
                return domain
        for aux in self.aux:
            if aux.namespace == namespace:
                return aux
        raise UnknownKey(f"命名空间未登记：{namespace!r}", key=key)

    def dangerous_keys(self) -> tuple[ConfigKey, ...]:
        return tuple(item for item in self.keys if item.dangerous)

    def stats(self) -> dict[str, Any]:
        by_risk = {risk: 0 for risk in RISK_LEVELS}
        for item in self.keys:
            by_risk[item.risk] += 1
        return {
            "domains": len(self.domains),
            "aux_namespaces": len(self.aux),
            "keys": len(self.keys),
            "by_risk": by_risk,
            "publishable": sum(1 for item in self.keys if item.publishable),
            "dangerous": sum(1 for item in self.keys if item.dangerous),
            "sensitive": sum(1 for item in self.keys if item.sensitive),
            "per_domain": {domain.code: len(self.by_domain(domain.code)) for domain in self.domains},
            "per_aux": {aux.namespace: len(self.by_domain(aux.namespace)) for aux in self.aux},
        }


# ───────────────────────────────────────────────────────────── 构建
def _key(**kwargs: Any) -> ConfigKey:
    return ConfigKey(**kwargs)


def _build(facts_path_str: str) -> Registry:  # noqa: ARG001 - 仅用于 lru_cache 键
    """按 facts 当前值构建注册表（facts 变了，默认值跟着变）。"""
    cooldowns = facts_mod.cooldowns()
    window = facts_mod.publish_window()
    rollback_modes = facts_mod.p0_rollback_modes()
    gray = facts_mod.gray_steps()
    gas = facts_mod.gas_defaults()
    points = facts_mod.points_defaults()
    fee_default = facts_mod.platform_fee_default_bps()
    fee_low, fee_high, fee_confirm = facts_mod.platform_fee_range_bps()
    fee_cap = facts_mod.fee_cap_pct()
    daily_send_at = facts_mod.report_daily_send_at()
    share_platform, share_provider, share_total = facts_mod.share_defaults_bps()
    pool = facts_mod.reserved_pool()
    slow_task, mesh = facts_mod.slow_task_discount_pcts()
    wallet_cap = facts_mod.wallet_cap_usd()

    keys: list[ConfigKey] = [
        # ── 1 产品开关（flag.）──────────────────────────────────────────
        _key(key="flag.slow_task_enabled", domain="flag", value_type="boolean", unit="boolean",
             default=False, default_source="policy:switch-default-off",
             risk="P1", owner="OPS", description="慢任务折扣总开关（§21.1.1 域 1；默认关闭）",
             expire_required=True, kill_switch=True, direction="reduce",
             consumers=("scheduler",)),
        _key(key="flag.invite_cop_enabled", domain="flag", value_type="boolean", unit="boolean",
             default=False, default_source="policy:switch-default-off",
             risk="P1", owner="OPS", description="邀请返 COP 开关（§21.1.1 域 1；默认关闭）",
             expire_required=True, kill_switch=True, direction="reduce",
             consumers=("reputation", "portal")),

        # ── 2 计费与价格（billing.，P0）────────────────────────────────
        _key(key="billing.service_fee_bps", domain="billing", value_type="integer", unit="bps",
             default=fee_default, default_source="facts:§4#平台费率默认",
             risk="P0", owner="FIN", minimum=fee_low, maximum=fee_high,
             description=f"平台服务费率（{fee_default} = {fee_default / 100:g}%；"
                         f"超过 {fee_confirm} 需决策人二次确认）",
             kill_switch=True, direction="reduce", escalate_above=fee_confirm,
             consumers=("scheduler", "settlement", "provider-console")),
        _key(key="billing.fee_cap_pct", domain="billing", value_type="integer", unit="pct",
             default=fee_cap, default_source="facts:§9#billing.fee_cap_pct（R-3 已补）",
             risk="P0", owner="FIN", minimum=0, maximum=fee_cap,
             description="费率承诺上限（公开承诺：服务费率不得超过该比例）",
             direction="reduce", tighten_only=True,
             consumers=("settlement", "transparency-page")),
        _key(key="billing.slow_task_discount_pct", domain="billing", value_type="integer", unit="pct",
             default=slow_task, default_source="facts:§4#慢任务 / 组网折扣",
             risk="P1", owner="FIN", minimum=0, maximum=units.PCT_MAX,
             description="慢任务折扣百分比（§4：40% off / 组网 50% off）",
             direction="reduce", consumers=("scheduler", "settlement")),
        _key(key="billing.channel_fee_bps", domain="billing", value_type="integer", unit="bps",
             default=gas["channel_fee_bps"], default_source="facts:§9#billing.channel_fee_bps",
             risk="P0", owner="FIN", minimum=0, maximum=units.BPS_MAX,
             description="渠道费率（facts：S3 前不启用，默认 0）",
             kill_switch=True, direction="reduce",
             consumers=("settlement", "payments")),
        _key(key="billing.gas_fee_mode", domain="billing", value_type="string", unit="enum",
             default=gas["mode"], default_source="facts:§9#billing.gas_fee_mode",
             risk="P0", owner="FIN", enum=("INTERNAL", "EXTERNAL"),
             description="gas 承担模式（EXTERNAL 时必须指定承担方）",
             consumers=("scheduler", "settlement")),
        _key(key="billing.gas_fee_bearer", domain="billing", value_type="string", unit="enum",
             default=gas["bearer"], default_source="facts:§9#billing.gas_fee_bearer",
             risk="P0", owner="FIN", enum=("PLATFORM", "PAYER"),
             description="gas 承担方（仅 EXTERNAL 生效）",
             consumers=("scheduler", "settlement")),
        _key(key="billing.gas_fee_scope", domain="billing", value_type="string", unit="enum",
             default=gas["scope"], default_source="facts:§9#billing.gas_fee_scope",
             risk="P1", owner="FIN", enum=("global", "chain", "batch"),
             description="gas 计费作用域（global / chain / batch）",
             consumers=("scheduler", "settlement")),

        # ── 3 风控（risk.，私有仓）────────────────────────────────────
        _key(key="risk.rule_version", domain="risk", value_type="string", unit="text",
             default=MISSING, default_source="unset:risk-config 私有仓部署期注入（§21.9）",
             risk="P0", owner="RISK", max_length=64,
             description="风控规则包版本（只存引用；值由私有仓部署期注入，不进控制台）",
             dangerous=True, sensitive=True, generated=True,
             consumers=("gateway", "risk")),

        # ── 4 配额与预留池（quota. / pool.）────────────────────────────
        _key(key="pool.reserved_default", domain="quota_pool", value_type="integer", unit="pct",
             default=pool["default"], default_source="facts:§4#预留池",
             risk="P0", owner="OPS", minimum=pool["min"], maximum=pool["max"],
             max_delta=10,                       # §21.4.4 例①：max-delta 10pp
             description=f"预留池基线（默认 {pool['default']}%，可调 {pool['min']}–{pool['max']}%；"
                         f"公共池保底 ≥{pool['public_floor']}%）",
             kill_switch=True, direction="reduce",
             consumers=("scheduler", "provider-console", "transparency-page")),
        _key(key="quota.per_user_daily_requests", domain="quota_pool", value_type="integer", unit="count",
             default=MISSING, default_source="unset:配额默认值由 M04/M11 配额策略定义，facts 未收录",
             risk="P1", owner="OPS", minimum=1,
             description="单用户单日请求上限（普通配额；上界由 M04/M11 叠加）",
             allow_scope=("global", "tenant"), direction="reduce", kill_switch=True,
             consumers=("gateway", "scheduler")),

        # ── 5 路由与调度（routing.）───────────────────────────────────
        _key(key="routing.policy_version", domain="routing", value_type="string", unit="text",
             default=MISSING, default_source="unset:由 M10 生成（policy_version = snapshot_digest 前 12 位）",
             risk="P0", owner="OPS", pattern=r"^[0-9a-f]{12}$", max_length=12,
             description="调度策略包版本（随快照 digest 变化，只读）",
             dangerous=True, generated=True,
             consumers=("gateway", "scheduler", "node")),

        # ── 6 通知模板（notify.，P2）──────────────────────────────────
        _key(key="notify.report.daily_send_at", domain="notify", value_type="string", unit="clock",
             default=daily_send_at, default_source="facts:§9#notify.report.daily_send_at（R-2 已补）",
             risk="P2", owner="OPS",
             description="日报发送时刻（HH:MM，UTC+8；产品 §23.7 为 01:15）",
             consumers=("reporting", "notify")),

        # ── 7 文案与词表（content.）───────────────────────────────────
        _key(key="content.wordlist_version", domain="content", value_type="string", unit="text",
             default=MISSING, default_source="unset:词表版本随 §14.4 G6 源发布，facts 未收录",
             risk="P2", owner="OPS", max_length=64,
             description="词表版本号（与 §14.4 G6 同源同版本，可回溯）",
             consumers=("gateway", "content")),
        _key(key="content.compliance_terms", domain="content", value_type="json", unit="json",
             default=MISSING, default_source="unset:豁免名单由合规维护，facts 未收录",
             risk="P0", owner="OPS", max_length=None,
             description="合规豁免名单（P0：改动需 OPS+AUDIT 复核）",
             sensitive=True, consumers=("gateway", "risk")),

        # ── 8 支付与 treasury 限额（treasury.，P0）────────────────────
        _key(key="treasury.platform_share_bps", domain="treasury", value_type="integer", unit="bps",
             default=share_platform, default_source="facts:§4#平台 / 共享方默认",
             risk="P0", owner="FIN", minimum=0, maximum=share_total,
             description=f"平台分润比例（与 provider_share_bps 之和 = {share_total}）",
             kill_switch=True, direction="reduce",
             consumers=("settlement", "treasury")),
        _key(key="treasury.provider_share_bps", domain="treasury", value_type="integer", unit="bps",
             default=share_provider, default_source="facts:§4#平台 / 共享方默认",
             risk="P0", owner="FIN", minimum=0, maximum=share_total,
             description=f"共享方分润比例（与 platform_share_bps 之和 = {share_total}）",
             kill_switch=True, direction="raise",
             consumers=("settlement", "treasury")),
        _key(key="treasury.hot_wallet_cap", domain="treasury", value_type="string", unit="usd",
             default=f"{wallet_cap:.2f}", default_source="facts:§2#单钱包 cap",
             risk="P0", owner="FIN", minimum="0.00", maximum=f"{wallet_cap:.2f}",
             description=f"热钱包单池上限（USD 十进制字符串；上限 {wallet_cap:,.0f} USD）",
             kill_switch=True, direction="reduce",
             consumers=("treasury", "wallet-pool")),
        _key(key="treasury.deposit_address_ref", domain="treasury", value_type="json", unit="json",
             default=MISSING, default_source="unset:secret_ref 由部署期注入（§21.10）",
             risk="P0", owner="FIN",
             description="收款地址引用（只存 {scheme,path,inject,version}，不存地址本身）",
             sensitive=True, secret_ref_only=True,
             consumers=("treasury", "payments")),
        _key(key="treasury.gas_fee_mode", domain="treasury", value_type="string", unit="enum",
             default=MISSING,
             default_source="unset:legacy 别名（DEV-0006 值 platform），只读兼容不双写",
             risk="P0", owner="FIN", enum=("platform", "provider"),
             description="gas 承担方（legacy 别名；规范键为 billing.gas_fee_mode）",
             dangerous=True, legacy_alias_of="billing.gas_fee_mode",
             consumers=("settlement",)),

        # ── 9 伙伴与渠道（partner.）───────────────────────────────────
        _key(key="partner.channel_rate_bps", domain="partner", value_type="integer", unit="bps",
             default=MISSING, default_source="unset:渠道费率按伙伴合同约定，facts 未收录",
             risk="P1", owner="OPS", minimum=0, maximum=units.BPS_MAX,
             description="伙伴渠道费率（结算适配器不进公开仓）",
             consumers=("settlement", "partner")),
        _key(key="partner.whitelist_enabled", domain="partner", value_type="boolean", unit="boolean",
             default=False, default_source="policy:switch-default-off",
             risk="P1", owner="OPS",
             description="伙伴白名单开关（临时放开必须带 expire_at）",
             expire_required=True, kill_switch=True, direction="reduce",
             consumers=("gateway", "partner")),

        # ── 10 实验（exp.，S3）────────────────────────────────────────
        _key(key="exp.route_weight_variant", domain="exp", value_type="string", unit="text",
             default=MISSING, default_source="unset:实验平台 S3 才启用（§21.14.2）",
             risk="P2", owner="OPS", max_length=64,
             description="路由权重实验分组（禁资金参数）",
             expire_required=True, consumers=("gateway", "scheduler")),
        _key(key="exp.ui_copy_variant", domain="exp", value_type="string", unit="text",
             default=MISSING, default_source="unset:实验平台 S3 才启用（§21.14.2）",
             risk="P2", owner="OPS", max_length=64,
             description="文案实验分组（禁资金参数）",
             expire_required=True, consumers=("portal",)),

        # ── 辅助：M10 自管键（config.，M10 §8.1）──────────────────────
        _key(key="config.p0_cooldown_h", domain="config", value_type="integer", unit="hours",
             default=cooldowns["P0"] // 3600, default_source="facts:§9#冷却",
             risk="P0", owner="OPS", minimum=0, maximum=168,
             description="P0 键二次发布冷却（小时；facts：24h）",
             consumers=("config-center",)),
        _key(key="config.p1_cooldown_min", domain="config", value_type="integer", unit="minutes",
             default=cooldowns["P1"] // 60, default_source="facts:§9#冷却",
             risk="P0", owner="OPS", minimum=0, maximum=1440,
             description="P1 键二次发布冷却（分钟；facts：60min）",
             consumers=("config-center",)),
        _key(key="config.publish_window", domain="config", value_type="json", unit="window",
             default=window.as_default(), default_source="facts:§9#发布窗口",
             risk="P1", owner="OPS",
             description="发布窗口（工作日 10:00–17:00 UTC+8；单一窗口）",
             consumers=("config-center", "ops-console")),
        _key(key="config.gray_steps", domain="config", value_type="json", unit="json",
             default=list(gray), default_source="facts:§9#灰度",
             risk="P1", owner="OPS",
             description="灰度步长（1→5→25→100；S2 起启用，末位必须 100）",
             consumers=("config-center",)),
        _key(key="config.p0_rollback_mode", domain="config", value_type="string", unit="enum",
             default=rollback_modes[0], default_source="facts:§9#P0 回滚",
             risk="P0", owner="OPS", enum=rollback_modes,
             description="P0 回滚模式（facts：只允许人工；自动回滚仅 P1/P2）",
             consumers=("config-center",)),

        # ── 辅助：points.*（M07 命名空间，M10 承载默认值）──────────────
        _key(key="points.transfer_enabled", domain="points", value_type="boolean", unit="boolean",
             default=points["transfer_enabled"], default_source="facts:§9#points.transfer_enabled",
             risk="P0", owner="OPS",
             description="COP 转让总开关（K4：默认不可转让，仅 admin 可开）",
             kill_switch=True, direction="reduce",
             consumers=("reputation", "portal")),
        _key(key="points.transfer_per_tx_cap", domain="points", value_type="integer", unit="count",
             default=points["transfer_per_tx_cap"], default_source="facts:§9#points.transfer_per_tx_cap",
             risk="P0", owner="OPS", minimum=0,
             description="单笔转让上限（COP）",
             consumers=("reputation",)),
        _key(key="points.transfer_daily_out_cap", domain="points", value_type="integer", unit="count",
             default=points["transfer_daily_out_cap"],
             default_source="facts:§9#points.transfer_daily_out_cap",
             risk="P0", owner="OPS", minimum=0,
             description="单日转出上限（COP）",
             consumers=("reputation",)),
        _key(key="points.transfer_daily_in_cap", domain="points", value_type="integer", unit="count",
             default=points["transfer_daily_in_cap"],
             default_source="facts:§9#points.transfer_daily_in_cap",
             risk="P0", owner="OPS", minimum=0,
             description="单日转入上限（COP）",
             consumers=("reputation",)),
        _key(key="points.transfer_lock_days", domain="points", value_type="integer", unit="days",
             default=points["transfer_lock_days"], default_source="facts:§9#points.transfer_lock_days",
             risk="P1", owner="OPS", minimum=0,
             description="转让锁定天数",
             tighten_only=False, direction="raise", consumers=("reputation",)),
        _key(key="points.redeem_rate_bps", domain="points", value_type="integer", unit="bps",
             default=points["redeem_rate_bps"], default_source="facts:§9#points.redeem_rate_bps",
             risk="P0", owner="OPS", minimum=0, maximum=units.BPS_MAX,
             description="兑换率（1 COP = 1 USD 分 → 10000 bps）",
             consumers=("reputation", "settlement")),
    ]
    registry = Registry(domains=DOMAINS, aux=AUX_NAMESPACES, keys=tuple(keys))
    _validate(registry)
    return registry


def _validate(registry: Registry) -> None:
    """构建期自检：注册表自身违反契约就导入期炸掉（不把坏契约带上线）。"""
    if len(registry.domains) != 10:
        raise ValidationFailed(f"配置域必须是十域（§21.1.1），实际 {len(registry.domains)}")
    codes = [domain.code for domain in registry.domains]
    if len(set(codes)) != len(codes):
        raise ValidationFailed(f"配置域 code 重复：{codes}")
    namespaces = [ns for domain in registry.domains for ns in domain.namespaces]
    namespaces += [aux.namespace for aux in registry.aux]
    if len(set(namespaces)) != len(namespaces):
        raise ValidationFailed(f"命名空间重复：{namespaces}")
    known_ns = set(namespaces)

    for domain in registry.domains:
        if domain.default_risk not in RISK_LEVELS:
            raise ValidationFailed(f"域 {domain.code} 风险级非法：{domain.default_risk}")
        if not domain.namespaces or not domain.proposer_roles or not domain.approver_roles:
            raise ValidationFailed(f"域 {domain.code} 定义不完整")
    for aux in registry.aux:
        if aux.default_risk not in RISK_LEVELS:
            raise ValidationFailed(f"辅助命名空间 {aux.namespace} 风险级非法：{aux.default_risk}")

    all_keys = {item.key for item in registry.keys}
    seen: set[str] = set()
    for item in registry.keys:
        if not KEY_PATTERN.match(item.key):
            raise ValidationFailed(f"key 形态非法：{item.key!r}（§21.1.3）")
        if item.key in seen:
            raise ValidationFailed(f"key 重复注册：{item.key}")
        seen.add(item.key)
        if forbidden_reason(item.key):
            raise ValidationFailed(f"key {item.key} 命中危险键黑名单，不得注册可写键（§21.3.5）")
        if item.namespace not in known_ns:
            raise ValidationFailed(f"key {item.key} 的命名空间未登记：{item.namespace}")
        if item.domain not in set(codes) | {aux.namespace for aux in registry.aux}:
            raise ValidationFailed(f"key {item.key} 的 domain 未登记：{item.domain}")
        if item.risk not in RISK_LEVELS:
            raise ValidationFailed(f"key {item.key} 风险级非法：{item.risk}")
        if item.value_type not in units.VALUE_TYPES:
            raise ValidationFailed(f"key {item.key} value_type 非法：{item.value_type}")
        allowed_types = units.UNIT_VALUE_TYPES.get(item.unit)
        if allowed_types is None:
            raise ValidationFailed(f"key {item.key} 单位未登记：{item.unit}")
        if item.value_type not in allowed_types:
            raise ValidationFailed(
                f"key {item.key} 的 value_type={item.value_type} 与 unit={item.unit} 不匹配"
                f"（允许 {allowed_types}）")
        if not item.owner:
            raise ValidationFailed(f"key {item.key} 缺 owner（§21.1.1 域内互斥）")
        if item.default is MISSING:
            if not item.default_source.startswith("unset:"):
                raise ValidationFailed(f"key {item.key} 无默认值，default_source 必须 unset: 开头")
        else:
            if item.default_source.startswith("unset:"):
                raise ValidationFailed(f"key {item.key} 有默认值却标 unset")
            # 默认值自检：注册表里的默认值必须能过自己的校验（否则第一次发布就会被自己的规则拒）
            normalized = units.normalize(item.unit, item.default, key=item.key,
                                         minimum=item.minimum, maximum=item.maximum,
                                         multiple_of=item.multiple_of, max_length=item.max_length)
            _check_registry_enum(item, normalized)
        if item.max_delta is not None and item.max_delta <= 0:
            raise ValidationFailed(f"key {item.key} max_delta 必须为正：{item.max_delta}")
        if item.tighten_only and item.direction == "none":
            raise ValidationFailed(f"key {item.key} tighten_only 必须声明 direction（reduce/raise）")
        if item.direction not in ("reduce", "raise", "none"):
            raise ValidationFailed(f"key {item.key} direction 非法：{item.direction}")
        if not set(item.allow_scope) <= set(SCOPES):
            raise ValidationFailed(f"key {item.key} allow_scope 非法：{item.allow_scope}")
        if item.legacy_alias_of and item.legacy_alias_of not in all_keys:
            raise ValidationFailed(f"key {item.key} 的 legacy_alias_of 指向未注册键：{item.legacy_alias_of}")
        if item.secret_ref_only and not item.value_type == "json":
            raise ValidationFailed(
                f"key {item.key} 的 secret_ref 键必须是 json 类型（{{scheme, path, inject, version}}）")

    # 十域全覆盖：每个域至少一个键（03-facts「S1 十域全覆盖」）
    for domain in registry.domains:
        if not registry.by_domain(domain.code):
            raise ValidationFailed(f"配置域 {domain.code} 没有任何注册键（十域全覆盖要求）")


def _check_registry_enum(item: ConfigKey, normalized: Any) -> None:
    if item.enum and normalized not in item.enum:
        raise ValidationFailed(f"key {item.key} 默认值不在枚举内：{normalized!r} ∉ {item.enum}")
    if item.pattern and isinstance(normalized, str) and not re.match(item.pattern, normalized):
        raise ValidationFailed(f"key {item.key} 默认值不匹配 pattern：{normalized!r}")


@lru_cache(maxsize=4)
def _load_cached(facts_path_str: str) -> Registry:
    return _build(facts_path_str)


def load() -> Registry:
    """当前 facts 下的注册表（按 facts 路径缓存；facts 变了缓存键跟着变）。"""
    return _load_cached(str(facts_mod.facts_path()))


def keys_of(registry: Registry, *, domain: str | None = None) -> Iterable[ConfigKey]:
    """遍历辅助函数（证据文件与测试用）。"""
    if domain is None:
        return iter(registry.keys)
    return iter(registry.by_domain(domain))
