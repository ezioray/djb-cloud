# SPDX-License-Identifier: Apache-2.0
"""校验器（T1）：类型 / 单位 / 范围 / 枚举 / 跨字段 / 危险键 / 密钥形态 / 过期要求。

四道校验里的第①道（提交时）与第②道（发布前）都用这一层（§21.3.4）；第③道（消费端加载）
由 SDK 复用同一组纯函数。纪律：

* **纯函数**：不连库、不读时钟（``now`` 由调用方给）、不写日志；同样的输入永远同样的结果；
* **只认注册表**：未注册的键一律 47001（不做「未知键放行」）；危险键/生成键一律 47004（INV-06）；
* **先量纲后业务**：单位与量纲硬规则在 :mod:`app.config_center.units`，本层叠加键级范围与跨字段；
* **不猜**：值像密钥就拒绝（INV-05），字段多一个就拒绝（§21.3.1 additionalProperties: false）。

错误码对应（M10 §4.1 / §9 验收）：

| 场景 | 异常 | code |
| --- | --- | --- |
| 未知键 / 类型 / 范围 / 枚举 / 跨字段 / 过期缺失 | :class:`ValidationFailed` 家族 | 47001 |
| 危险键（黑名单或 ``dangerous=true``）与生成键被写 | :class:`DangerousKeyForbidden` | 47004 |
| 发布前缺声明默认值 | :class:`ValidationFailed` | 47001 |
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Iterable, Mapping

from . import facts as facts_mod
from . import units
from .errors import (
    CrossFieldViolation,
    DangerousKeyForbidden,
    RangeViolation,
    SecretShapeForbidden,
    TypeMismatch,
    ValidationFailed,
)
from .registry import MISSING, ConfigKey, Registry, forbidden_reason, load

__all__ = [
    "ValidationResult",
    "CrossFieldRule",
    "SECRET_PATTERNS",
    "SECRET_REF_SCHEMES",
    "SECRET_REF_INJECTS",
    "as_utc",
    "check_writable",
    "check_publishable",
    "assert_not_secret",
    "validate_secret_ref",
    "validate_value",
    "validate_group",
    "validate_cross_field",
    "cross_field_rules",
]

# ───────────────────────────────────────────────────────────── 密钥形态（INV-05）
#: (正则, 人类可读类别)。命中即 47001：配置 ≠ 密钥，只能存 secret_ref（§21.3.5 / §21.10.3）。
SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "PEM 私钥"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key"),
    (re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "支付网关密钥"),
    (re.compile(r"\b0x[0-9a-fA-F]{64}\b"), "链上私钥"),
    (re.compile(r"\b[0-9a-fA-F]{64}\b"), "64 位十六进制串（私钥 / 摘要形态）"),
    (re.compile(r"(?i)\b(?:password|passwd|secret|token)\s*[:=]\s*\S+"), "口令 / 令牌赋值"),
)

#: secret_ref 结构（§21.10.1）：{scheme: kms / hsm / env / file, path, inject, version}
SECRET_REF_SCHEMES: tuple[str, ...] = ("kms", "hsm", "env", "file")
SECRET_REF_INJECTS: tuple[str, ...] = ("env", "file", "sdk")
SECRET_REF_FIELDS: tuple[str, ...] = ("scheme", "path", "inject", "version")

_MNEMONIC_WORD = re.compile(r"^[a-z]{3,8}$")


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _looks_like_mnemonic(text: str) -> bool:
    """助记词启发式：≥12 个纯小写字母词、空格分隔、无标点。

    BIP39 助记词就是「12/15/18/21/24 个常见英文单词」；配置值里出现这种形态几乎一定是误存。
    启发式只在**整段值**上判定（不是子串），降低误报。
    """
    tokens = text.split()
    if len(tokens) < 12:
        return False
    if not all(_MNEMONIC_WORD.match(token) for token in tokens):
        return False
    return len(set(tokens)) >= 8      # 自然语言里常见词重复多；助记词几乎不重复


def assert_not_secret(value: Any, *, key: str | None = None) -> None:
    """值（含 JSON 内的字符串）出现密钥形态即拒绝（INV-05）。"""
    for text in _iter_strings(value):
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                raise SecretShapeForbidden(
                    f"{key or '值'} 出现{label}形态，拒绝落库（INV-05 / §21.10.3）", key=key)
        if _looks_like_mnemonic(text):
            raise SecretShapeForbidden(
                f"{key or '值'} 像助记词（≥12 个单词），拒绝落库（INV-05 / §21.10.3）", key=key)


def validate_secret_ref(value: Any, *, key: str | None = None) -> dict[str, Any]:
    """secret_ref 只接受 ``{scheme, path, inject, version}`` 四字段（INV-05 / §21.10.1）。"""
    if not isinstance(value, dict):
        raise TypeMismatch(f"{key or 'secret_ref'} 必须是对象：{value!r}", key=key)
    extra = sorted(set(value) - set(SECRET_REF_FIELDS))
    if extra:
        raise ValidationFailed(f"{key or 'secret_ref'} 含未定义字段：{', '.join(extra)}", key=key,
                               details=[{"field": field} for field in extra])
    missing = [field for field in SECRET_REF_FIELDS if field not in value]
    if missing:
        raise ValidationFailed(f"{key or 'secret_ref'} 缺字段：{', '.join(missing)}", key=key,
                               details=[{"field": field} for field in missing])
    scheme, path, inject, version = (value[field] for field in SECRET_REF_FIELDS)
    if scheme not in SECRET_REF_SCHEMES:
        raise ValidationFailed(
            f"{key or 'secret_ref'} 的 scheme 必须是 {SECRET_REF_SCHEMES}：{scheme!r}", key=key)
    if not isinstance(path, str) or not 1 <= len(path) <= 256 or any(ch.isspace() for ch in path):
        raise ValidationFailed(f"{key or 'secret_ref'} 的 path 非法：{path!r}", key=key)
    if inject not in SECRET_REF_INJECTS:
        raise ValidationFailed(
            f"{key or 'secret_ref'} 的 inject 必须是 {SECRET_REF_INJECTS}：{inject!r}", key=key)
    if isinstance(version, bool) or not isinstance(version, (str, int)) or version == "":
        raise ValidationFailed(f"{key or 'secret_ref'} 的 version 非法：{version!r}", key=key)
    if isinstance(version, str) and (len(version) > 64 or any(ch.isspace() for ch in version)):
        raise ValidationFailed(f"{key or 'secret_ref'} 的 version 非法：{version!r}", key=key)
    # 引用路径本身也不许带密钥（防止把 AK 写进 path）
    assert_not_secret(path, key=key)
    return {"scheme": scheme, "path": path, "inject": inject, "version": version}


# ───────────────────────────────────────────────────────────── 危险键 / 默认值
def check_writable(key: str, *, registry: Registry | None = None) -> ConfigKey:
    """写路径入口：黑名单 → 47004；未注册 → 47001；dangerous/generated → 47004（INV-06）。"""
    blocked = forbidden_reason(key)
    if blocked:
        raise DangerousKeyForbidden(
            f"危险键禁改：{key!r} 属「{blocked}」，不进控制台可编辑范围（INV-06 / §21.3.5）", key=key)
    reg = registry or load()
    item = reg.require(key)
    if item.dangerous:
        raise DangerousKeyForbidden(
            f"危险键禁改：{key!r} 标记 dangerous，只能只读展示（INV-06）", key=key)
    if item.generated:
        raise DangerousKeyForbidden(
            f"{key!r} 由 M10 生成（policy_version / 私有仓注入），不接受人工写入（INV-06）", key=key)
    return item


def check_publishable(key: str, *, registry: Registry | None = None) -> ConfigKey:
    """发布前检查：没有声明默认值的键不得发布（§21.2.3）。"""
    reg = registry or load()
    item = reg.require(key)
    if item.dangerous or item.generated:
        raise DangerousKeyForbidden(f"{key!r} 是危险/生成键，不可发布（INV-06）", key=key)
    if not item.publishable:
        raise ValidationFailed(
            f"{key!r} 没有声明默认值（{item.default_source}），发布前必须补齐 default_value（§21.2.3）",
            key=key)
    return item


# ───────────────────────────────────────────────────────────── 单值校验
@dataclass(frozen=True)
class ValidationResult:
    """一次校验的结果：规范化后的值 + 是否需要升级审批（不拒绝，但走 P0 流程）。"""

    key: ConfigKey
    value: Any
    requires_escalation: bool = False
    escalation_reasons: tuple[str, ...] = ()


def _metric(unit: str, value: Any) -> Any:
    if unit in ("bps", "pct", "usd", "usd_minor", "count", "seconds", "minutes", "hours", "days"):
        return Decimal(str(value))
    return value


def as_utc(value: Any, *, field: str) -> datetime:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value:
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValidationFailed(f"{field} 不是合法 RFC3339 时间：{value!r}") from None
    else:
        raise ValidationFailed(f"{field} 必须是 RFC3339 时间：{value!r}")
    if moment.tzinfo is None:
        raise ValidationFailed(f"{field} 必须带时区（UTC）：{value!r}")
    return moment.astimezone(timezone.utc)


def validate_value(
    key: str,
    value: Any,
    *,
    registry: Registry | None = None,
    current: Any = None,
    expire_at: Any = None,
    now: datetime | None = None,
) -> ValidationResult:
    """校验单个键的值并规范化。

    ``current``：当前生效值（用于 x-djb-max-delta 与 x-djb-tighten-only）。
    ``expire_at``：x-djb-expire-required 的键必填（开关 / 实验 / 临时放宽，§21.3.1）。
    ``now``：注入时钟（测试确定性）；缺省取 UTC 当前时间。
    """
    reg = registry or load()
    item = reg.require(key)

    if not units.value_type_matches(item.value_type, value):
        raise TypeMismatch(
            f"{key} 的 value_type={item.value_type}，收到 {units.json_type(value) or type(value).__name__}："
            f"{value!r}", key=key)

    normalized = units.normalize(
        item.unit, value, key=key,
        minimum=item.minimum, maximum=item.maximum,
        multiple_of=item.multiple_of, max_length=item.max_length,
    )

    if item.enum and normalized not in item.enum:
        raise RangeViolation(f"{key} 取值必须在 {item.enum} 内：{normalized!r}", key=key)
    if item.pattern and isinstance(normalized, str) and not re.match(item.pattern, normalized):
        raise RangeViolation(f"{key} 不匹配 {item.pattern}：{normalized!r}", key=key)

    if item.secret_ref_only:
        normalized = validate_secret_ref(normalized, key=key)
    else:
        assert_not_secret(normalized, key=key)

    # 过期要求（§21.3.1 x-djb-expire-required / §21.11.3 第 9 项）
    if item.expire_required and expire_at is None:
        raise ValidationFailed(f"{key} 必须带 expire_at（x-djb-expire-required）", key=key)
    if expire_at is not None:
        deadline = as_utc(expire_at, field=f"{key}.expire_at")
        if deadline <= (now or datetime.now(timezone.utc)):
            raise ValidationFailed(f"{key}.expire_at 已过期：{expire_at!r}（§21.11.3 第 9 项）", key=key)

    escalations: list[str] = []

    # 变化幅度超限不拒绝，强制升级审批（§21.3.2；「合法但过猛」正是手滑事故）
    if item.max_delta is not None and current is not None:
        delta = abs(_metric(item.unit, normalized) - _metric(item.unit, current))
        if delta > item.max_delta:
            escalations.append(
                f"变化幅度 {delta} 超过 x-djb-max-delta {item.max_delta}（升级审批）")
    if item.escalate_above is not None and _metric(item.unit, normalized) > _metric(
            item.unit, item.escalate_above):
        escalations.append(
            f"取值超过强制升级阈值 {item.escalate_above}（需决策人二次确认）")

    # x-djb-tighten-only：只允许收紧方向（放开一律 47001）
    if item.tighten_only and current is not None:
        new_metric = _metric(item.unit, normalized)
        old_metric = _metric(item.unit, current)
        loosened = (item.direction == "reduce" and new_metric > old_metric) or (
            item.direction == "raise" and new_metric < old_metric)
        if loosened:
            raise ValidationFailed(
                f"{key} 只允许收紧（direction={item.direction}）：{current!r} → {normalized!r}（§21.3.1）",
                key=key)

    return ValidationResult(key=item, value=normalized,
                            requires_escalation=bool(escalations),
                            escalation_reasons=tuple(escalations))


# ───────────────────────────────────────────────────────────── 跨字段断言
@dataclass(frozen=True)
class CrossFieldRule:
    """注册式跨字段断言（§21.3.3）：schema 表达不了的求和 / 依赖 / 承诺上限。"""

    name: str
    keys: tuple[str, ...]
    check: Callable[[Mapping[str, Any]], None]


def cross_field_rules() -> tuple[CrossFieldRule, ...]:
    """跨字段规则集（数值来自 facts；规则随代码 PR 评审，不随发布单变化）。"""

    def treasury_share_sum(merged: Mapping[str, Any]) -> None:
        platform = merged.get("treasury.platform_share_bps")
        provider = merged.get("treasury.provider_share_bps")
        if platform is None or provider is None:
            return
        total = facts_mod.share_defaults_bps()[2]
        if platform + provider != total:
            raise CrossFieldViolation(
                f"treasury.platform_share_bps + treasury.provider_share_bps 必须 = {total}："
                f"{platform} + {provider} = {platform + provider}（§21.3.3 求和约束）")

    def gas_bearer_required(merged: Mapping[str, Any]) -> None:
        mode = merged.get("billing.gas_fee_mode")
        bearer = merged.get("billing.gas_fee_bearer")
        if mode == "EXTERNAL" and bearer is None:
            raise CrossFieldViolation(
                "billing.gas_fee_mode=EXTERNAL 时必须指定 billing.gas_fee_bearer（§21.3.3 依赖）")
        if mode == "INTERNAL" and bearer is not None and bearer != "PLATFORM":
            raise CrossFieldViolation(
                f"billing.gas_fee_mode=INTERNAL 时承担方只能是 PLATFORM，收到 {bearer!r}"
                "（§21.3.3 互斥）")

    def fee_cap_commitment(merged: Mapping[str, Any]) -> None:
        fee = merged.get("billing.service_fee_bps")
        cap_pct = merged.get("billing.fee_cap_pct")
        if fee is None or cap_pct is None:
            return
        cap_bps = int(Decimal(str(cap_pct)) * 100)
        if fee > cap_bps:
            raise CrossFieldViolation(
                f"billing.service_fee_bps={fee} 超过承诺上限 {cap_pct}%（{cap_bps} bps）（§21.3.3 上界承诺）")

    def gray_steps_shape(merged: Mapping[str, Any]) -> None:
        steps = merged.get("config.gray_steps")
        if steps is None:
            return
        if not isinstance(steps, list) or not steps:
            raise CrossFieldViolation(f"config.gray_steps 必须是非空数组：{steps!r}")
        if any(isinstance(step, bool) or not isinstance(step, int) or not 0 <= step <= units.PCT_MAX
               for step in steps):
            raise CrossFieldViolation(f"config.gray_steps 的每步必须是 0–100 整数：{steps!r}")
        if any(b <= a for a, b in zip(steps, steps[1:])):
            raise CrossFieldViolation(f"config.gray_steps 必须严格递增：{steps!r}")
        if steps[-1] != units.PCT_MAX:
            raise CrossFieldViolation(f"config.gray_steps 末位必须是 100：{steps!r}")

    def publish_window_shape(merged: Mapping[str, Any]) -> None:
        window = merged.get("config.publish_window")
        if window is None:
            return
        weekdays = window.get("weekdays") if isinstance(window, dict) else None
        if not weekdays or any(day > 5 for day in weekdays):
            raise CrossFieldViolation(
                f"config.publish_window 只允许工作日（周一–周五，ISO 1–5）：{window!r}（M10 §8.1 单一窗口）")

    def transfer_caps(merged: Mapping[str, Any]) -> None:
        per_tx = merged.get("points.transfer_per_tx_cap")
        daily_out = merged.get("points.transfer_daily_out_cap")
        if per_tx is not None and daily_out is not None and per_tx > daily_out:
            raise CrossFieldViolation(
                f"points.transfer_per_tx_cap={per_tx} 不得超过单日转出上限 {daily_out}（§12 转让限额）")

    return (
        CrossFieldRule("treasury_share_sum",
                       ("treasury.platform_share_bps", "treasury.provider_share_bps"),
                       treasury_share_sum),
        CrossFieldRule("gas_bearer_required",
                       ("billing.gas_fee_mode", "billing.gas_fee_bearer"), gas_bearer_required),
        CrossFieldRule("fee_cap_commitment",
                       ("billing.service_fee_bps", "billing.fee_cap_pct"), fee_cap_commitment),
        CrossFieldRule("gray_steps_shape", ("config.gray_steps",), gray_steps_shape),
        CrossFieldRule("publish_window_shape", ("config.publish_window",), publish_window_shape),
        CrossFieldRule("transfer_caps",
                       ("points.transfer_per_tx_cap", "points.transfer_daily_out_cap"), transfer_caps),
    )


def validate_cross_field(
    merged: Mapping[str, Any],
    *,
    touched: Iterable[str] | None = None,
) -> None:
    """对合并后的值集合跑跨字段断言。

    ``touched``：本次变更涉及的键；只跑与它相交的规则（避免同一次提交里被无关规则误伤）。
    """
    touched_set = set(touched) if touched is not None else None
    for rule in cross_field_rules():
        if touched_set is not None and not touched_set & set(rule.keys):
            continue
        rule.check(merged)


def validate_group(
    values: Mapping[str, Any],
    *,
    registry: Registry | None = None,
    effective: Mapping[str, Any] | None = None,
    expire_at: Any = None,
    now: datetime | None = None,
) -> dict[str, ValidationResult]:
    """一组键的提交校验（建发布单 / 预发前重跑）：逐键校验 + 跨字段断言。

    ``effective``：当前生效值；用于幅度/收紧判断，并与新值合并后跑跨字段断言
    （只改 platform_share_bps 时也要能和已有 provider_share_bps 求和）。
    """
    reg = registry or load()
    if not values:
        raise ValidationFailed("提交至少需要一个配置键（空变更不允许建发布单）")
    results: dict[str, ValidationResult] = {}
    merged: dict[str, Any] = {key: value for key, value in (effective or {}).items() if key in reg}
    for key, value in values.items():
        result = validate_value(key, value, registry=reg,
                                current=(effective or {}).get(key),
                                expire_at=expire_at, now=now)
        results[key] = result
        merged[key] = result.value
    validate_cross_field(merged, touched=values.keys())
    return results
