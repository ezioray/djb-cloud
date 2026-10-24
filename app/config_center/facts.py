# SPDX-License-Identifier: AGPL-3.0-or-later
"""M10 常量的事实源读取层：``contracts/facts.yaml``（W0-QA 生成的机器源）。

纪律（03-facts §13、W1-EXECUTION-PLAN §2、_boundary-checks §1.5）：
  · **只读**：本模块不写 facts、不缓存落盘、不复制业务数字；facts.yaml 变了默认值就变；
  · **缺失即报错**（:class:`FactsError`），不静默降级：配置中心宁可起不来，也不能用猜出来的
    默认值签发版本（那会让「默认值 = 事实」这条链断在最关键的地方）；
  · 不引第三方依赖：facts.yaml 的形状由 ``tools/gen_facts.py`` 固定（sections → facts →
    key/value/note），这里实现一个够用的最小解析器；测试用 ``yaml.safe_load`` 交叉验证形状。

与 M06 的 ``app/ledger/facts.py`` 是**同构的两份实现**（不是 import）：01-ownership §6 与
``tools/ci/architecture_check.py`` 禁止模块包之间互相 import，最小解析器只有 60 行，
复制比耦合更安全。

本模块读取的段：
  · §2 钱包池与扩容（M08）：单钱包 cap → treasury.hot_wallet_cap 默认值；
  · §4 费率、分润与 gas（M04/M08）：平台费率默认/范围、平台与共享方分成、慢任务折扣、预留池；
  · §9 配置与发布（M10）：冷却 / 发布窗口 / P0 回滚 / 灰度 / billing.* / points.*；
  · §12 信誉与 COP（M07）：转让限额（与 §9 的 points.* 交叉校验）。
"""
from __future__ import annotations

import os
import pathlib
import re
from datetime import timedelta
from decimal import Decimal
from functools import lru_cache
from typing import Any, NamedTuple

from .errors import FactsError

__all__ = [
    "FactsError",
    "PublishWindow",
    "facts_path",
    "parse",
    "load",
    "sections",
    "section",
    "section_facts",
    "fact",
    "cooldowns",
    "publish_window",
    "p0_rollback_modes",
    "gray_steps",
    "drift_scan_policy",
    "approval_timeout",
    "fee_cap_pct",
    "gas_defaults",
    "points_defaults",
    "report_daily_send_at",
    "step_up_ttl",
    "platform_fee_default_bps",
    "platform_fee_range_bps",
    "share_defaults_bps",
    "reserved_pool",
    "slow_task_discount_pcts",
    "transfer_limits",
    "wallet_cap_usd",
]

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_FACTS_PATH = _REPO_ROOT / "contracts" / "facts.yaml"


def facts_path() -> pathlib.Path:
    """facts 文件位置（``DJB_FACTS_FILE`` 可覆盖，供测试与多环境注入）。"""
    override = os.environ.get("DJB_FACTS_FILE")
    return pathlib.Path(override) if override else DEFAULT_FACTS_PATH


# ────────────────────────────────────────────── 最小 YAML 子集解析
_SECTION_RE = re.compile(r"^-\s+id:\s*(\d+)\s*$")
_TOP_RE = re.compile(r"^([A-Za-z_][\w-]*):\s*(.*)$")
_INLINE_QUOTED = re.compile(r"^'(.*)'$|^\"(.*)\"$", re.S)


def _unquote(value: str) -> str:
    value = value.strip()
    match = _INLINE_QUOTED.match(value)
    if not match:
        return value
    if match.group(1) is not None:
        return match.group(1).replace("''", "'")       # YAML 单引号转义
    return match.group(2).replace('\\"', '"')


def parse(text: str) -> dict:
    """解析 gen_facts.py 生成的 facts.yaml（缩进敏感，只覆盖该形状）。"""
    doc: dict = {"top": {}, "sections": []}
    section: dict | None = None
    fact_item: dict | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0:
            match = _SECTION_RE.match(stripped)
            if match:
                section = {"id": int(match.group(1)), "title": "", "owner": "", "facts": []}
                doc["sections"].append(section)
                fact_item = None
                continue
            top = _TOP_RE.match(stripped)
            if top:
                doc["top"][top.group(1)] = _unquote(top.group(2))
                section = None
            continue

        if section is None:
            continue
        if indent <= 2 and stripped.startswith("- key:"):
            fact_item = {"key": _unquote(stripped.split(":", 1)[1]), "value": "", "note": ""}
            section["facts"].append(fact_item)
            continue
        if indent <= 2:
            for field in ("title", "owner"):
                if stripped.startswith(f"{field}:"):
                    section[field] = _unquote(stripped.split(":", 1)[1])
                    break
            continue
        if fact_item is not None:
            for field in ("key", "value", "note"):
                if stripped.startswith(f"{field}:"):
                    fact_item[field] = _unquote(stripped.split(":", 1)[1])
                    break
    return doc


@lru_cache(maxsize=8)
def _load_cached(path_str: str) -> dict:
    path = pathlib.Path(path_str)
    if not path.exists():
        raise FactsError(f"facts 文件不存在：{path}（用 DJB_FACTS_FILE 指定）")
    doc = parse(path.read_text(encoding="utf-8"))
    if not doc["sections"]:
        raise FactsError(f"{path} 解析出 0 个 section，形状与 gen_facts.py 不符")
    return doc


def load() -> dict:
    """整份 facts（含 top / sections）。"""
    return _load_cached(str(facts_path()))


def sections() -> list[dict]:
    """全部段（顺序与 03-facts 一致）。"""
    return list(load()["sections"])


def section(owner: str, section_id: int | None = None) -> dict:
    """按 owner（可再按段 id）取段。

    注意 **owner 不唯一**：03-facts 里 M08 同时是 §1（链与确认）与 §2（钱包池与扩容）的
    owner。因此 ``section("M08")`` 返回第一个匹配段，取事实请用 :func:`section_facts`
    （按 owner 合并全部段）或显式传 ``section_id``。
    """
    matches = [sec for sec in load()["sections"]
               if sec["owner"] == owner and (section_id is None or sec["id"] == section_id)]
    if not matches:
        raise FactsError(f"facts.yaml 中没有 owner={owner!r}"
                         + (f" / id={section_id}" if section_id is not None else "") + " 的段")
    return matches[0]


def section_facts(owner: str, section_id: int | None = None) -> dict[str, str]:
    """按 owner 合并全部段的 key→value（同 key 后出现的段覆盖前面的）。"""
    matches = [sec for sec in load()["sections"]
               if sec["owner"] == owner and (section_id is None or sec["id"] == section_id)]
    if not matches:
        raise FactsError(f"facts.yaml 中没有 owner={owner!r} 的段")
    merged: dict[str, str] = {}
    for sec in matches:
        merged.update({f["key"]: f["value"] for f in sec["facts"]})
    return merged


def fact(key: str, owner: str, section_id: int | None = None) -> str:
    """取一条事实；缺失或空值直接抛错（不静默降级）。"""
    facts = section_facts(owner, section_id)
    if key not in facts or not facts[key]:
        where = f"{owner} 段" + (f"（id={section_id}）" if section_id is not None else "")
        raise FactsError(f"facts.yaml {where}缺关键事实：{key!r}")
    return facts[key]


def _require(pattern: str, value: str, what: str) -> re.Match[str]:
    match = re.search(pattern, value)
    if not match:
        raise FactsError(f"{what} 无法解析：{value!r}（期望匹配 {pattern}）")
    return match


# ────────────────────────────────────────────── §9 配置与发布（M10）
_DURATION_UNITS = {"h": 3600, "min": 60, "m": 60, "s": 1}


def cooldowns() -> dict[str, int]:
    """冷却期（秒）：P0 / P1 / P2（03-facts §9「P0 24h / P1 60min / P2 无」）。"""
    value = fact("冷却", "M10")
    values: dict[str, int] = {}
    for risk, amount, unit in re.findall(r"(P\d)\s+(\d+)\s*(h|min|m|s)", value):
        values[risk] = int(amount) * _DURATION_UNITS[unit]
    if "P2" not in values:                      # 「P2 无」→ 0，显式补 0 而不是缺键
        if not re.search(r"P2\s*无", value):
            raise FactsError(f"冷却 无法解析 P2：{value!r}")
        values["P2"] = 0
    for risk in ("P0", "P1", "P2"):
        if risk not in values:
            raise FactsError(f"冷却 缺 {risk}：{value!r}")
    return values


class PublishWindow(NamedTuple):
    """发布窗口（§9「工作日 10:00–17:00（UTC+8）」）。"""

    start: str               # "HH:MM"
    end: str                 # "HH:MM"
    timezone: str            # "+08:00"（固定偏移；不依赖 tzdata）
    weekdays: tuple[int, ...]  # ISO 周几，1 = 周一

    def as_default(self) -> dict[str, Any]:
        """配置键 ``config.publish_window`` 的声明默认值（JSON 可存）。"""
        return {
            "start": self.start,
            "end": self.end,
            "timezone": self.timezone,
            "weekdays": list(self.weekdays),
        }


def publish_window() -> PublishWindow:
    value = fact("发布窗口", "M10")
    match = _require(r"工作日\s*(\d{1,2}:\d{2})\s*[–\-~—]\s*(\d{1,2}:\d{2})（UTC\+(\d{1,2})）",
                     value, "发布窗口")
    start, end, offset = match.groups()
    if not re.search(r"工作日", value):
        raise FactsError(f"发布窗口 不是工作日口径：{value!r}")
    for clock in (start, end):
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", clock):
            raise FactsError(f"发布窗口 时刻非法：{clock!r}")
    if start >= end:
        raise FactsError(f"发布窗口 起止倒挂：{value!r}")
    return PublishWindow(start=start, end=end, timezone=f"+{int(offset):02d}:00",
                         weekdays=(1, 2, 3, 4, 5))


def p0_rollback_modes() -> tuple[str, ...]:
    """P0 回滚模式（§9「P0 回滚 只允许人工」→ ('manual',)）。"""
    value = fact("P0 回滚", "M10")
    if "只允许人工" not in value:
        raise FactsError(f"P0 回滚 不再是 manual-only：{value!r}（若产品放开自动回滚需同步改本模块）")
    return ("manual",)


def gray_steps() -> tuple[int, ...]:
    """灰度步长（§9「1% → 5% → 25% → 100%」→ (1, 5, 25, 100)）。"""
    value = fact("灰度", "M10")
    steps = tuple(int(pct) for pct in re.findall(r"(\d+)\s*%", value))
    if not steps:
        raise FactsError(f"灰度 无法解析步长：{value!r}")
    if steps[-1] != 100:
        raise FactsError(f"灰度 末位必须 100：{value!r}")
    if any(b <= a for a, b in zip(steps, steps[1:])):
        raise FactsError(f"灰度 步长必须递增：{value!r}")
    return steps


def drift_scan_policy() -> str:
    """漂移扫描口径（§9「每日扫描；三源对比」）。"""
    return fact("漂移", "M10")


def gas_defaults() -> dict[str, Any]:
    """billing.gas_fee_* 默认值（§9 三个直接键；CR-5 已把默认值补进 facts）。"""
    defaults: dict[str, Any] = {
        "mode": fact("billing.gas_fee_mode", "M10"),
        "bearer": fact("billing.gas_fee_bearer", "M10"),
        "scope": fact("billing.gas_fee_scope", "M10"),
    }
    raw_channel = fact("billing.channel_fee_bps", "M10")
    if not re.fullmatch(r"\d+", raw_channel):
        raise FactsError(f"billing.channel_fee_bps 不是整数：{raw_channel!r}")
    defaults["channel_fee_bps"] = int(raw_channel)
    if defaults["mode"] not in ("INTERNAL", "EXTERNAL"):
        raise FactsError(f"billing.gas_fee_mode 枚举外：{defaults['mode']!r}")
    if defaults["bearer"] not in ("PLATFORM", "PAYER"):
        raise FactsError(f"billing.gas_fee_bearer 枚举外：{defaults['bearer']!r}")
    if defaults["scope"] not in ("global", "chain", "batch"):
        raise FactsError(f"billing.gas_fee_scope 枚举外：{defaults['scope']!r}")
    return defaults


def fee_cap_pct() -> int:
    """平台费率承诺上限（%）（§9「billing.fee_cap_pct = 20」；R-3 已补 facts）。"""
    value = fact("billing.fee_cap_pct", "M10")
    if not re.fullmatch(r"\d{1,3}", value):
        raise FactsError(f"billing.fee_cap_pct 不是整数百分比：{value!r}")
    pct = int(value)
    if not 0 <= pct <= 100:
        raise FactsError(f"billing.fee_cap_pct 越界 0–100：{pct}")
    return pct


def report_daily_send_at() -> str:
    """值班日报发送时刻（HH:MM，UTC+8）（§9；R-2 已补 facts，产品 §23.7 为 01:15）。"""
    value = fact("notify.report.daily_send_at", "M10")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
        raise FactsError(f"notify.report.daily_send_at 不是 HH:MM：{value!r}")
    return value


def approval_timeout() -> timedelta:
    """双人复核作废时长（§8「双人复核 | 4h 作废；step-up ≤5 分钟」）。"""
    value = fact("双人复核", "M01 / M14 / M16")
    match = _require(r"(\d+)\s*h\s*作废", value, "双人复核.作废时长")
    return timedelta(hours=int(match.group(1)))


def step_up_ttl() -> timedelta:
    """step-up 有效期（§8「step-up ≤5 分钟」）。"""
    value = fact("双人复核", "M01 / M14 / M16")
    match = _require(r"step-up\s*≤\s*(\d+)\s*分钟", value, "双人复核.step-up")
    return timedelta(minutes=int(match.group(1)))


def _int_fact(key: str) -> int:
    value = fact(key, "M10")
    if not re.fullmatch(r"-?\d+", value):
        raise FactsError(f"{key} 不是整数：{value!r}")
    return int(value)


def points_defaults() -> dict[str, Any]:
    """points.* 默认值（§9 直接键；K4 = 默认不可转让，仅 admin 可开）。"""
    raw_enabled = fact("points.transfer_enabled", "M10").lower()
    if raw_enabled not in ("true", "false"):
        raise FactsError(f"points.transfer_enabled 不是布尔：{raw_enabled!r}")
    return {
        "transfer_enabled": raw_enabled == "true",
        "transfer_per_tx_cap": _int_fact("points.transfer_per_tx_cap"),
        "transfer_daily_out_cap": _int_fact("points.transfer_daily_out_cap"),
        "transfer_daily_in_cap": _int_fact("points.transfer_daily_in_cap"),
        "transfer_lock_days": _int_fact("points.transfer_lock_days"),
        "redeem_rate_bps": _int_fact("points.redeem_rate_bps"),
    }


def transfer_limits() -> dict[str, int]:
    """COP 转让限额（§12「单笔 1000；单日转出 10000；单日转入 10000；锁定 7 天」）。

    与 §9 的 ``points.transfer_*`` 是同一组事实的两处表述；测试交叉校验两者一致
    （任何一处改了另一处没改 → 红），避免「facts 内部漂移」。
    """
    value = fact("转让限额", "M07")
    per_tx = _require(r"单笔\s*(\d+)", value, "转让限额.单笔")
    daily_out = _require(r"单日转出\s*(\d+)", value, "转让限额.单日转出")
    daily_in = _require(r"单日转入\s*(\d+)", value, "转让限额.单日转入")
    lock_days = _require(r"锁定\s*(\d+)\s*天", value, "转让限额.锁定")
    return {
        "per_tx_cap": int(per_tx.group(1)),
        "daily_out_cap": int(daily_out.group(1)),
        "daily_in_cap": int(daily_in.group(1)),
        "lock_days": int(lock_days.group(1)),
    }


# ────────────────────────────────────────────── §4 费率与预留池（M04 / M08）
def platform_fee_default_bps() -> int:
    """平台费率默认（§4「平台费率默认 1500 bps（15%）」）。"""
    value = fact("平台费率默认", "M04 / M08")
    return int(_require(r"(\d+)\s*bps", value, "平台费率默认").group(1))


def platform_fee_range_bps() -> tuple[int, int, int]:
    """平台费率范围（§4「0–10000 bps；>3000 需决策人二次确认」→ (0, 10000, 3000)）。"""
    value = fact("平台费率范围", "M04 / M08")
    match = _require(r"(\d+)\s*[–\-~]\s*(\d+)\s*bps", value, "平台费率范围")
    threshold = _require(r">\s*(\d+)\s*需决策人二次确认", value, "平台费率二次确认阈值")
    low, high = int(match.group(1)), int(match.group(2))
    if high <= low:
        raise FactsError(f"平台费率范围 倒挂：{value!r}")
    return low, high, int(threshold.group(1))


def share_defaults_bps() -> tuple[int, int, int]:
    """平台 / 共享方分成默认（§4「1500 / 8500 bps，和为 10000」→ (1500, 8500, 10000)）。"""
    value = fact("平台 / 共享方默认", "M04 / M08")
    match = _require(r"(\d+)\s*/\s*(\d+)\s*bps", value, "平台/共享方默认")
    total = _require(r"和为\s*(\d+)", value, "平台/共享方分成总和")
    platform, provider, sum_ = int(match.group(1)), int(match.group(2)), int(total.group(1))
    if platform + provider != sum_:
        raise FactsError(f"平台/共享方分成与总和矛盾：{value!r}")
    return platform, provider, sum_


def reserved_pool() -> dict[str, int]:
    """预留池（§4「默认 30%，可调 10–50%；公共池保底 ≥50%」）。"""
    value = fact("预留池", "M04 / M08")
    default = _require(r"默认\s*(\d+)\s*%", value, "预留池默认")
    span = _require(r"可调\s*(\d+)\s*[–\-~]\s*(\d+)\s*%", value, "预留池可调区间")
    floor = _require(r"公共池保底\s*≥\s*(\d+)\s*%", value, "公共池保底")
    low, high = int(span.group(1)), int(span.group(2))
    result = {"default": int(default.group(1)), "min": low, "max": high,
              "public_floor": int(floor.group(1))}
    if not low <= result["default"] <= high:
        raise FactsError(f"预留池默认值不在区间内：{value!r}")
    return result


def slow_task_discount_pcts() -> tuple[int, int]:
    """慢任务 / 组网折扣（§4「40% off / 50% off」→ (40, 50)）。"""
    value = fact("慢任务 / 组网折扣", "M04 / M08")
    pcts = tuple(int(pct) for pct in re.findall(r"(\d+)\s*%\s*off", value))
    if len(pcts) != 2:
        raise FactsError(f"慢任务 / 组网折扣 解析出 {len(pcts)} 个值（期望 2）：{value!r}")
    return pcts  # type: ignore[return-value]


# ────────────────────────────────────────────── §2 钱包池（M08）
def wallet_cap_usd() -> Decimal:
    """单钱包 cap 的硬上限（§2「单钱包 cap | min(10,000 USD, 5 天预测)」→ Decimal('10000')）。"""
    value = fact("单钱包 cap", "M08")
    match = _require(r"min\(\s*([\d,]+)\s*USD", value, "单钱包 cap")
    return Decimal(match.group(1).replace(",", ""))
