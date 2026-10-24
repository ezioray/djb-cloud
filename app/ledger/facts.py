# SPDX-License-Identifier: AGPL-3.0-or-later
"""M06 常量的事实源读取层：``contracts/facts.yaml``（W0-QA 生成的机器源）。

纪律（03-facts §13 / 任务卡 T2 第 3 条）：
  · **只读**：不写、不缓存落盘、不复制业务数字；facts.yaml 变了本模块读到的就变；
  · 不给运行时加依赖：facts.yaml 的形状由 tools/gen_facts.py 固定（sections → facts →
    key/value/note），这里实现一个够用的最小解析器；测试用 ``yaml.safe_load`` 交叉验证，
    防止事实源换了形状却静默读空；
  · 缺失即报错（``FactsError``），不静默降级：账本宁可起不来，也不能用猜出来的常量。

facts.yaml 里 M06 段只有「散文级」事实（科目数 42 / 资金事件 E1–E17 / 整数最小单位 /
Merkle 四类根）。**42 个科目码本身与枚举清单不在其中**，它们以
``product/v4/src/20-payment-ledger.md`` §20.2/§20.4.4 与 spec 1.2.0 的 SourceType 为准，
在 :mod:`app.ledger.constants` 单点定义，并由 ``tests/ledger/test_facts.py`` 与数据库
CHECK 约束逐条对齐（见证据 §风险 R-1）。
"""
from __future__ import annotations

import os
import pathlib
import re
from functools import lru_cache

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_FACTS_PATH = _REPO_ROOT / "contracts" / "facts.yaml"


class FactsError(RuntimeError):
    """facts.yaml 缺失 / 形状不符 / 关键事实读不出来。"""


def facts_path() -> pathlib.Path:
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
    fact: dict | None = None
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
                fact = None
                continue
            top = _TOP_RE.match(stripped)
            if top:
                doc["top"][top.group(1)] = _unquote(top.group(2))
                section = None
            continue

        if section is None:
            continue
        # 缩进 2 = 段字段或新的事实项；缩进 4 = 事实项字段（key/value/note）
        if indent <= 2 and stripped.startswith("- key:"):
            fact = {"key": _unquote(stripped.split(":", 1)[1]), "value": "", "note": ""}
            section["facts"].append(fact)
            continue
        if indent <= 2:
            for field in ("title", "owner"):
                if stripped.startswith(f"{field}:"):
                    section[field] = _unquote(stripped.split(":", 1)[1])
                    break
            continue
        if fact is not None:
            for field in ("key", "value", "note"):
                if stripped.startswith(f"{field}:"):
                    fact[field] = _unquote(stripped.split(":", 1)[1])
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


def section(owner: str) -> dict:
    """按 owner 取段（M06 段在 03-facts 是「账本」）。"""
    for sec in load()["sections"]:
        if sec["owner"] == owner:
            return sec
    raise FactsError(f"facts.yaml 中没有 owner={owner} 的段")


def section_facts(owner: str) -> dict[str, str]:
    return {f["key"]: f["value"] for f in section(owner)["facts"]}


def _require(key: str, owner: str = "M06") -> str:
    facts = section_facts(owner)
    if key not in facts or not facts[key]:
        raise FactsError(f"facts.yaml M06 段缺关键事实：{key!r}")
    return facts[key]


# ────────────────────────────────────────────── M06 专用读取器
_GROUP_RE = re.compile(r"([^\d\s/（）]+)\s*(\d+)")


def coa_count() -> int:
    """科目总数（03-facts §6「科目数 42（资产 12 / …）」）。"""
    value = _require("科目数")
    match = re.match(r"\s*(\d+)", value)
    if not match:
        raise FactsError(f"科目数无法解析：{value!r}")
    return int(match.group(1))


def coa_group_counts() -> dict[str, int]:
    """分组科目数：{资产: 12, 负债权益: 12, 收入: 6, 费用损失: 10, 非现金: 2}。"""
    value = _require("科目数")
    inner = value[value.find("（") + 1: value.rfind("）")] if "（" in value else ""
    groups = {name.strip(): int(count) for name, count in _GROUP_RE.findall(inner)}
    if not groups:
        raise FactsError(f"科目分组无法解析：{value!r}")
    return groups


_EVENT_RANGE_RE = re.compile(r"^E(\d+)\s*[–\-~]\s*E(\d+)$")


def event_types() -> tuple[str, ...]:
    """资金事件白名单（03-facts §6「E1–E17」）。"""
    value = _require("资金事件").strip()
    match = _EVENT_RANGE_RE.match(value)
    if not match:
        raise FactsError(f"资金事件无法解析：{value!r}")
    low, high = int(match.group(1)), int(match.group(2))
    if high < low:
        raise FactsError(f"资金事件区间倒挂：{value!r}")
    return tuple(f"E{i}" for i in range(low, high + 1))


def merkle_kinds() -> tuple[str, ...]:
    """Merkle 根类别（四类：journal / audit / por / daily_close；M06 只拥有其中两类）。

    值形如 ``journal / audit / por / daily_close 四类根``：只取 ASCII 标识符，
    这样后面跟着的中文说明（"四类根"）不会混进来。
    """
    value = _require("Merkle")
    kinds = tuple(re.findall(r"[a-z][a-z0-9_]*", value))
    if not kinds:
        raise FactsError(f"Merkle 类别无法解析：{value!r}")
    return kinds


def amount_unit() -> str:
    """记账单位说明（整数最小单位；不 UPDATE/DELETE）。"""
    return _require("记账单位")
