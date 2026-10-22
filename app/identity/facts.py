# SPDX-License-Identifier: Apache-2.0
"""M01 事实常量：唯一来源是 ``contracts/facts.yaml``（CR-4）。

背景：M01 §8.2 与本模块相关的数字（五态、冻结上限、八角色、会话 TTL、step-up）在
03-facts §8 已冻结。T1 把它们抄在 ``models.py`` 顶部（当时 facts.yaml 还没落地），
T2 起改为**运行时读取**机器源，模块里不再写字面量。

解析策略：facts.yaml 是给人看的投影（值是自然语言，如「30 分钟滑动 / 15 分钟空闲 /
12 小时绝对」），因此这里用**严格正则**抽取数字：模式对不上就抛 ``FactsContractError``
（带 key 与原始值），由 CI/单测立刻暴露契约漂移——绝不静默回退到默认值。

模块内**非** facts 的常量（本模块内部算法常量，03-facts §13.4 明确不覆盖）仍留在
``models.py``：Key 前缀长度、Key 熵、单账户 Key 上限、默认 QPS、邀请 TTL、
待验证清理期限、访问 / 刷新令牌 TTL、org 角色、配额种类等（出处 M01 §8.1 / §8.2）。
"""
from __future__ import annotations

import os
import pathlib
import re
from functools import lru_cache
from typing import Any, Iterable

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FACTS_PATH = REPO_ROOT / "contracts" / "facts.yaml"
FACTS_ENV = "DJB_FACTS_FILE"

# 本模块依赖的 03-facts §8 行（账户、权限与保留）
SECTION_ID = 8


class FactsContractError(RuntimeError):
    """facts.yaml 与本模块期望的形状不一致（漂移 / 生成器变更 / 手改）。"""


# --------------------------------------------------------------------------- 读取
def facts_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get(FACTS_ENV) or FACTS_PATH)


def load(path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """读 facts.yaml（不缓存；缓存见 :func:`section`）。"""
    target = pathlib.Path(path) if path is not None else facts_path()
    try:
        return yaml.safe_load(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:                       # pragma: no cover - 部署缺文件
        raise FactsContractError(f"facts.yaml 缺失：{target}") from exc
    except yaml.YAMLError as exc:                          # pragma: no cover - 生成器坏了
        raise FactsContractError(f"facts.yaml 解析失败：{target}: {exc}") from exc


def _sections(doc: dict[str, Any]) -> Iterable[dict[str, Any]]:
    sections = doc.get("sections")
    if not isinstance(sections, list):
        raise FactsContractError("facts.yaml 缺 sections 列表")
    return sections


def section(section_id: int = SECTION_ID, path: pathlib.Path | str | None = None) -> dict[str, str]:
    """把某一节折成 ``{key: value}``；重复 key 直接报错（生成器保证唯一）。"""
    for item in _sections(load(path)):
        if int(item.get("id", -1)) != section_id:
            continue
        out: dict[str, str] = {}
        for fact in item.get("facts") or []:
            key = str(fact.get("key", "")).strip()
            if not key:
                raise FactsContractError(f"§{section_id} 存在空 key")
            if key in out:
                raise FactsContractError(f"§{section_id} key 重复：{key}")
            out[key] = str(fact.get("value", "")).strip()
        if not out:
            raise FactsContractError(f"§{section_id} 没有任何 fact")
        return out
    raise FactsContractError(f"facts.yaml 找不到 §{section_id}")


# --------------------------------------------------------------------------- 解析工具
def _value(facts: dict[str, str], key: str) -> str:
    if key not in facts:
        raise FactsContractError(f"§{SECTION_ID} 缺 key：{key}")
    return facts[key]


def _grep(pattern: str, value: str, key: str, *, cast=int):
    match = re.search(pattern, value)
    if match is None:
        raise FactsContractError(f"§{SECTION_ID}「{key}」形状不符：{value!r} 不匹配 /{pattern}/")
    return cast(match.group(1))


def _states(value: str) -> tuple[str, ...]:
    """从「pending_verify → normal ⇄ frozen(frozen_until) → closing(30d) → closed」抽状态名。"""
    cleaned = re.sub(r"\([^)]*\)", "", value)              # 去掉括号内的补充说明
    names = re.findall(r"[a-z][a-z_]+", cleaned)
    if len(names) < 2:
        raise FactsContractError(f"§{SECTION_ID}「账户状态」解析不出状态：{value!r}")
    return tuple(dict.fromkeys(names))


# --------------------------------------------------------------------------- 常量（导入即校验）
@lru_cache(maxsize=1)
def constants(path: str | None = None) -> dict[str, Any]:
    """把 §8 归一成模块可直接用的类型；任何形状不符都抛错（fail fast）。"""
    facts = section(SECTION_ID, path)

    state_value = _value(facts, "账户状态")
    freeze_value = _value(facts, "冻结上限")
    role_value = _value(facts, "后台角色")
    step_up_value = _value(facts, "双人复核")
    session_value = _value(facts, "会话")

    return {
        "account_states": _states(state_value),
        # 「closing(30d)」→ 冷静期 30 天
        "closing_cooloff_days": _grep(r"closing\((\d+)d\)", state_value, "账户状态"),
        # 「单次 ≤180 天」→ 冻结上限
        "freeze_max_days": _grep(r"≤\s*(\d+)\s*天", freeze_value, "冻结上限"),
        # 「8 个：SUPER / SVC / ...」→ 八角色（顺序即口径，按 facts 排）
        "admin_roles": tuple(part.strip() for part in role_value.split("：", 1)[-1].split("/")),
        "dual_control_expiry_hours": _grep(r"(\d+)\s*h\s*作废", step_up_value, "双人复核"),
        "step_up_minutes": _grep(r"step-up\s*≤\s*(\d+)\s*分钟", step_up_value, "双人复核"),
        "session_slide_minutes": _grep(r"(\d+)\s*分钟滑动", session_value, "会话"),
        "session_idle_minutes": _grep(r"(\d+)\s*分钟空闲", session_value, "会话"),
        "session_absolute_hours": _grep(r"(\d+)\s*小时绝对", session_value, "会话"),
    }


def reload(path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """清缓存后重读（测试 / 热更新用）。"""
    constants.cache_clear()
    return constants(str(path) if path is not None else None)


_CONST = constants()

# 五态（顺序即账户状态机的状态序）
ACCOUNT_STATES: tuple[str, ...] = _CONST["account_states"]
FREEZE_MAX_DAYS: int = _CONST["freeze_max_days"]
CLOSING_COOLOFF_DAYS: int = _CONST["closing_cooloff_days"]
ADMIN_ROLES: tuple[str, ...] = _CONST["admin_roles"]
STEP_UP_MINUTES: int = _CONST["step_up_minutes"]
DUAL_CONTROL_EXPIRY_HOURS: int = _CONST["dual_control_expiry_hours"]
SESSION_SLIDE_MINUTES: int = _CONST["session_slide_minutes"]
SESSION_IDLE_MINUTES: int = _CONST["session_idle_minutes"]
SESSION_ABSOLUTE_HOURS: int = _CONST["session_absolute_hours"]

__all__ = [
    "FACTS_PATH", "FACTS_ENV", "SECTION_ID", "FactsContractError",
    "facts_path", "load", "section", "constants", "reload",
    "ACCOUNT_STATES", "FREEZE_MAX_DAYS", "CLOSING_COOLOFF_DAYS", "ADMIN_ROLES",
    "STEP_UP_MINUTES", "DUAL_CONTROL_EXPIRY_HOURS",
    "SESSION_SLIDE_MINUTES", "SESSION_IDLE_MINUTES", "SESSION_ABSOLUTE_HOURS",
]
