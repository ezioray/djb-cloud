# SPDX-License-Identifier: Apache-2.0
"""边界门禁：无跨模块 import、迁移段正确、不转发事件、不碰只读适配器、facts 纪律。

对应 `tools/ci/architecture_check.py` / `migration_check.py` / `_boundary-checks.md`：
这些检查本应由 CI 兜底，模块测试先跑一遍，失败信息更具体。
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app.config_center import migrate, registry

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "app" / "config_center"
MIGRATIONS = ROOT / "migrations"

IMPORT_RE = re.compile(r"^\s*(?:from\s+app\.([a-zA-Z0-9_]+)|import\s+app\.([a-zA-Z0-9_]+))")


def package_files() -> list[pathlib.Path]:
    return sorted(PACKAGE.glob("*.py"))


def test_package_has_no_cross_module_imports():
    violations = []
    for path in package_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = IMPORT_RE.match(line)
            if not match:
                continue
            module = match.group(1) or match.group(2)
            if module != "config_center":
                violations.append(f"{path.name}:{lineno}: import app.{module}")
    assert not violations, f"跨模块 import：{violations}"


def test_package_does_not_import_readonly_adapter_or_api():
    """ops_center.py / app/api.py 是只读适配器与共享入口，M10 领域层不得 import 它们。"""
    offenders = []
    for path in package_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = IMPORT_RE.match(line)
            module = (match.group(1) or match.group(2)) if match else None
            if module in ("admin", "api"):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
            if re.match(r"^\s*from\s+\.\.(admin|api)\b", line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, f"import 了只读适配器 / 共享入口：{offenders}"


def test_relative_imports_stay_inside_package():
    """本包只用 ``from .`` 引用自身模块，不得出现 ``from ..``（越出包边界）。"""
    offenders = []
    for path in package_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if re.match(r"^\s*from\s+\.\.", line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, f"跨包相对 import：{offenders}"


def test_migration_segment_is_1000_to_1099_and_unique():
    numbers = {}
    for path in MIGRATIONS.glob("*.sql"):
        match = re.match(r"^(\d{3,4})_[a-z0-9_]+\.sql$", path.name)
        assert match is not None, f"{path.name} 不符合 NNNN_name.sql"
        number = int(match.group(1))
        assert number not in numbers, f"{path.name} 与 {numbers[number]} 编号重复"
        numbers[number] = path.name
    module_numbers = sorted(n for n in numbers if 1000 <= n <= 1099)
    assert module_numbers == list(range(1000, 1009))                      # 1000–1008
    assert len(migrate.MODULE_MIGRATIONS) == 9
    assert set(migrate.MODULE_MIGRATIONS) == {numbers[n] for n in module_numbers}
    # 迁移段独占：M11 的 1100+ 尚未出现，本任务不越界
    assert all(n < 1100 for n in module_numbers)


def test_base_migrations_exclude_module_files():
    assert all(not re.match(r"^10\d\d_", name) for name in migrate.BASE_MIGRATIONS)
    assert "001_init.sql" in migrate.BASE_MIGRATIONS
    assert "100_identity_core.sql" in migrate.BASE_MIGRATIONS
    assert "1000_config_items.sql" not in migrate.BASE_MIGRATIONS
    assert migrate.M10_TABLES == ("config_items", "config_versions",
                                  "config_publish_requests", "config_snapshots", "config_drifts",
                                  "config_outbox")


def test_migrations_do_not_touch_other_modules_tables():
    """M10 迁移只创建 config_* 表 / m10_* 函数；不得 ALTER / DROP 存量对象。"""
    for name in migrate.MODULE_MIGRATIONS:
        sql = (MIGRATIONS / name).read_text(encoding="utf-8")
        # 去掉注释行后再找 DDL 动词
        body = "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))
        # 允许 ALTER 自己的 config_* 表（1006 给发布单加列/约束），其它模块的表一个都不许碰
        assert not re.search(r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?!config_)[a-z_]", body, re.I), name
        assert not re.search(r"\bDROP\s+(TABLE|VIEW|COLUMN)\b", body, re.I), name
        for table in re.findall(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-z0-9_]+)", body, re.I):
            assert table.startswith("config_"), f"{name} 建了非本模块表 {table}"
        for func in re.findall(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+([a-zA-Z0-9_]+)", body, re.I):
            assert func.startswith("m10_"), f"{name} 建了非本模块函数 {func}"


def test_registry_has_no_duplicated_facts_numbers():
    """注册表里的默认值必须能追到 facts/spec/policy/unset 四类来源之一，且 facts 来源可复算。"""
    from app.config_center import facts

    fact_defaults = {
        "billing.service_fee_bps": facts.platform_fee_default_bps(),
        "pool.reserved_default": facts.reserved_pool()["default"],
        "treasury.platform_share_bps": facts.share_defaults_bps()[0],
        "treasury.provider_share_bps": facts.share_defaults_bps()[1],
        "points.transfer_per_tx_cap": facts.points_defaults()["transfer_per_tx_cap"],
        "config.p0_cooldown_h": facts.cooldowns()["P0"] // 3600,
        "billing.fee_cap_pct": facts.fee_cap_pct(),
        "notify.report.daily_send_at": facts.report_daily_send_at(),
    }
    reg = registry.load()
    for key, expected in fact_defaults.items():
        item = reg.require(key)
        assert item.default_source.startswith("facts:")
        assert item.default == expected, f"{key} 默认值与 facts 不一致"
