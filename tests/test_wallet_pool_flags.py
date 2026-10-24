# SPDX-License-Identifier: AGPL-3.0-or-later
"""钱包池特性开关到期强制关（审计 AUDIT-DEVSTATUS P2-6）。

纯函数用例，不依赖数据库：到期后即使环境变量/override 打开也必须为 False，
且 expire_at 非法时 fail-closed。
"""
from __future__ import annotations

from datetime import date

from app import wallet_pool as wp


def test_flag_enabled_before_expiry(monkeypatch):
    monkeypatch.setenv("DJB_FF_WALLET_POOL_V2", "1")
    assert wp.flag_enabled("wallet_pool_v2", today=date(2026, 12, 30)) is True


def test_flag_enabled_forced_off_on_expiry_day_after(monkeypatch):
    monkeypatch.setenv("DJB_FF_WALLET_POOL_V2", "1")
    assert wp.flag_enabled("wallet_pool_v2", today=date(2026, 12, 31)) is True
    assert wp.flag_enabled("wallet_pool_v2", today=date(2027, 1, 1)) is False


def test_override_cannot_bypass_expiry(monkeypatch):
    monkeypatch.setenv("DJB_FF_WALLET_POOL_V2", "1")
    assert wp.flag_enabled("wallet_pool_v2", override=True,
                           today=date(2027, 1, 1)) is False


def test_invalid_expire_at_fails_closed(monkeypatch):
    monkeypatch.setenv("DJB_FF_WALLET_POOL_V2", "1")
    flag = wp.FeatureFlag(name="wallet_pool_v2", default=False, owner="cloud-dev",
                          expire_at="not-a-date", rollback_rule="test")
    assert wp.flag_expired(flag, today=date(2026, 10, 24)) is True
    assert wp.flag_enabled(flag, today=date(2026, 10, 24)) is False


def test_flag_expired_reflects_expire_at(monkeypatch):
    assert wp.flag_expired("wallet_pool_v2", today=date(2026, 12, 31)) is False
    assert wp.flag_expired("wallet_pool_v2", today=date(2027, 1, 1)) is True
