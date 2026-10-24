# SPDX-License-Identifier: AGPL-3.0-or-later
"""特性开关契约：三字段（owner / expire_at / rollback_rule）+ 默认关闭 + 无可写面。

硬约束第 4 条：特性开关必须带三字段、默认关闭；T1/T2 不引入可写开关。
"""
from __future__ import annotations

from datetime import date

import pytest

from app.config_center import features
from app.config_center.features import FEATURE_SWITCHES, WRITE_SURFACE, FeatureSwitch


def test_every_switch_has_three_fields_and_defaults_off():
    assert FEATURE_SWITCHES, "至少登记一个开关（T3/T4 要接线）"
    for switch in FEATURE_SWITCHES:
        assert switch.owner.strip()
        assert isinstance(switch.expire_at, date)
        assert len(switch.rollback_rule.strip()) >= 8
        assert switch.default is False
        assert switch.name.startswith("config_center.")


def test_all_switches_disabled_in_t1_t2():
    for switch in FEATURE_SWITCHES:
        assert features.enabled(switch.name) is False


def test_no_writable_surface():
    """T1/T2 不提供任何运行时写入口（不是「默认关闭」，是「根本改不了」）。"""
    assert WRITE_SURFACE == ()
    public = {name for name in dir(features)
              if not name.startswith("_") and not name.isupper()}
    verbs = ("set_", "enable_", "disable_", "toggle_", "flip_", "write_", "update_", "force_")
    suspicious = {name for name in public if name.lower().startswith(verbs)}
    assert not suspicious, f"features 暴露了写入口：{suspicious}"


def test_unknown_switch_raises():
    with pytest.raises(KeyError):
        features.get("config_center.not_registered")
    with pytest.raises(KeyError):
        features.enabled("config_center.not_registered")


@pytest.mark.parametrize("overrides", [
    {"default": True},
    {"owner": ""},
    {"owner": "   "},
    {"expire_at": "2027-01-01"},
    {"rollback_rule": "关掉"},
    {"name": "notdot"},
])
def test_bad_switch_definitions_are_rejected(overrides):
    fields = dict(name="config_center.x", owner="config-seat", expire_at=date(2027, 1, 1),
                  rollback_rule="关闭即回滚到上一个链路", default=False)
    fields.update(overrides)
    with pytest.raises(ValueError):
        FeatureSwitch(**fields)


def test_as_dict_shape():
    payload = FEATURE_SWITCHES[0].as_dict()
    assert set(payload) == {"name", "owner", "expire_at", "rollback_rule", "default", "description"}
    assert payload["expire_at"] == FEATURE_SWITCHES[0].expire_at.isoformat()
    assert payload["default"] is False


def test_switch_names_are_unique_and_planned_coverage():
    names = [switch.name for switch in FEATURE_SWITCHES]
    assert len(names) == len(set(names))
    # T3/T4 需要的四个接线点都已登记（灰度 / 漂移 / kill switch / git 直连）
    assert set(names) == {
        "config_center.gray_rollout",
        "config_center.drift_scan",
        "config_center.kill_switch",
        "config_center.publish_from_git",
    }
