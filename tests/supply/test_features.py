# SPDX-License-Identifier: AGPL-3.0-or-later
"""特性开关登记（硬约束第 4 条）：三字段 + 默认关闭 + 无可写面。"""
from __future__ import annotations

from datetime import date

import pytest

from app.supply import features


def test_every_switch_has_the_three_mandatory_fields():
    for switch in features.switches():
        assert switch.owner.strip(), switch.name
        assert isinstance(switch.expire_at, date), switch.name
        assert len(switch.rollback_rule.strip()) >= 8, switch.name


def test_every_switch_is_closed_by_default():
    for switch in features.switches():
        assert switch.default is False, switch.name
        assert features.enabled(switch.name) is False


def test_there_is_no_write_surface():
    assert features.WRITE_SURFACE == ()


def test_switch_names_are_unique_and_namespaced():
    names = [switch.name for switch in features.switches()]
    assert len(set(names)) == len(names)
    assert all(name.startswith("supply.") for name in names)


def test_unregistered_switch_raises_keyerror():
    with pytest.raises(KeyError):
        features.get("supply.not_registered")


def test_as_dict_is_serializable():
    payload = features.switches()[0].as_dict()
    assert set(payload) == {"name", "owner", "expire_at", "rollback_rule", "default",
                            "description"}
    assert isinstance(payload["expire_at"], str)


@pytest.mark.parametrize("overrides,message", [
    ({"name": "noprefix"}, "开关名"),
    ({"owner": " "}, "owner"),
    ({"expire_at": "2027-01-01"}, "expire_at"),
    ({"rollback_rule": "short"}, "rollback_rule"),
    ({"default": True}, "默认必须关闭"),
])
def test_switch_validation_rejects_bad_definitions(overrides, message):
    params = {"name": "supply.ok", "owner": "supply-seat", "expire_at": date(2027, 1, 1),
              "rollback_rule": "关闭开关后回到上一个行为，历史数据保留"}
    params.update(overrides)
    with pytest.raises(ValueError) as excinfo:
        features.FeatureSwitch(**params)
    assert message in str(excinfo.value)
