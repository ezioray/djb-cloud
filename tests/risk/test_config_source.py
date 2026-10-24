# SPDX-License-Identifier: AGPL-3.0-or-later
"""M10 risk.* 只读绑定：只解析版本（不读值）+ LKG 降级（INV-01 / §7）。"""
from __future__ import annotations

from datetime import timedelta

from app.risk import config_source
from riskkit import FIXED_NOW


class FakeProvider:
    def __init__(self, versions: dict[str, int], published=None) -> None:
        self.versions = versions
        self.published = published

    def config_version(self, config_ref: str) -> int | None:
        return self.versions.get(config_ref)

    def published_at(self, config_ref: str):
        return self.published


def test_no_config_ref_means_no_stamp() -> None:
    stamp = config_source.stamp_for(None, FakeProvider({}))
    assert stamp.source == "none"
    assert stamp.version is None
    assert stamp.as_dict() == {"config_ref": None, "config_version": None,
                               "config_source": "none"}


def test_live_m10_version_is_stamped_without_values() -> None:
    provider = FakeProvider({"risk.case.auto_action": 7}, published=FIXED_NOW - timedelta(hours=1))
    stamp = config_source.stamp_for("risk.case.auto_action", provider, now=FIXED_NOW)
    assert stamp.source == "m10"
    assert stamp.version == 7
    assert set(stamp.as_dict()) == {"config_ref", "config_version", "config_source"}


def test_stale_version_degrades_to_lkg() -> None:
    provider = FakeProvider({"risk.case.auto_action": 7},
                            published=FIXED_NOW - timedelta(hours=25))
    stamp = config_source.stamp_for("risk.case.auto_action", provider, now=FIXED_NOW)
    assert stamp.source == "lkg"
    assert stamp.version == 7                     # 只降级处置能力，不读任何阈值


def test_missing_version_degrades_to_lkg() -> None:
    stamp = config_source.stamp_for("risk.limit.qps", FakeProvider({}), now=FIXED_NOW)
    assert stamp.source == "lkg"
    assert stamp.version is None


def test_null_provider_is_lkg() -> None:
    stamp = config_source.stamp_for("risk.limit.qps", None, now=FIXED_NOW)
    assert stamp.source == "lkg"
