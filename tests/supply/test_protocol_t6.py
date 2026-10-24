# SPDX-License-Identifier: AGPL-3.0-or-later
"""协议能力 / 弃用清单（M02 §1 / INV-05 / spec ProtocolCapabilities · DeprecationList）。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.supply import facts, protocol
from app.supply.errors import InvalidArgument, ProtocolIncompatible


def _entry(**overrides):
    deprecated = datetime(2026, 1, 1, tzinfo=timezone.utc)
    entry = {"path": "/api/v1/node/legacy", "method": "POST",
             "deprecated_at": deprecated.isoformat().replace("+00:00", "Z"),
             "sunset_at": (deprecated + timedelta(days=120)).isoformat().replace("+00:00", "Z"),
             "replacement": "/api/v1/node/new", "supported_majors": ["1", "2"]}
    entry.update(overrides)
    return entry


# --------------------------------------------------------------------------- 能力清单
def test_capability_catalog_is_well_formed():
    ids = [item["id"] for item in protocol.CAPABILITIES]
    assert len(set(ids)) == len(ids)
    assert len(ids) == len(protocol.SERVER_CAPABILITIES)
    for item in protocol.CAPABILITIES:
        assert item["status"] in facts.CAPABILITY_STATUSES
        assert item["version"].isdigit()


def test_capabilities_payload_contains_spec_required_fields():
    moment = datetime(2026, 10, 23, tzinfo=timezone.utc)
    payload = protocol.capabilities_payload(server_time=moment)
    assert set(payload) >= {"protocol_version", "min_supported_version", "capabilities",
                            "server_time"}
    assert payload["protocol_version"] == facts.PROTOCOL_VERSION
    assert payload["min_supported_version"] == protocol.min_supported_version()
    assert payload["server_time"].endswith("Z")
    for item in payload["capabilities"]:
        assert set(item) == {"id", "version", "status"}


def test_capabilities_intersection_ignores_unknown():
    payload = protocol.capabilities_payload(server_time=datetime.now(timezone.utc),
                                            client_capabilities=["policy_etag", "brand_new"])
    assert payload["enabled"] == ["policy_etag"]
    # 未知 capability 不报错，清单仍返回全部服务端能力
    assert len(payload["capabilities"]) == len(protocol.CAPABILITIES)


def test_parse_capability_header():
    assert protocol.parse_capability_header("a, b ,c") == ["a", "b", "c"]
    assert protocol.parse_capability_header("") == []
    assert protocol.parse_capability_header(None) == []
    assert protocol.parse_capability_header(" , ") == []


def test_capability_header_protocol_guard():
    """spec：客户端带 DJB-Protocol-Version 且不受支持 → 426/42601。"""
    with pytest.raises(ProtocolIncompatible) as excinfo:
        protocol.check("2.0.0")
    assert excinfo.value.code == "42601"


# --------------------------------------------------------------------------- 弃用清单
def test_deprecations_payload_is_empty_at_s1():
    payload = protocol.deprecations_payload()
    assert payload["items"] == []
    assert payload["protocol_version"] == facts.PROTOCOL_VERSION


def test_validate_deprecation_accepts_a_compliant_entry():
    assert protocol.validate_deprecation(_entry()) is None


@pytest.mark.parametrize("overrides,field", [
    ({"path": ""}, "path"),
    ({"method": ""}, "method"),
    ({"deprecated_at": ""}, "deprecated_at"),
    ({"sunset_at": ""}, "sunset_at"),
])
def test_validate_deprecation_requires_fields(overrides, field):
    with pytest.raises(InvalidArgument) as excinfo:
        protocol.validate_deprecation(_entry(**overrides))
    assert excinfo.value.details["field"] == field


def test_validate_deprecation_requires_90_days_notice():
    deprecated = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(InvalidArgument) as excinfo:
        protocol.validate_deprecation(_entry(
            sunset_at=(deprecated + timedelta(days=89)).isoformat().replace("+00:00", "Z")))
    assert excinfo.value.details["field"] == "sunset_at"


def test_validate_deprecation_requires_two_majors():
    with pytest.raises(InvalidArgument) as excinfo:
        protocol.validate_deprecation(_entry(supported_majors=["1"]))
    assert excinfo.value.details["field"] == "supported_majors"
    with pytest.raises(InvalidArgument):
        protocol.validate_deprecation(_entry(supported_majors="1,2"))


def test_deprecation_filter_by_major(monkeypatch):
    monkeypatch.setattr(protocol, "DEPRECATIONS", (_entry(),))
    assert len(protocol.deprecations_payload()["items"]) == 1
    assert len(protocol.deprecations_payload(protocol_major=1)["items"]) == 1
    assert protocol.deprecations_payload(protocol_major=9)["items"] == []


def test_deprecation_filter_rejects_bad_major():
    with pytest.raises(InvalidArgument):
        protocol.deprecations_payload(protocol_major=0)
    with pytest.raises(InvalidArgument):
        protocol.deprecations_payload(protocol_major=True)      # type: ignore[arg-type]
    with pytest.raises(InvalidArgument):
        protocol.deprecations_payload(protocol_major="1")       # type: ignore[arg-type]
