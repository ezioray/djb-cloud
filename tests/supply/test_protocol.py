# SPDX-License-Identifier: Apache-2.0
"""协议矩阵（INV-05 / M02 §1）：N / N-1 / N-2、42601 与能力交集。纯函数。"""
from __future__ import annotations

import pytest

from app.supply import facts, protocol
from app.supply.errors import InvalidArgument, ProtocolIncompatible


def test_parse_accepts_semver_triples():
    assert protocol.parse("1.0.0") == (1, 0, 0)
    assert protocol.parse("12.34.56") == (12, 34, 56)
    assert protocol.parse(" 2.1.0 ") == (2, 1, 0)


@pytest.mark.parametrize("value", ["1.0", "v1.0.0", "1.0.0-rc1", "", "1,0,0", None, 100])
def test_parse_rejects_malformed_versions(value):
    with pytest.raises(InvalidArgument) as excinfo:
        protocol.parse(value)
    assert excinfo.value.code == "40001"


def test_supported_majors_is_n_to_n_minus_2():
    assert protocol.supported_majors("1.0.0") == (1, 0)
    assert protocol.supported_majors("3.0.0") == (3, 2, 1)
    # 不出现负 MAJOR
    assert protocol.supported_majors("0.9.0") == (0,)


def test_min_supported_version():
    assert protocol.min_supported_version("1.0.0") == "0.0.0"
    assert protocol.min_supported_version("3.0.0") == "1.0.0"


@pytest.mark.parametrize("client,server,expected", [
    ("1.0.0", "1.0.0", True),        # N
    ("0.9.0", "1.0.0", True),        # N-1
    ("0.7.3", "1.0.0", True),        # 同 MAJOR 更低 MINOR 仍兼容
    ("2.0.0", "1.0.0", False),       # N+1：客户端过新
    ("2.5.0", "3.0.0", True),        # N-1
    ("0.9.0", "3.0.0", False),       # N-3 → 越界
])
def test_is_supported_matrix(client, server, expected):
    assert protocol.is_supported(client, server_version=server) is expected


def test_a4_client_n_minus_3_gets_42601_with_min_version():
    """验收 A4：客户端协议 N-3 → 42601 + min_supported_version。"""
    with pytest.raises(ProtocolIncompatible) as excinfo:
        protocol.check("0.9.0", server_version="3.0.0")
    err = excinfo.value
    assert err.status_code == 426
    assert err.code == "42601"
    assert err.details["min_supported_version"] == "1.0.0"
    assert err.details["server_version"] == "3.0.0"
    assert "升级" in err.details["upgrade_hint"]


def test_newer_major_hint_tells_client_to_wait_for_server():
    with pytest.raises(ProtocolIncompatible) as excinfo:
        protocol.check("9.0.0")
    assert "高于" in excinfo.value.details["upgrade_hint"]


def test_check_returns_parsed_triple_when_supported():
    assert protocol.check("1.2.3") == (1, 2, 3)


def test_capability_intersection_ignores_unknown():
    client = ["capacity_announcement", "brand_new_thing"]
    assert protocol.capability_intersection(client) == ["capacity_announcement"]
    assert protocol.capability_intersection([]) == sorted(protocol.SERVER_CAPABILITIES)
    assert protocol.capability_intersection(None) == sorted(protocol.SERVER_CAPABILITIES)
    assert protocol.capability_intersection(["x"], server=[]) == []


def test_server_capabilities_are_declared_once():
    assert len(set(protocol.SERVER_CAPABILITIES)) == len(protocol.SERVER_CAPABILITIES)
    assert "runtime_state" in protocol.SERVER_CAPABILITIES
