# SPDX-License-Identifier: Apache-2.0
"""协议版本与能力协商（M02 §1 / INV-05 / §6 版本与弃用）。

规则（spec 1.2.0 / 04-api-contracts §6）：

* 只支持 **N / N-1 / N-2** 三个 MAJOR；MAJOR 越界 → ``42601`` + ``min_supported_version``；
* 未知 capability **忽略不报错**（双方只启用交集；交集计算在 T6 的
  ``/api/v1/protocol/capabilities`` 落地）；
* 更早版本（合法但低于当前 MINOR）只读 + 保守模式（T6 落地）。

本文件只放**纯函数**（无 DB、无 IO），T2 的注册 / pair / 审核复用它做 42601 判定。
"""
from __future__ import annotations

import re

from . import facts
from .errors import InvalidArgument, ProtocolIncompatible

_PATTERN = re.compile(facts.PROTOCOL_PATTERN)

#: S1 服务端能力清单（spec ``ProtocolCapabilities``：id / version / status）
CAPABILITIES: tuple[dict[str, str], ...] = (
    {"id": "capacity_announcement", "version": "1", "status": "stable"},
    {"id": "policy_etag", "version": "1", "status": "stable"},
    {"id": "protocol_deprecations", "version": "1", "status": "stable"},
    {"id": "runtime_state", "version": "1", "status": "beta"},
    {"id": "upstream_probe_receipt", "version": "1", "status": "stable"},
)
SERVER_CAPABILITIES: tuple[str, ...] = tuple(item["id"] for item in CAPABILITIES)

#: 弃用清单（spec ``DeprecationList``）。S1 尚无弃用；条目必须满足 ≥90 天 + ≥2 MAJOR 才能登记。
DEPRECATIONS: tuple[dict[str, object], ...] = ()


def parse(version: str, *, field: str = "protocol_version") -> tuple[int, int, int]:
    """``MAJOR.MINOR.PATCH`` → 三元组；形态不合法即 40001（spec pattern）。"""
    if not isinstance(version, str) or not _PATTERN.match(version.strip()):
        raise InvalidArgument(f"{field} 必须形如 1.0.0", field=field)
    major, minor, patch = (int(part) for part in version.strip().split("."))
    return major, minor, patch


def supported_majors(server_version: str = facts.PROTOCOL_VERSION) -> tuple[int, ...]:
    """N / N-1 / N-2（INV-05）：返回**降序**的 MAJOR 列表（不出现负 MAJOR）。"""
    server_major = parse(server_version, field="server_version")[0]
    floor = max(0, server_major - (facts.PROTOCOL_SUPPORT_DEPTH - 1))
    return tuple(range(server_major, floor - 1, -1))


def min_supported_version(server_version: str = facts.PROTOCOL_VERSION) -> str:
    """兼容下限（42601 的 ``min_supported_version``）。"""
    return f"{supported_majors(server_version)[-1]}.0.0"


def is_supported(client_version: str, *, server_version: str = facts.PROTOCOL_VERSION) -> bool:
    major = parse(client_version, field="protocol_version")[0]
    return major in supported_majors(server_version)


def upgrade_hint(client_version: str, *, server_version: str = facts.PROTOCOL_VERSION) -> str:
    """给客户端的升级指引（不泄露内部阈值）。"""
    client_major = parse(client_version, field="protocol_version")[0]
    floor = min_supported_version(server_version)
    if client_major > parse(server_version, field="server_version")[0]:
        return f"客户端协议高于服务端当前版本 {server_version}，请等待服务端升级或降级客户端"
    return f"请升级客户端到协议 ≥ {floor}（服务端支持 {min_supported_version(server_version)}–{server_version}）"


def check(client_version: str, *, server_version: str = facts.PROTOCOL_VERSION) -> tuple[int, int, int]:
    """注册 / 心跳 / 策略前统一校验；越界 → 42601（INV-05）。"""
    parsed = parse(client_version, field="protocol_version")
    if not is_supported(client_version, server_version=server_version):
        raise ProtocolIncompatible(
            f"协议版本不兼容：{client_version}",
            min_supported_version=min_supported_version(server_version),
            server_version=server_version,
            upgrade_hint=upgrade_hint(client_version, server_version=server_version))
    return parsed


def capability_intersection(client: list[str] | None,
                            server: list[str] | None = None) -> list[str]:
    """双方只启用交集（M02 §1）；未知 capability 忽略不报错（INV-05）。"""
    server_set = set(SERVER_CAPABILITIES if server is None else server)
    if not client:
        return sorted(server_set)
    return sorted({item for item in client if item in server_set})



# --------------------------------------------------------------------------- 能力协商与弃用（T6）
def parse_capability_header(value: str | None) -> list[str]:
    """``DJB-Capabilities`` 头：逗号分隔；空值 / 非法形态一律当「没声明」（宽容读取）。"""
    if not value:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def capabilities_payload(*, server_time: "object", client_version: str | None = None,
                        client_capabilities: "list[str] | None" = None) -> dict:
    """spec ``ProtocolCapabilities``：双方只启用交集；未知 capability 忽略不报错（INV-05）。"""
    effective = capability_intersection(client_capabilities)
    return {
        "protocol_version": facts.PROTOCOL_VERSION,
        "min_supported_version": min_supported_version(),
        "capabilities": [
            {"id": item["id"], "version": item["version"], "status": item["status"]}
            for item in CAPABILITIES
        ],
        "enabled": effective,
        "client_protocol_version": client_version or facts.PROTOCOL_VERSION,
        "server_time": _iso(server_time),
    }


def _iso(moment: object) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(__import__("datetime").timezone.utc).isoformat().replace(
        "+00:00", "Z")


def validate_deprecation(entry: dict, *, expected_min_days: int = facts.DEPRECATION_MIN_DAYS,
                         expected_min_majors: int = facts.DEPRECATION_MIN_MAJORS) -> None:
    """弃用条目校验（spec：提前 ≥90 天公示、且至少跨 2 个 MAJOR）。"""
    from datetime import datetime

    required = ("path", "method", "deprecated_at", "sunset_at")
    missing = [key for key in required if not entry.get(key)]
    if missing:
        raise InvalidArgument(f"弃用条目缺少 {','.join(missing)}", field=missing[0])
    try:
        deprecated = datetime.fromisoformat(str(entry["deprecated_at"]).replace("Z", "+00:00"))
        sunset = datetime.fromisoformat(str(entry["sunset_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidArgument("弃用条目时间必须是 RFC 3339", field="sunset_at") from exc
    if (sunset - deprecated).days < expected_min_days:
        raise InvalidArgument(f"弃用公示期必须 ≥{expected_min_days} 天", field="sunset_at")
    majors = entry.get("supported_majors")
    if not isinstance(majors, (list, tuple)) or len(set(map(str, majors))) < expected_min_majors:
        raise InvalidArgument(f"弃用必须跨 ≥{expected_min_majors} 个 MAJOR",
                              field="supported_majors")


def deprecations_payload(*, protocol_major: int | None = None) -> dict:
    """spec ``DeprecationList``；可按 MAJOR 过滤（``supported_majors`` 命中或 ``all``）。"""
    if protocol_major is not None and (isinstance(protocol_major, bool)
                                       or not isinstance(protocol_major, int)
                                       or protocol_major < 1):
        raise InvalidArgument("protocol_major 必须是 ≥1 的整数", field="protocol_major")
    items = []
    for entry in DEPRECATIONS:
        majors = [str(item) for item in entry.get("supported_majors", [])]
        if protocol_major is not None and "all" not in majors \
                and str(protocol_major) not in majors:
            continue
        items.append(dict(entry))
    return {"items": items, "protocol_version": facts.PROTOCOL_VERSION}


__all__ = [
    "parse", "supported_majors", "min_supported_version", "is_supported", "upgrade_hint",
    "check", "capability_intersection", "CAPABILITIES", "SERVER_CAPABILITIES", "DEPRECATIONS",
    "parse_capability_header", "capabilities_payload", "validate_deprecation",
    "deprecations_payload",
]
