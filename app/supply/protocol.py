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
    server_set = set(facts.SERVER_CAPABILITIES if server is None else server)
    if not client:
        return sorted(server_set)
    return sorted({item for item in client if item in server_set})


__all__ = [
    "parse", "supported_majors", "min_supported_version", "is_supported", "upgrade_hint",
    "check", "capability_intersection",
]
