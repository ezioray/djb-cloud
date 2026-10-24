# SPDX-License-Identifier: AGPL-3.0-or-later
"""协议版本与能力协商（T4 / M03 §4.3）。

口径：

* ``DJB-Protocol-Version: MAJOR.MINOR.PATCH``；URL 里的 ``v1`` 是协议 MAJOR，**冻结**。
* **不兼容**（MAJOR 不在 ``facts.PROTOCOL_MAJOR_SUPPORTED``）→ ``426 / 42601``。
  闸门 ``gateway.protocol_version_strict`` **默认关闭**（硬约束第 4 条）：关闭时按当前
  MAJOR 兼容读取、只记日志（灰度期不打断老客户端）；打开后严格执行 426。
* 缺省 / 非法格式的头**不报错**：缺省按服务端当前版本；非法格式忽略（容错读取 INV-M03-07）。
  只有「格式合法且 MAJOR 不受支持」才可能 426。
* ``DJB-Capabilities`` 逗号分隔；双方只启用**交集**，未知 capability **忽略不报错**。
* 弃用提前 90 天公告并带 ``Sunset`` 头（``facts.DEPRECATION_NOTICE_DAYS``）——S1 尚无弃用
  版本，本模块提供 :func:`sunset_header` 供后续接线。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from . import errors, facts

log = logging.getLogger("djb.gateway.protocol")

__all__ = ["VERSION_PATTERN", "ProtocolInfo", "parse", "check", "capabilities", "enabled_set",
           "response_headers", "sunset_header", "SUPPORTED_CAPABILITIES"]

VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

SUPPORTED_CAPABILITIES: tuple[str, ...] = ("chat_completions", "batch", "models")
"""本网关已实现的能力标识（未知 capability 忽略）。"""


@dataclass(frozen=True)
class ProtocolInfo:
    """一次请求的协议版本判定结果。"""

    raw: str | None
    major: int | None
    minor: int | None
    patch: int | None
    compatible: bool
    strict: bool = False

    @property
    def present(self) -> bool:
        return self.raw is not None


def parse(raw: str | None) -> ProtocolInfo | None:
    """解析版本头；缺省 / 空 → ``None``（按服务端当前版本处理）；格式非法 → ``None`` + 日志。"""
    text = (raw or "").strip()
    if not text:
        return None
    if not VERSION_PATTERN.match(text):
        log.info("gateway.protocol.malformed_version",
                 extra={"event": "protocol.malformed_version"})
        return None
    major, minor, patch = (int(part) for part in text.split("."))
    return ProtocolInfo(raw=text, major=major, minor=minor, patch=patch,
                        compatible=major in facts.PROTOCOL_MAJOR_SUPPORTED)


def check(raw: str | None, *, strict: bool | None = None) -> ProtocolInfo:
    """判定并（在严格模式下）对不兼容版本抛 426 / 42601。"""
    from . import features

    strict_mode = features.enabled("gateway.protocol_version_strict") if strict is None else strict
    info = parse(raw)
    if info is None:
        return ProtocolInfo(raw=None, major=None, minor=None, patch=None, compatible=True,
                            strict=bool(strict_mode))
    info = ProtocolInfo(raw=info.raw, major=info.major, minor=info.minor, patch=info.patch,
                        compatible=info.compatible, strict=bool(strict_mode))
    if info.compatible:
        return info
    log.warning("gateway.protocol.incompatible",
                extra={"event": "protocol.incompatible", "version": info.raw,
                       "strict": bool(strict_mode)})
    if strict_mode:
        raise errors.GatewayError(
            "protocol_incompatible",
            f"协议版本不受支持：本网关支持 MAJOR {facts.PROTOCOL_MAJOR_SUPPORTED}",
            details={"supported_major": list(facts.PROTOCOL_MAJOR_SUPPORTED),
                     "current": facts.PROTOCOL_VERSION_CURRENT})
    return info


def capabilities(raw: str | None) -> tuple[str, ...]:
    """解析 ``DJB-Capabilities``（逗号分隔；未知值保留但由 :func:`enabled_set` 过滤）。"""
    text = (raw or "").strip()
    if not text:
        return ()
    return tuple(item.strip() for item in text.split(",") if item.strip())


def enabled_set(raw: str | None) -> tuple[str, ...]:
    """双方交集（未知 capability 忽略，不报错）。"""
    return tuple(sorted(set(capabilities(raw)) & set(SUPPORTED_CAPABILITIES)))


def response_headers(info: ProtocolInfo) -> dict[str, str]:
    """回显协议版本（只加不改：新增响应头不破坏客户端）。"""
    return {facts.PROTOCOL_VERSION_HEADER: facts.PROTOCOL_VERSION_CURRENT}


def sunset_header(deprecated_at: datetime) -> dict[str, str]:
    """弃用公示（M03 §4.3：提前 90 天）→ ``Sunset`` 头（RFC 8594）。"""
    sunset = deprecated_at + timedelta(days=facts.DEPRECATION_NOTICE_DAYS)
    return {"Sunset": sunset.strftime("%a, %d %b %Y %H:%M:%S GMT")}
