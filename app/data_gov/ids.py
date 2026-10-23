# SPDX-License-Identifier: Apache-2.0
"""UUIDv7 生成（00-conventions §2：时间有序；RFC 9562 布局，与本仓其它模块一致）。"""
from __future__ import annotations

import os
import time
import uuid

__all__ = ["uuid7"]


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    millis = int(time.time() * 1000) if now_ms is None else int(now_ms)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (millis & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 62) & 0x0FFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return uuid.UUID(int=value)
