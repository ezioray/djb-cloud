# SPDX-License-Identifier: AGPL-3.0-or-later
"""UUIDv7 生成（00-conventions §2：时间有序）。

stdlib 3.11 没有 ``uuid.uuid7``，这里按 RFC 9562 布局实现（与 M01/M02 同口径）：
48 位毫秒时间戳 + 版本 7 + 12 位随机 + 变体 10 + 62 位随机。事件 / 案件 / 申诉 id 都用它，
保证同一聚合内按时间有序。
"""
from __future__ import annotations

import os
import time
import uuid

__all__ = ["uuid7"]


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    millis = int(time.time() * 1000) if now_ms is None else int(now_ms)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (millis & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76                       # version 7
    value |= ((rand >> 62) & 0x0FFF) << 64   # rand_a
    value |= 0b10 << 62                      # variant 10
    value |= rand & ((1 << 62) - 1)          # rand_b
    return uuid.UUID(int=value)
