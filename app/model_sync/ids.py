# SPDX-License-Identifier: AGPL-3.0-or-later
"""UUIDv7（RFC 9562 布局，与 M01/M02/M11 同口径：时间有序，同聚合按时间可排）。"""
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
