# SPDX-License-Identifier: AGPL-3.0-or-later
"""ID 生成（00-conventions §2：内部主键 UUIDv7；对外单号 ≤32 字符、全局唯一、创建后不变）。

UUIDv7 按 RFC 9562 布局自实现（stdlib 3.11 没有 uuid.uuid7，与 M01/M02/M11 同口径）：
48 位毫秒时间戳 + 版本 7 + 12 位随机 + 变体 10 + 62 位随机。

对外单号由**数据库序列**生成（PO-/PB-/RF- 前缀 + 日期 + 6 位序号），保证并发唯一；
这里只提供纯函数形式的前缀常量与兜底生成（迁移未建序列时测试可用）。
"""
from __future__ import annotations

import os
import time
import uuid

__all__ = ["uuid7", "ORDER_PREFIX", "BATCH_PREFIX", "REFUND_PREFIX", "PROVISION_PREFIX",
           "SWEEP_PREFIX", "format_no", "random_hex"]

ORDER_PREFIX = "PO"
BATCH_PREFIX = "PB"
REFUND_PREFIX = "RF"
PROVISION_PREFIX = "WB"
SWEEP_PREFIX = "SW"


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    millis = int(time.time() * 1000) if now_ms is None else int(now_ms)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (millis & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76                       # version 7
    value |= ((rand >> 62) & 0x0FFF) << 64   # rand_a
    value |= 0b10 << 62                      # variant 10
    value |= rand & ((1 << 62) - 1)          # rand_b
    return uuid.UUID(int=value)


def format_no(prefix: str, moment, serial: int) -> str:
    """对外单号：<PREFIX>-YYYYMMDD-NNNNNN（≤32 字符）。"""
    day = moment.strftime("%Y%m%d")
    return f"{prefix}-{day}-{int(serial):06d}"


def random_hex(nbytes: int = 16) -> str:
    return os.urandom(int(nbytes)).hex()
