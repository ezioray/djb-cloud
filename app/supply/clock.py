# SPDX-License-Identifier: AGPL-3.0-or-later
"""可注入时钟（与 ``app/identity/clock.py`` 同款约定）。

00-conventions §10 要求测试确定性，§4 要求「时间比较只用服务端时间」。
业务代码不直接调 ``datetime.now``；测试用 ``monkeypatch.setattr(clock, "utcnow", ...)`` 钉死时钟。
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """当前 UTC 时间（本模块唯一取时入口）。"""
    return datetime.now(timezone.utc)


__all__ = ["utcnow"]
