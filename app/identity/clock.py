# SPDX-License-Identifier: Apache-2.0
"""可注入时钟：领域层与路由都通过 ``clock.utcnow()`` 取时间。

00-conventions §10 要求测试确定性；00-conventions §4 要求「时间比较只用服务端时间」。
因此业务代码不直接调 ``datetime.now``，测试用 ``monkeypatch.setattr(clock, "utcnow", ...)``
把时间钉死，生产默认走真实时钟。
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """当前 UTC 时间（唯一取时入口）。"""
    return datetime.now(timezone.utc)


__all__ = ["utcnow"]
