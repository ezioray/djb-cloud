# SPDX-License-Identifier: AGPL-3.0-or-later
"""把 DSN 里的口令从 argv 移到 PGPASSWORD（测试基础设施卫生）。

问题：psql 子进程如果把 ``postgresql://user:pass@host/db`` 作为命令行参数，
任何能读进程表的本地用户都能看到口令（2026-10-24 发现）。

做法：``safe_dsn()`` 解析 URL，把口令放进 ``PGPASSWORD`` 环境变量，返回去掉口令的 URL；
libpq / psycopg / psql 都会自动读取 PGPASSWORD。非 URL 形式或本来无口令时原样返回。
"""
from __future__ import annotations

import os
from urllib.parse import quote, unquote, urlsplit, urlunsplit


def safe_dsn(value: str) -> str:
    if not value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or parts.scheme not in ("postgres", "postgresql"):
        return value
    if parts.password is None:
        return value
    password = unquote(parts.password)
    if password:
        os.environ["PGPASSWORD"] = password
    userinfo = ""
    if parts.username:
        userinfo = quote(unquote(parts.username), safe="")
    netloc = (userinfo + "@" if userinfo else "") + (parts.hostname or "")
    if parts.port:
        netloc += ":" + str(parts.port)
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
