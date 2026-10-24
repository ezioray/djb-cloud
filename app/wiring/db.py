# SPDX-License-Identifier: AGPL-3.0-or-later
"""S1 demo 的数据库接线：独立 schema + 全链迁移 + 连接工厂。

只做三件事：

1. 从 ``DJB_DSN`` 取开发库连接串（**凭据只在环境里**）；
2. 建一个一次性 schema，按迁移文件的**数字序**跑完整链（001–1008）；
3. 给每个 provider 发独立连接，避免跨模块共享事务 / 游标。
"""
from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass

import psycopg
from psycopg import sql

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "migrations"
_NUMERIC_PREFIX = re.compile(r"^(\d+)_")


def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库）")
    return value


def migration_files() -> list[pathlib.Path]:
    """按数字序返回全部迁移文件（001→1008；不依赖字典序）。"""
    files = [p for p in MIGRATIONS_DIR.glob("*.sql") if p.is_file()]

    def key(path: pathlib.Path) -> tuple[int, str]:
        match = _NUMERIC_PREFIX.match(path.name)
        return (int(match.group(1)) if match else 10**9, path.name)

    return sorted(files, key=key)


@dataclass(frozen=True)
class Database:
    """一次性 schema 的连接工厂。"""

    schema: str
    dsn: str

    @classmethod
    def create(cls, schema: str) -> "Database":
        return cls(schema=schema, dsn=dsn())

    def connect(self, *, autocommit: bool = True) -> psycopg.Connection:
        return psycopg.connect(
            self.dsn,
            autocommit=autocommit,
            options=f"-c search_path={self.schema},public",
        )

    def create_schema(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute(
                sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema))
            )

    def migrate(self) -> list[str]:
        """空库全链迁移；返回实际执行的文件名（数字序）。"""
        self.create_schema()
        applied: list[str] = []
        with self.connect() as conn:
            for path in migration_files():
                conn.execute(path.read_text(encoding="utf-8"))
                applied.append(path.name)
        return applied

    def drop(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(self.schema))
            )
