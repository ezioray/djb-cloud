# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移 CLI（``python -m app.notify.migrate``）与语句切分：三跑入口必须能直接用。"""
from __future__ import annotations

import uuid

import pytest

from app.notify import migrate as m12_migrate
from notifykit import create_schema, drop_schema


def test_split_statements_keeps_dollar_quoted_bodies():
    script = """
CREATE OR REPLACE FUNCTION f() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'x';
END;
$$ LANGUAGE plpgsql;
SELECT 1;
"""
    statements = m12_migrate._split_statements(script)
    assert len(statements) == 2
    assert statements[0].startswith("CREATE OR REPLACE FUNCTION")
    assert statements[1] == "SELECT 1;"


def test_migration_files_order_is_numeric():
    files = m12_migrate.migration_files()
    numbers = [int(path.name.split("_", 1)[0]) for path in files]
    assert numbers == sorted(numbers)
    assert [path.name for path in files[-5:]] == list(m12_migrate.MODULE_MIGRATIONS)
    assert all(int(path.name.split("_", 1)[0]) < 1200 for path in files[:-5])


def test_cli_status_and_down_on_empty_schema(monkeypatch):
    name = f"m12_cli_{uuid.uuid4().hex[:8]}"
    create_schema(name)
    try:
        assert m12_migrate.main(["--schema", name, "--status"]) == 0
        assert m12_migrate.main(["--schema", name, "--down"]) == 0
    finally:
        drop_schema(name)


def test_cli_up_with_only_module_files(monkeypatch):
    name = f"m12_cli_{uuid.uuid4().hex[:8]}"
    create_schema(name)
    try:
        module_files = tuple(m12_migrate.migration_files()[-5:])
        monkeypatch.setattr(m12_migrate, "migration_files", lambda: module_files)
        assert m12_migrate.main(["--schema", name, "--up"]) == 0
        assert m12_migrate.main(["--schema", name, "--up"]) == 0      # 幂等重跑
        assert m12_migrate.main(["--schema", name, "--status"]) == 0
    finally:
        drop_schema(name)


def test_cli_requires_dsn(monkeypatch):
    monkeypatch.delenv("DJB_DSN", raising=False)
    assert m12_migrate.main(["--schema", "m12_cli_missing", "--status"]) == 2


def test_connect_and_ensure_schema(monkeypatch):
    name = f"m12_cli_{uuid.uuid4().hex[:8]}"
    import os

    m12_migrate.ensure_schema(os.environ["DJB_DSN"], name)
    try:
        conn = m12_migrate.connect(os.environ["DJB_DSN"], name)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT current_schema()")
                assert cur.fetchone()[0] == name
        finally:
            conn.close()
    finally:
        drop_schema(name)


def test_up_reports_failure(monkeypatch, tmp_path):
    """失败即停：坏 SQL 要让 up() 抛出来并带 rc=1 记录（不吞错）。"""
    import psycopg

    name = f"m12_cli_{uuid.uuid4().hex[:8]}"
    create_schema(name)
    bad = tmp_path / "1299_bad.sql"
    bad.write_text("THIS IS NOT SQL;", encoding="utf-8")
    conn = m12_migrate.connect(__import__("os").environ["DJB_DSN"], name)
    try:
        with pytest.raises(psycopg.Error):
            m12_migrate.up(conn, files=[bad])
    finally:
        conn.close()
        drop_schema(name)
