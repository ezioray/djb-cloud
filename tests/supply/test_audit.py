# SPDX-License-Identifier: AGPL-3.0-or-later
"""上线前盘点（R5）：重复硬件指纹必须为 0（只读 CLI + 领域函数）。"""
from __future__ import annotations

import json

import pytest

from app.supply import audit, models


def test_clean_schema_is_ready(conn, factory):
    factory.active_node()
    report = audit.report(conn)
    assert report["duplicate_fingerprints"] == []
    assert report["ready"] is True
    assert report["summary"]["nodes"] == 1
    assert report["summary"]["active"] == 1


def test_duplicate_fingerprints_are_reported(conn, factory):
    """存量重复指纹（003 时代没有唯一约束）——上线前必须归并到 0。"""
    first = factory.register(hardware_fingerprint="fp-dup-0001-aaaa").node
    with conn.transaction():
        with conn.cursor() as cur:            # 模拟「唯一索引尚未建立」的存量库
            cur.execute("DROP INDEX nodes_platform_fp_uq")
            cur.execute(
                """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                      protocol_version, state, key_prefix, key_hash)
                   VALUES ('n_dup2', %s, %s, '1.0.0', '1.0.0', 'pending', 'abcdefgh', %s)""",
                (first.platform, first.hardware_fingerprint, "9" * 64))
        report = audit.report(conn)
        assert len(report["duplicate_fingerprints"]) == 1
        group = report["duplicate_fingerprints"][0]
        assert group["copies"] == 2
        assert sorted(group["node_ids"]) == sorted([first.id, "n_dup2"])
        assert report["ready"] is False
        assert any("重复硬件指纹" in item for item in report["blockers"])


def test_retired_without_timestamp_is_a_blocker(conn, factory):
    node = factory.active_node()[0]
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE nodes DROP CONSTRAINT nodes_retired_chk")
            cur.execute("UPDATE nodes SET state = 'retired', retired_at = NULL WHERE id = %s",
                        (node.id,))
        report = audit.report(conn)
        assert report["summary"]["retired_without_ts"] == 1
        assert report["ready"] is False


def test_cli_reports_json_and_exit_code(migrated, capsys):
    assert audit.main(["--schema", migrated, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] in (True, False)
    assert "summary" in payload and "duplicate_fingerprints" in payload


def test_cli_human_output(migrated, capsys):
    assert audit.main(["--schema", migrated]) == 0
    out = capsys.readouterr().out
    assert "schema=" in out and "上线前置检查" in out


def test_cli_requires_dsn(monkeypatch, capsys):
    monkeypatch.delenv("DJB_DSN", raising=False)
    assert audit.main(["--schema", "public"]) == 2
    assert "连接失败" in capsys.readouterr().err


def test_summary_counts_states(conn, factory):
    active = factory.active_node()[0]
    factory.register()
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (active.id,))
    counts = audit.summary(conn)
    assert counts["nodes"] == 2
    assert counts["pending"] == 1
    assert counts["frozen"] == 1
    assert models.get_node(conn, active.id).state == "frozen"
