# SPDX-License-Identifier: AGPL-3.0-or-later
"""``djb-config`` 只读 CLI（T5）：verify / replay / tick / dlq。

只读保证：``verify`` 与 ``replay`` 用 ``default_transaction_read_only=on`` 的连接，数据库层面
拒绝任何写操作（不是「代码里没写」这种自觉）；``tick`` / ``dlq --requeue`` 需要写，另开普通连接。

用法::

    djb-config verify [--schema S] [--expect-zero]
    djb-config replay --digest <sha256> | --period <p> [--schema S]
    djb-config tick [--schema S]
    djb-config dlq [--list] [--requeue <event_id>] [--schema S]
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg

from . import dispatcher, migrate, snapshot, store, worker

__all__ = ["main", "read_only_connection", "connection", "cmd_verify", "cmd_replay"]


def _dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库）")
    return value


def _options(schema: str | None, *, read_only: bool) -> str:
    parts = []
    if schema:
        parts.append(f"-c search_path={schema}")
    if read_only:
        parts.append("-c default_transaction_read_only=on")
    parts.append("-c statement_timeout=60000")
    return " ".join(parts)


def read_only_connection(schema: str | None = None) -> psycopg.Connection:
    """只读连接：数据库层拒绝写（verify / replay 用）。"""
    return psycopg.connect(_dsn(), autocommit=True, options=_options(schema, read_only=True))


def connection(schema: str | None = None) -> psycopg.Connection:
    return psycopg.connect(_dsn(), autocommit=True, options=_options(schema, read_only=False))


def cmd_verify(conn: psycopg.Connection) -> dict[str, Any]:
    """全量复算版本 digest + 快照 digest（只读）。"""
    versions = store.recompute_digests(conn)
    snapshots = snapshot.list_snapshots(conn, limit=200)
    bad_snapshots = [row["snapshot_digest"] for row in snapshots
                     if not snapshot.verify_snapshot(row)]
    current = None
    if conn.execute("SELECT count(*) FROM config_versions WHERE status = 'active'").fetchone()[0]:
        from . import publish
        current = publish.current_policy_version(conn)
    return {
        "versions": versions,
        "snapshots": {"total": len(snapshots), "bad": bad_snapshots},
        "active_policy": current,
        "diff": versions["diff"] + len(bad_snapshots),
    }


def cmd_replay(conn: psycopg.Connection, *, digest: str | None,
               period: str | None) -> dict[str, Any] | None:
    row = snapshot.replay_snapshot(conn, snapshot_digest=digest, period=period)
    if row is None:
        return None
    return {
        "snapshot_digest": row["snapshot_digest"],
        "policy_version": row["policy_version"],
        "period": row["period"],
        "created_at": row["created_at"].isoformat(),
        "entries": row["entries"],
        "verified": snapshot.verify_snapshot(row),
    }


def cmd_tick(conn: psycopg.Connection, *, now: datetime | None = None) -> dict[str, Any]:
    return worker.tick(conn, now=now)


def cmd_dlq(conn: psycopg.Connection, *, requeue: str | None = None,
            limit: int = 50) -> dict[str, Any]:
    if requeue:
        return {"requeued": dispatcher.requeue_dead_letter(conn, requeue)}
    return {"dead_letters": dispatcher.dead_letters(conn, limit=limit)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="djb-config", description="M10 config-center CLI")
    parser.add_argument("--schema", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="复算版本与快照 digest（只读）")
    verify.add_argument("--expect-zero", action="store_true")

    replay = sub.add_parser("replay", help="按快照回放（只读）")
    group = replay.add_mutually_exclusive_group(required=True)
    group.add_argument("--digest", default=None)
    group.add_argument("--period", default=None)

    sub.add_parser("tick", help="一轮 worker（过期复核 / scheduled 生效 / kill switch 到期 / outbox 重投）")

    dlq = sub.add_parser("dlq", help="死信清单 / 人工重放")
    dlq.add_argument("--list", action="store_true")
    dlq.add_argument("--requeue", default=None)
    dlq.add_argument("--limit", type=int, default=50)

    args = parser.parse_args(argv)

    if args.command == "verify":
        with read_only_connection(args.schema) as conn:
            report = cmd_verify(conn)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        if args.expect_zero:
            return 0 if report["diff"] == 0 else 1
        return 0 if report["versions"]["diff"] >= 0 else 1

    if args.command == "replay":
        with read_only_connection(args.schema) as conn:
            report = cmd_replay(conn, digest=args.digest, period=args.period)
        if report is None:
            print(json.dumps({"error": "snapshot not found"}, ensure_ascii=False))
            return 1
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "tick":
        with connection(args.schema) as conn:
            report = cmd_tick(conn, now=datetime.now(timezone.utc))
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str))
        return 0

    with connection(args.schema) as conn:
        report = cmd_dlq(conn, requeue=args.requeue, limit=args.limit)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
