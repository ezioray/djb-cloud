# SPDX-License-Identifier: AGPL-3.0-or-later
"""M04 运维 CLI（M04 §4.1「CLI ``djb-sched replay`` 只读」/ 02-events §2.4 人工重放）。

两个子命令，都是**运维/排障**用途，不提供任何写业务数据的入口：

    python -m app.scheduling.cli replay --from 2026-10-22 --to 2026-10-24 [--ids id1,id2]
    python -m app.scheduling.cli outbox [--dispatch] [--limit 100]

``replay``
    复算回放（只读）：打印 JSON 报告；**不一致即 exit 1**（便于 cron / CI 当门禁用）。
``outbox``
    查看待投递 / 死信；``--dispatch`` 手动派发一轮（失败按 1s/5s/30s/5min/30min 退避）。

DSN 从 ``DJB_DSN`` 读（与测试 / CI 同源）；schema 用 ``--schema`` 或 ``PGOPTIONS`` 指定。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import psycopg

from . import decisions, outbox, replay


def _connect(schema: str | None = None) -> psycopg.Connection:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        raise SystemExit("缺 DJB_DSN（或 --dsn）")
    options = f"-c search_path={schema}" if schema else None
    return psycopg.connect(dsn, autocommit=False, options=options) if options \
        else psycopg.connect(dsn, autocommit=False)


def _parse_ts(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    moment = datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def cmd_replay(args: argparse.Namespace) -> int:
    conn = _connect(args.schema)
    try:
        report = replay.run(conn, from_ts=_parse_ts(args.start), to_ts=_parse_ts(args.end),
                            decision_ids=args.ids.split(",") if args.ids else None,
                            limit=args.limit)
        conn.rollback()                                    # 只读：不留下任何事务痕迹
    finally:
        conn.close()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["inconsistent"] == 0 else 1


def cmd_outbox(args: argparse.Namespace) -> int:
    conn = _connect(args.schema)
    try:
        if args.dispatch:
            result = outbox.dispatch(conn, limit=args.limit)
            conn.commit()
            print(json.dumps({"dispatch": result, "stats": outbox.stats(conn)},
                             ensure_ascii=False, indent=2))
            return 0
        payload = {"stats": outbox.stats(conn),
                   "dead_letters": [dict(item, event_id=str(item["event_id"]))
                                    for item in outbox.dead_letters(conn, limit=args.limit)]}
        conn.rollback()
    finally:
        conn.close()
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="djb-sched", description="M04 调度与定价运维 CLI")
    parser.add_argument("--schema", default=os.environ.get("DJB_SCHEMA"),
                        help="目标 schema（缺省用 DSN 的 search_path）")
    sub = parser.add_subparsers(dest="command", required=True)

    replay_parser = sub.add_parser("replay", help="复算回放（只读，不一致 exit 1）")
    replay_parser.add_argument("--from", dest="start", required=True, help="窗口起点（ISO-8601）")
    replay_parser.add_argument("--to", dest="end", required=True, help="窗口终点（ISO-8601）")
    replay_parser.add_argument("--ids", default=None, help="只复算这些 decision_id（逗号分隔）")
    replay_parser.add_argument("--limit", type=int, default=replay.MAX_DECISIONS_PER_JOB)
    replay_parser.set_defaults(handler=cmd_replay)

    outbox_parser = sub.add_parser("outbox", help="查看 / 派发事件出站")
    outbox_parser.add_argument("--dispatch", action="store_true", help="派发一轮（会提交事务）")
    outbox_parser.add_argument("--limit", type=int, default=100)
    outbox_parser.set_defaults(handler=cmd_outbox)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":                                        # pragma: no cover - CLI
    raise SystemExit(main())


__all__ = ["build_parser", "main", "cmd_replay", "cmd_outbox"]
