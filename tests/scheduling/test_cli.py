# SPDX-License-Identifier: AGPL-3.0-or-later
"""运维 CLI（M04 §4.1「CLI djb-sched replay 只读」/ 02-events §2.4 人工重放）。"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest

from app.scheduling import candidates, cli, decisions, models, outbox, pipeline


def _run(argv: list[str]) -> tuple[int, dict | None]:
    return cli.main(argv), None


def test_replay_cli_returns_zero_when_consistent(migrated, now, tenant, factory, capsys):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    from schedulingkit import connect

    conn = connect(migrated, autocommit=False)
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                      trace_id="t-cli")
        pipeline.execute(conn, route, now=now)
        conn.commit()
    finally:
        conn.close()

    code = cli.main(["--schema", migrated, "replay",
                     "--from", (now - timedelta(minutes=1)).isoformat(),
                     "--to", (now + timedelta(minutes=1)).isoformat()])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["total"] == 1
    assert payload["inconsistent"] == 0


def test_replay_cli_exits_one_on_inconsistency(migrated, now, capsys):
    from schedulingkit import connect

    digest = uuid.uuid4().hex + uuid.uuid4().hex
    decision = models.Decision(
        decision_id=decisions.decision_id(now, 1, "000000000000", digest),
        trace_id="trace-bad", attempt_no=1, snapshot_ts=now, quote_version=1,
        policy_version="000000000000", request_digest=digest,
        candidates=[{"node_id": "n1", "access": "A1", "model": "m1", "unit": "token",
                     "ask_price_minor": 800, "price_max_minor": 1_000},
                    {"node_id": "n2", "access": "A1", "model": "m1", "unit": "token",
                     "ask_price_minor": 900, "price_max_minor": 1_000}],
        chosen={"node_id": "n2", "upstream_id": "", "access": "A1", "model": "m1",
                "unit": "token"},                     # 输入里 n1 更便宜 → 一致率红
        tie_break="cost", outcome="routed", price_minor=900, decided_at=now)
    conn = connect(migrated, autocommit=False)
    try:
        decisions.record(conn, decision)
        conn.commit()
    finally:
        conn.close()

    code = cli.main(["--schema", migrated, "replay",
                     "--from", (now - timedelta(minutes=1)).isoformat(),
                     "--to", (now + timedelta(minutes=1)).isoformat()])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["inconsistent"] == 1


def test_outbox_cli_reports_stats(migrated, now, tenant, factory, capsys):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)          # 未提交（事务里）→ 用独立连接再看
    from schedulingkit import connect

    conn = connect(migrated, autocommit=False)
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                      trace_id="t-outbox")
        pipeline.execute(conn, route, now=now)
        conn.commit()
    finally:
        conn.close()

    assert cli.main(["--schema", migrated, "outbox"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["pending"] >= 1
    assert payload["stats"]["published"] == 0

    assert cli.main(["--schema", migrated, "outbox", "--dispatch"]) == 0
    dispatched = json.loads(capsys.readouterr().out)
    assert dispatched["dispatch"]["sent"] >= 1
    assert dispatched["stats"]["pending"] == 0


def test_cli_requires_a_dsn(monkeypatch, capsys):
    monkeypatch.delenv("DJB_DSN", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["--schema", "whatever", "outbox"])


def test_parser_rejects_unknown_command():
    with pytest.raises(SystemExit):
        cli.main(["nonsense"])


def test_parser_requires_a_command():
    with pytest.raises(SystemExit):
        cli.main([])
