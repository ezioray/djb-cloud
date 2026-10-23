# SPDX-License-Identifier: Apache-2.0
"""M06 E6 的注入式对接：金额换算 / 幂等键 / 开关闸门 / 不 import 账本（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid

import pytest

from app.metering import errors, facts, settlement
from meterkit import NOW, connect


def _seed_usage(schema: str, *, amount_minor: int = 125, account_id=None) -> str:
    usage_id = str(uuid.uuid4())
    with connect(schema) as conn:
        conn.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1','m1','A1',1000,500,'1500','token',%s,'dual','recorded',
                       %s,%s)""",
            (usage_id, f"req_{uuid.uuid4().hex[:10]}", account_id or uuid.uuid4(),
             amount_minor, f"rcpt_{uuid.uuid4().hex[:10]}", NOW))
    return usage_id


# ─────────────────────────────────────────────────────── E6 形状（纯函数）
def test_e6_request_matches_ledger_contract():
    usage = {"usage_id": "u-1", "account_id": "a-1", "request_id": "r-1", "amount_minor": 125}
    request = settlement.e6_request(usage, policy_version="v4.0-t5", trace_id="trace-1")
    assert request["event_type"] == "E6"
    assert request["source_type"] == "usage_settle"
    assert request["source_id"] == "u-1"
    assert request["event_seq"] == 1
    assert request["idempotency_key"] == "usage_settle:u-1:1"
    assert request["unit_type"] == "USD"
    assert request["correlation_id"] == "r-1"
    lines = request["lines"]
    assert [(line["coa_code"], line["dc"]) for line in lines] == list(facts.E6_LINES) == \
        [("2101", "D"), ("4101", "C")]
    # 分 → micro（×10^4）：125 分 = 1.25 USD = 1_250_000 micro
    assert {line["amount_minor"] for line in lines} == {125 * facts.MICRO_PER_MINOR}
    assert request["amount_minor_cents"] == 125 and request["amount_micro"] == 1_250_000
    assert lines[0]["account_id"] == "a-1"                 # 借方挂需方账户
    assert lines[1]["account_id"] == facts.E6_CREDIT_ACCOUNT
    assert {line["entry_type"] for line in lines} == {"consume"}


def test_e6_request_rejects_zero_amount():
    with pytest.raises(errors.InvalidArgument):
        settlement.e6_request({"usage_id": "u", "account_id": "a", "amount_minor": 0},
                              policy_version="v1")


@pytest.mark.parametrize("version", ["", "x" * 65, None])
def test_e6_request_requires_policy_version(version):
    with pytest.raises(errors.InvalidArgument):
        settlement.e6_request({"usage_id": "u", "account_id": "a", "amount_minor": 1},
                              policy_version=version)


def test_e6_amounts_are_integers_and_round_trip():
    request = settlement.e6_request({"usage_id": "u", "account_id": "a", "amount_minor": 1},
                                    policy_version="v1")
    assert request["amount_micro"] % facts.MICRO_PER_MINOR == 0
    assert request["amount_micro"] // facts.MICRO_PER_MINOR == 1


# ─────────────────────────────────────────────────────── 闸门 / provider
def test_post_usage_settle_is_blocked_by_default_switch(migrated):
    usage_id = _seed_usage(migrated)
    calls: list[dict] = []
    with connect(migrated) as conn:
        result = settlement.post_usage_settle(
            conn, usage_id, policy_version="v1",
            provider=lambda request: calls.append(dict(request)))
    assert result == {"posted": False, "reason": "switch_off"}
    assert calls == []


def test_post_usage_settle_with_force_calls_provider(migrated):
    """管理面重放（force）才允许同步落账；provider 由 Lead 接到 M06。"""
    usage_id = _seed_usage(migrated, amount_minor=300)
    calls: list[dict] = []

    def provider(request):
        calls.append(dict(request))
        return {"journal_id": "j-1"}

    with connect(migrated) as conn:
        result = settlement.post_usage_settle(conn, usage_id, policy_version="v4.0-t5",
                                              provider=provider, force=True, trace_id="t1")
    assert result["posted"] is True
    assert result["idempotency_key"] == f"usage_settle:{usage_id}:1"
    assert result["amount_minor"] == 300 and result["amount_micro"] == 3_000_000
    assert result["amount_text"] == "3.00"
    assert calls and calls[0]["lines"][0]["amount_minor"] == 3_000_000
    assert result["provider_result"] == {"journal_id": "j-1"}


def test_post_usage_settle_fails_closed_without_provider(migrated, monkeypatch):
    from app.metering import features

    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "metering.usage_settle_sync_fallback")
    usage_id = _seed_usage(migrated)
    with connect(migrated) as conn:
        with pytest.raises(errors.LedgerUnavailable) as exc:
            settlement.post_usage_settle(conn, usage_id, policy_version="v1",
                                         provider=None, force=True)
    assert exc.value.code == "50001"


def test_post_usage_settle_unknown_usage_is_not_found(migrated):
    with connect(migrated) as conn:
        with pytest.raises(errors.NotFound):
            settlement.post_usage_settle(conn, str(uuid.uuid4()), policy_version="v1",
                                         provider=lambda request: None, force=True)


def test_post_usage_settle_zero_amount_is_skipped(migrated, monkeypatch):
    from app.metering import features

    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "metering.usage_settle_sync_fallback")
    usage_id = _seed_usage(migrated, amount_minor=0)
    with connect(migrated) as conn:
        result = settlement.post_usage_settle(conn, usage_id, policy_version="v1",
                                              provider=lambda request: None, force=True)
    assert result == {"posted": False, "reason": "zero_amount", "usage_id": usage_id}


def test_set_ledger_provider_hook_roundtrip():
    calls: list[dict] = []
    settlement.set_ledger_provider(lambda request: calls.append(dict(request)))
    try:
        assert settlement.current_ledger_provider() is not None
    finally:
        settlement.set_ledger_provider(None)
    assert settlement.current_ledger_provider() is None


def test_settlement_does_not_import_ledger_module():
    """架构铁律：M05 不 import app.ledger（E6 由 M06 消费事件产生）。

    只看 **import 语句**（AST），不扫文档字符串——模块文档里说明「不 import app.ledger」
    是允许的，注释里的字样不算违规。
    """
    import ast
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[2] / "app" / "metering" / "settlement.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level:
            imported.append(node.module or "")
    assert not [name for name in imported if name.startswith("app.ledger")], imported
