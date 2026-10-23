# SPDX-License-Identifier: Apache-2.0
"""INV-01 阈值扫描（验收硬指标）：代码 / 库表 / 响应 JSON / 事件 payload 中 0 处阈值。

口径（写进证据）：

* **阈值 / 权重 / 名单的键与值**：库表列名、响应键、事件 payload 键、库内 JSONB 键；
* **代码**：``app/risk`` 不出现浮点字面量（阈值通常是比例 / 权重），也不出现
  ``threshold=数字`` 形式的赋值；
* **允许**：``risk_limits.value / window_s`` 是**对单个主体的限额**（spec ``RiskLimit`` 的
  required 字段，不是规则阈值）；``risk.*`` 配置引用与 ``rule_version`` 只出现引用与版本。
"""
from __future__ import annotations

import json
import pathlib
import re
from datetime import timedelta

from app.risk import events, facts
from conftest import ADMIN_PRINCIPAL, build_client
from riskkit import (
    FIXED_NOW,
    FORBIDDEN_KEY_RE,
    FLOAT_LITERAL_RE,
    M11_TABLES,
    find_forbidden_keys,
    make_case,
    outbox_events,
    risk_values,
    session,
    table_columns,
)

STEP_UP = {"X-Admin-Step-Up": "step-up-token-123"}
REVIEWER = {"admin_id": "reviewer", "tenant_id": "tenant-a",
            "scopes": ["risk.read", "risk.write"]}
APP_DIR = pathlib.Path(__file__).resolve().parents[2] / "app" / "risk"


# ───────────────────────────────────────────────────────────── 代码扫描
def test_no_float_literals_in_app_risk() -> None:
    """AST 口径：只扫**代码里的数值字面量**（不扫注释 / 文档串里的版本号）。"""
    import ast

    hits = []
    for path in sorted(APP_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, float):
                hits.append(f"{path.name}:{getattr(node, 'lineno', '?')}: {node.value}")
    assert hits == [], f"app/risk 代码出现浮点字面量（疑似阈值 / 权重）：{hits}"


def test_no_threshold_numeric_assignment_in_source() -> None:
    import ast

    pattern = re.compile(
        r"(threshold|weight|blocklist|blacklist|allowlist|whitelist)", re.IGNORECASE)
    hits = []
    for path in sorted(APP_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if not any(pattern.search(name) for name in names):
                continue
            if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, (int, float)):
                hits.append(f"{path.name}:{node.lineno}: {names} = {node.value.value}")
    assert hits == [], f"源码把阈值 / 权重 / 名单赋成数字：{hits}"


def test_module_never_writes_account_or_money_tables() -> None:
    """INV-04：本模块不得直接改 accounts / payments / ledger / wallet（只提案给 M01）。"""
    forbidden = re.compile(
        r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(accounts|user_accounts|api_keys|"
        r"payment_orders|refund_requests|ledger_journal|ledger_entry|wallet_pool)",
        re.IGNORECASE)
    hits = []
    for path in sorted(APP_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in forbidden.finditer(text):
            hits.append(f"{path.name}: {match.group(0)}")
    assert hits == []


# ───────────────────────────────────────────────────────────── 库表扫描
def test_no_threshold_columns_in_risk_tables(migrated: str) -> None:
    hits = [(row["table_name"], row["column_name"]) for row in table_columns(migrated)
            if FORBIDDEN_KEY_RE.search(row["column_name"])]
    assert hits == []


def test_rule_table_has_only_metadata_columns(migrated: str) -> None:
    columns = {row["column_name"] for row in table_columns(migrated)
               if row["table_name"] == "risk_rules"}
    assert columns == {
        "rule_key", "version", "enabled", "severity", "action_class", "config_ref",
        "created_by", "created_at", "idempotency_key",
    }


def test_db_values_have_no_threshold_tokens(savepoint_conn) -> None:
    _exercise_full_flow(savepoint_conn)
    token = re.compile(r"(threshold|blocklist|blacklist|score_weight|rule_score)", re.IGNORECASE)
    hits = []
    for table in M11_TABLES:
        for value in risk_values(savepoint_conn, table):
            if token.search(value):
                hits.append(f"{table}: {value[:120]}")
    assert hits == []


# ───────────────────────────────────────────────────────────── 响应扫描
def test_all_endpoint_responses_have_no_threshold_keys(savepoint_conn) -> None:
    responses = _collect_responses(savepoint_conn)
    assert len(responses) >= 12, f"响应样本不足：{len(responses)}"
    hits = []
    for name, body in responses:
        if body is None:
            continue
        for path, key in find_forbidden_keys(body):
            hits.append(f"{name} {path} ({key})")
        text = json.dumps(body, ensure_ascii=False).lower()
        for token in ("threshold", "blocklist", "blacklist", "score_weight", "rule_score"):
            if token in text:
                hits.append(f"{name} 文本含 {token}")
    assert hits == [], f"响应出现阈值 / 名单字段：{hits}"


def test_rule_response_numeric_fields_are_version_only(client) -> None:
    response = client.post("/api/v1/admin/risk/rules",
                           json={"rule_key": "wash_volume.ratio", "severity": "P1",
                                 "action_class": "throttle",
                                 "config_ref": "risk.case.auto_action"}, headers=STEP_UP)
    assert response.status_code == 201
    payload = response.json()
    numeric = {key for key, value in payload.items()
               if isinstance(value, int) and not isinstance(value, bool)}
    assert numeric == {"version"}


# ───────────────────────────────────────────────────────────── 事件扫描
def test_all_event_payloads_match_02_events_whitelist(savepoint_conn) -> None:
    _exercise_full_flow(savepoint_conn)
    seen = set()
    for event in outbox_events(savepoint_conn):
        seen.add(event["type"])
        assert event["type"] in facts.EVENT_PAYLOAD_FIELDS
        allowed = facts.EVENT_PAYLOAD_FIELDS[event["type"]]
        assert set(event["payload"]) <= allowed, (event["type"], event["payload"])
        for path, key in find_forbidden_keys(event["payload"]):
            raise AssertionError(f"事件 {event['type']} 出现敏感字段 {path}")
    assert {facts.EVENT_CASE_OPENED, facts.EVENT_ACTION_REQUESTED,
            facts.EVENT_CASE_CLOSED, facts.EVENT_LIMIT_HIT} <= seen


def test_event_payloads_have_no_config_values_only_refs(savepoint_conn) -> None:
    """事件里只有 case_id / subject_id / risk_type / severity / rule_version —— 没有阈值。"""
    _exercise_full_flow(savepoint_conn)
    opened = [event for event in outbox_events(savepoint_conn)
              if event["type"] == facts.EVENT_CASE_OPENED][0]
    assert set(opened["payload"]) == {
        "case_id", "subject_id", "risk_type", "severity", "rule_version"}
    assert isinstance(opened["payload"]["rule_version"], int)


# ───────────────────────────────────────────────────────────── 夹具：全流程
def _exercise_full_flow(connection) -> None:
    """开案 → 冻结提案 → 申诉 → 撤销（覆盖四类事件 + 大多数响应）。"""
    subject = "sha256:" + "9" * 64
    case = make_case(connection, status="opened", subject_hash=subject,
                     risk_type="malicious_occupancy")
    with build_client(connection) as client:
        open_body = {"case_id": str(case["case_id"]), "subject_id": subject,
                     "risk_type": "malicious_occupancy", "severity": "P2",
                     "rule_version": 1}
        events.enqueue(connection, events.build_event(
            facts.EVENT_CASE_OPENED, aggregate_type="risk_case",
            aggregate_id=str(case["case_id"]), payload=open_body, occurred_at=FIXED_NOW,
            idempotency_key=f"risk_case:{case['case_id']}"))
        freeze = client.post(
            f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
            json={"action": "freeze", "reason": "占用攻击",
                  "evidence_refs": ["evt-9001"],
                  "expires_at": (FIXED_NOW + timedelta(days=10)).isoformat()},
            headers=STEP_UP)
        assert freeze.status_code == 201, freeze.text
        appeal = client.post("/api/v1/admin/risk/appeals",
                            json={"case_id": str(case["case_id"]), "reason": "误伤"})
        assert appeal.status_code == 201, appeal.text
    with build_client(connection, admin=REVIEWER) as reviewer:
        decided = reviewer.post(
            f"/api/v1/admin/risk/appeals/{appeal.json()['appeal_id']}/decide",
            json={"outcome": "overturned", "reason": "误伤撤销"}, headers=STEP_UP)
        assert decided.status_code == 200, decided.text
    signal = events.record_limit_hit(
        connection, subject_hash=subject, limit_type="qps", value=10, window_s=60,
        occurred_at=FIXED_NOW, source_event_id=None, source_module="M03",
        payload={"request_id": "req-scan-1"})
    assert signal["created"] is True


def _collect_responses(connection) -> list[tuple[str, dict | None]]:
    """九条操作各打一次（含成功与主要错误），返回 (name, json)。"""
    case = make_case(connection, status="opened", subject_hash="sha256:" + "8" * 64,
                     risk_type="self_trade")
    actioned = make_case(connection, status="actioned",
                         subject_hash="sha256:" + "7" * 64, risk_type="sybil",
                         decided_at=FIXED_NOW - timedelta(days=1))
    responses: list[tuple[str, dict | None]] = []
    with build_client(connection) as client:
        responses.append(("rules.create", _json(client.post(
            "/api/v1/admin/risk/rules",
            json={"rule_key": "self_trade.ratio", "severity": "P2",
                  "action_class": "observe", "config_ref": "risk.case.auto_action"},
            headers=STEP_UP))))
        responses.append(("rules.list", _json(client.get("/api/v1/admin/risk/rules"))))
        responses.append(("limits.create", _json(client.post(
            "/api/v1/admin/risk/limits",
            json={"subject_type": "account", "subject_id": "acct-scan", "limit_type": "qps",
                  "value": 10, "window_s": 60}, headers=STEP_UP))))
        responses.append(("limits.list", _json(client.get("/api/v1/admin/risk/limits"))))
        responses.append(("cases.list", _json(client.get("/api/v1/admin/risk/cases"))))
        responses.append(("cases.get", _json(client.get(
            f"/api/v1/admin/risk/cases/{case['case_id']}"))))
        responses.append(("cases.get.missing", _json(client.get(
            "/api/v1/admin/risk/cases/00000000-0000-0000-0000-000000000000"))))
        responses.append(("decisions.freeze", _json(client.post(
            f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
            json={"action": "freeze", "reason": "自成交",
                  "evidence_refs": ["evt-1"],
                  "expires_at": (FIXED_NOW + timedelta(days=5)).isoformat()},
            headers=STEP_UP))))
        responses.append(("decisions.no_evidence", _json(client.post(
            f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
            json={"action": "close", "reason": "无证据", "evidence_refs": []},
            headers=STEP_UP))))
        created_appeal = _json(client.post(
            "/api/v1/admin/risk/appeals",
            json={"case_id": str(actioned["case_id"]), "reason": "误伤"}))
        responses.append(("appeals.create", created_appeal))
        appeal_id = (created_appeal or {}).get("appeal_id")
        responses.append(("appeals.duplicate", _json(client.post(
            "/api/v1/admin/risk/appeals",
            json={"case_id": str(actioned["case_id"]), "reason": "重复"}))))
    if appeal_id:
        with build_client(connection, admin=REVIEWER) as reviewer:
            responses.append(("appeals.decide", _json(reviewer.post(
                f"/api/v1/admin/risk/appeals/{appeal_id}/decide",
                json={"outcome": "upheld", "reason": "维持"}, headers=STEP_UP))))
    return responses


def _json(response) -> dict | None:
    try:
        return response.json()
    except Exception:                                     # noqa: BLE001
        return None
