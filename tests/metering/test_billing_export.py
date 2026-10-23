# SPDX-License-Identifier: Apache-2.0
"""spec 1.2.6 账单导出（M05 §4.1）：GET /api/v1/user/billing/export。

覆盖：成功（csv / json）/ 未认证 / 越权（只导本人）/ 边界（format、时间窗、cursor 无关）/
流式头（Content-Disposition + X-DJB-Export-Expires-At ≤15 分钟）/ 不含正文。

隔离：沿用 ``tests/metering`` 的 ``client`` fixture（router 连接指向隔离 schema）；
每个用例用独立账户造 usage，断言不跨用例。
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.metering import export, facts, router as router_module
from meterkit import NOW, connect, seed_account

EXPORT = "/api/v1/user/billing/export"
WINDOW = {"from": "2026-10-01", "to": "2026-10-31"}


# --------------------------------------------------------------------------- 夹具 / 工具
def _seed_usage(schema: str, *, account_id, amount_minor: int = 1250,
                recorded_at: datetime = NOW, model: str = "m1") -> str:
    """直接种一条 usage（只读导出用；不触发收据 / 事件链路）。"""
    usage_id = str(uuid.uuid4())
    with connect(schema) as c:
        c.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1',%s,'A1',1000,500,'1500','token',%s,'dual','recorded',
                       %s,%s)""",
            (usage_id, f"req_{uuid.uuid4().hex[:10]}", account_id, model, amount_minor,
             f"rcpt_{uuid.uuid4().hex[:10]}", recorded_at))
    return usage_id


def _error(response) -> dict:
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert {"type", "code", "message", "request_id"} <= set(error)
    assert isinstance(error["code"], int)
    return error


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- 认证
def test_export_requires_user_auth(client):
    response = client.get(EXPORT, params=WINDOW)
    assert response.status_code == 401
    assert _error(response)["code"] == 40101
    assert response.headers["X-Request-Id"]


def test_export_auth_hook_without_account_is_rejected(client):
    router_module.set_user_authenticator(lambda request: {"tenant_id": "t1"})
    try:
        response = client.get(EXPORT, params=WINDOW)
        assert response.status_code == 401
        assert _error(response)["code"] == 40101
    finally:
        router_module.set_user_authenticator(None)


# --------------------------------------------------------------------------- CSV 成功
def test_export_csv_stream_headers_and_body(client, auth, api_account):
    usage_ids = {_seed_usage(auth["schema"], account_id=api_account, amount_minor=1250),
                 _seed_usage(auth["schema"], account_id=api_account, amount_minor=700)}
    foreign = seed_account(auth["schema"])
    _seed_usage(auth["schema"], account_id=foreign, amount_minor=9900)

    response = client.get(EXPORT, params={**WINDOW, "format": "csv"},
                          headers={"X-Request-Id": "req-export-csv-1"})
    assert response.status_code == 200, response.text
    assert response.headers["X-Request-Id"] == "req-export-csv-1"
    assert response.headers["content-type"].startswith("text/csv")

    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment; filename=")
    assert ".csv" in disposition
    assert "/" not in disposition.split("filename=")[1]       # 不暴露内部路径

    expires = _parse_iso(response.headers["X-DJB-Export-Expires-At"])
    now = datetime.now(timezone.utc)
    assert now - timedelta(seconds=5) <= expires <= now + timedelta(
        seconds=facts.EXPORT_TTL_S + 5)                        # TTL ≤15 分钟

    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 2                                      # 只导本人
    assert {row["usage_id"] for row in rows} == usage_ids
    assert list(rows[0].keys()) == list(export.ROW_FIELDS)
    for row in rows:
        assert row["currency"] == facts.CURRENCY
        assert int(row["amount_minor"]) in {1250, 700}
        assert row["recorded_at"].endswith("Z")
    assert "prompt" not in response.text and "response" not in response.text


# --------------------------------------------------------------------------- JSON 成功
def test_export_json_stream_shape(client, auth, api_account):
    usage_id = _seed_usage(auth["schema"], account_id=api_account, amount_minor=450)
    response = client.get(EXPORT, params={**WINDOW, "format": "json"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].endswith('.json"')

    payload = response.json()
    assert isinstance(payload, list) and len(payload) == 1
    row = payload[0]
    assert set(row) == set(export.ROW_FIELDS)
    assert row["usage_id"] == usage_id
    assert row["amount_minor"] == 450 and isinstance(row["amount_minor"], int)
    assert row["currency"] == facts.CURRENCY
    assert row["recorded_at"].endswith("Z")


# --------------------------------------------------------------------------- 空结果 / 默认值
def test_export_empty_result_still_has_header(client, auth):
    account = seed_account(auth["schema"])
    router_module.set_user_authenticator(
        lambda request: {"account_id": str(account), "tenant_id": str(account)})
    try:
        csv_response = client.get(EXPORT, params={**WINDOW, "format": "csv"})
        assert csv_response.status_code == 200
        assert csv_response.text == export.csv_header()

        json_response = client.get(EXPORT, params={**WINDOW, "format": "json"})
        assert json_response.status_code == 200
        assert json_response.json() == []
    finally:
        router_module.set_user_authenticator(None)


def test_export_defaults_to_csv_and_current_month(client, auth, api_account):
    _seed_usage(auth["schema"], account_id=api_account,
                recorded_at=datetime.now(timezone.utc))
    response = client.get(EXPORT)                              # 不带 format / from / to
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 1


# --------------------------------------------------------------------------- 边界
def test_export_rejects_unknown_format(client, auth):
    response = client.get(EXPORT, params={**WINDOW, "format": "xlsx"})
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_export_rejects_oversized_window(client, auth):
    response = client.get(EXPORT, params={"from": "2019-01-01", "to": "2026-10-31"})
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == 40001
    assert error["reason"] == "window_too_large"


@pytest.mark.parametrize("params", [{"from": "2026-10-31", "to": "2026-10-01"},
                                    {"from": "not-a-date"},
                                    {"to": "2026-13-01"}])
def test_export_rejects_bad_window(client, auth, params):
    response = client.get(EXPORT, params=params)
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_export_window_is_half_open_inclusive_on_both_ends(client, auth, api_account):
    inside_first = _seed_usage(auth["schema"], account_id=api_account,
                               recorded_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
    inside_last = _seed_usage(auth["schema"], account_id=api_account,
                              recorded_at=datetime(2026, 10, 31, 23, 59, tzinfo=timezone.utc))
    outside = _seed_usage(auth["schema"], account_id=api_account,
                          recorded_at=datetime(2026, 11, 1, 0, 1, tzinfo=timezone.utc))
    response = client.get(EXPORT, params={**WINDOW, "format": "json"})
    assert response.status_code == 200
    returned = {row["usage_id"] for row in response.json()}
    assert returned == {inside_first, inside_last}
    assert outside not in returned

def test_iter_rows_streams_in_keyset_batches(auth, api_account):
    """批读不依赖 OFFSET：batch_size=2 时 5 行分 3 批且顺序稳定（流式内存有界）。"""
    schema = auth["schema"]
    seeded = [_seed_usage(schema, account_id=api_account,
                          recorded_at=NOW + timedelta(minutes=index)) for index in range(5)]
    with connect(schema) as c:
        rows = list(export.iter_rows(
            c, account_id=str(api_account),
            date_from=datetime(2026, 10, 1, tzinfo=timezone.utc),
            date_to=datetime(2026, 10, 31, 23, 59, tzinfo=timezone.utc), batch_size=2))
    assert [row["usage_id"] for row in rows] == seeded

# --------------------------------------------------------------------------- 契约（spec 1.2.6）

def _spec() -> dict:
    """spec 来源：$DJB_SPEC_FILE → 仓库 spec/ → 向上最多 4 级祖先的 spec/（CI 与工作区同一实现）。"""
    import os
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[2]
    candidates = [pathlib.Path(os.environ["DJB_SPEC_FILE"])] if os.environ.get("DJB_SPEC_FILE") \
        else []
    candidates.append(root / "spec" / "openapi.yaml")
    candidates += [parent / "spec" / "openapi.yaml" for parent in list(root.parents)[:4]]
    for candidate in candidates:
        if candidate.exists():
            return yaml.safe_load(candidate.read_text(encoding="utf-8"))
    pytest.skip("spec/openapi.yaml 缺失（设置 DJB_SPEC_FILE 或先同步 spec）")


def test_route_and_headers_match_spec_1_2_6():
    spec = _spec()
    operation = spec["paths"]["/api/v1/user/billing/export"]["get"]
    assert operation["operationId"] == "exportUserBilling"

    routes = {(method.upper(), route.path) for route in router_module.router.routes
              for method in (getattr(route, "methods", set()) or set())
              - {"HEAD", "OPTIONS"}}
    assert ("GET", EXPORT) in routes

    formats = [item for item in operation["parameters"] if item.get("name") == "format"][0]
    assert tuple(formats["schema"]["enum"]) == facts.EXPORT_FORMATS
    assert formats["schema"]["default"] == facts.EXPORT_FORMATS[0]

    headers = operation["responses"]["200"]["headers"]
    assert export.EXPORT_DISPOSITION_HEADER in headers
    assert export.EXPORT_EXPIRES_HEADER in headers


