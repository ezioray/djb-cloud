# SPDX-License-Identifier: AGPL-3.0-or-later
"""契约测试：实现 vs ``spec/openapi.yaml``（spec 1.2.4）与 ``02-events.md``。

四件事（任务卡验收 2）：

1. **只实现 spec 声明过的端点**，且十条一个不少（多了不行——合并进 ``app.api`` 后 CI 按这个口径卡）；
2. 响应载荷含 spec 的 ``required`` 字段（``additionalProperties`` 允许我们多给）；
3. 错误信封 ``{error:{type,code,message,request_id}}`` 与 spec 一致，``code`` 是**已登记整数**；
4. 事件矩阵里的每个事件都在 02-events §3 登记过。
"""
from __future__ import annotations

import os
import pathlib
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.reputation import errors, facts, models, outbox, router

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
#: spec 在仓库里被 .gitignore（CI 构建期拉取）；工作区根目录有一份权威副本（tag spec-1.2.4）
SPEC_CANDIDATES = (
    os.environ.get("DJB_SPEC_FILE"),
    REPO_ROOT / "spec" / "openapi.yaml",
    REPO_ROOT.parents[1] / "spec" / "openapi.yaml",
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

M07_OPERATIONS = {
    ("get", "/api/v1/user/reputation"): "getMyReputation",
    ("get", "/api/v1/user/reputation/events"): "listMyReputationEvents",
    ("get", "/api/v1/user/cop"): "getMyCopBalance",
    ("get", "/api/v1/user/cop/ledger"): "listMyCopLedger",
    ("post", "/api/v1/user/cop/redemptions"): "createCopRedemption",
    ("get", "/api/v1/user/cop/redemptions/{id}"): "getCopRedemption",
    ("post", "/api/v1/user/cop/transfers"): "createCopTransfer",
    ("get", "/api/v1/user/cop/invites"): "listMyInvites",
    ("get", "/api/v1/admin/reputation/scores"): "listReputationScores",
    ("post", "/api/v1/admin/reputation/grants"): "createReputationGrant",
}


def _spec() -> dict:
    yaml = pytest.importorskip("yaml")
    for candidate in SPEC_CANDIDATES:
        if candidate and pathlib.Path(candidate).exists():
            return yaml.safe_load(pathlib.Path(candidate).read_text(encoding="utf-8"))
    pytest.skip(f"spec 缺失（{SPEC_CANDIDATES}）；CI 会先拉固定版本")


def _product_module(name: str) -> pathlib.Path | None:
    for base in (REPO_ROOT.parent.parent, REPO_ROOT.parent, REPO_ROOT):
        candidate = base / "product" / "v4" / "modules" / name
        if candidate.exists():
            return candidate
    return None


# --------------------------------------------------------------------------- 端点
def test_router_only_implements_declared_endpoints():
    spec = _spec()
    declared = {(method, path) for path, item in spec["paths"].items()
                for method in item if method in HTTP_METHODS}
    implemented = set()
    for route in router.create_router().routes:
        for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
            implemented.add((method.lower(), route.path))
    assert implemented, "路由为空"
    assert implemented <= declared, f"实现了 spec 未声明的端点：{sorted(implemented - declared)}"
    assert len(implemented) == 10, sorted(implemented)


def test_all_ten_operations_and_ids_match_spec():
    spec = _spec()
    for (method, path), operation_id in M07_OPERATIONS.items():
        item = spec["paths"].get(path)
        assert item is not None, f"spec 缺路径 {path}"
        operation = item.get(method)
        assert operation is not None, f"spec 缺 {method.upper()} {path}"
        assert operation["operationId"] == operation_id


def test_openapi_version_is_frozen_1_2_4():
    assert _spec()["info"]["version"] == "1.2.4"


# --------------------------------------------------------------------------- 响应字段
def test_schemas_required_fields_are_present():
    spec = _spec()
    schemas = spec["components"]["schemas"]
    moment = datetime(2026, 10, 23, 4, 0, 0, tzinfo=timezone.utc)

    profile = models.ReputationScore(
        account_id="user:1", score=912, tier="L2", quality_coef=Decimal("1.2"),
        stability_coef=Decimal("1.1"), window_days=30, policy_version="rep-v1",
        computed_at=moment, reasons=("tier_promoted",))
    _assert_required(schemas["ReputationProfile"], profile.as_dict())

    event = models.ReputationEvent(id=uuid.uuid4(), account_id="user:1", metric="online_rate",
                                   value=Decimal("960"), weight=2000, delta=Decimal("192"),
                                   ref_id="u-1", occurred_at=moment)
    _assert_required(schemas["ReputationEvent"], event.as_dict())
    _assert_required(schemas["ReputationEventPage"],
                     {"data": [event.as_dict()],
                      "page": {"has_more": False, "cursor": None, "next_cursor": None}})

    balance = models.CopBalance(available=100, locked=20, total_earned=120, redeemable=True,
                                transferable=False, updated_at=moment)
    _assert_required(schemas["CopBalance"], balance.as_dict())
    assert balance.as_dict()["unit"] == "COP"

    entry = models.CopLedgerEntry(id=uuid.uuid4(), account_id="user:1", direction="credit",
                                  amount=100, source="usage", ref_id="u-1",
                                  status="locked", lock_until=moment, created_at=moment)
    _assert_required(schemas["CopLedgerEntry"], entry.as_dict())
    _assert_required(schemas["CopLedgerPage"],
                     {"data": [entry.as_dict()], "page": {"has_more": False}})

    redemption = models.Redemption(redemption_id=uuid.uuid4(), units=10, state="posted",
                                   created_at=moment)
    _assert_required(schemas["CopRedemption"], redemption.as_dict())

    transfer = models.Transfer(transfer_id=uuid.uuid4(), units=10, state="posted",
                               created_at=moment)
    _assert_required(schemas["CopTransfer"], transfer.as_dict())

    invite = models.Invite(id=uuid.uuid4(), inviter_id="user:1", invitee_id="user:2",
                           code="ABCDEFGHJK", status="bound", bound_at=moment,
                           expire_at=moment, created_at=moment, earned_units=40)
    _assert_required(schemas["InviteRecord"], invite.as_dict())
    overview = models.InviteOverview(items=[invite], bound=1, pending=0, earned_units=40,
                                     start_cursor=None, next_cursor=None)
    _assert_required(schemas["InviteOverview"], overview.as_dict())

    _assert_required(schemas["ReputationScoreRow"], profile.as_admin_row())
    _assert_required(schemas["ReputationScorePage"],
                     {"data": [profile.as_admin_row()], "page": {"has_more": False}})

    grant = models.Grant(id=uuid.uuid4(), account_id="user:1", kind="grant", units=100,
                         reason="运营补发", approval_id=None, created_at=moment,
                         actor="admin:a", approved_by="admin:b")
    _assert_required(schemas["ReputationGrant"], grant.as_dict())


def test_request_schemas_required_fields():
    spec = _spec()
    schemas = spec["components"]["schemas"]
    assert set(schemas["CopRedemptionRequest"]["required"]) == {"units"}
    assert set(schemas["CopTransferRequest"]["required"]) == {"to_account_id", "units"}
    assert set(schemas["ReputationGrantRequest"]["required"]) == {
        "account_id", "kind", "units", "reason"}


def test_cop_ledger_source_enum_matches_inv05():
    spec = _spec()
    enum = spec["components"]["schemas"]["CopLedgerEntry"]["properties"]["source"]["enum"]
    assert set(enum) == {"usage", "invite", "reward", "transfer_in", "transfer_out",
                         "redeem", "revoke"}
    status_enum = spec["components"]["schemas"]["CopLedgerEntry"]["properties"]["status"]["enum"]
    assert set(status_enum) == {"pending", "locked", "available", "spent", "revoked"}


def test_reputation_profile_has_no_rate_field():
    """INV-08：本模块只输出等级与系数，spec 也不允许出现费率 / 折扣字段。"""
    spec = _spec()
    properties = spec["components"]["schemas"]["ReputationProfile"]["properties"]
    assert not [name for name in properties
                if re.search(r"(rate|discount|price|fee)", name)]
    payload = models.ReputationScore(
        account_id="user:1", score=1, tier="L1", quality_coef=Decimal("0.5"),
        stability_coef=Decimal("0.5"), window_days=30, policy_version="rep-v1",
        computed_at=datetime(2026, 1, 1, tzinfo=timezone.utc)).as_dict()
    assert not [key for key in payload if re.search(r"(rate|discount|price|fee)", key)]


# --------------------------------------------------------------------------- 错误信封
def test_error_envelope_matches_spec():
    spec = _spec()
    error = spec["components"]["schemas"]["Error"]["properties"]["error"]
    assert set(error["required"]) == {"type", "code", "message", "request_id"}
    for code, status in ((40001, 400), (40101, 401), (40201, 402), (40401, 404),
                         (40902, 409), (40919, 409), (42240, 422), (42401, 424)):
        body = {"error": {"type": errors.error_type_for(status), "code": code,
                          "message": "x", "request_id": "r"}}
        _assert_required(spec["components"]["schemas"]["Error"], body)
        assert body["error"]["type"] in error["properties"]["type"]["enum"]
        assert isinstance(body["error"]["code"], int)


def test_error_codes_are_registered_in_spec_text():
    """契约码必须有出处：细分码在 spec ``Error.code`` 说明里，通用段位码在 00-conventions §5。"""
    spec = _spec()
    description = spec["components"]["schemas"]["Error"]["properties"]["error"][
        "properties"]["code"]["description"]
    # M07 专用 / 复用的细分码：spec 1.2.4 逐条登记
    for code in (40201, 40401, 40902, 40919, 42240, 42401):
        assert str(code) in description, f"spec 未登记错误码 {code}"
    # 40001 / 40101 是 00-conventions §5 的通用段位码（400xx / 401xx），全模块共用
    conventions = _product_module("00-conventions.md")
    if conventions is not None:
        text = conventions.read_text(encoding="utf-8")
        assert "400xx" in text and "401xx" in text
    # 工程兜底码 50001 不是契约码（模块文档里已说明），不要求出现在 spec
    assert errors.StoreUnavailable.code == "50001"


def test_error_classes_expose_spec_codes():
    assert (errors.InvalidArgument.status_code, errors.InvalidArgument.code) == (400, "40001")
    assert (errors.Unauthorized.status_code, errors.Unauthorized.code) == (401, "40101")
    assert (errors.InsufficientBalance.status_code, errors.InsufficientBalance.code) == (402, "40201")
    assert (errors.NotFound.status_code, errors.NotFound.code) == (404, "40401")
    assert (errors.TransferDisabled.status_code, errors.TransferDisabled.code) == (409, "40902")
    assert (errors.ReviewerConflict.status_code, errors.ReviewerConflict.code) == (409, "40919")
    assert (errors.ValidationFailed.status_code, errors.ValidationFailed.code) == (422, "42240")
    assert (errors.StepUpRequired.status_code, errors.StepUpRequired.code) == (424, "42401")
    for cls in (errors.InvalidArgument, errors.Unauthorized, errors.NotFound, errors.Conflict,
                errors.TransferDisabled, errors.ReviewerConflict, errors.ValidationFailed,
                errors.StepUpRequired, errors.InsufficientBalance):
        assert int(cls.code) in {40001, 40101, 40201, 40401, 40902, 40919, 42240, 42401}


# --------------------------------------------------------------------------- 事件
def test_event_matrix_is_registered_in_events_contract():
    path = _product_module("02-events.md")
    if path is None:
        pytest.skip("02-events.md 不在本工作树可读范围内")
    text = path.read_text(encoding="utf-8")
    for event_type in outbox.EVENT_TYPES:
        assert event_type in text, f"02-events 未登记 {event_type}"
    for consumed in ("usage.settled", "account.state.changed"):
        assert consumed in text


def test_produced_events_match_spec_modules():
    """生产事件名与 spec/02-events 的 M07 行一致（reputation.changed / cop.* / invite.bound）。"""
    assert set(outbox.EVENT_TYPES) == {"reputation.changed", "cop.earned", "cop.spent",
                                       "invite.bound"}


def test_envelope_builder_requires_facts():
    with pytest.raises(ValueError):
        outbox.build_envelope("not.registered", aggregate_id="a", payload={},
                              idempotency_key="k")
    with pytest.raises(ValueError):
        outbox.reputation_changed(account_id="a", score=1, tier="L1", reasons=[],
                                  policy_version="rep-v1")
    with pytest.raises(ValueError):
        outbox.cop_earned(account_id="a", units=1, source="redeem", ref_id="r",
                          lock_until=None)


def test_module_constants_stay_in_contract_ranges():
    """§8.1 / §8.2：权重和 = 10000、窗口 7–90、邀请费率 0–1000 等。"""
    assert sum(facts.WEIGHTS_BPS.values()) == 10_000
    assert 7 <= facts.DEFAULT_CONFIG.window_days <= 90
    assert 0 <= facts.DEFAULT_CONFIG.invite_bps <= 1000
    assert 1 <= facts.DEFAULT_CONFIG.invite_months <= 24
    assert facts.PENALTY_CYCLE_CAP == 1000
    assert set(facts.PENALTY_WEIGHTS) == {"violation", "false_report", "malicious_occupancy"}
    assert facts.TIERS == ("L1", "L2", "L3", "L4", "L5")


def _assert_required(schema: dict, payload: dict) -> None:
    if "allOf" in schema:
        for item in schema["allOf"]:
            _assert_required(item, payload)
        return
    required = set(schema.get("required", ()))
    assert required <= set(payload), f"缺必填字段：{sorted(required - set(payload))}"
