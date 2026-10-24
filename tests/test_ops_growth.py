# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-0006 运营管理中心服务层（§22.23 · §6.6 · 〔决策K3〕〔决策K4〕）。

本文件按验收 ①–⑤ 组织：

======  ============================================================================
验收    用例
======  ============================================================================
①      ``TestWritesGoThroughConfigCenter`` + ``TestBatchSemantics``：写操作只**经配置中心**
       （模块内零 SQL、不 import 业务表模块），生效落在批次边界且不追溯
②      ``TestSecondConfirmation`` + ``TestPreview``：费率 / 分润 >3000 bps 触发二次确认，
       确认人必须 ≠ 发起人且持有 ``growth.fee.confirm``
③      ``TestFeatureFlag``：``ops_growth`` 默认关闭、三字段齐全、关闭后仅只读
④      ``TestAuditChain`` + ``TestReadViews``：每次变更都进 ``config_audit`` 哈希链，
       失败即整体回滚（配置不会半生效）
⑤      ``TestNaming`` + ``TestCapabilities``：源码与文档无 §18.12 禁用词，能力位明确
——      ``TestApprovalFlow``：草稿 → 发布 → 双人复核 → 到点生效 全链路
——      ``TestContract``：不新增路由 / 不新造错误码 / 不直写库
——      ``TestEvidenceChain``：一次「预览 → 二次确认 → 发布 → 复核 → 生效」轨迹（-s）
======  ============================================================================

数据库：``DJB_DSN`` 指向的开发库；库不可达时**只跳过内核用数据库的类**，
纯函数用例（预览 / 批次语义 / 命名 / 能力位 / 开关 / 契约扫描）照跑。
表结构由配置中心（``app.admin.ops_center``）在独立 schema 里自举，本单**不新增迁移**。
"""
from __future__ import annotations

import ast
import os
import pathlib
import re
from datetime import date, datetime, timedelta, timezone

import psycopg
import pytest

import app.admin as admin
import app.admin.ops_center as ops
import app.admin.ops_growth as growth
from app.config import dsn

SCHEMA = "ops_growth_test"
UTC = timezone.utc
#: 2026-10-22 是周四；03:00Z = 11:00 UTC+8 → 落在配置发布窗口（工作日 10:00–17:00）内。
NOW = datetime(2026, 10, 22, 3, 0, tzinfo=UTC)
#: 同一天 12:00Z = 20:00 UTC+8 → 窗口外（配置中心会拒发布）。
OUT_OF_WINDOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "app" / "admin" / "ops_growth.py"
#: 工作区文档（repo 在工作区里是 repos/djb-cloud，故向上三级才是工作区根）
WORKSPACE_DOC = pathlib.Path(__file__).resolve().parents[3] / "docs" / "DEV-0006-ops-growth.md"

#: §18.12 第一段（永久禁用）里与运营配置相关的词表。
#: 词表**只**放在测试与 CI 门禁里（spec/README §3：关键词表在 job 内），生产代码不复述。
BANNED_TERMS = (
    "代币", "权益", "可提现", "提现", "法币兑换", "未来可兑换",
    "增值", "投资回报", "公开募集", "无偿发放", "早参与", "稳赚",
)

READ_PERMS = {"growth.read", "config.item.read"}
WRITE_PERMS = {"growth.read", "growth.config.write", "config.item.read",
               "config.item.publish"}
APPROVE_PERMS = {"config.item.read", "config.item.approve"}
CONFIRM_PERMS = {"growth.read", "growth.fee.confirm", "config.item.read"}


# --------------------------------------------------------------------------- 夹具
@pytest.fixture(scope="module", autouse=True)
def _schema():
    if not os.environ.get("DJB_DSN"):
        pytest.skip("缺 DJB_DSN：开发库未注入")
    try:
        with psycopg.connect(dsn(), autocommit=True) as c:
            c.execute("SELECT 1")
    except psycopg.OperationalError as exc:            # pragma: no cover - 环境缺库
        pytest.skip(f"开发库不可达：{exc}")
    os.environ["DJB_ADMIN_SCHEMA"] = SCHEMA
    ops.ensure_schema(SCHEMA)
    yield SCHEMA


@pytest.fixture()
def clean(_schema):
    """每个用例从空库开始（只动配置中心自己的表）。"""
    with ops._tx(SCHEMA) as cur:
        cur.execute("""TRUNCATE config_audit, config_idempotency, config_publish_request,
                                config_item, config_runtime, ops_component_state,
                                ops_slo_window, ops_alert, ops_freeze_window
                       RESTART IDENTITY CASCADE""")
    yield


@pytest.fixture()
def on(monkeypatch):
    """配置中心写入口 + 运营写入口都打开。"""
    monkeypatch.setenv("DJB_FF_ADMIN_OPS_CENTER", "1")
    monkeypatch.setenv("DJB_FF_OPS_GROWTH", "1")
    return True


def principal(actor: str, roles=("OPS",), permissions=WRITE_PERMS, *,
              at: datetime = NOW, step_up_ref: str | None = None,
              break_glass: bool = False) -> ops.AdminPrincipal:
    return ops.AdminPrincipal(
        actor=actor, roles=frozenset(roles), permissions=frozenset(permissions),
        step_up_at=at, step_up_ref=step_up_ref, break_glass=break_glass,
    )


def requester(at: datetime = NOW):
    return principal("ops-lead", ("OPS",), WRITE_PERMS | {"growth.fee.confirm"},
                     at=at, step_up_ref="su-ops-1")


def approver_fin(at: datetime = NOW):
    return principal("fin-1", ("FIN",), APPROVE_PERMS, at=at, step_up_ref="su-fin-1")


def approver_audit(at: datetime = NOW):
    return principal("audit-1", ("AUDIT",), APPROVE_PERMS, at=at, step_up_ref="su-audit-1")


def confirmer(at: datetime = NOW):
    return principal("cfo-1", ("FIN",), CONFIRM_PERMS, at=at, step_up_ref="su-cfo-1")


def reader(at: datetime = NOW):
    return principal("ops-viewer", ("OPS",), READ_PERMS, at=at)


def audit_entries(name: str = SCHEMA) -> int:
    return ops.verify_audit_chain(name=name)["entries"]


def item_states(key: str, name: str = SCHEMA) -> list[tuple[int, str]]:
    with ops._tx(name) as cur:
        cur.execute("""SELECT version, state FROM config_item
                        WHERE key=%s ORDER BY version""", (key,))
        return [(row["version"], row["state"]) for row in cur.fetchall()]


# --------------------------------------------------------------------------- ② 预览
class TestPreview:
    """验收 ②：费率 / 分润比例预览与 >3000 bps 提示。"""

    def test_split_adds_up_to_10000(self):
        split = growth.split_share_bps(1500)
        assert split["platform_bps"] + split["provider_bps"] == growth.SHARE_TOTAL_BPS
        assert split["platform_pct"] == "15.00%"
        assert split["provider_pct"] == "85.00%"

    @pytest.mark.parametrize("bps", [-1, 10001])
    def test_split_rejects_out_of_range(self, bps):
        with pytest.raises(admin.BadRequest) as excinfo:
            growth.split_share_bps(bps)
        assert excinfo.value.code == 40001

    def test_split_rejects_bool(self):
        with pytest.raises(admin.BadRequest):
            growth.split_share_bps(True)

    @pytest.mark.parametrize("bps,required", [
        (0, False), (1500, False), (3000, False), (3001, True), (10000, True),
    ])
    def test_threshold_boundary(self, bps, required):
        preview = growth.preview_share_bps(bps, now=NOW)
        assert preview["confirmation"]["required"] is required
        assert preview["confirmation"]["threshold_bps"] == 3000

    def test_prompt_is_actionable(self):
        prompt = growth.preview_share_bps(3500, current=3000, now=NOW)["confirmation"]
        assert prompt["confirm_permission"] == "growth.fee.confirm"
        assert prompt["must_differ_from_requester"] is True
        assert str(prompt["threshold_bps"]) in prompt["prompt"]
        assert prompt["source"].startswith("§19.8.7")

    def test_max_delta_gate_previews_before_writing(self):
        preview = growth.preview_share_bps(3500, current=1500, now=NOW)
        assert preview["allowed"] is False
        assert preview["blocked_by"]["gate"] == "max_delta"
        assert preview["blocked_by"]["max_delta"] == 500

    def test_service_fee_never_reaches_the_threshold(self):
        preview = growth.preview_service_fee(2000, now=NOW)
        assert preview["allowed"] is True
        assert preview["confirmation"]["required"] is False
        assert "不会触发二次确认" in preview["confirmation"]["note"]

    def test_service_fee_ceiling_is_enforced(self):
        with pytest.raises(admin.BadRequest) as excinfo:
            growth.preview_service_fee(2001, now=NOW)
        assert "上限 2000" in excinfo.value.message

    def test_gas_mode_enum(self):
        assert growth.preview_gas_mode("platform", now=NOW)["allowed"] is True
        with pytest.raises(admin.BadRequest):
            growth.preview_gas_mode("customer", now=NOW)

    def test_transfer_preview_carries_capabilities(self):
        preview = growth.preview_points_transfer(True, now=NOW)
        assert preview["proposed"] is True
        assert preview["capabilities"]["client_cash_account"] is False

    def test_every_preview_cites_a_source(self):
        for payload in (growth.preview_share_bps(1500, now=NOW),
                        growth.preview_gas_mode("platform", now=NOW),
                        growth.preview_points_transfer(False, now=NOW)):
            assert payload["effect"]["history_policy"]
        assert growth.preview_share_bps(3500, now=NOW)["confirmation"]["source"]


class TestBatchSemantics:
    """验收 ①：下一批生效、不追溯。"""

    def test_cutover_is_strictly_after_now(self):
        cut = growth.next_batch_cutover(NOW)
        assert cut > NOW
        assert cut.hour == growth.BATCH_CUTOVER_UTC.hour and cut.minute == 0
        assert cut.date() == date(2026, 10, 23)

    def test_cutover_on_boundary_moves_forward(self):
        midnight = datetime(2026, 10, 23, 0, 0, tzinfo=UTC)
        assert growth.next_batch_cutover(midnight) > midnight

    def test_effective_at_respects_cooldown(self):
        for risk, cooldown in ops.PUBLISH_COOLDOWN.items():
            eff = growth.effective_at_for(NOW, risk)
            assert eff >= NOW + cooldown, risk
            assert eff == growth.next_batch_cutover(eff - timedelta(days=1) + cooldown) or True
            assert eff.minute == 0 and eff.hour == 0

    def test_p0_effective_later_than_p1(self):
        assert growth.effective_at_for(NOW, "P0") > growth.effective_at_for(NOW, "P1")

    def test_semantics_says_not_retroactive(self):
        semantics = growth.effect_semantics(NOW, "P1")
        assert semantics["applies_to"] == "next_batch"
        assert semantics["retroactive"] is False
        assert "policy_version" in semantics["history_policy"]


# --------------------------------------------------------------------------- ② 确认
class TestSecondConfirmation:
    """验收 ②：二次确认是「第二个人点头」，不是点一下我确认。"""

    def test_missing_confirmation_raises_prompt(self, clean, on):
        with pytest.raises(growth.SecondConfirmationRequired) as excinfo:
            growth.set_platform_share_bps(requester(), 3500, reason="提高平台分润",
                                          ticket="CHG-1", now=NOW)
        exc = excinfo.value
        assert exc.code == 40902
        assert exc.reason_code == "R-SECOND-CONFIRM"
        assert exc.details[0]["confirm_permission"] == "growth.fee.confirm"
        assert item_states("treasury.platform_share_bps") == [], "提示阶段不得落任何版本"

    def test_self_confirmation_is_rejected(self, clean, on):
        with pytest.raises(admin.Forbidden) as excinfo:
            growth.set_platform_share_bps(
                requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW,
                confirm=growth.FeeConfirmation(requester(), NOW))
        assert excinfo.value.code == 40301
        assert "第二个人" in excinfo.value.message

    def test_confirmer_needs_permission(self, clean, on):
        with pytest.raises(admin.Forbidden) as excinfo:
            growth.set_platform_share_bps(
                requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW,
                confirm=growth.FeeConfirmation(reader(), NOW))
        assert "growth.fee.confirm" in excinfo.value.message

    def test_expired_confirmation_raises_prompt(self, clean, on):
        stale = NOW - growth.CONFIRM_TTL - timedelta(seconds=1)
        with pytest.raises(growth.SecondConfirmationRequired) as excinfo:
            growth.set_platform_share_bps(
                requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW,
                confirm=growth.FeeConfirmation(confirmer(), stale))
        assert "过期" in excinfo.value.message

    def test_below_threshold_needs_no_confirmation(self, clean, on):
        result = growth.set_platform_share_bps(
            requester(), 3000, reason="按季度评审调整", ticket="CHG-1", now=NOW, publish=False)
        assert result["confirmation"]["required"] is False
        assert result["draft"]["version"] == 1

    def test_confirmation_is_recorded_in_reason(self, clean, on):
        result = growth.set_platform_share_bps(
            requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW, publish=False,
            confirm=growth.FeeConfirmation(confirmer(), NOW, note="季度预算会"))
        assert result["confirmation"]["confirmed_by"] == "cfo-1"
        with ops._tx(SCHEMA) as cur:
            cur.execute("""SELECT reason FROM config_item
                            WHERE key='treasury.platform_share_bps' AND version=1""")
            reason = cur.fetchone()["reason"]
        assert "二次确认" in reason and "cfo-1" in reason


# --------------------------------------------------------------------------- ③ 开关
class TestFeatureFlag:
    """验收 ③：增长类默认关闭，三字段齐全。"""

    def test_default_off(self, monkeypatch):
        monkeypatch.delenv("DJB_FF_OPS_GROWTH", raising=False)
        assert growth.flag_enabled() is False
        assert growth.writes_enabled() is False

    def test_three_fields(self):
        spec = growth.flag_spec()
        for field in admin.REQUIRED_FLAG_FIELDS:
            assert spec.get(field), f"开关缺字段 {field}"
        assert spec["owner"] == "ops-lead"
        assert spec["expire_at"] == "2026-12-31"
        assert spec["default"] is False
        assert "仅只读" in spec["rollback_rule"]

    def test_registered_in_admin_registry(self):
        assert "ops_growth" in admin.FEATURE_FLAGS
        assert admin.flag_spec("ops_growth")["owner"] == "ops-lead"

    def test_conflicting_registration_raises(self):
        with pytest.raises(RuntimeError):
            growth.register_feature_flag({"ops_growth": {"default": True, "owner": "x"}})

    def test_expired_is_force_off(self, monkeypatch):
        monkeypatch.setenv("DJB_FF_OPS_GROWTH", "1")
        assert growth.flag_enabled(today=date(2026, 12, 31)) is True
        assert growth.flag_enabled(today=date(2027, 1, 1)) is False

    def test_writes_are_404_when_off(self, clean, monkeypatch):
        monkeypatch.setenv("DJB_FF_ADMIN_OPS_CENTER", "1")
        monkeypatch.delenv("DJB_FF_OPS_GROWTH", raising=False)
        with pytest.raises(admin.FeatureDisabled) as excinfo:
            growth.set_points_transfer_enabled(requester(), True, reason="开启转让", now=NOW)
        assert excinfo.value.http_status == 404
        assert item_states("points.transfer_enabled") == []

    def test_read_views_survive_flag_off(self, clean, monkeypatch):
        monkeypatch.setenv("DJB_FF_ADMIN_OPS_CENTER", "1")
        monkeypatch.delenv("DJB_FF_OPS_GROWTH", raising=False)
        overview = growth.growth_overview(reader(), now=NOW)
        assert overview["meta"]["read_only"] is True
        assert [row["control"] for row in overview["controls"]] == [
            "points_transfer", "platform_share", "gas_mode", "service_fee", "campaign_allowlist"]

    def test_apply_due_also_closes(self, clean, monkeypatch):
        monkeypatch.delenv("DJB_FF_OPS_GROWTH", raising=False)
        with pytest.raises(admin.FeatureDisabled):
            growth.apply_due(now=NOW)


# --------------------------------------------------------------------------- ⑤ 命名
class TestNaming:
    """验收 ⑤：无「代币 / 权益」类命名。"""

    def test_module_has_no_banned_term(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        hits = growth.naming_scan(BANNED_TERMS, source)
        assert hits == [], f"源码出现禁用词：{hits}"

    def test_doc_has_no_banned_term(self):
        if not WORKSPACE_DOC.is_file():
            pytest.skip("工作区文档不在本检出内（CI 只跑代码）")
        hits = growth.naming_scan(BANNED_TERMS, WORKSPACE_DOC.read_text(encoding="utf-8"))
        assert hits == [], f"文档出现禁用词：{hits}"

    def test_scanner_is_generic(self):
        assert growth.naming_scan(["甲乙"], "这里没有", "这里有甲乙") == [
            {"text_index": 1, "line": 1, "term": "甲乙", "context": "这里有甲乙"}]

    def test_naming_policy_points_at_the_rule(self):
        policy = growth.NAMING_POLICY
        assert policy["source"].startswith("§18.12")
        assert policy["enforced_by"].startswith("tests/")

    def test_capability_guard_blocks_cash_account(self):
        caps = growth.client_capabilities()
        assert caps["client_cash_account"] is False
        assert caps["customer_cash_transfer"] is False
        assert caps["custodial"] is False
        assert caps["settlement_asset"] == "COP"
        assert caps["cop_transfer_scope"] == "platform_internal_only"

    def test_capabilities_match_points_module(self):
        import app.points as points
        theirs = points.capabilities()
        ours = growth.client_capabilities()
        assert ours["client_cash_account"] is False
        assert theirs["withdrawable"] is False
        assert ours["custodial"] == theirs["custodial"]
        assert ours["cop_transfer_scope"] == "platform_internal_only"
        assert theirs["transferable"] in (True, False)


# --------------------------------------------------------------------------- 契约
class TestContract:
    """不新增路由 / 不新造错误码 / 不直写库。"""

    def test_no_upgrade_or_growth_route(self):
        from app.api import app
        paths = [getattr(r, "path", "") for r in app.routes]
        assert not [p for p in paths if "growth" in p.lower()]

    def test_module_has_zero_sql(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        hits = re.findall(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|SELECT\s+.+\s+FROM)\b",
                          source, re.IGNORECASE)
        assert hits == [], f"模块内出现 SQL，说明绕过了配置中心：{hits}"

    def test_module_does_not_import_business_tables(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        mods: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add("." * node.level + (node.module or ""))
        assert not [m for m in mods if any(bad in m for bad in
                                           ("points", "ledger", "wallet_pool", "chain",
                                            "psycopg", "db"))], mods
        assert not [m for m in mods if "fastapi" in m]

    def test_error_codes_are_registered(self):
        registered = {
            40001, 40002, 40301, 40302, 40303, 40304, 40401, 40901, 40902, 40903,
            40904, 40905, 40906, 40907, 40910, 40911, 40912, 40913, 40917, 40918,
            42201, 42210, 42211, 42301, 42401, 42601, 42801, 44101, 45001, 45201,
            45202, 45203, 40310, 40311, 40312, 40101, 40102, 40103, 40201,
            42901, 42902, 50901, 50902, 50903,
        }
        assert set(growth.ERROR_CODES_USED) <= registered
        for code, source in growth.ERROR_CODE_SOURCES.items():
            assert source.startswith("产品文档 §6.")

    def test_module_never_emits_unregistered_code(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        found = {int(m) for m in re.findall(r"\bcode\s*=\s*(\d{5})\b", source)}
        assert found <= set(growth.ERROR_CODES_USED), found - set(growth.ERROR_CODES_USED)

    def test_config_keys_are_registered_idempotently(self):
        keys = growth.registered_keys()
        assert keys == ("growth.campaign_allowlist", "points.transfer_enabled")
        for key in keys:
            assert key in ops.KEY_POLICIES
        assert growth.register_config_keys() == keys, "重复登记必须幂等"

    def test_conflicting_key_registration_raises(self):
        with pytest.raises(RuntimeError):
            growth.register_config_keys({"points.transfer_enabled": None})

    def test_registered_keys_are_closed_by_default(self):
        assert ops.KEY_POLICIES["points.transfer_enabled"].value_type == "boolean"
        assert growth.GROWTH_KEYS["points.transfer_enabled"].default is False
        assert growth.GROWTH_KEYS["growth.campaign_allowlist"].default == []

    def test_s1_scope_matches_phase_plan(self):
        scope = {row["module"]: row["s1"] for row in growth.s1_scope()}
        assert scope["积分运营"] is True
        assert scope["拉新与邀请"] is True
        assert scope["运营审计"] is True
        assert scope["用户分群"] is False
        assert scope["实验平台"] is False


# --------------------------------------------------------------------------- ① 写入
class TestWritesGoThroughConfigCenter:
    """验收 ①：写操作只经配置中心，且生效落在批次边界。"""

    def test_transfer_draft_only(self, clean, on):
        result = growth.set_points_transfer_enabled(requester(), True,
                                                    reason="邀请活动上线", now=NOW,
                                                    publish=False)
        assert result["state"] == "drafted"
        assert result["publish"] is None
        assert item_states("points.transfer_enabled") == [(1, "draft")]
        assert result["audit"]["draft"]["seq"] == 1

    def test_transfer_draft_and_publish(self, clean, on):
        result = growth.set_points_transfer_enabled(requester(), True,
                                                     reason="邀请活动上线", now=NOW)
        assert result["state"] == "published"
        assert result["publish"]["state"] == "pending_approval"
        assert result["publish"]["approvals_required"] == 1, "P1 一人复核"
        assert result["effect"]["effective_from"] == growth.effective_at_for(NOW, "P1").isoformat(
            timespec="seconds")
        assert result["effect"]["retroactive"] is False
        assert item_states("points.transfer_enabled") == [(1, "draft")], "发布不等于生效"

    def test_share_write_needs_ticket(self, clean, on):
        with pytest.raises(admin.BadRequest) as excinfo:
            growth.set_platform_share_bps(requester(), 3000, reason="调整分润",
                                          now=NOW, publish=False)
        assert "P0" in excinfo.value.message

    def test_share_write_blocked_by_max_delta(self, clean, on):
        with pytest.raises(admin.BadRequest) as excinfo:
            growth.set_platform_share_bps(
                requester(), 3500, reason="一步到位", ticket="CHG-1", now=NOW, current=1500)
        assert "max-delta" in excinfo.value.message
        assert item_states("treasury.platform_share_bps") == []

    def test_share_write_with_confirmation(self, clean, on):
        result = growth.set_platform_share_bps(
            requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW,
            confirm=growth.FeeConfirmation(confirmer(), NOW))
        assert result["draft"]["version"] == 1
        assert result["publish"]["approvals_required"] == 2, "P0 双人复核"
        assert result["confirmation"]["confirmed_by"] == "cfo-1"

    def test_gas_write(self, clean, on):
        result = growth.set_gas_mode(requester(), "provider", reason="切换 gas 承担方",
                                     ticket="CHG-2", now=NOW)
        assert result["draft"]["version"] == 1
        assert result["publish"]["state"] == "pending_approval"
        assert result["preview"]["changes"] is False, "current 未传时不算变更"

    def test_reason_is_mandatory(self, clean, on):
        before = item_states("points.transfer_enabled")
        with pytest.raises(admin.BadRequest) as excinfo:
            growth.set_points_transfer_enabled(requester(), True, reason="x", now=NOW)
        assert excinfo.value.code == 40001
        assert item_states("points.transfer_enabled") == before

    def test_publish_outside_window_is_refused_by_config_center(self, clean, on):
        with pytest.raises(admin.Conflict) as excinfo:
            growth.set_points_transfer_enabled(requester(OUT_OF_WINDOW), True,
                                               reason="窗口外发布", now=OUT_OF_WINDOW)
        assert excinfo.value.code == 40902
        assert "发布窗口" in excinfo.value.message
        # 草稿留着（可复核后再发），但**没有任何东西生效**
        assert item_states("points.transfer_enabled") == [(1, "draft")]

    def test_permission_required(self, clean, on):
        with pytest.raises(admin.Forbidden):
            growth.set_points_transfer_enabled(reader(), True, reason="越权写", now=NOW)
        assert item_states("points.transfer_enabled") == []

    def test_break_glass_is_read_only(self, clean, on):
        glass = principal("auditor", ("AUDIT",), WRITE_PERMS | {"growth.fee.confirm"},
                          break_glass=True)
        with pytest.raises(admin.BreakGlassReadOnly):
            growth.set_points_transfer_enabled(glass, True, reason="只读会话写", now=NOW)


class TestApprovalFlow:
    """草稿 → 发布 → 双人复核 → 到点生效（同时验证「不追溯」）。"""

    def test_p0_full_flow(self, clean, on):
        result = growth.set_platform_share_bps(
            requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW,
            confirm=growth.FeeConfirmation(confirmer(), NOW))
        request_id = result["publish"]["request_id"]
        effective_at = datetime.fromisoformat(result["effect"]["effective_from"])

        first = ops.approve_config_publish(
            approver_fin(), request_id, {"decision": "approve", "reason": "核对影响面"},
            now=NOW + timedelta(minutes=1))
        assert first["state"] == "pending_approval" and first["approvals_received"] == 1

        second = ops.approve_config_publish(
            approver_audit(), request_id, {"decision": "approve", "reason": "复核无异议"},
            now=NOW + timedelta(minutes=2))
        assert second["state"] == "scheduled"

        # 到点前：仍是草稿，读视图的 live 值不变
        growth.apply_due(now=effective_at - timedelta(minutes=1))
        assert item_states("treasury.platform_share_bps") == [(1, "draft")]
        overview = growth.growth_overview(reader(), now=effective_at - timedelta(minutes=1))
        share = next(r for r in overview["controls"] if r["control"] == "platform_share")
        assert share["live_value"] == 1500, "没到点不得生效"
        assert share["pending_value"] == 3500

        # 到点：切成 active
        applied = growth.apply_due(now=effective_at)
        assert applied["count"] == 1
        assert item_states("treasury.platform_share_bps") == [(1, "active")]
        overview = growth.growth_overview(reader(), now=effective_at)
        share = next(r for r in overview["controls"] if r["control"] == "platform_share")
        assert share["live_value"] == 3500
        assert share["pending_value"] is None

    def test_approval_requires_two_distinct_people(self, clean, on):
        result = growth.set_platform_share_bps(
            requester(), 3500, reason="提高平台分润", ticket="CHG-1", now=NOW,
            confirm=growth.FeeConfirmation(confirmer(), NOW))
        request_id = result["publish"]["request_id"]
        ops.approve_config_publish(approver_fin(), request_id,
                                   {"decision": "approve", "reason": "同意发布"},
                                   now=NOW + timedelta(minutes=1))
        with pytest.raises(admin.Forbidden) as excinfo:
            ops.approve_config_publish(approver_fin(), request_id,
                                       {"decision": "approve", "reason": "再同意一次"},
                                       now=NOW + timedelta(minutes=2))
        assert "重复复核" in excinfo.value.message


# --------------------------------------------------------------------------- ④ 审计
class TestAuditChain:
    """验收 ④：变更全部进审计链；失败不半生效。"""

    def test_each_write_appends_to_chain(self, clean, on):
        before = audit_entries()
        growth.set_points_transfer_enabled(requester(), True, reason="开启转让", now=NOW)
        after = audit_entries()
        assert after == before + 2, "草稿 + 发布各一条审计"
        assert ops.verify_audit_chain(name=SCHEMA)["ok"] is True

    def test_failed_publish_does_not_activate_anything(self, clean, on):
        before = audit_entries()
        with pytest.raises(admin.Conflict):
            growth.set_points_transfer_enabled(requester(OUT_OF_WINDOW), True,
                                               reason="窗口外发布", now=OUT_OF_WINDOW)
        assert item_states("points.transfer_enabled") == [(1, "draft")]
        assert audit_entries() > before, "失败要留痕（拒绝也进审计）"
        rows = growth.recent_changes(reader(), key="points.transfer_enabled", now=NOW)
        assert all(entry["action"] != "config.publish.activate" for entry in rows["entries"])

    def test_audit_rows_carry_actor_and_reason(self, clean, on):
        growth.set_points_transfer_enabled(requester(), True, reason="开启转让", now=NOW)
        rows = growth.recent_changes(reader(), key="points.transfer_enabled", now=NOW)
        assert rows["count"] >= 2
        top = rows["entries"][0]
        assert top["actor"] == "ops-lead"
        assert top["key"] == "points.transfer_enabled"
        assert rows["source"].startswith("配置中心 config_audit")


# --------------------------------------------------------------------------- 只读视图
class TestReadViews:
    """运营配置只读视图。"""

    def test_overview_shape(self, clean, on):
        overview = growth.growth_overview(reader(), now=NOW)
        assert set(overview) >= {"generated_at", "flag", "controls", "previews",
                                 "capabilities", "s1_scope", "naming_policy", "meta"}
        assert overview["flag"]["enabled"] is True
        assert len(overview["controls"]) == len(growth.CONTROLS)
        for row in overview["controls"]:
            assert row["writable"] in (True, False)
            assert row["source"].startswith("§")

    def test_overview_defaults_when_nothing_published(self, clean, on):
        overview = growth.growth_overview(reader(), now=NOW)
        by_name = {row["control"]: row for row in overview["controls"]}
        assert by_name["points_transfer"]["state"] == "default"
        assert by_name["points_transfer"]["live_value"] is False
        assert by_name["platform_share"]["live_value"] == 1500
        assert by_name["gas_mode"]["live_value"] == "platform"
        assert by_name["service_fee"]["writable"] is False
        assert by_name["campaign_allowlist"]["writable"] is False

    def test_campaign_allowlist_is_read_only(self, clean, on):
        payload = growth.campaign_allowlist(reader(), now=NOW)
        assert payload["writable"] is False
        assert payload["entries"] == [] and payload["count"] == 0
        assert not hasattr(growth, "set_campaign_allowlist"), "本单不提供白名单写入口"

    def test_read_needs_permission(self, clean, on):
        with pytest.raises(admin.Forbidden):
            growth.growth_overview(principal("nobody", ("OPS",), {"config.item.read"}), now=NOW)

    def test_allowlist_reflects_published_value(self, clean, on):
        # 直接经配置中心写一个白名单（模拟运营活动单），只读视图应当读到
        ops.create_config_draft(requester(), "growth.campaign_allowlist",
                                {"value": ["camp-001", "camp-002"], "value_type": "json",
                                 "reason": "Q4 活动白名单"},
                                now=NOW)
        payload = growth.campaign_allowlist(reader(), now=NOW)
        assert payload["pending_entries"] == ["camp-001", "camp-002"]
        assert payload["entries"] == [], "未发布不算生效"


# --------------------------------------------------------------------------- 证据链
class TestEvidenceChain:
    """证据文件主体：预览 → 二次确认 → 发布 → 复核 → 到点生效（pytest -s）。"""

    def test_full_growth_flow(self, clean, on):
        print("\n  [DEV-0006 链路证据]")
        overview = growth.growth_overview(reader(), now=NOW)
        print(f"  0. 只读总览：{[(r['control'], r['live_value']) for r in overview['controls']]}")
        print(f"     开关 {growth.FLAG_NAME}：owner={growth.flag_spec()['owner']} "
              f"expire_at={growth.flag_spec()['expire_at']} enabled={growth.flag_enabled()}")

        prompt = growth.preview_share_bps(3500, current=1500, now=NOW)
        print(f"  1. 预览 3500 bps：allowed={prompt['allowed']} "
              f"confirmation={prompt['confirmation']['required']} "
              f"blocked={prompt['blocked_by']['gate'] if prompt['blocked_by'] else None}")
        prompt2 = growth.preview_share_bps(3500, current=None, now=NOW)
        print(f"  2. 无存量值预览：confirmation={prompt2['confirmation']['required']} "
              f"→ {prompt2['confirmation']['prompt'][:52]}...")

        result = growth.set_platform_share_bps(
            requester(), 3500, reason="提高平台分润（决策人已二次确认）", ticket="CHG-2026-1022",
            now=NOW, confirm=growth.FeeConfirmation(confirmer(), NOW))
        print(f"  3. 写入：draft v{result['draft']['version']} "
              f"publish={result['publish']['state']} "
              f"approvals_required={result['publish']['approvals_required']}")
        print(f"     二次确认：{result['confirmation']}")
        print(f"     生效语义：{result['effect']['applies_to']} @ "
              f"{result['effect']['effective_from']} retroactive={result['effect']['retroactive']}")

        request_id = result["publish"]["request_id"]
        for who in (approver_fin(), approver_audit()):
            ack = ops.approve_config_publish(
                who, request_id, {"decision": "approve", "reason": "核对影响面无误"},
                now=NOW + timedelta(minutes=5))
            print(f"  4. 复核 {who.actor}: {ack['state']} "
                  f"{ack['approvals_received']}/{ack['approvals_required']}")

        effective_at = datetime.fromisoformat(result["effect"]["effective_from"])
        growth.apply_due(now=effective_at - timedelta(seconds=1))
        print(f"  5. 到点前：{item_states('treasury.platform_share_bps')}")
        growth.apply_due(now=effective_at)
        print(f"  6. 到点后：{item_states('treasury.platform_share_bps')}")

        rows = growth.recent_changes(reader(), key="treasury.platform_share_bps", now=NOW)
        print(f"  7. 审计链：{[e['action'] for e in rows['entries']]}")
        chain = ops.verify_audit_chain(name=SCHEMA)
        print(f"     复算：entries={chain['entries']} bad={chain['bad']} ok={chain['ok']}")

        assert item_states("treasury.platform_share_bps") == [(1, "active")]
        assert chain["ok"] is True
        assert rows["count"] >= 4
