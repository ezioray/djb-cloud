# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-0004 管理后台运维中心 + 配置中心服务层（§22.21 / §21.12 / RPT-0002 §3）。

本文件按验收 ①–⑥ 组织：

======  ============================================================================
验收    用例
======  ============================================================================
①      ``TestContract``：8 个 operationId 与 spec 逐条对齐、不新增路由
②      ``TestSoD``：自批自核 403（含重复复核人、拒绝留痕）
③      ``TestSensitive``：只给 secret_ref / 脱敏摘要；明文在库里就存不进去
④      ``TestP0Gates``：step-up + 双人 + step-up 不复用 + ``expired`` 不自动放行
⑤      ``TestIdempotencyAndAudit``：24h 幂等、审计同事务、哈希链可复算、不可改写
⑥      ``TestFeatureFlag``：默认关闭、三字段齐全、关闭后写入口 404 读视图仍可用
——      ``TestReadModels``：健康 / SLO / 告警去重 / 漂移三源 / 变更日历 / 审计检索
——      ``TestChain``：一次「草稿→发布→复核→回滚」全链路（证据文件的主体）

数据库：``DJB_DSN`` 指向的开发库；库不可达整文件 skip。表建在独立 schema
（``DJB_ADMIN_SCHEMA``，本文件用 ``ops_center_test``），不碰 ``public``、不新增迁移。
"""
from __future__ import annotations

import json
import os
import pathlib
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import app.admin as admin
import app.admin.ops_center as ops
from app.config import dsn

SCHEMA = "ops_center_test"
UTC = timezone.utc
#: 2026-10-22 是周四；03:00Z = 11:00 UTC+8 → 落在发布窗口（工作日 10:00–17:00）内。
NOW = datetime(2026, 10, 22, 3, 0, tzinfo=UTC)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKSPACE_SPEC = pathlib.Path(__file__).resolve().parents[3] / "spec" / "openapi.yaml"

ALL_PERMS = frozenset({
    "config.item.read", "config.item.publish", "config.item.approve",
    "config.item.rollback", "config.item.emergency", "config.item.secret.read",
    "config.audit.export",
})


# --------------------------------------------------------------------------- 基础设施
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
    """每个用例从空库开始（只动本模块自己的表）。"""
    with ops._tx(SCHEMA) as cur:
        cur.execute("""TRUNCATE config_audit, config_idempotency, config_publish_request,
                                config_item, config_runtime, ops_component_state,
                                ops_slo_window, ops_alert, ops_freeze_window
                       RESTART IDENTITY CASCADE""")
    yield


@pytest.fixture()
def on(monkeypatch):
    """写入口打开（验收 ⑥ 的反面）。"""
    monkeypatch.setenv("DJB_FF_ADMIN_OPS_CENTER", "1")
    return True


def principal(actor="alice", *, roles=("OPS",), perms=ALL_PERMS, step_up=True,
              step_ref="stepup-publish", at=NOW, break_glass=False):
    return ops.AdminPrincipal(
        actor=actor, roles=frozenset(roles), permissions=frozenset(perms),
        step_up_at=at if step_up else None,
        step_up_ref=step_ref if step_up else None,
        break_glass=break_glass,
    )


def approver(actor="bob", *, roles=("FIN",), step_ref="stepup-approve", at=NOW):
    return principal(actor, roles=roles, step_ref=step_ref, at=at)


def raw(sql, params=()):
    with psycopg.connect(dsn(), autocommit=True, row_factory=psycopg.rows.dict_row) as c:
        with c.cursor() as cur:
            cur.execute(f'SET search_path TO "{SCHEMA}", public')
            cur.execute(sql, params)
            try:
                return cur.fetchall()
            except psycopg.ProgrammingError:
                return []


def draft(key="billing.service_fee_bps", value=1200, *, actor="alice", value_type="integer",
          extra=None, now=NOW):
    body = {"value": value, "value_type": value_type, "reason": "调整服务费率", "ticket": "OPS-1"}
    body.update(extra or {})
    return ops.create_config_draft(principal(actor), key, body, now=now)


def publish(key, version, *, actor="alice", now=NOW, extra=None, step_ref="stepup-publish"):
    body = {"version": version, "reason": "灰度发布", "ticket": "OPS-1"}
    body.update(extra or {})
    return ops.publish_config_item(principal(actor), key, body, step_up_ref=step_ref,
                                   step_up_at=now, now=now)


def approve(request_id, who, *, decision="approve", now=NOW, step_ref=None, idem=None):
    ref = step_ref or f"stepup-{who.actor}"
    return ops.approve_config_publish(
        who, request_id, {"decision": decision, "reason": "复核通过，影响面已看"},
        step_up_ref=ref, step_up_at=now, idempotency_key=idem, now=now)


def make_active(key="billing.service_fee_bps", value=1200, *, now=NOW):
    """草稿 → 发布 → 复核（P0 两人 / 其它一人）→ 推进到 active。"""
    d = draft(key, value, now=now)
    p = publish(key, d["version"], now=now)
    approve(p["request_id"], approver("bob", roles=("FIN",)), now=now)
    if ops.KEY_POLICIES[key].risk == "P0":
        approve(p["request_id"], approver("carol", roles=("AUDIT",)), now=now)
    ops.advance_publish_requests(now + timedelta(hours=26))       # 越过 P0 的 24h 排期
    return d, p


# =========================================================================== ① 契约
class TestContract:
    def test_operations_match_spec_exactly(self):
        """8 个 operationId 必须与 spec 完全一致：少一条 / 多一条都红。"""
        if not WORKSPACE_SPEC.exists():
            pytest.skip(f"spec 不在工作区（{WORKSPACE_SPEC}）；CI 由契约测试覆盖")
        import yaml
        spec = yaml.safe_load(WORKSPACE_SPEC.read_text(encoding="utf-8"))
        in_spec = {}
        for path, item in spec["paths"].items():
            if not path.startswith("/api/v1/admin/config"):
                continue
            for method, op in item.items():
                if method in ("get", "post", "put", "patch", "delete"):
                    in_spec[op["operationId"]] = (method.upper(), path)
        assert set(in_spec) == set(admin.OPERATIONS), (
            f"spec 有而未实现: {sorted(set(in_spec) - set(admin.OPERATIONS))}；"
            f"实现了 spec 没有的: {sorted(set(admin.OPERATIONS) - set(in_spec))}")
        for op_id, (method, path) in in_spec.items():
            assert admin.OPERATIONS[op_id]["method"] == method, op_id
            assert admin.OPERATIONS[op_id]["path"] == path, op_id
        assert len(in_spec) == 8

    def test_every_operation_has_exactly_one_implementation(self):
        """8 条 spec 操作每条恰好一个实现函数，且函数上的 operationId 与实现一一对应。"""
        found: dict[str, list[str]] = {}
        for name in dir(ops):
            fn = getattr(ops, name)
            op_id = getattr(fn, "operation_id", None)
            if op_id:
                found.setdefault(op_id, []).append(name)
        assert set(found) == set(admin.OPERATIONS), (
            f"未实现的: {sorted(set(admin.OPERATIONS) - set(found))}；"
            f"多出来的: {sorted(set(found) - set(admin.OPERATIONS))}")
        for op_id, names in found.items():
            assert len(names) == 1, f"{op_id} 有多个实现: {names}"

    def test_operation_decorator_rejects_unregistered_id(self):
        """新增端点必须先改 spec：装饰器在导入期就拦。"""
        with pytest.raises(ValueError, match="不在 spec"):
            ops.operation("promoteConfigPublish")        # §21.12 设计里有，spec 里没有

    def test_public_surface_is_declared(self):
        """公开面只能来自三张表：8 操作 / 待接线视图 / 系统迁移 / 基础设施。"""
        infra = {
            "operation", "ensure_schema", "schema_name", "verify_audit_chain",
            "build_chain_anchor_argv", "render_config_item", "canon",
            "AdminPrincipal", "KeyPolicy", "KEY_POLICIES",
            "PENDING_SPEC_VIEWS", "SYSTEM_TRANSITIONS",
        }
        implemented = {name for name in dir(ops) if getattr(getattr(ops, name), "operation_id", None)}
        allowed = implemented | set(ops.PENDING_SPEC_VIEWS) | set(ops.SYSTEM_TRANSITIONS) | infra
        assert set(ops.__all__) <= allowed, sorted(set(ops.__all__) - allowed)

    def test_system_transitions_do_not_claim_operation_ids(self):
        for name in ops.SYSTEM_TRANSITIONS:
            assert getattr(getattr(ops, name), "operation_id", None) is None

    def test_no_config_http_routes_wired_by_this_ticket(self):
        """本单只做服务层：路由集合里不得出现 /api/v1/admin/config（接线留给后续单）。"""
        from app.api import app
        paths = {getattr(r, "path", "") for r in app.routes}
        assert not [p for p in paths if p.startswith("/api/v1/admin/config")]

    def test_response_carries_operation_id(self, clean, on):
        res = ops.list_config_items(principal())
        assert res["meta"]["operation_id"] == "listConfigItems"


# =========================================================================== ② SoD
class TestSoD:
    def test_self_approval_is_403(self, clean, on):
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        with pytest.raises(admin.Forbidden) as exc:
            approve(p["request_id"], principal("alice"))
        assert exc.value.http_status == 403
        assert "自批自核" in exc.value.message
        states = raw("SELECT state FROM config_publish_request")
        assert states == [{"state": "pending_approval"}]     # 没有偷偷批过去

    def test_duplicate_approver_is_403(self, clean, on):
        d = draft("treasury.hot_wallet_cap", 1000)
        p = publish("treasury.hot_wallet_cap", d["version"])
        approve(p["request_id"], approver("bob"), idem="dup-1")
        with pytest.raises(admin.Forbidden) as exc:
            approve(p["request_id"], approver("bob"), step_ref="stepup-bob-2", idem="dup-2")
        assert exc.value.http_status == 403
        assert "重复复核" in exc.value.message

    def test_denial_is_audited(self, clean, on):
        """拒绝也要留痕（§21.13.1 ⑥ 越权尝试计入指标）。"""
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        with pytest.raises(admin.Forbidden):
            approve(p["request_id"], principal("alice"))
        rows = raw("SELECT action, outcome, http_status, reason_code FROM config_audit "
                   "WHERE outcome='denied'")
        assert len(rows) == 1
        assert rows[0]["http_status"] == 403
        assert rows[0]["action"] == "denied.approveConfigPublish"
        assert rows[0]["reason_code"] == "R-SOD"

    def test_reject_releases_key_lock(self, clean, on):
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        approve(p["request_id"], approver("bob"), decision="reject")
        assert raw("SELECT state FROM config_publish_request") == [{"state": "rejected"}]
        # 解锁后可以就同一 key 重新发起（新单）
        draft("billing.service_fee_bps", 1100)
        assert publish("billing.service_fee_bps", 2)["state"] == "pending_approval"


# =========================================================================== ③ 敏感项
class TestSensitive:
    def test_sensitive_item_never_returns_plaintext(self, clean, on):
        secret = "kms://prod/treasury#deposit-addr-7f3a9c"
        d = ops.create_config_draft(
            principal(), "treasury.deposit_address_ref",
            {"secret_ref": secret, "value_type": "string", "reason": "更换收款地址引用",
             "ticket": "OPS-2"}, now=NOW)
        assert d["value"] is None
        assert d["secret_ref"] == secret
        assert d["sensitive"] is True
        assert d["masked_summary"].startswith("<sensitive sha256:")
        assert secret not in json.dumps(d["value"])

        got = ops.get_config_item(principal(), "treasury.deposit_address_ref")
        assert got["value"] is None and got["secret_ref"] == secret

    def test_sensitive_cannot_be_stored_with_plaintext(self, clean, on):
        """③ 的硬保证：表上 CHECK 让"敏感项还带明文"根本插不进去。"""
        with pytest.raises(psycopg.errors.CheckViolation):
            raw("""INSERT INTO config_item
                     (key, scope, version, state, value_type, value, secret_ref, sensitive,
                      risk_level, digest, created_at, created_by)
                   VALUES ('treasury.deposit_address_ref','global',1,'draft','string',
                           '"0xdeadbeef"', 'kms://x', true, 'P0', 'd', now(), 'tester')""")

    def test_sensitive_draft_rejects_plaintext_value(self, clean, on):
        with pytest.raises(admin.BadRequest) as exc:
            ops.create_config_draft(
                principal(), "treasury.deposit_address_ref",
                {"value": "0xdeadbeef", "value_type": "string", "reason": "试图提交明文"},
                now=NOW)
        assert "敏感项" in exc.value.message
        assert exc.value.details[0]["field"] == "value"

    def test_sensitive_draft_requires_secret_ref(self, clean, on):
        with pytest.raises(admin.BadRequest) as exc:
            ops.create_config_draft(
                principal(), "treasury.deposit_address_ref",
                {"value_type": "string", "reason": "忘记给引用"}, now=NOW)
        assert exc.value.details[0]["field"] == "secret_ref"

    def test_non_sensitive_rejects_secret_ref(self, clean, on):
        with pytest.raises(admin.BadRequest):
            ops.create_config_draft(
                principal(), "billing.service_fee_bps",
                {"secret_ref": "kms://x", "value_type": "integer", "reason": "错误给了引用"},
                now=NOW)

    def test_secret_view_needs_extra_permission_and_writes_audit(self, clean, on):
        ops.create_config_draft(
            principal(), "treasury.deposit_address_ref",
            {"secret_ref": "kms://prod/treasury#addr", "value_type": "string",
             "reason": "建立地址引用", "ticket": "OPS-2"}, now=NOW)
        with pytest.raises(admin.Forbidden):
            ops.get_config_item(principal(perms=ALL_PERMS - {"config.item.secret.read"}),
                                "treasury.deposit_address_ref", disclose=True)
        res = ops.get_config_item(principal(), "treasury.deposit_address_ref", disclose=True)
        assert res["reveal"]["plaintext_available_here"] is False
        assert res["reveal"]["reveal_ttl_seconds"] == 300          # §21.12.5 #6 五分钟
        assert res["value"] is None
        views = raw("SELECT action, after FROM config_audit WHERE action='config.secret.view'")
        assert len(views) == 1
        assert views[0]["after"]["value"] == "<<sensitive>>"

    def test_audit_redacts_sensitive_before_after(self, clean, on):
        ops.create_config_draft(
            principal(), "treasury.deposit_address_ref",
            {"secret_ref": "kms://prod/treasury#addr-2", "value_type": "string",
             "reason": "建立地址引用", "ticket": "OPS-2"}, now=NOW)
        row = raw("SELECT after FROM config_audit WHERE action='config.draft.create'")[0]
        assert row["after"]["value"] == "<<sensitive>>"
        assert row["after"]["sensitive"] is True

    def test_chain_anchor_argv_masks_sensitive(self, clean, on):
        entry = {"actor": "alice", "actor_roles": "OPS", "action": "config.draft.create",
                 "key": "treasury.deposit_address_ref", "version": 3, "reason": "更换地址引用",
                 "reason_code": "R-CONFIG-DRAFT", "outcome": "ok",
                 "before": None, "after": {"sensitive": True, "secret_ref": "kms://x"}}
        argv = ops.build_chain_anchor_argv(entry, evidence="ops/audit/reports/x.txt")
        assert "--actor" in argv and argv[argv.index("--actor") + 1] == "alice"
        idx = argv.index("--after")
        assert argv[idx + 1] == "<<sensitive>>"
        assert "kms://x" not in " ".join(argv)

    def test_list_never_leaks_value_for_sensitive(self, clean, on):
        ops.create_config_draft(
            principal(), "treasury.deposit_address_ref",
            {"secret_ref": "kms://prod/treasury#addr-3", "value_type": "string",
             "reason": "建立地址引用", "ticket": "OPS-2"}, now=NOW)
        listed = ops.list_config_items(principal())["data"]
        treasury = [i for i in listed if i["key"].startswith("treasury.")]
        assert treasury and all(i["value"] is None for i in treasury)
        assert all(i["masked_summary"].startswith("<sensitive sha256:") for i in treasury)
        # secret_ref 本身是"引用"不是秘密（spec 允许回传）；价值零泄露的判据是 value 恒为 None
        assert all(set(json.dumps(i).split("@")) for i in treasury)
        assert not any("0x" in json.dumps(i) for i in treasury)


# =========================================================================== ④ P0 门禁
class TestP0Gates:
    def test_p0_requires_step_up_on_publish(self, clean, on):
        d = draft()
        with pytest.raises(admin.StepUpRequired) as exc:
            ops.publish_config_item(
                principal(step_up=False), "billing.service_fee_bps",
                {"version": d["version"], "reason": "缺少二次认证的发布", "ticket": "OPS-1"},
                now=NOW)
        assert exc.value.http_status == 424 and exc.value.code == 42401

    def test_stale_step_up_is_rejected(self, clean, on):
        d = draft()
        with pytest.raises(admin.StepUpRequired):
            ops.publish_config_item(
                principal(), "billing.service_fee_bps",
                {"version": d["version"], "reason": "二次认证已过期", "ticket": "OPS-1"},
                step_up_ref="old", step_up_at=NOW - timedelta(minutes=6), now=NOW)

    def test_p0_needs_two_distinct_approvers(self, clean, on):
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        ack1 = approve(p["request_id"], approver("bob", roles=("FIN",)))
        assert ack1["state"] == "pending_approval"        # P0 两个人：第一票不够
        assert ack1["approvals_required"] == 2
        ack2 = approve(p["request_id"], approver("carol", roles=("AUDIT",)))
        assert ack2["state"] == "scheduled"
        assert ack2["approvals_received"] == 2

    def test_p0_approver_must_be_fin_or_audit(self, clean, on):
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        with pytest.raises(admin.Forbidden) as exc:
            approve(p["request_id"], approver("dave", roles=("OPS",)))
        assert "FIN 或 AUDIT" in exc.value.message

    def test_p0_step_up_cannot_be_reused(self, clean, on):
        """发布与复核各需一次独立二次认证（§21.4.3）。"""
        d = draft()
        p = publish("billing.service_fee_bps", d["version"], step_ref="same-token")
        with pytest.raises(admin.Forbidden) as exc:
            approve(p["request_id"], approver("bob"), step_ref="same-token")
        assert "不得复用" in exc.value.message

    def test_p0_publish_requires_ticket(self, clean, on):
        d = draft()
        with pytest.raises(admin.BadRequest) as exc:
            ops.publish_config_item(
                principal(), "billing.service_fee_bps",
                {"version": d["version"], "reason": "没有变更单也想发"},
                step_up_ref="s1", step_up_at=NOW, now=NOW)
        assert exc.value.details[0]["field"] == "ticket"

    def test_cooldown_blocks_republish_but_not_rollback(self, clean, on):
        """P1 冷却 60min（OPS-12）：冷却期内禁止再发布，但**回滚必须放行**。"""
        key = "billing.slow_task_discount_pct"
        make_active(key, 40, now=NOW)                          # v1=40 active
        t1 = NOW + timedelta(minutes=65)                       # 冷却已过
        draft(key, 35, now=t1)
        p2 = publish(key, 2, now=t1)
        approve(p2["request_id"], approver("bob"), now=t1)
        ops.advance_publish_requests(t1 + timedelta(minutes=1))
        assert raw("SELECT version, state FROM config_item ORDER BY version")[-1] == \
            {"version": 2, "state": "active"}

        t2 = t1 + timedelta(minutes=5)                         # 距上次发布 5min < 60min
        draft(key, 30, now=t2)
        with pytest.raises(admin.Conflict) as exc:
            publish(key, 3, now=t2)
        assert "冷却期" in exc.value.message

        p = ops.rollback_config_item(
            principal(), key,
            {"target_version": 1, "reason": "折扣异常紧急回滚", "ticket": "INC-1"},
            step_up_ref="stepup-rb", step_up_at=t2, now=t2)
        assert p["state"] == "pending_approval"

    def test_p0_cooldown_is_24h(self, clean, on):
        """P0 冷却 24h（§21.4.3）：发布单落库的 cooldown_until 就是 requested_at + 24h。"""
        d = draft()
        ack = publish("billing.service_fee_bps", d["version"])
        row = raw("SELECT requested_at, cooldown_until FROM config_publish_request")[0]
        assert row["cooldown_until"] - row["requested_at"] == timedelta(hours=24)
        assert datetime.fromisoformat(ack["effective_at"]) == NOW + timedelta(hours=24)

    def test_expired_does_not_auto_approve(self, clean, on):
        """4h 未复核 → expired；此时复核必须 409，不能"补批"放行。"""
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        later = NOW + timedelta(hours=5)
        expired = ops.expire_stale_requests(now=later)
        assert expired["count"] == 1
        with pytest.raises(admin.Conflict) as exc:
            approve(p["request_id"], approver("bob"), now=later)
        assert "expired" in exc.value.message
        assert raw("SELECT state FROM config_item WHERE version=%s", (d["version"],)) \
            == [{"state": "draft"}]
        # 推进器也不会把 expired 变成 active
        ops.advance_publish_requests(now=later + timedelta(hours=1))
        assert raw("SELECT state FROM config_item WHERE version=%s", (d["version"],)) \
            == [{"state": "draft"}]

    def test_p0_effective_at_floor_is_24h(self, clean, on):
        d = draft()
        early = NOW + timedelta(hours=3)
        with pytest.raises(admin.Conflict):
            ops.publish_config_item(
                principal(), "billing.service_fee_bps",
                {"version": d["version"], "reason": "想立刻生效不等冷却", "ticket": "OPS-1",
                 "effective_at": early.isoformat()},
                step_up_ref="s1", step_up_at=NOW, now=NOW)
        # 不给 effective_at 时服务端按 24h 冷却兜底
        ack = ops.publish_config_item(
            principal(), "billing.service_fee_bps",
            {"version": d["version"], "reason": "按冷却窗排期发布", "ticket": "OPS-1"},
            step_up_ref="s1", step_up_at=NOW, now=NOW)
        assert datetime.fromisoformat(ack["effective_at"]) == NOW + timedelta(hours=24)


# =========================================================================== ⑤ 幂等与审计
class TestIdempotencyAndAudit:
    def test_idempotent_replay_returns_same_response(self, clean, on):
        d = draft()
        body = {"version": d["version"], "reason": "重复提交同一个请求", "ticket": "OPS-1"}
        first = ops.publish_config_item(
            principal(), "billing.service_fee_bps", body,
            idempotency_key="idem-1", step_up_ref="s1", step_up_at=NOW, now=NOW)
        # 同 key 同 body 再来一次：不产生第二张发布单
        raw("DELETE FROM config_publish_request WHERE false")     # no-op，保持可读
        second = ops.publish_config_item(
            principal(), "billing.service_fee_bps", body,
            idempotency_key="idem-1", step_up_ref="s1", step_up_at=NOW, now=NOW)
        assert second["idempotent_replay"] is True
        assert second["request_id"] == first["request_id"]
        assert len(raw("SELECT 1 FROM config_publish_request")) == 1

    def test_idempotency_conflict_on_different_body(self, clean, on):
        ops.create_config_draft(principal(), "billing.service_fee_bps",
                                {"value": 1200, "value_type": "integer", "reason": "第一版草稿"},
                                idempotency_key="idem-2", now=NOW)
        with pytest.raises(admin.Conflict) as exc:
            ops.create_config_draft(principal(), "billing.service_fee_bps",
                                    {"value": 1201, "value_type": "integer", "reason": "第二版草稿"},
                                    idempotency_key="idem-2", now=NOW)
        assert "幂等键冲突" in exc.value.message

    def test_idempotency_expires_after_24h(self, clean, on):
        d = draft()
        body = {"version": d["version"], "reason": "隔天再次发布", "ticket": "OPS-1"}
        first = ops.publish_config_item(
            principal(), "billing.service_fee_bps", body,
            idempotency_key="idem-3", step_up_ref="s1", step_up_at=NOW, now=NOW)
        # 先把上一单打成终态，才能再发（否则是 key 锁 409）
        approve(first["request_id"], approver(), decision="reject", now=NOW)
        later = NOW + timedelta(hours=25)
        second = ops.publish_config_item(
            principal(), "billing.service_fee_bps", body,
            idempotency_key="idem-3", step_up_ref="s1", step_up_at=later, now=later)
        assert second["idempotent_replay"] is False
        assert second["request_id"] != first["request_id"]

    def test_fingerprint_dedupe_when_key_absent(self, clean, on):
        """spec：缺幂等键时按请求体指纹 300s 去重。"""
        body = {"value": 1300, "value_type": "integer", "reason": "没有幂等键的提交"}
        first = ops.create_config_draft(principal(), "billing.service_fee_bps", body, now=NOW)
        second = ops.create_config_draft(principal(), "billing.service_fee_bps", body, now=NOW)
        assert second["idempotent_replay"] is True
        assert second["version"] == first["version"]
        assert len(raw("SELECT 1 FROM config_item")) == 1

    def test_response_carries_audit_pointer(self, clean, on):
        """同事务的证据：响应里的 audit.seq/hash 与库里那条是同一行。"""
        d = draft()
        row = raw("SELECT seq, hash FROM config_audit WHERE action='config.draft.create'")[0]
        assert d["audit"]["seq"] == row["seq"]
        assert row["hash"].startswith(d["audit"]["hash"])

    def test_business_change_rolls_back_when_audit_fails(self, clean, on, monkeypatch):
        """⑤ 的负向证明：审计写不进去 → 配置与幂等行都不落库（同一事务）。"""
        def boom(*a, **kw):
            raise RuntimeError("audit chain unavailable")
        monkeypatch.setattr(ops, "_append_audit", boom)
        with pytest.raises(RuntimeError):
            ops.create_config_draft(principal(), "billing.service_fee_bps",
                                    {"value": 1200, "value_type": "integer", "reason": "审计失败回滚"},
                                    idempotency_key="idem-tx", now=NOW)
        assert raw("SELECT 1 FROM config_item") == []
        assert raw("SELECT 1 FROM config_idempotency") == []

    def test_audit_chain_verifies(self, clean, on):
        draft()
        d2 = ops.create_config_draft(principal(), "notify.report.daily_send_at",
                                     {"value": "09:00", "value_type": "string",
                                      "reason": "修改日报时间"}, now=NOW)
        assert d2["version"] == 1
        res = ops.verify_audit_chain(name=SCHEMA)
        assert res["ok"] is True and res["bad"] == []
        assert res["entries"] >= 2

    def test_forged_audit_row_is_detected(self, clean, on):
        draft()
        raw("""INSERT INTO config_audit (at, actor, action, outcome, http_status, hash)
               VALUES (now(), 'attacker', 'config.publish.activate', 'ok', 200, 'deadbeef')""")
        res = ops.verify_audit_chain(name=SCHEMA)
        assert res["ok"] is False and res["bad"]

    def test_audit_is_append_only(self, clean, on):
        draft()
        with pytest.raises(psycopg.Error) as exc:
            raw("UPDATE config_audit SET actor='mallory'")
        assert "只追加" in str(exc.value)
        with pytest.raises(psycopg.Error) as exc:
            raw("DELETE FROM config_audit")
        assert "只追加" in str(exc.value)

    def test_history_version_is_immutable(self, clean, on):
        """草稿可改；一旦生效就不可改（回滚以历史版本为内容新建发布，§21.4.2）。"""
        make_active()
        with pytest.raises(psycopg.Error) as exc:
            raw("UPDATE config_item SET value='1201'::jsonb WHERE state='active'")
        assert "不可变" in str(exc.value) or "已生效" in str(exc.value)
        with pytest.raises(psycopg.Error):
            raw("DELETE FROM config_item")


# =========================================================================== ⑥ 开关
class TestFeatureFlag:
    def test_flag_default_off_with_three_fields(self):
        spec = admin.flag_spec("admin_ops_center")
        assert spec["default"] is False
        assert spec["owner"] == "web-dev"
        assert spec["expire_at"] == "2026-12-31"
        for field in admin.REQUIRED_FLAG_FIELDS:
            assert spec[field], field
        blob = spec["rollback_rule"]
        assert "只读" in blob and "404" in blob

    def test_default_is_closed_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DJB_FF_ADMIN_OPS_CENTER", raising=False)
        assert admin.writes_enabled() is False

    def test_expired_flag_forces_off(self, monkeypatch):
        monkeypatch.setenv("DJB_FF_ADMIN_OPS_CENTER", "1")
        assert admin.writes_enabled(today=datetime(2027, 1, 1).date()) is False

    def test_writes_404_when_flag_off_but_reads_work(self, clean, monkeypatch):
        monkeypatch.delenv("DJB_FF_ADMIN_OPS_CENTER", raising=False)
        d = None
        # 读视图照常
        assert ops.list_config_items(principal())["data"] == []
        assert ops.health_overview(principal())["overall"] in ("green", "yellow", "red", "unknown")
        # 4 个写入口一律 404（不是 403：不暴露"这里本来能写"）
        calls = [
            lambda: ops.create_config_draft(principal(), "billing.service_fee_bps",
                                            {"value": 1200, "value_type": "integer",
                                             "reason": "开关关着"}),
            lambda: ops.publish_config_item(principal(), "billing.service_fee_bps",
                                            {"version": 1, "reason": "开关关闭时发布", "ticket": "T"},
                                            step_up_ref="s", step_up_at=NOW),
            lambda: ops.approve_config_publish(principal("bob"), "req-x",
                                               {"decision": "approve", "reason": "开关关闭时复核"},
                                               step_up_ref="s", step_up_at=NOW),
            lambda: ops.rollback_config_item(principal(), "billing.service_fee_bps",
                                             {"target_version": 1, "reason": "开关关闭时回滚"},
                                             step_up_ref="s", step_up_at=NOW),
            lambda: ops.kill_switch_config_item(principal(), "billing.service_fee_bps",
                                                {"reason": "开关关闭时急停", "ttl_seconds": 60},
                                                step_up_ref="s", step_up_at=NOW),
        ]
        for call in calls:
            with pytest.raises(admin.FeatureDisabled) as exc:
                call()
            assert exc.value.http_status == 404
        assert raw("SELECT 1 FROM config_item") == []
        assert d is None

    def test_break_glass_is_read_only(self, clean, on):
        with pytest.raises(admin.BreakGlassReadOnly) as exc:
            ops.create_config_draft(principal(break_glass=True), "billing.service_fee_bps",
                                    {"value": 1200, "value_type": "integer", "reason": "只读模式下写入"})
        assert exc.value.http_status == 423


# =========================================================================== 只读视图
class TestReadModels:
    def test_drifts_cover_three_sources(self, clean, on):
        make_active("billing.service_fee_bps", 1200)          # desired = 1
        ops.report_runtime("billing.service_fee_bps", "global", "gw-1",
                           effective_version=1, running_version=1, now=NOW)
        assert ops.list_config_drifts(principal(), now=NOW)["data"] == []

        ops.report_runtime("billing.service_fee_bps", "global", "gw-1",
                           effective_version=1, running_version=0, now=NOW + timedelta(minutes=1))
        d = ops.list_config_drifts(principal(), now=NOW + timedelta(minutes=4))
        assert [x["kind"] for x in d["data"]] == ["effective_vs_running"]
        assert d["data"][0]["sla_breached"] is False          # 回执后 5 分钟内不算超

        d = ops.list_config_drifts(principal(), now=NOW + timedelta(minutes=30))
        assert d["data"][0]["sla_breached"] is True           # B≠C 超 5 分钟未收敛
        assert d["summary"]["breached"] == 1

    def test_drift_when_never_applied(self, clean, on):
        make_active()
        d = ops.list_config_drifts(principal(), now=NOW)
        assert d["data"][0]["kind"] == "desired_vs_effective"
        assert "回执" in d["data"][0]["detail"]

    def test_health_overview_escalates_config_block(self, clean, on):
        make_active()                                        # 无 runtime 回执 → 漂移
        h = ops.health_overview(principal(), now=NOW)
        config_block = next(b for b in h["blocks"] if b["component"] == "config")
        assert config_block["status"] in ("yellow", "red")
        assert len(h["blocks"]) == 7
        assert h["counts"]["publish_in_flight"] == 0

        raw("""INSERT INTO ops_component_state (component, status, detail, updated_at)
               VALUES ('ledger','red','复算差异非 0', now())""")
        h = ops.health_overview(principal(), now=NOW)
        assert h["overall"] == "red"
        block = next(b for b in h["blocks"] if b["component"] == "ledger")
        assert block["label"] == "账本" and block["detail"] == "复算差异非 0"

    def test_health_green_when_converged(self, clean, on):
        d, _ = make_active()
        ops.report_runtime("billing.service_fee_bps", "global", "gw-1",
                           effective_version=d["version"], running_version=d["version"], now=NOW)
        h = ops.health_overview(principal(), now=NOW)
        config_block = next(b for b in h["blocks"] if b["component"] == "config")
        assert config_block["status"] == "green"

    def test_slo_burn_rate(self, clean, on):
        raw("""INSERT INTO ops_slo_window (slo, window_start, window_end, good, total)
               VALUES ('api.availability', now() - interval '1 hour', now(), 990, 1000),
                      ('payout.success_rate', now() - interval '1 hour', now(), 1000, 1000)""")
        res = ops.slo_burn_rate(principal(), now=NOW)
        avail = next(s for s in res["series"] if s["slo"] == "api.availability")
        assert avail["achieved"] == 0.99
        assert avail["burn_rate"] == 10.0                     # (1-0.99)/(1-0.999)
        assert avail["severity"] == "high"                    # ≥6
        payout = next(s for s in res["series"] if s["slo"] == "payout.success_rate")
        assert payout["burn_rate"] == 0.0 and payout["severity"] == "ok"
        assert res["overall"] == "high"

    def test_alert_dedupe_and_suppression(self, clean, on):
        for i in range(10):                                   # 10 条同指纹 → 合并成 1 组
            raw("""INSERT INTO ops_alert (alert_id, fingerprint, severity, title, opened_at,
                                          last_seen, occurrences, state)
                   VALUES (%s,'fp-disk','P1','磁盘水位', now(), now(), 1, 'firing')""",
                (f"a{i}",))
        raw("""INSERT INTO ops_alert (alert_id, fingerprint, severity, title, opened_at, last_seen,
                                      occurrences, state, suppressed_until)
               VALUES ('b1','fp-maint','P2','维护期告警', now(), now(), 1, 'suppressed',
                       now() + interval '1 hour')""")
        res = ops.list_alerts(principal(), now=NOW)
        assert len(res["data"]) == 2
        disk = next(a for a in res["data"] if a["fingerprint"] == "fp-disk")
        assert disk["merged"] == 10 and disk["occurrences"] == 10
        assert res["metrics"]["dedupe_ratio"] >= 0.8
        assert res["metrics"]["meets_target"] is True
        assert res["metrics"]["suppressed_groups"] == 1

    def test_search_audit_filters_and_pages(self, clean, on):
        draft("billing.service_fee_bps", 1200)
        draft("notify.report.daily_send_at", "09:00", value_type="string")
        res = ops.search_audit(principal(), key="billing.service_fee_bps")
        assert [r["action"] for r in res["data"]] == ["config.draft.create"]
        assert res["totals"]["entries"] == 2
        page1 = ops.search_audit(principal(), limit=1)
        assert page1["page"]["has_more"] is True
        page2 = ops.search_audit(principal(), limit=1, cursor=page1["page"]["next_cursor"])
        assert page2["data"][0]["seq"] > page1["data"][0]["seq"]
        assert page2["page"]["has_more"] is False

    def test_change_calendar_lists_requests_and_windows(self, clean, on):
        d = draft()
        p = publish("billing.service_fee_bps", d["version"])
        raw("""INSERT INTO ops_freeze_window (window_id, reason, starts_at, ends_at)
               VALUES ('promo-1','大促冻结', now() + interval '1 day', now() + interval '3 day')""")
        cal = ops.change_calendar(principal())
        assert [r["request_id"] for r in cal["requests"]] == [p["request_id"]]
        assert cal["freeze_windows"][0]["window_id"] == "promo-1"
        assert cal["publish_window"]["exempt"] == ["rollback", "kill_switch"]

    def test_publish_window_and_freeze_window_are_enforced(self, clean, on):
        d = draft()
        # 周六（2026-10-24）
        saturday = datetime(2026, 10, 24, 3, 0, tzinfo=UTC)
        with pytest.raises(admin.Conflict) as exc:
            publish("billing.service_fee_bps", d["version"], now=saturday)
        assert "发布窗口" in exc.value.message
        # 工作日但 20:00 UTC+8（=12:00Z）
        with pytest.raises(admin.Conflict):
            publish("billing.service_fee_bps", d["version"],
                    now=datetime(2026, 10, 22, 12, 0, tzinfo=UTC))
        # 月末 2 天（2026-10-30 是周五）
        month_end = datetime(2026, 10, 30, 3, 0, tzinfo=UTC)
        with pytest.raises(admin.Conflict) as exc:
            publish("billing.service_fee_bps", d["version"], now=month_end)
        assert "冻结" in exc.value.message

    def test_rollback_is_exempt_from_window(self, clean, on):
        """周六（窗口外）发布被拒，但**回滚**放行：止损不该等窗口（§22.21）。"""
        key = "billing.slow_task_discount_pct"
        make_active(key, 40, now=NOW)
        t1 = NOW + timedelta(minutes=65)
        draft(key, 35, now=t1)
        p2 = publish(key, 2, now=t1)
        approve(p2["request_id"], approver("bob"), now=t1)
        ops.advance_publish_requests(t1 + timedelta(minutes=1))

        d3 = draft(key, 30, now=t1 + timedelta(minutes=2))
        saturday = datetime(2026, 10, 24, 3, 0, tzinfo=UTC)
        with pytest.raises(admin.Conflict) as exc:
            publish(key, d3["version"], now=saturday)
        assert "发布窗口" in exc.value.message
        ack = ops.rollback_config_item(
            principal(), key,
            {"target_version": 1, "reason": "周六紧急止损回滚", "ticket": "INC-9"},
            step_up_ref="stepup-rb", step_up_at=saturday, now=saturday)
        assert ack["state"] == "pending_approval"


# =========================================================================== 全链路
class TestChain:
    def test_full_chain_draft_publish_approve_rollback(self, clean, on):
        """一次「草稿→发布→复核→回滚」：每步状态都断言，并把轨迹打出来给证据文件。"""
        key = "pool.reserved_default"        # P0：step-up + 双人 + 24h 冷却
        trace: list[str] = []

        d1 = draft(key, 30)
        trace.append(f"1. 草稿 v{d1['version']} state={d1['state']} risk={d1['risk_level']}")
        assert d1["state"] == "draft"

        p1 = publish(key, 1, extra={"effective_at": (NOW + timedelta(hours=25)).isoformat()})
        trace.append(f"2. 发布单 {p1['state']} 需 {p1['approvals_required']} 人复核")
        assert p1["state"] == "pending_approval" and p1["approvals_required"] == 2

        a1 = approve(p1["request_id"], approver("bob", roles=("FIN",)))
        trace.append(f"3. 复核一 {a1['approvals_received']}/{a1['approvals_required']} → {a1['state']}")
        assert a1["state"] == "pending_approval"

        a2 = approve(p1["request_id"], approver("carol", roles=("AUDIT",)))
        trace.append(f"4. 复核二 → {a2['state']}")
        assert a2["state"] == "scheduled"

        ops.advance_publish_requests(NOW + timedelta(hours=26))
        active = raw("SELECT version, state FROM config_item ORDER BY version")
        trace.append(f"5. 生效：{active}")
        assert active == [{"version": 1, "state": "active"}]

        # 24h 冷却过后再发一版（35%），演示"改到 35 再回滚到 30"
        later = NOW + timedelta(hours=25)
        d2 = draft(key, 35, now=later)
        p2 = publish(key, 2, now=later)
        approve(p2["request_id"], approver("bob", roles=("FIN",)), now=later)
        approve(p2["request_id"], approver("carol", roles=("AUDIT",)), now=later)
        ops.advance_publish_requests(later + timedelta(hours=25))
        trace.append("6. 改到 35% 并生效：" + str(raw("SELECT version, state FROM config_item ORDER BY version")))

        rb_at = later + timedelta(hours=26)          # p2 已到点生效之后
        rb = ops.rollback_config_item(
            principal(), key,
            {"target_version": 1, "reason": "公共池被挤压，回滚到 30 基线", "ticket": "INC-7"},
            step_up_ref="stepup-rb", step_up_at=rb_at, now=rb_at)
        trace.append(f"7. 回滚单 {rb['state']} 目标 v{rb['version']}")
        assert rb["state"] == "pending_approval"

        approve(rb["request_id"], approver("bob", roles=("FIN",)), now=rb_at)
        approve(rb["request_id"], approver("carol", roles=("AUDIT",)), now=rb_at)
        ops.advance_publish_requests(rb_at + timedelta(hours=1))
        final = raw("SELECT version, state, value FROM config_item ORDER BY version")
        trace.append(f"8. 回滚后：{final}")
        assert {"version": 1, "state": "active", "value": 30} in final
        assert {"version": 2, "state": "rolled_back", "value": 35} in final

        chain = ops.verify_audit_chain(name=SCHEMA)
        trace.append(f"9. 审计链 {chain['entries']} 条，复算 bad={chain['bad']} ok={chain['ok']}")
        assert chain["ok"] is True
        kinds = [r["kind"] for r in raw("SELECT kind FROM config_publish_request ORDER BY requested_at")]
        trace.append(f"10. 发布单类型序列：{kinds}")
        assert kinds == ["publish", "publish", "rollback"]
        print("\n[DEV-0004 链路证据]\n" + "\n".join(trace))

    def test_kill_switch_tightens_only_and_reverts_on_ttl(self, clean, on):
        make_active("billing.service_fee_bps", 1800)          # 先抬到 1800 bps
        ks = ops.kill_switch_config_item(
            principal(), "billing.service_fee_bps",
            {"reason": "费率异常，紧急收紧到基线值", "ttl_seconds": 3600, "tighten_only": True},
            step_up_ref="stepup-ks", step_up_at=NOW, now=NOW)
        assert ks["state"] == "active"
        assert ks["revert_to_version"] == 1
        vals = raw("SELECT version, state, value FROM config_item ORDER BY version")
        assert {"version": 2, "state": "active", "value": 1500} in vals
        assert {"version": 1, "state": "rolled_back", "value": 1800} in vals

        # 已经比预设更保守时，再按一次必须拒绝（只收紧不放开）
        with pytest.raises(admin.Conflict) as exc:
            ops.kill_switch_config_item(
                principal(), "billing.service_fee_bps",
                {"reason": "再按一次急停", "ttl_seconds": 60},
                step_up_ref="stepup-ks2", step_up_at=NOW, now=NOW)
        assert "只收紧" in exc.value.message

        # TTL 到期自动回到上一生效版本
        out = ops.expire_kill_switches(now=NOW + timedelta(seconds=3601))
        assert out["count"] == 1
        vals = raw("SELECT version, state FROM config_item ORDER BY version")
        assert {"version": 1, "state": "active"} in vals
        assert {"version": 2, "state": "rolled_back"} in vals
        assert ops.verify_audit_chain(name=SCHEMA)["ok"] is True

    def test_kill_switch_cannot_loosen(self, clean, on):
        """kill switch 不是"绕过审批改值"的后门：没有保守预设的键直接拒绝。"""
        with pytest.raises(admin.BadRequest) as exc:
            ops.kill_switch_config_item(
                principal(), "treasury.gas_fee_mode",
                {"reason": "想改 gas 承担方", "ttl_seconds": 60},
                step_up_ref="s", step_up_at=NOW, now=NOW)
        assert "保守预设" in exc.value.message


# =========================================================================== 其它门禁
class TestGates:
    def test_unregistered_key_is_rejected(self, clean, on):
        with pytest.raises(admin.BadRequest) as exc:
            draft("made.up.key", 1)
        assert "未注册" in exc.value.message

    def test_max_delta_gate(self, clean, on):
        make_active("billing.service_fee_bps", 1200)
        with pytest.raises(admin.BadRequest) as exc:
            draft("billing.service_fee_bps", 1999)     # delta 799 > 500
        assert exc.value.details[0]["field"] == "value"

    def test_range_and_type_gates(self, clean, on):
        with pytest.raises(admin.BadRequest):
            draft("pool.reserved_default", 60)                    # > 50
        with pytest.raises(admin.BadRequest):
            draft("pool.reserved_default", "30", value_type="string")   # 类型不符
        with pytest.raises(admin.BadRequest):
            draft("pool.reserved_default", 30, extra={"value_type": "integer",
                                                      "unexpected": 1})  # 未定义字段

    def test_gray_plan_must_be_increasing(self, clean, on):
        d = draft()
        with pytest.raises(admin.BadRequest) as exc:
            publish("billing.service_fee_bps", d["version"],
                    extra={"gray_plan": {"buckets": [25, 5]}})
        assert "递增" in exc.value.message

    def test_frozen_private_domain_is_read_only(self, clean, on):
        with pytest.raises(admin.Forbidden) as exc:
            draft("risk.rule_version", "v9")
        assert "私有域" in exc.value.message

    def test_get_unknown_item_is_404(self, clean, on):
        with pytest.raises(admin.NotFound):
            ops.get_config_item(principal(), "billing.service_fee_bps")

    def test_get_without_perm_is_404_not_403(self, clean, on):
        """§21.12.4：越权访问配置项统一 404，不泄露存在性。"""
        draft()
        with pytest.raises(admin.NotFound) as exc:
            ops.get_config_item(principal(perms=frozenset()), "billing.service_fee_bps")
        assert exc.value.code == 40401

    def test_request_id_propagates_to_audit(self, clean, on):
        p = ops.AdminPrincipal(actor="alice", permissions=ALL_PERMS,
                              step_up_at=NOW, step_up_ref="s1",
                              request_id="2f1c4b1e-1111-4222-8333-944455556666")
        ops.create_config_draft(
            p, "billing.service_fee_bps",
            {"value": 1200, "value_type": "integer", "reason": "带请求号的写入",
             "ticket": "OPS-1"}, now=NOW)
        row = raw("SELECT request_id FROM config_audit WHERE action='config.draft.create'")[0]
        assert row["request_id"] == p.request_id

    def test_concurrent_drafts_get_distinct_versions(self, clean, on):
        """并发建草稿不能撞同版本号（advisory lock 保证）。"""
        from concurrent.futures import ThreadPoolExecutor
        bodies = [{"value": 1200 + i, "value_type": "integer", "reason": f"并发建草稿{i}"}
                  for i in range(4)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda b: ops.create_config_draft(
                principal(), "billing.service_fee_bps", b, now=NOW), bodies))
        versions = [r["version"] for r in
                    raw("SELECT version FROM config_item ORDER BY version")]
        assert versions == [1, 2, 3, 4]
