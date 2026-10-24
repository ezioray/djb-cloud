# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-0005 技术升级中心服务层（§22.22 · §18.7.1 · §22.9 · 〔决策K8〕）。

本文件按验收 ①–⑥ 组织：

======  ============================================================================
验收    用例
======  ============================================================================
①      ``TestVersionInventory``：版本清单 / 回滚点从 ``spec/CHANGELOG-协议.md`` 解析，
       并与 ``spec/openapi.yaml`` 的 ``info.version`` 做**显式**对齐判定
②      ``TestCanary`` + ``TestAdvanceDB``：按桶推进（internal → 1% → 10% → 50% → 全量），
       命中阈值自动停并落库留证（40907）
③      ``TestRollbackDB``：回滚到上一版，记录时间（回滚时刻 + 回滚点记录时间）与证据
④      ``TestCompatMatrix``：N/N-1/N-2 三行状态；缺证据即 ``unknown``，不假装通过
⑤      ``TestErrorCodes`` + ``TestNoRoutes``：只使用 §6.3/§6.3b 已登记码；不新增 HTTP 路由
⑥      ``TestFeatureFlag``：``upgrade_center`` 默认关闭、三字段齐全、关闭后只剩只读版本列表
——      ``TestAuditAndGuards``：审计哈希链可复算 + 证据只追加（不可 UPDATE/DELETE）
——      ``TestEvidenceChain``：一次「建单→灰度→自动停→回滚」全链路（证据文件主体）
——      ``TestSpecEdgeCases``：合成 CHANGELOG（多版本 / 混合兼容结论 / 缺段）
======  ============================================================================

数据库：``DJB_DSN`` 指向的开发库；库不可达时**只跳过内核用数据库的类**，
纯函数用例（版本解析 / 兼容矩阵 / 分桶 / 阈值 / 发布窗 / 错误码）仍然跑。
表建在独立 schema（``DJB_UPGRADE_SCHEMA``，本文件用 ``upgrade_center_test``），
不碰 ``public``、不新增迁移。
"""
from __future__ import annotations

import os
import pathlib
import re
from datetime import date, datetime, timedelta, timezone

import psycopg
import pytest

import app.admin as admin
import app.admin.upgrade_center as up
from app.config import dsn

SCHEMA = "upgrade_center_test"
UTC = timezone.utc
#: 2026-10-22 是周四；03:00Z = 11:00 UTC+8 → 落在发布窗口（工作日 10:00–17:00）内。
NOW = datetime(2026, 10, 22, 3, 0, tzinfo=UTC)
#: 同一天 12:00Z = 20:00 UTC+8 → 窗口外。
OUT_OF_WINDOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
#: 2026-10-24 是周六；03:00Z = 11:00 UTC+8 → 时间对但非工作日。
WEEKEND = datetime(2026, 10, 24, 3, 0, tzinfo=UTC)
#: 2026-10-30 是周五；03:00Z = 11:00 UTC+8，但落在月末 2 天冻结窗（29/30/31）。
MONTH_END = datetime(2026, 10, 30, 3, 0, tzinfo=UTC)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "app" / "admin" / "upgrade_center.py"


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
    os.environ[up.SCHEMA_ENV] = SCHEMA
    up.ensure_schema(SCHEMA)
    yield SCHEMA


@pytest.fixture()
def clean(_schema):
    """每个用例从空库开始（只动本模块自己的表）。"""
    with up._tx(SCHEMA) as cur:
        cur.execute("""TRUNCATE upgrade_run, upgrade_stage_event, upgrade_rollback,
                                upgrade_audit, upgrade_idempotency
                       RESTART IDENTITY CASCADE""")
    yield


@pytest.fixture()
def on(monkeypatch):
    """写入口打开（验收 ⑥ 的反面）。"""
    monkeypatch.setenv("DJB_FF_UPGRADE_CENTER", "1")
    return True


def principal(at: datetime = NOW, *, actor: str = "release-manager",
              permissions=None) -> up.UpgradePrincipal:
    """默认是一个权限齐全、step-up 新鲜的发布经理。"""
    return up.UpgradePrincipal(
        actor=actor,
        roles=frozenset({"RELEASE"}),
        permissions=up.PERMISSIONS if permissions is None else frozenset(permissions),
        step_up_at=at,
    )


def good_metrics(**overrides) -> dict:
    metrics = {
        "error_rate_pct": 0.4,
        "smoke_pass_pct": 100,
        "install_success_pct": 99.3,
        "ledger_recompute_diff_minor": 0,
        "reserve_coverage_delta_pct": 0.0,
    }
    metrics.update(overrides)
    return metrics


def run_body(**overrides) -> dict:
    body = {
        "kind": "app",
        "from_version": "1.0.0",
        "to_version": "1.1.0",
        "change_ticket": "CHG-2026-1022-01",
        "impact": "网关 + 管理面，灰度 5 桶",
        "rollback_plan": "回滚到 1.0.0，保留上一版镜像（§22.22 应用发布）",
        "acceptance_owner": "release-manager",
        "observation_seconds": 86400,
    }
    body.update(overrides)
    return body


CHANGELOG_SKELETON = """# 协议变更记录（测试样例）

## {newest} · 2026-10-15 · MINOR

**类型**：MINOR（示例）

**变更**
1. 示例变更

**影响面**
- 示例影响面

**兼容矩阵**
{compat}

**复核人**：lead（制单）
"""


def write_spec(tmp_path: pathlib.Path, *, versions=("1.2.0", "1.1.0", "1.0.0"),
               compat: str = "- N：通过；N-1：通过；N-2：通过。",
               info_version: str = "1.2.0") -> pathlib.Path:
    """造一份「多版本 + 指定兼容结论」的 spec 目录，供解析与回滚点用例使用。"""
    spec = tmp_path / "spec"
    spec.mkdir(parents=True, exist_ok=True)
    body = CHANGELOG_SKELETON.format(newest=versions[0], compat=compat)
    for version in versions[1:]:
        body += (f"\n## {version} · 2026-09-01 · MINOR\n\n**类型**：MINOR\n\n**变更**\n"
                 f"1. 历史条目\n\n**影响面**\n- 示例\n\n**兼容矩阵**\n- N/N-1/N-2 不适用\n\n"
                 f"**复核人**：lead\n")
    (spec / up.CHANGELOG_NAME).write_text(body, encoding="utf-8")
    (spec / up.OPENAPI_NAME).write_text(
        f'openapi: 3.1.0\ninfo:\n  title: DJB Protocol API\n  version: "{info_version}"\n'
        f'paths: {{}}\n', encoding="utf-8")
    return spec


# --------------------------------------------------------------------------- ① 版本清单
class TestVersionInventory:
    """验收 ①：版本清单 / 回滚点从 CHANGELOG 解析，并与 openapi info.version 对齐。"""

    def test_changelog_is_parsed_with_evidence(self):
        releases = up.load_changelog()
        assert releases, "CHANGELOG-协议.md 必须至少解析出一条版本记录"
        for entry in releases:
            assert re.fullmatch(r"\d+\.\d+\.\d+", entry.version), entry.version
            assert entry.kind in ("MAJOR", "MINOR", "PATCH")
            assert entry.released_at.year >= 2020
            assert entry.line > 0
            assert entry.as_dict()["evidence"].endswith(f"#L{entry.line}")

    def test_changelog_fields_are_complete(self):
        """每条记录必须写全：版本 / 日期 / 类型 / 影响面 / 兼容矩阵 / 复核人。"""
        entry = up.load_changelog()[0]
        assert entry.type_note, "缺「类型」段"
        assert entry.impact_items, "缺「影响面」段"
        assert entry.compat_notes, "缺「兼容矩阵」段"
        assert entry.reviewers, "缺「复核人」段"

    def test_openapi_info_version_read_from_spec(self):
        version = up.openapi_info_version()
        assert re.fullmatch(r"\d+\.\d+\.\d+(?:-.+)?", version), version

    @pytest.mark.parametrize("spec_version,info_version,status,attention", [
        ("1.1.0", "1.1.0", "aligned", False),
        ("1.1.0", "1.1.0-rc.1", "aligned_core_prerelease", False),
        ("1.1.0", "1.0.0-skeleton", "mismatch", True),
        ("1.1.0", "1.0.0", "mismatch", True),
        ("1.1.0", "not-a-version", "unknown", True),
    ])
    def test_align_versions_is_explicit(self, spec_version, info_version, status, attention):
        """对齐判定只有四种结果，且「不一致」一定带 attention（不糊过去）。"""
        got_status, detail, needs_attention = up.align_versions(spec_version, info_version)
        assert got_status == status
        assert needs_attention is attention
        assert detail

    def test_inventory_carries_both_versions_and_alignment(self):
        inv = up.version_inventory(now=NOW)
        assert inv.spec_version == inv.releases[0].version
        assert inv.openapi_version
        assert inv.alignment in ("aligned", "aligned_core_prerelease", "mismatch", "unknown")
        data = inv.as_dict()
        assert data["alignment"]["status"] == inv.alignment
        assert data["sources"]["changelog"].endswith(up.CHANGELOG_NAME)
        assert data["sources"]["openapi"].endswith(up.OPENAPI_NAME)
        # 不一致时 detail 必须同时点名两个版本号，方便一眼看出差在哪
        if inv.alignment == "mismatch":
            assert inv.spec_version in data["alignment"]["detail"]
            assert inv.openapi_version in data["alignment"]["detail"]

    def test_mismatch_is_not_swallowed(self):
        """当前工作区实际状态：CHANGELOG 最新与 info.version 不一致时必须如实暴露。"""
        inv = up.version_inventory(now=NOW)
        if inv.spec_version != inv.openapi_version:
            assert inv.alignment in ("mismatch", "aligned_core_prerelease", "unknown")
            assert inv.needs_attention is (inv.alignment in ("mismatch", "unknown"))
            assert inv.alignment_detail

    def test_rollback_points_come_from_changelog(self):
        inv = up.version_inventory(now=NOW)
        assert len(inv.rollback_points) == len(inv.releases)
        assert sum(1 for p in inv.rollback_points if p.is_current) == 1
        for point in inv.rollback_points:
            assert point.recorded_at.tzinfo is not None
            assert f"#L" in point.evidence
            assert point.evidence.split("#L")[0] == up.CHANGELOG_NAME
            assert point.age_seconds >= 0

    def test_previous_release_walks_backwards(self, tmp_path):
        releases = up.load_changelog(write_spec(tmp_path) / up.CHANGELOG_NAME)
        assert up.previous_release("1.2.0", releases).version == "1.1.0"
        assert up.previous_release("1.1.0", releases).version == "1.0.0"
        assert up.previous_release("1.0.0", releases) is None, "最老一版没有更早的可回滚点"

    def test_unreadable_spec_raises_clearly(self, tmp_path):
        with pytest.raises(up.SpecSourceMissing):
            up.load_changelog(tmp_path / "nope.md")


# --------------------------------------------------------------------------- ④ 兼容矩阵
class TestCompatMatrix:
    """验收 ④：N/N-1/N-2 三行；未知即 unknown，不假装通过。"""

    def test_three_slots_always_present(self):
        rows = up.compat_matrix()
        assert tuple(r.slot for r in rows) == ("N", "N-1", "N-2")
        assert tuple(r.offset for r in rows) == (0, 1, 2)

    def test_every_row_status_is_in_enum(self):
        for row in up.compat_matrix():
            assert row.status in up.COMPAT_STATUSES, row
            assert row.evidence_level in ("green", "yellow", "none")
            assert row.note, "每一行都要能说清依据（哪怕依据是「没有证据」）"

    def test_real_changelog_never_claims_pass(self):
        """当前 CHANGELOG 写的是「v1 未发布 → N/N-1/N-2 不适用」，绝不能由此推出 pass。"""
        inv = up.version_inventory(now=NOW)
        assert inv.compat_overall in ("not_applicable", "unknown", "partial")
        assert inv.compat_overall != "pass"
        if inv.compat_overall == "not_applicable":
            assert all(r.status == "not_applicable" for r in inv.compat)

    def test_missing_evidence_is_unknown_not_pass(self, tmp_path):
        spec = write_spec(tmp_path, compat="- 无（本期未做兼容性验证）")
        rows = up.compat_matrix(up.load_changelog(spec / up.CHANGELOG_NAME))
        assert [r.status for r in rows] == ["unknown", "unknown", "unknown"]
        assert all(r.evidence == "none" for r in rows)
        assert all(r.evidence_level == "none" for r in rows)
        assert up.compat_overall(rows) == "unknown"

    def test_all_pass_needs_versions_for_every_slot(self, tmp_path):
        spec = write_spec(tmp_path, versions=("1.2.0", "1.1.0", "1.0.0"),
                          compat="- N：通过；N-1：通过；N-2：通过。")
        rows = up.compat_matrix(up.load_changelog(spec / up.CHANGELOG_NAME))
        assert [r.status for r in rows] == ["pass", "pass", "pass"]
        assert [r.version for r in rows] == ["1.2.0", "1.1.0", "1.0.0"]
        assert up.compat_overall(rows) == "pass"
        assert all(r.evidence == rows[0].evidence for r in rows)

    def test_pass_without_version_is_downgraded(self, tmp_path):
        """只有一条版本记录却声称 N-1 通过 → 自相矛盾，降级 unknown。"""
        spec = write_spec(tmp_path, versions=("1.2.0",),
                          compat="- N：通过；N-1：通过；N-2：通过。")
        rows = up.compat_matrix(up.load_changelog(spec / up.CHANGELOG_NAME))
        assert rows[0].status == "pass"
        assert rows[1].status == "unknown" and rows[1].version is None
        assert rows[2].status == "unknown"
        assert up.compat_overall(rows) == "unknown"

    def test_one_failing_slot_fails_the_matrix(self, tmp_path):
        spec = write_spec(tmp_path, compat="- N：通过；N-1：通过；N-2：失败（不兼容）。")
        rows = up.compat_matrix(up.load_changelog(spec / up.CHANGELOG_NAME))
        assert [r.status for r in rows] == ["pass", "pass", "fail"]
        assert up.compat_overall(rows) == "fail"

    def test_not_applicable_never_promoted_to_pass(self):
        rows = tuple(up.CompatRow(slot=s, offset=i, version=None, status="not_applicable",
                                  evidence="x", evidence_level="green", note="未发布")
                     for i, s in enumerate(up.COMPAT_SLOTS))
        assert up.compat_overall(rows) == "not_applicable"
        assert up.compat_overall(rows) != "pass"

    def test_client_shell_policy_is_declared_not_evidence(self):
        rows = up.client_shell_matrix()
        assert [r["shell"] for r in rows] == ["N", "N-1", "N-2"]
        assert all(r["evidence_level"] == "yellow" for r in rows)
        assert "不保证可安装" in rows[2]["rule"]

    def test_client_surfaces_follow_decision_k8(self):
        rows = up.client_surface_matrix()
        assert [r["stage"] for r in rows] == ["S1", "S2", "S3"]
        assert "CLI" in rows[0]["surface"]
        assert "托盘" in rows[1]["surface"]

    def test_version_gate(self):
        # 支持面是滚动的 N / N-1 / N-2：用当前最新版本断言 supported，
        # 不再硬编码旧版本号（否则每发一个 MINOR 就会误报）。
        supported_version = up.load_changelog()[0].version
        assert up.require_version_supported(supported_version)["stage"] == "supported"
        assert up.require_version_supported("9.9.9")["stage"] == "unknown"

    def test_version_below_floor_is_rejected_with_42601(self):
        with pytest.raises(up.VersionIncompatible) as excinfo:
            up.require_version_supported("0.9.0")
        assert excinfo.value.code == 42601
        assert excinfo.value.http_status == 426
        assert "最低支持版本" in excinfo.value.message


# --------------------------------------------------------------------------- ② 灰度
class TestCanary:
    """验收 ②：按桶推进 + 命中阈值自动停（纯函数部分）。"""

    def test_app_ladder_matches_product_doc(self):
        percents = [s.percent for s in up.APP_RELEASE_LADDER]
        assert [s.key for s in up.APP_RELEASE_LADDER] == [
            "internal", "pct_1", "pct_10", "pct_50", "full"]
        assert percents == sorted(percents) == [0.0, 1.0, 10.0, 50.0, 100.0]

    def test_client_ladder_has_24h_dwell(self):
        assert [s.key for s in up.CLIENT_UPDATE_LADDER] == ["pct_5", "pct_25", "full"]
        assert all(s.required_dwell == timedelta(hours=24) for s in up.CLIENT_UPDATE_LADDER)

    def test_app_ladder_has_no_invented_dwell(self):
        """产品文档没规定应用发布每桶时长 → 显式 None，不替产品编一个数字。"""
        assert all(s.required_dwell is None for s in up.APP_RELEASE_LADDER)

    def test_unsupported_kind_is_rejected(self):
        with pytest.raises(admin.BadRequest) as excinfo:
            up.ladder_for("schema")
        assert excinfo.value.code == 40001

    def test_bucket_is_stable_and_bounded(self):
        assert up.bucket_of("node-42") == up.bucket_of("node-42")
        buckets = [up.bucket_of(f"node-{i}") for i in range(2000)]
        assert all(0 <= b < 10_000 for b in buckets)
        # 1% 桶应落 2000/100 ≈ 20，给足容差只证明"没退化成全放/全停"
        one_pct = sum(1 for b in buckets if b < 100)
        assert 3 <= one_pct <= 80, one_pct

    def test_bucket_rejects_empty_subject(self):
        with pytest.raises(admin.BadRequest):
            up.bucket_of("")

    def test_rollout_is_monotonic(self):
        for subject in (f"node-{i}" for i in range(200)):
            flags = [up.in_rollout(subject, stage) for stage in up.APP_RELEASE_LADDER]
            assert flags[0] is False, "internal 是显式名单桶，不在名单里就不该命中"
            assert flags == sorted(flags), f"{subject} 的桶序不单调：{flags}"
            assert flags[-1] is True, "全量桶必须覆盖所有主体"

    def test_internal_bucket_is_allowlist(self):
        stage = up.APP_RELEASE_LADDER[0]
        assert up.in_rollout("node-1", stage) is False
        assert up.in_rollout("node-1", stage, allowlist=["node-1"]) is True

    @pytest.mark.parametrize("compat_status", ["pass", "not_applicable"])
    def test_release_gate_opens_only_on_clean_matrix(self, compat_status):
        rows = tuple(up.CompatRow(slot=s, offset=i, version="1.1.0", status=compat_status,
                                  evidence="x", evidence_level="green", note="证据")
                     for i, s in enumerate(up.COMPAT_SLOTS))
        gate = up.release_gate(now=NOW, kind="app", compat=rows, alignment="aligned")
        assert gate["ok"] is True
        assert gate["window"]["open"] is True

    def test_release_gate_blocks_unknown_matrix(self):
        rows = tuple(up.CompatRow(slot=s, offset=i, version="1.1.0", status="unknown",
                                  evidence="none", evidence_level="none", note="无证据")
                     for i, s in enumerate(up.COMPAT_SLOTS))
        gate = up.release_gate(now=NOW, kind="app", compat=rows, alignment="aligned")
        assert gate["ok"] is False
        assert [b["gate"] for b in gate["blocked_by"]] == ["compat_matrix"]
        assert gate["compat_overall"] == "unknown"

    def test_release_gate_blocks_on_failing_slot(self):
        rows = tuple(up.CompatRow(slot=s, offset=i, version="1.1.0",
                                  status="fail" if s == "N-2" else "pass",
                                  evidence="x", evidence_level="green", note="证据")
                     for i, s in enumerate(up.COMPAT_SLOTS))
        gate = up.release_gate(now=NOW, kind="app", compat=rows)
        assert gate["ok"] is False
        assert gate["compat_overall"] == "fail"

    def test_alignment_mismatch_is_only_a_warning(self):
        rows = tuple(up.CompatRow(slot=s, offset=i, version="1.1.0", status="pass",
                                  evidence="x", evidence_level="green", note="证据")
                     for i, s in enumerate(up.COMPAT_SLOTS))
        gate = up.release_gate(now=NOW, kind="app", compat=rows, alignment="mismatch")
        assert gate["ok"] is True
        assert any("mismatch" in w for w in gate["warnings"])

    def test_release_gate_blocks_outside_window(self):
        rows = tuple(up.CompatRow(slot=s, offset=i, version="1.1.0", status="pass",
                                  evidence="x", evidence_level="green", note="证据")
                     for i, s in enumerate(up.COMPAT_SLOTS))
        gate = up.release_gate(now=OUT_OF_WINDOW, kind="app", compat=rows)
        assert gate["ok"] is False
        assert [b["gate"] for b in gate["blocked_by"]] == ["release_window"]


class TestCanaryThresholds:
    """阈值判定：缺指标 → hold（不装通过）；越线 → stop；全过 → advance。"""

    def test_all_good_advances(self):
        verdict = up.evaluate_stage(good_metrics())
        assert verdict.decision == "advance"
        assert verdict.unknown == ()
        assert len(verdict.hits) == len(up.DEFAULT_THRESHOLDS)

    @pytest.mark.parametrize("key,value", [
        ("error_rate_pct", 2.1),
        ("smoke_pass_pct", 99.9),
        ("install_success_pct", 94.9),
        ("ledger_recompute_diff_minor", 1),
        ("reserve_coverage_delta_pct", -0.1),
    ])
    def test_single_threshold_breach_stops(self, key, value):
        verdict = up.evaluate_stage(good_metrics(**{key: value}))
        assert verdict.decision == "stop"
        assert key in [h.key for h in verdict.failed]

    def test_boundary_values_pass(self):
        verdict = up.evaluate_stage(good_metrics(error_rate_pct=2.0,
                                                 install_success_pct=95.0,
                                                 reserve_coverage_delta_pct=0.0))
        assert verdict.decision == "advance", "阈值是含边界的（<= / >= / ==）"

    def test_missing_metric_is_hold_not_pass(self):
        metrics = good_metrics()
        metrics.pop("error_rate_pct")
        verdict = up.evaluate_stage(metrics)
        assert verdict.decision == "hold"
        assert verdict.unknown == ("error_rate_pct",)
        assert "error_rate_pct" in verdict.reason

    @pytest.mark.parametrize("bad", [None, "", "n/a", float("nan")])
    def test_unusable_metric_is_unknown(self, bad):
        verdict = up.evaluate_stage(good_metrics(error_rate_pct=bad))
        assert verdict.decision == "hold"
        assert "error_rate_pct" in verdict.unknown

    def test_every_threshold_cites_a_source(self):
        for th in up.DEFAULT_THRESHOLDS:
            assert th.source.startswith("§"), th
            assert th.unit

    def test_verdict_dict_is_auditable(self):
        payload = up.evaluate_stage(good_metrics(error_rate_pct=5)).as_dict()
        assert payload["decision"] == "stop"
        assert payload["failed"] == ["error_rate_pct"]
        assert payload["hits"][0]["source"].startswith("§")


class TestReleaseWindow:
    """发布列车窗口（§22.22）。"""

    def test_inside_window(self):
        window = up.release_window(NOW)
        assert window.open is True and window.code is None
        assert window.local.hour == 11 and window.local.utcoffset() == timedelta(hours=8)

    def test_outside_hours(self):
        window = up.release_window(OUT_OF_WINDOW)
        assert window.open is False and window.code == 40902
        assert "窗口外" in window.reason

    def test_weekend_is_closed(self):
        window = up.release_window(WEEKEND)
        assert window.open is False and window.is_workday is False

    def test_month_end_freeze(self):
        window = up.release_window(MONTH_END)
        assert window.open is False and window.is_month_end_freeze is True

    def test_declared_freeze(self):
        window = up.release_window(NOW, declared_freeze=True)
        assert window.open is False and window.is_declared_freeze is True
        assert window.code == 40902


# --------------------------------------------------------------------------- ② DB 推进
class TestAdvanceDB:
    """验收 ②：灰度按桶推进 + 命中阈值自动停并留证。"""

    def test_advance_walks_the_ladder_in_order(self, clean, on):
        created = up.create_run(principal(), run_body(), now=NOW)
        uid = created["upgrade_id"]
        assert created["run"]["stage"] == "internal"

        seen = ["internal"]
        at = NOW
        for _ in range(4):
            at += timedelta(hours=1)
            result = up.advance(principal(at), uid, metrics=good_metrics(),
                                dwell=timedelta(hours=1), now=at)
            seen.append(result["next"]["key"])
            assert result["decision"] == "advance"
        assert seen == ["internal", "pct_1", "pct_10", "pct_50", "full"]

        events = up.get_run(principal(at), uid)["events"]
        assert [e["decision"] for e in events] == ["start", "advance", "advance", "advance",
                                                   "advance"]
        assert [e["to_stage"] for e in events] == seen

    def test_threshold_breach_auto_stops_and_keeps_evidence(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        up.advance(principal(at), uid, metrics=good_metrics(), dwell=timedelta(hours=1), now=at)

        at += timedelta(hours=1)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(error_rate_pct=7.5),
                       dwell=timedelta(hours=1), now=at)
        assert excinfo.value.code == 40907
        assert excinfo.value.http_status == 409

        detail = up.get_run(principal(at), uid)
        assert detail["run"]["state"] == "stopped"
        last = detail["events"][-1]
        assert last["decision"] == "stop"
        assert last["reason_code"] == "R-GATE-STOP"
        assert last["verdict"]["failed"] == ["error_rate_pct"]
        assert last["verdict"]["hits"][0]["observed"] == 7.5

        # 停桶要进审计链，不能只留在业务表里
        chain = up.verify_audit_chain(name=SCHEMA)
        assert chain["ok"] is True
        assert chain["entries"] >= 3

    def test_missing_metric_holds_without_advancing(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics={"smoke_pass_pct": 100},
                       dwell=timedelta(hours=1), now=at)
        assert excinfo.value.code == 40907
        detail = up.get_run(principal(at), uid)
        assert detail["run"]["stage"] == "internal", "hold 不得推进桶"
        assert detail["run"]["state"] == "running"
        assert detail["events"][-1]["decision"] == "hold"

    def test_app_ladder_requires_explicit_dwell(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=3)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(), now=at)
        assert excinfo.value.code == 40907
        assert "变更单" in excinfo.value.message

    def test_dwell_window_not_met(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(minutes=20)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(),
                       dwell=timedelta(hours=1), now=at)
        assert "观测窗未满" in excinfo.value.message

    def test_client_ladder_enforces_24h(self, clean, on):
        body = run_body(kind="client", from_version="2.3.0", to_version="2.4.0")
        uid = up.create_run(principal(), body, now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=23)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(), now=at)
        assert "86400" in excinfo.value.message

        at = NOW + timedelta(hours=24)
        result = up.advance(principal(at), uid, metrics=good_metrics(), now=at)
        assert result["next"]["key"] == "pct_25"

    def test_outside_window_blocked_unless_p0(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(OUT_OF_WINDOW), uid, metrics=good_metrics(),
                       dwell=timedelta(hours=1), now=OUT_OF_WINDOW)
        assert excinfo.value.code == 40907
        assert "发布窗关闭" in excinfo.value.message

    def test_p0_channel_needs_p0_ticket(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        with pytest.raises(admin.BadRequest) as excinfo:
            up.advance(principal(OUT_OF_WINDOW), uid, metrics=good_metrics(),
                       dwell=timedelta(hours=1), p0_emergency=True, now=OUT_OF_WINDOW)
        assert excinfo.value.code == 40001

    def test_p0_channel_records_post_ticket_due(self, clean, on):
        body = run_body(change_ticket="P0-2026-1022-hotfix")
        uid = up.create_run(principal(), body, now=NOW)["upgrade_id"]
        result = up.advance(principal(OUT_OF_WINDOW), uid, metrics=good_metrics(),
                            dwell=timedelta(hours=1), p0_emergency=True, now=OUT_OF_WINDOW)
        assert result["p0_exception"] is True
        assert result["post_ticket_due_at"] is not None
        due = datetime.fromisoformat(result["post_ticket_due_at"])
        assert due - OUT_OF_WINDOW == timedelta(hours=up.P0_POST_TICKET_HOURS)
        assert result["run"]["p0_exception"] is True

    def test_step_up_required_and_expiring(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        fresh = up.UpgradePrincipal(actor="rm", permissions=up.PERMISSIONS, step_up_at=None)
        with pytest.raises(admin.StepUpRequired) as excinfo:
            up.advance(fresh, uid, metrics=good_metrics(), dwell=timedelta(hours=1), now=at)
        assert excinfo.value.code == 42401

        stale = up.UpgradePrincipal(actor="rm", permissions=up.PERMISSIONS,
                                    step_up_at=at - timedelta(minutes=6))
        with pytest.raises(admin.StepUpRequired):
            up.advance(stale, uid, metrics=good_metrics(), dwell=timedelta(hours=1), now=at)

    def test_idempotent_replay_does_not_double_advance(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        first = up.advance(principal(at), uid, metrics=good_metrics(),
                           dwell=timedelta(hours=1), now=at, idempotency_key="k-adv-1")
        second = up.advance(principal(at + timedelta(seconds=30)), uid, metrics=good_metrics(),
                            dwell=timedelta(hours=1), now=at, idempotency_key="k-adv-1")
        assert first["idempotent_replay"] is False
        assert second["idempotent_replay"] is True
        assert second["next"]["key"] == first["next"]["key"]
        assert len(up.get_run(principal(at), uid)["events"]) == 2, "重放不得多写一条轨迹"

    def test_idempotency_key_conflict(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        up.advance(principal(at), uid, metrics=good_metrics(), dwell=timedelta(hours=1),
                   now=at, idempotency_key="k-x")
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(error_rate_pct=9),
                       dwell=timedelta(hours=1), now=at, idempotency_key="k-x")
        assert excinfo.value.code == 40901

    def test_stop_any_bucket_without_window(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        up.advance(principal(at), uid, metrics=good_metrics(), dwell=timedelta(hours=1), now=at)
        stopped = up.stop_run(principal(OUT_OF_WINDOW), uid, reason="值班发现延迟抖动",
                              now=OUT_OF_WINDOW)
        assert stopped["decision"] == "stop"
        assert stopped["run"]["state"] == "stopped"
        assert stopped["run"]["stage"] == "pct_1", "停桶不改桶位，便于事后取证"

    def test_completed_requires_observation_window(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW
        for _ in range(4):
            at += timedelta(hours=1)
            up.advance(principal(at), uid, metrics=good_metrics(),
                       dwell=timedelta(hours=1), now=at)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(), now=at,
                       observation_completed=False)
        assert "观测窗未满" in excinfo.value.message

        at += timedelta(hours=25)
        done = up.advance(principal(at), uid, metrics=good_metrics(), now=at,
                          observation_completed=True, observation_seconds=90000)
        assert done["decision"] == "complete"
        assert done["run"]["state"] == "completed"

    def test_state_guards(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        up.stop_run(principal(NOW), uid, reason="人工停桶", now=NOW)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(NOW), uid, metrics=good_metrics(),
                       dwell=timedelta(hours=1), now=NOW)
        assert excinfo.value.code == 40902

    def test_create_run_validation(self, clean, on):
        with pytest.raises(admin.BadRequest):
            up.create_run(principal(), run_body(kind="schema"), now=NOW)
        with pytest.raises(admin.BadRequest):
            up.create_run(principal(), run_body(to_version="1.0.0"), now=NOW)
        with pytest.raises(admin.BadRequest):
            up.create_run(principal(), run_body(rollback_plan=""), now=NOW)
        with pytest.raises(admin.BadRequest):
            up.create_run(principal(), run_body(observation_seconds=0), now=NOW)

    def test_create_run_pins_spec_state(self, clean, on):
        created = up.create_run(principal(), run_body(), now=NOW)
        run = created["run"]
        inv = up.version_inventory(now=NOW)
        assert run["spec_alignment"] == inv.alignment
        assert run["compat_overall"] == inv.compat_overall
        assert created["spec"]["spec_version"] == inv.spec_version
        assert created["spec"]["openapi_version"] == inv.openapi_version

    def test_permission_denied(self, clean, on):
        with pytest.raises(admin.Forbidden) as excinfo:
            up.create_run(principal(permissions={"upgrade.run.read"}), run_body(), now=NOW)
        assert excinfo.value.code == 40301

    def test_break_glass_is_read_only(self, clean, on):
        glass = up.UpgradePrincipal(actor="auditor", permissions=up.PERMISSIONS,
                                    break_glass=True)
        with pytest.raises(admin.BreakGlassReadOnly) as excinfo:
            up.create_run(glass, run_body(), now=NOW)
        assert excinfo.value.code == 42301

    def test_unknown_run_is_404(self, clean, on):
        with pytest.raises(admin.NotFound) as excinfo:
            up.get_run(principal(), "UPG-NOPE")
        assert excinfo.value.code == 40401


# --------------------------------------------------------------------------- ③ 回滚
class TestRollbackDB:
    """验收 ③：回滚到上一版，记录时间与证据。"""

    def _stopped_run(self) -> str:
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        up.advance(principal(at), uid, metrics=good_metrics(), dwell=timedelta(hours=1), now=at)
        at += timedelta(hours=1)
        with pytest.raises(admin.Conflict):
            up.advance(principal(at), uid, metrics=good_metrics(error_rate_pct=4.2),
                       dwell=timedelta(hours=1), now=at)
        return uid

    def test_rollback_records_time_and_evidence(self, clean, on):
        uid = self._stopped_run()
        at = NOW + timedelta(hours=3, minutes=4)
        result = up.rollback(
            principal(at), uid, reason="错误率 4.2% 超阈值，回滚上一版",
            evidence={"ledger_recompute": {"diff_minor": 0},
                      "smoke": {"pass_pct": 100},
                      "audit_anchor": "ops/audit/chain.jsonl#seq"},
            rollback_started_at=at - timedelta(minutes=4), now=at)

        assert result["from_version"] == "1.1.0"
        assert result["to_version"] == "1.0.0"
        assert result["rolled_back_at"].startswith("2026-10-22T06:04")
        assert result["duration_seconds"] == 240.0
        assert result["budget_seconds"] == up.ROLLBACK_BUDGET_SECONDS["app"] == 300
        assert result["within_budget"] is True
        assert result["rollback_point"]["recorded_at"]
        assert result["rollback_point"]["source"]
        assert result["evidence"]["ledger_recompute"]["diff_minor"] == 0
        assert result["run"]["state"] == "rolled_back"

        rows = up.list_rollbacks(principal(at), uid)
        assert len(rows) == 1
        row = rows[0]
        assert row["to_version"] == "1.0.0"
        assert row["rollback_point_at"]
        assert row["within_budget"] is True
        assert row["evidence"]["from_version"] == "1.1.0"
        assert row["reason_code"] == "R-ROLLBACK"

    def test_rollback_point_uses_changelog_record_time(self, clean, on, monkeypatch, tmp_path):
        spec = write_spec(tmp_path, versions=("1.2.0", "1.1.0", "1.0.0"))
        monkeypatch.setenv(up.SPEC_DIR_ENV, str(spec))
        body = run_body(from_version="1.1.0", to_version="1.2.0")
        uid = up.create_run(principal(), body, now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=2)
        result = up.rollback(principal(at), uid, reason="灰度异常回滚",
                             evidence={"smoke": {"pass_pct": 100}}, now=at)
        point = result["rollback_point"]
        assert point["version"] == "1.1.0"
        assert point["recorded_at"].startswith("2026-09-01"), "回滚点时间应来自 CHANGELOG 记录"
        assert point["source"].startswith(up.CHANGELOG_NAME + "#L")
        assert point["evidence_level"] == "green"

    def test_rollback_point_falls_back_transparently(self, clean, on):
        """目标版本不在 CHANGELOG 时退化为部署时间，并如实写明来源。"""
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        result = up.rollback(principal(NOW + timedelta(hours=1)), uid,
                             reason="异常回滚", evidence={"smoke": {"pass_pct": 100}},
                             now=NOW + timedelta(hours=1))
        assert result["rollback_point"]["source"].startswith("run:created_at")
        assert result["rollback_point"]["evidence_level"] == "yellow"

    def test_rollback_over_budget_is_recorded_not_hidden(self, clean, on):
        uid = self._stopped_run()
        at = NOW + timedelta(hours=4)
        result = up.rollback(principal(at), uid, reason="回滚超时演练",
                             evidence={"smoke": {"pass_pct": 100}},
                             rollback_started_at=at - timedelta(minutes=9), now=at)
        assert result["duration_seconds"] == 540.0
        assert result["within_budget"] is False

    def test_rollback_requires_evidence(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        with pytest.raises(admin.BadRequest) as excinfo:
            up.rollback(principal(NOW), uid, reason="回滚", evidence=None, now=NOW)
        assert excinfo.value.code == 40001

    def test_rollback_is_idempotent(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        args = dict(reason="异常回滚", evidence={"smoke": {"pass_pct": 100}}, now=at,
                    idempotency_key="rb-1")
        first = up.rollback(principal(at), uid, **args)
        second = up.rollback(principal(at), uid, **args)
        assert first["idempotent_replay"] is False
        assert second["idempotent_replay"] is True
        assert len(up.list_rollbacks(principal(at), uid)) == 1

    def test_second_rollback_is_rejected(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        up.rollback(principal(at), uid, reason="异常回滚",
                    evidence={"smoke": {"pass_pct": 100}}, now=at)
        with pytest.raises(admin.Conflict) as excinfo:
            up.rollback(principal(at + timedelta(minutes=5)), uid, reason="再滚一次",
                        evidence={"smoke": {"pass_pct": 100}},
                        now=at + timedelta(minutes=5))
        assert excinfo.value.code == 40902


# --------------------------------------------------------------------------- ⑤⑥ 契约
class TestErrorCodes:
    """验收 ⑤：不新增未登记错误码。"""

    def test_registry_codes_are_from_section_6_3b(self):
        #: §6.3b 已登记码（人工从产品文档抄录，改了产品文档就要一起改这里）
        registered = {
            40001, 40002, 40301, 40302, 40303, 40304, 40401, 40901, 40902, 40903,
            40904, 40905, 40906, 40907, 40910, 40911, 40912, 40913, 40917, 40918,
            42201, 42210, 42211, 42301, 42401, 42601, 42801, 44101, 45001, 45201,
            45202, 45203, 40310, 40311, 40312, 40101, 40102, 40103, 40201,
            42901, 42902, 50901, 50902, 50903,
        }
        assert set(up.ERROR_CODES_USED) <= registered, \
            f"出现了未登记码：{set(up.ERROR_CODES_USED) - registered}"

    def test_every_used_code_has_a_source(self):
        for code, meaning in up.ERROR_CODES_USED.items():
            assert meaning
            assert up.ERROR_CODE_SOURCES[code].startswith("产品文档 §6.")

    def test_module_never_emits_an_unregistered_code(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        found = {int(m) for m in re.findall(r"\bcode\s*=\s*(\d{5})\b", source)}
        assert found, "扫描不到任何错误码，说明正则失效了"
        assert found <= set(up.ERROR_CODES_USED), \
            f"模块里出现了未登记/未声明码：{found - set(up.ERROR_CODES_USED)}"

    def test_error_envelope_shape(self):
        exc = admin.Conflict("冲突", code=40907, details=[{"a": 1}])
        envelope = exc.envelope("req-1")
        assert set(envelope) == {"error"}
        assert set(envelope["error"]) >= {"type", "code", "message", "request_id"}
        assert envelope["error"]["code"] == 40907
        assert envelope["error"]["request_id"] == "req-1"

    def test_stop_uses_40907_semantics(self):
        assert up.ERROR_CODES_USED[40907] == "灰度观测窗未满 / 健康门槛未过，禁止推进"


class TestNoRoutes:
    """验收 ⑤：不新增 HTTP 路由 / 不改 spec。"""

    def test_no_upgrade_route_registered(self):
        from app.api import app
        paths = [getattr(r, "path", "") for r in app.routes]
        assert not [p for p in paths if "upgrade" in p.lower()], \
            "升级中心是服务层，本单不接路由"

    def test_spec_has_no_upgrade_path(self):
        from app.api import app  # noqa: F401  （确认导入链正常）
        import yaml
        spec = yaml.safe_load(up.openapi_path().read_text(encoding="utf-8"))
        assert not [p for p in spec["paths"] if "upgrade" in p.lower()]

    @staticmethod
    def _imported_modules() -> set[str]:
        import ast
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        mods: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add("." * node.level + (node.module or ""))
        return mods

    def test_module_does_not_import_web_framework(self):
        mods = self._imported_modules()
        assert not [m for m in mods if "fastapi" in m or "starlette" in m]

    def test_module_does_not_import_ledger_or_chain(self):
        mods = self._imported_modules()
        assert not [m for m in mods
                    if any(bad in m for bad in ("ledger", "chain", "wallet_pool"))], mods


class TestFeatureFlag:
    """验收 ⑥：开关默认关闭、三字段齐全、关闭后只保留只读版本列表。"""

    def test_default_off(self, monkeypatch):
        monkeypatch.delenv("DJB_FF_UPGRADE_CENTER", raising=False)
        assert up.flag_enabled() is False
        assert up.writes_enabled() is False

    def test_three_fields_present(self):
        spec = up.flag_spec()
        for field in admin.REQUIRED_FLAG_FIELDS:
            assert spec.get(field), f"开关缺字段 {field}"
        assert spec["owner"] == "release-manager"
        assert spec["expire_at"] == "2026-12-31"
        assert "只读版本列表" in spec["rollback_rule"]
        assert spec["default"] is False

    def test_registered_in_admin_registry(self):
        assert "upgrade_center" in admin.FEATURE_FLAGS
        assert admin.flag_spec("upgrade_center")["owner"] == "release-manager"

    def test_conflicting_registration_raises(self):
        with pytest.raises(RuntimeError):
            up.register_feature_flag({"upgrade_center": {"default": True, "owner": "x"}})

    def test_expired_flag_is_force_off(self, monkeypatch):
        monkeypatch.setenv("DJB_FF_UPGRADE_CENTER", "1")
        assert up.flag_enabled(today=date(2026, 12, 31)) is True
        assert up.flag_enabled(today=date(2027, 1, 1)) is False, "到期必须 fail-closed"

    def test_writes_are_404_when_off(self, clean, monkeypatch):
        monkeypatch.delenv("DJB_FF_UPGRADE_CENTER", raising=False)
        with pytest.raises(admin.FeatureDisabled) as excinfo:
            up.create_run(principal(), run_body(), now=NOW)
        assert excinfo.value.http_status == 404
        assert excinfo.value.code == 40401

    def test_readonly_version_list_survives_flag_off(self, monkeypatch):
        monkeypatch.delenv("DJB_FF_UPGRADE_CENTER", raising=False)
        payload = up.render_version_list(now=NOW)
        assert payload["spec_version"]
        assert len(payload["releases"]) >= 1
        assert [r["slot"] for r in payload["compat"]["rows"]] == ["N", "N-1", "N-2"]

    def test_rollback_rule_says_which_entries_close(self):
        rule = up.flag_spec()["rollback_rule"]
        for entry in ("create_run", "advance", "stop_run", "rollback"):
            assert entry in rule, f"rollback_rule 必须写明关闭后 {entry} 的行为"


# --------------------------------------------------------------------------- 留痕
class TestAuditAndGuards:
    """审计哈希链 + 证据只追加。"""

    def test_audit_chain_recomputes(self, clean, on):
        uid = up.create_run(principal(), run_body(), now=NOW)["upgrade_id"]
        at = NOW + timedelta(hours=1)
        up.advance(principal(at), uid, metrics=good_metrics(), dwell=timedelta(hours=1), now=at)
        chain = up.verify_audit_chain(name=SCHEMA)
        assert chain == {"entries": 2, "bad": [], "ok": True}

    def test_audit_is_append_only(self, clean, on):
        up.create_run(principal(), run_body(), now=NOW)
        with pytest.raises(psycopg.Error):
            with up._tx(SCHEMA) as cur:
                cur.execute("UPDATE upgrade_audit SET reason='改一下' WHERE seq=1")
        with pytest.raises(psycopg.Error):
            with up._tx(SCHEMA) as cur:
                cur.execute("DELETE FROM upgrade_audit WHERE seq=1")

    def test_stage_events_are_append_only(self, clean, on):
        up.create_run(principal(), run_body(), now=NOW)
        with pytest.raises(psycopg.Error):
            with up._tx(SCHEMA) as cur:
                cur.execute("UPDATE upgrade_stage_event SET reason='改一下' WHERE seq=1")

    def test_denials_are_audited(self, clean, on):
        before = up.verify_audit_chain(name=SCHEMA)["entries"]
        with pytest.raises(admin.Forbidden):
            up.create_run(principal(permissions={"upgrade.run.read"}), run_body(), now=NOW)
        after = up.verify_audit_chain(name=SCHEMA)["entries"]
        assert after == before + 1, "被拒绝的动作也要留痕"

    def test_chain_anchor_argv_is_wired_but_not_executed(self):
        entry = {"actor": "release-manager", "actor_roles": "RELEASE",
                 "action": "upgrade.rollback", "upgrade_id": "UPG-1",
                 "outcome": "ok", "reason_code": "R-ROLLBACK", "reason": "回滚"}
        argv = up.build_chain_anchor_argv(entry, evidence="ops/audit/reports/x.txt")
        assert argv[:2] == ["node", "ops/audit/append.mjs"]
        assert "--action" in argv and "upgrade.rollback" in argv
        assert "--evidence" in argv
        assert "--task" in argv and "DEV-0005" in argv


# --------------------------------------------------------------------------- 证据链
class TestEvidenceChain:
    """证据文件主体：一次完整的「建单 → 灰度 → 自动停 → 回滚」链路（pytest -s）。"""

    def test_simulated_canary_and_rollback(self, clean, on):
        print("\n  [DEV-0005 链路证据]")
        inv = up.version_inventory(now=NOW)
        print(f"  0. 版本清单：CHANGELOG 最新={inv.spec_version} · openapi={inv.openapi_version}"
              f" · 对齐={inv.alignment}")
        print(f"     兼容矩阵汇总={inv.compat_overall} "
              f"行={[(r.slot, r.status) for r in inv.compat]}")
        print(f"     回滚点={[(p.version, p.recorded_at.date().isoformat()) for p in inv.rollback_points]}")

        created = up.create_run(principal(), run_body(), now=NOW)
        uid = created["upgrade_id"]
        print(f"  1. 建单 {uid} → 首桶 {created['run']['stage']} "
              f"（gate.ok={created['gate']['ok']}, 变更单={created['run']['change_ticket']}）")

        at = NOW
        for _ in range(3):
            at += timedelta(hours=1)
            result = up.advance(principal(at), uid, metrics=good_metrics(),
                                dwell=timedelta(hours=1), now=at)
            print(f"  2. 推进 → {result['next']['key']:>7} "
                  f"（{result['verdict']['decision']}, audit#{result['audit']['seq']}）")

        at += timedelta(hours=1)
        with pytest.raises(admin.Conflict) as excinfo:
            up.advance(principal(at), uid, metrics=good_metrics(error_rate_pct=6.8),
                       dwell=timedelta(hours=1), now=at)
        print(f"  3. 命中阈值自动停：{excinfo.value.http_status}/{excinfo.value.code} "
              f"{excinfo.value.message}")

        at += timedelta(minutes=4)
        result = up.rollback(
            principal(at), uid, reason="错误率 6.8% 超阈值，按 §22.22 决策回滚",
            evidence={"ledger_recompute": {"diff_minor": 0},
                      "smoke": {"pass_pct": 100},
                      "audit_chain": "ops/audit/chain.jsonl"},
            rollback_started_at=at - timedelta(minutes=4), now=at)
        print(f"  4. 回滚 {result['from_version']} → {result['to_version']} "
              f"@ {result['rolled_back_at']}；回滚点记录时间="
              f"{result['rollback_point']['recorded_at']}（{result['rollback_point']['source']}）")
        print(f"     耗时 {result['duration_seconds']}s / 预算 {result['budget_seconds']}s "
              f"→ within_budget={result['within_budget']}")

        detail = up.get_run(principal(at), uid)
        print(f"  5. 状态={detail['run']['state']}；轨迹="
              f"{[(e['decision'], e['from_stage'], e['to_stage']) for e in detail['events']]}")
        chain = up.verify_audit_chain(name=SCHEMA)
        print(f"  6. 审计链复算：entries={chain['entries']} bad={chain['bad']} ok={chain['ok']}")
        print(f"  7. 回滚记录：at={detail['rollbacks'][0]['at']} "
              f"point_at={detail['rollbacks'][0]['rollback_point_at']} "
              f"within_budget={detail['rollbacks'][0]['within_budget']}")

        assert chain["ok"] is True
        assert detail["run"]["state"] == "rolled_back"
        assert detail["events"][-2]["decision"] == "stop"
        assert detail["events"][-1]["decision"] == "rollback"
        assert detail["rollbacks"][0]["within_budget"] is True


# --------------------------------------------------------------------------- 边界
class TestSpecEdgeCases:
    """解析边界：多版本顺序、混合兼容结论、缺段。"""

    def test_versions_are_sorted_newest_first(self, tmp_path):
        spec = write_spec(tmp_path, versions=("1.2.0", "1.1.0", "1.0.0"))
        inv = up.version_inventory(now=NOW, changelog=spec / up.CHANGELOG_NAME,
                                   openapi=spec / up.OPENAPI_NAME)
        assert [r.version for r in inv.releases] == ["1.2.0", "1.1.0", "1.0.0"]
        assert inv.alignment == "aligned"

    def test_core_prerelease_suffix(self, tmp_path):
        spec = write_spec(tmp_path, info_version="1.2.0-rc.3")
        inv = up.version_inventory(now=NOW, changelog=spec / up.CHANGELOG_NAME,
                                   openapi=spec / up.OPENAPI_NAME)
        assert inv.alignment == "aligned_core_prerelease"
        assert inv.needs_attention is False

    def test_breaking_changes_are_surfaced(self):
        entry = up.load_changelog()[0]
        if entry.breaking:
            assert all("破坏性" in line or "breaking" in line.lower() for line in entry.breaking)

    def test_empty_changelog_is_an_error(self, tmp_path):
        path = tmp_path / "CHANGELOG-协议.md"
        path.write_text("# 协议变更记录\n\n（还没写）\n", encoding="utf-8")
        with pytest.raises(up.SpecSourceMissing):
            up.load_changelog(path)

    def test_spec_dir_env_override(self, tmp_path, monkeypatch):
        spec = write_spec(tmp_path)
        monkeypatch.setenv(up.SPEC_DIR_ENV, str(spec))
        assert up.spec_dir() == spec

    def test_missing_spec_dir_reports_how_to_fix(self, tmp_path, monkeypatch):
        monkeypatch.setenv(up.SPEC_DIR_ENV, str(tmp_path / "nothing"))
        monkeypatch.setattr(up, "_repo_root", lambda: tmp_path / "nowhere")
        with pytest.raises(up.SpecSourceMissing) as excinfo:
            up.spec_dir()
        assert "DJB_SPEC_DIR" in str(excinfo.value)
