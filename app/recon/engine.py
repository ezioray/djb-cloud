# SPDX-License-Identifier: Apache-2.0
"""对账引擎（M09 §6.1 / §6.3）：五个 scope 全部实现。

    receipt      M05 逐条核对（usage_records ↔ metering_receipts），四类差异 + 重复入账。
                 only_platform（平台有、节点未上报；宽限期内算在途）/ only_node（节点有、平台无）
                 / amount_mismatch（金额不一致）/ signature_bad（签名不可验，P0）
                 / duplicate_receipt（同一 task_id 多张收据，重复入账，P0）
    daily_close  M06 试算平衡（Σ借 = Σ贷）+ 科目余额漂移（派生缓存 vs 分录），按单位各一 run。
    chain        M08 wallet.balance_minor ↔ journal_line(wallet_id, 1101/1102) 累计净额。
    psp          M08 payment_attempts ↔ E3/E4（payment_attempt / provider_txn_id / seq 1/2/3）。
    bank         M08 payout / refund ↔ E8/E11 + 银行流水夹具。

三方 scope 的 planner 在 :mod:`app.recon.threeway`（懒加载注册，避免循环 import）；
扩展点：往 ``SCOPE_PLANNERS`` 注册一个 ``planner(conn, spec, deps, now)`` 即可，
``run()`` 的落库 / 幂等 / INV-04 / 差异入库 / 状态机逻辑全部复用，不需要改其它文件。

金额纪律（INV-08）：全部整数最小单位；``diff_minor`` 有符号（book − external），
run 的 ``diff_minor`` 由库层触发器按「未关闭差异之和」维护（INV-01），引擎不写它。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

import psycopg

from . import clock, facts, grading, m06, models, store
from .errors import BadRequest, Conflict

__all__ = [
    "ScopeNotImplemented", "EngineDeps", "Observation", "Plan", "SCOPE_PLANNERS",
    "SIGNATURE_SHAPE", "default_signature_check", "scan_receipt", "scan_daily_close",
    "plan", "run",
]

#: 收据签名形态（M05 INV-01/INV-02 钉死 hmac-sha256 + 64 hex）
SIGNATURE_SHAPE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")


class ScopeNotImplemented(NotImplementedError):
    """scope 未实现（依赖 M08 未合并）：明确报错，**不返回假数据**。"""

    def __init__(self, scope: str) -> None:
        self.scope = scope
        super().__init__(
            f"scope={scope} 未实现（依赖 {facts.DEFERRED_SCOPE_OWNER.get(scope, 'M08')}）；"
            "本轮只实现 receipt / daily_close")


@dataclass(frozen=True)
class EngineDeps:
    """可注入依赖（签名校验器 / 默认责任人 / 宽限期）。"""

    signature_verifier: Callable[[Mapping[str, Any]], bool] | None = None
    default_owner: str | None = "treasury-ops"
    grace_seconds: int | None = None
    #: scope=psp 的 PSP 结算文件夹具（provider_txn_id / settled_minor / fee_minor / currency）。
    #: None = 该维度无数据源（metrics 如实标 settlement_source=absent）；正文不落库，只存哈希。
    psp_settlement: Sequence[Mapping[str, Any]] | None = None
    #: scope=bank 的银行流水夹具（txid / amount / currency / posted_at）。
    #: None = 该维度无数据源（metrics 标 bank_statement_source=absent）；正文不落库，只存哈希。
    bank_statement: Sequence[Mapping[str, Any]] | None = None


@dataclass
class Observation:
    """一次扫描的结果（落库前的纯数据）。"""

    matched_count: int = 0
    book_minor: int = 0
    external_minor: int = 0
    pending_upload: int = 0
    exceptions: list[models.ExceptionDraft] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def unmatched_count(self) -> int:
        return len(self.exceptions)


@dataclass
class Plan:
    """一个待落库的 run（scope=receipt 一个；scope=daily_close 每个单位一个）。"""

    spec: models.RunSpec
    observation: Observation


# ───────────────────────────────────────────────────────────── 签名校验（可注入）
def default_signature_check(receipt: Mapping[str, Any]) -> bool:
    """默认只做**形态**校验：M09 不持有 M05 的签名密钥（M09 §1「不做链上签名」）。

    完整 HMAC 复验需要 M05 的密钥（或 M05 的服务间校验接口）——通过
    ``EngineDeps.signature_verifier`` 注入；未注入时形态非法即判 ``signature_bad``。
    """
    for field in ("sig_provider", "sig_consumer"):
        value = receipt.get(field)
        if not isinstance(value, str) or not SIGNATURE_SHAPE.match(value):
            return False
    return True


# ───────────────────────────────────────────────────────────── scope=receipt
def _platform_rows(conn: psycopg.Connection, spec: models.RunSpec) -> list[dict[str, Any]]:
    """平台侧：M05 usage_records（只读；期间按 recorded_at 半开区间）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT usage_id::text AS usage_id, request_id AS task_id, amount_minor,
                      recorded_at, node_id, receipt_id
                 FROM usage_records
                WHERE recorded_at >= %s AND recorded_at < %s
                ORDER BY request_id, recorded_at, usage_id""",
            (spec.period_start, spec.period_end))
        rows = cur.fetchall()
    return [
        {"usage_id": row[0], "task_id": row[1], "amount_minor": int(row[2]),
         "recorded_at": row[3], "node_id": row[4], "receipt_id": row[5]}
        for row in rows
    ]


def _node_rows(conn: psycopg.Connection, spec: models.RunSpec) -> list[dict[str, Any]]:
    """节点侧：M05 metering_receipts 的 accepted 行（只读；期间按 reported_at）。

    ⚠ M05 的收据表名是 ``metering_receipts``（502 迁移）；001 里的 legacy ``receipts`` /
    ``node_receipts`` 属旧适配器，M09 不读、不写（见 502 头注释的 Lead 裁决说明）。
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT receipt_id, task_id, price_minor, reported_at, node_id, usage_id::text,
                      sig_provider, sig_consumer
                 FROM metering_receipts
                WHERE state = 'accepted' AND reported_at >= %s AND reported_at < %s
                ORDER BY task_id, reported_at, receipt_id""",
            (spec.period_start, spec.period_end))
        rows = cur.fetchall()
    return [
        {"receipt_id": row[0], "task_id": row[1], "price_minor": int(row[2]),
         "reported_at": row[3], "node_id": row[4], "usage_id": row[5],
         "sig_provider": row[6], "sig_consumer": row[7]}
        for row in rows
    ]


def _draft(kind: str, ref_type: str, ref_id: str, diff_minor: int, *, raised_at: datetime,
           scope: str, deps: EngineDeps, root_cause: str | None = None,
           evidence_ref: str | None = None) -> models.ExceptionDraft:
    severity, due = grading.classify_and_schedule(diff_minor, kind=kind, raised_at=raised_at)
    return models.ExceptionDraft(kind=kind, severity=severity, ref_type=ref_type, ref_id=ref_id,
                                 diff_minor=int(diff_minor), sla_due=due, scope=scope,
                                 owner=deps.default_owner, root_cause=root_cause,
                                 evidence_ref=evidence_ref)


def scan_receipt(conn: psycopg.Connection, spec: models.RunSpec, *,
                 deps: EngineDeps | None = None,
                 now: datetime | None = None) -> Observation:
    """scope=receipt：以 task_id 配对平台用量与节点收据（M09 §6.3 第 3 条）。"""
    deps = deps or EngineDeps()
    moment = clock.as_utc(now or clock.utcnow())
    grace = (spec.grace_seconds if deps.grace_seconds is None else deps.grace_seconds)
    verifier = deps.signature_verifier or default_signature_check

    platform = _platform_rows(conn, spec)
    node = _node_rows(conn, spec)

    by_task_p: dict[str, list[dict]] = {}
    for row in platform:
        by_task_p.setdefault(row["task_id"], []).append(row)
    by_task_n: dict[str, list[dict]] = {}
    for row in node:
        by_task_n.setdefault(row["task_id"], []).append(row)

    obs = Observation(
        book_minor=sum(row["amount_minor"] for row in platform),
        external_minor=sum(row["price_minor"] for row in node),
    )
    owner = deps.default_owner

    def add(kind: str, ref_type: str, ref_id: str, diff_minor: int,
            *, root_cause: str | None = None, evidence_ref: str | None = None) -> None:
        obs.exceptions.append(_draft(kind, ref_type, ref_id, diff_minor, raised_at=moment,
                                     scope=spec.scope, deps=deps, root_cause=root_cause,
                                     evidence_ref=evidence_ref))

    for task_id in sorted(set(by_task_p) | set(by_task_n)):
        p_rows = by_task_p.get(task_id, [])
        n_rows = by_task_n.get(task_id, [])
        paired = min(len(p_rows), len(n_rows))

        # ── 1) 逐对比较（配对顺序：平台按 recorded_at，节点按 reported_at，均稳定排序）
        for index in range(paired):
            p_row, n_row = p_rows[index], n_rows[index]
            if not verifier(n_row):
                # 签名不可验：结构性 P0；金额不可信 → 不再计金额差（避免双计）
                add("signature_bad", "receipt", n_row["receipt_id"], 0,
                    root_cause="signature_unverifiable", evidence_ref=n_row["node_id"])
                continue
            if p_row["amount_minor"] != n_row["price_minor"]:
                add("amount_mismatch", "task", task_id,
                    p_row["amount_minor"] - n_row["price_minor"],
                    evidence_ref=f"usage:{p_row['usage_id']}")

        # ── 2) 平台多出来的行：宽限期内算在途（不计差），超期才是 only_platform
        for p_row in p_rows[paired:]:
            age = (moment - clock.as_utc(p_row["recorded_at"])).total_seconds()
            if age < grace:
                obs.pending_upload += 1
                continue
            add("only_platform", "task", task_id, p_row["amount_minor"],
                root_cause="node_not_reported", evidence_ref=f"usage:{p_row['usage_id']}")

        # ── 3) 节点多出来的行：平台侧完全没有 → only_node（P0）；平台有同 task 但少 → 重复入账
        extra = n_rows[paired:]
        if extra and p_rows:
            add("duplicate_receipt", "task", task_id, -sum(row["price_minor"] for row in extra),
                root_cause="duplicate_posting",
                evidence_ref=",".join(row["receipt_id"] for row in extra))
        elif extra:
            add("only_node", "task", task_id, -sum(row["price_minor"] for row in extra),
                root_cause="platform_missing",
                evidence_ref=",".join(row["receipt_id"] for row in extra))

        obs.matched_count += paired

    total = len(platform) + len(node)
    obs.metrics = {
        "grace_seconds": grace,
        "platform_rows": len(platform),
        "node_rows": len(node),
        "pending_upload": obs.pending_upload,
        "owner": owner,
        # S1 指标（03-facts §10）：收据差异率；**不**据此自动开差异（阈值属验收指标）
        "diff_rate_bps": (0 if total == 0 else round(10000.0 * obs.unmatched_count / total)),
        "diff_rate_target_bps": facts.RECEIPT_DIFF_RATE_TARGET_BPS,
    }
    return obs


# ───────────────────────────────────────────────────────────── scope=daily_close
def scan_daily_close(conn: psycopg.Connection, spec: models.RunSpec, *,
                     deps: EngineDeps | None = None,
                     now: datetime | None = None) -> list[tuple[models.RunSpec, Observation]]:
    """scope=daily_close：M06 试算平衡 + 科目余额漂移，**按单位各一条 run**。

    为什么按单位拆：``book_minor`` / ``external_minor`` 是整数最小单位，跨单位（USD/COP）
    相加没有意义（INV-04 同因）。单位放在 ``subject_ref``，天然满足 INV-04 唯一键。
    """
    deps = deps or EngineDeps()
    moment = clock.as_utc(now or clock.utcnow())
    units = [spec.subject_ref] if spec.subject_ref else m06.unit_types_as_of(conn, spec.cutoff_at)
    if not units:
        # 期间内一条分录都没有：不是失败，产出 0 差异的 matched 批次（空账本也要留痕）
        units = [spec.subject_ref or "USD"]

    plans: list[tuple[models.RunSpec, Observation]] = []
    for unit in units:
        totals = m06.trial_totals(conn, unit_type=unit, as_of=spec.cutoff_at)
        drift = m06.balance_drift_as_of(conn, unit_type=unit, as_of=spec.cutoff_at)
        obs = Observation(matched_count=totals["line_count"],
                          book_minor=totals["debit_minor"],
                          external_minor=totals["credit_minor"])
        if not totals["balanced"]:
            obs.exceptions.append(_draft(
                "trial_imbalance", "unit_type", unit, totals["diff_minor"], raised_at=moment,
                scope=spec.scope, deps=deps, root_cause="debit_credit_imbalance",
                evidence_ref=f"entries:{totals['entry_count']}"))
        # 该单位在截止时刻没有任何 account_balances 版本 → M06 余额派生尚未启用，
        # 没有可比对象。此时既不能造假 P0，也不能静默：记进 metrics 的 drift_checked=false。
        drift_checked = drift["stored_keys"] > 0
        if drift_checked and drift["diff"]:
            first = (drift["mismatched"] or drift["missing_in_store"]
                     or drift["missing_in_ledger"])[0]
            obs.exceptions.append(_draft(
                "balance_drift", "account", f"{first[0]}:{first[1]}", drift["amount_gap_minor"],
                raised_at=moment, scope=spec.scope, deps=deps,
                root_cause="derived_balance_mismatch",
                evidence_ref=(f"mismatched:{len(drift['mismatched'])},"
                              f"missing_store:{len(drift['missing_in_store'])},"
                              f"missing_ledger:{len(drift['missing_in_ledger'])}")))
        obs.metrics = {"unit_type": unit, "entry_count": totals["entry_count"],
                       "line_count": totals["line_count"], "drift_checked": drift_checked,
                       "drift_keys": drift["diff"] if drift_checked else 0,
                       "drift_gap_minor": drift["amount_gap_minor"] if drift_checked else 0,
                       "balance_keys_derived": drift["derived_keys"],
                       "balance_keys_stored": drift["stored_keys"]}
        unit_spec = models.RunSpec(
            scope=spec.scope, period_start=spec.period_start, period_end=spec.period_end,
            cutoff_at=spec.cutoff_at, subject_ref=unit, block_height=spec.block_height,
            trigger_event_id=(f"{spec.trigger_event_id}:{unit}"
                              if spec.trigger_event_id else None),
            tenant_id=spec.tenant_id, created_by=spec.created_by,
            grace_seconds=spec.grace_seconds, rule_version=spec.rule_version,
            policy_version=spec.policy_version)
        plans.append((unit_spec, obs))
    return plans


# ───────────────────────────────────────────────────────────── 扩展点注册表
def _threeway_planner(scope: str) -> Callable[..., Any]:
    """三方 scope 的懒加载入口（threeway 依赖本模块的 Observation，避免循环 import）。"""

    def planner(conn: psycopg.Connection, spec: models.RunSpec, deps: EngineDeps,
                now: datetime) -> list[tuple[models.RunSpec, Observation]]:
        from . import threeway

        return threeway.plan(conn, spec, deps=deps, now=now)

    planner.__name__ = f"plan_{scope}"
    return planner


#: scope → planner（五个 scope 全部实现；接口固定，run() 不区分 scope）。
SCOPE_PLANNERS: dict[str, Callable[..., Any]] = {
    "receipt": lambda conn, spec, deps, now: [(spec, scan_receipt(conn, spec, deps=deps, now=now))],
    "daily_close": lambda conn, spec, deps, now: scan_daily_close(conn, spec, deps=deps, now=now),
    "chain": _threeway_planner("chain"),
    "psp": _threeway_planner("psp"),
    "bank": _threeway_planner("bank"),
}


def plan(conn: psycopg.Connection, spec: models.RunSpec, *,
         deps: EngineDeps | None = None, now: datetime | None = None) -> list[Plan]:
    """按 scope 扫描并生成待落库计划（纯读，不写库）。"""
    if spec.scope not in facts.SCOPES:
        raise BadRequest(f"scope 必须是 {list(facts.SCOPES)} 之一", field="scope")
    planner = SCOPE_PLANNERS.get(spec.scope)
    if planner is None:
        raise ScopeNotImplemented(spec.scope)
    resolved = deps or EngineDeps()
    pairs: Sequence[tuple[models.RunSpec, Observation]] = planner(
        conn, spec, resolved, clock.as_utc(now or clock.utcnow()))
    return [Plan(run_spec, observation) for run_spec, observation in pairs]


def run(conn: psycopg.Connection, spec: models.RunSpec, *, deps: EngineDeps | None = None,
        now: datetime | None = None) -> list[dict[str, Any]]:
    """执行对账：run + 差异 + 状态同事务落库（M09 §6.1 第 5 步）。

    幂等：
    * INV-04 同键（scope, subject_ref, period_start, period_end, cutoff_at）→ 返回既有批次
      （``duplicate=True``），不重复开差异；
    * ``trigger_event_id`` 唯一冲突 → 按已落库的批次返回（事件重放）。
    """
    moment = clock.as_utc(now or clock.utcnow())
    resolved = deps or EngineDeps()
    plans = plan(conn, spec, deps=resolved, now=moment)

    results: list[dict[str, Any]] = []
    with conn.transaction():
        for item in plans:
            existing = store.find_run_by_key(conn, item.spec)
            if existing is not None:
                results.append({"run": existing, "duplicate": True, "exception_ids": []})
                continue
            try:
                # 内层 SAVEPOINT：唯一冲突只回滚这一次插入，外层事务（含其它单位的 run）不受影响
                with conn.transaction():
                    run_row = store.insert_run(conn, item.spec,
                                               book_minor=item.observation.book_minor,
                                               external_minor=item.observation.external_minor,
                                               matched_count=item.observation.matched_count,
                                               unmatched_count=item.observation.unmatched_count,
                                               metrics=item.observation.metrics,
                                               status="running", now=moment)
            except psycopg.errors.UniqueViolation:
                replay = (store.find_run_by_key(conn, item.spec)
                          or store.find_run_by_trigger(conn, item.spec.trigger_event_id))
                if replay is None:                       # pragma: no cover - 触发器路径
                    raise Conflict("对账批次冲突：请重试或查询既有批次",
                                   reason="run_conflict")
                results.append({"run": replay, "duplicate": True, "exception_ids": []})
                continue

            exception_ids: list[str] = []
            for draft in item.observation.exceptions:
                row = store.insert_exception(conn, run_id=str(run_row["run_id"]),
                                             scope=item.spec.scope, draft=draft, now=moment)
                exception_ids.append(str(row["exception_id"]))

            final_status = (facts.RUN_STATUS_MATCHED if not item.observation.exceptions
                            else facts.RUN_STATUS_EXCEPTIONS_OPEN)
            run_row = store.update_run(conn, str(run_row["run_id"]), status=final_status,
                                       now=moment)
            results.append({
                "run": run_row,
                "duplicate": False,
                "exception_ids": exception_ids,
                "metrics": item.observation.metrics,
            })
    return results
