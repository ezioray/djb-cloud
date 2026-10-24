# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 §5.2 / §5.4 canary 与 L4 行为指纹（C13；服务端核心）。

做什么
======

1. :func:`issue_run` —— 从内置合成 canary 题面里按 ``(node_id, model, 时间桶)`` **可复算**地选一条，
   追加运行级 nonce，创建 ``issued`` 运行（deadline = now + 120s）；题面可下发；
2. :func:`submit_response` —— 归一化响应后按 ``exact / contains / regex`` 比对 expected：
   命中 → ``passed``，否则 ``failed``；**响应正文绝不落库**，只存 ``sha256`` 与 score；
   重复回填 / 已过期 → 409（40919）；跨 node / 未知 run → 404（40401）；
3. :func:`expire_due` —— ``issued`` 超 deadline → ``missed`` + 事件；
4. :func:`stats` —— 最近 N 次 pass/fail/missed 与通过率；
5. :func:`behavioral_evidence` —— **连续 3 次 pass** 给 ``{"level": "L4", "pass": true}`` 线索；
   **不直接改 M17 定级**（``model_attestations`` 由 C12 / 风控决定），只作为证据源；
6. 查询 :func:`list_runs` / :func:`get_run`。

不变量
======

* **响应正文不落库、不进日志、不进事件 detail**：``canary_runs.response_hash`` = sha256(正文)，
  ``detail`` 只有匹配类型 / 长度 / 耗时 / 原因；DB 另有 detail 键黑名单兜底；
* **一次一运行**：同一 ``(node_id, model)`` 同时只有 1 条 ``issued``（部分唯一索引），
  并发重复 issue 由库层拒绝 → 409；
* **单向状态机**：issued → passed / failed / missed；终态不可回写；
* **不碰账本**：没有任何 ledger / account_balances / loss_pool 写路径；
* **开关默认关闭**：``supply.canary.enabled``（owner=risk-seat）默认 False；S2 测试网
  ``DJB_CANARY=1`` 显式激活；关闭时写接口 503 / 50001，读接口只读。
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import uuid
from datetime import datetime
from typing import Any, Mapping, Sequence

from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import clock, facts, features, models
from .errors import BadRequest, Conflict, FeatureUnavailable, NotFound
from .ids import uuid7

__all__ = [
    "feature_enabled", "require_feature", "normalize_answer", "normalize_regex_text",
    "match_response", "selection_seed", "pick_prompt_key", "issue_run", "submit_response",
    "expire_due", "stats", "behavioral_evidence", "list_runs", "get_run",
    "prompt_payload", "run_payload", "event_payload",
]


# ───────────────────────────────────────────────────────── 开关（fail-closed）
def feature_enabled() -> bool:
    """只读开关：``supply.canary.enabled``（默认 False；S2 测试网 ``DJB_CANARY=1``）。"""
    return features.enabled(facts.CANARY_FLAG) or os.environ.get(facts.CANARY_ENV) == "1"


def require_feature() -> None:
    if not feature_enabled():
        raise FeatureUnavailable(
            "canary 未启用（supply.canary.enabled=false，默认关闭；"
            "S2 测试网用 DJB_CANARY=1 激活）：写接口 fail-closed；历史运行只读",
            reason="feature_disabled")


# ───────────────────────────────────────────────────────── 归一化 / 匹配
_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)
_WS_RE = re.compile(r"\s+", re.UNICODE)


def normalize_answer(text: Any) -> str:
    """答案归一化：小写 + 标点替空格 + 折叠空白（用于 exact / contains）。"""
    lowered = str(text if text is not None else "").lower()
    return _WS_RE.sub(" ", _PUNCT_RE.sub(" ", lowered)).strip()


def normalize_regex_text(text: Any) -> str:
    """正则输入归一化：小写 + 折叠空白（**保留标点**，否则 ``#RRGGBB`` 会被吃掉）。"""
    lowered = str(text if text is not None else "").lower()
    return _WS_RE.sub(" ", lowered).strip()


def match_response(expected_kind: Any, expected_value: Any, response_text: Any
                   ) -> dict[str, Any]:
    """按 expected_kind 比对响应；返回 ``{passed, score, match, reason}``（不含正文）。"""
    kind = str(expected_kind or "").strip().lower()
    if kind not in facts.CANARY_EXPECTED_KINDS:
        raise BadRequest("expected_kind 必须是 exact / contains / regex", field="expected_kind")
    expected = str(expected_value if expected_value is not None else "")
    text = "" if response_text is None else str(response_text)
    if kind == "exact":
        passed = normalize_answer(text) == normalize_answer(expected)
    elif kind == "contains":
        passed = normalize_answer(expected) in normalize_answer(text)
    else:
        try:
            passed = re.search(expected, normalize_regex_text(text), re.IGNORECASE) is not None
        except re.error as exc:
            raise BadRequest("expected_value 不是合法正则", field="expected_value") from exc
    return {"passed": bool(passed), "match": kind,
            "score": facts.CANARY_PASS_SCORE if passed else facts.CANARY_FAIL_SCORE,
            "reason": "match" if passed else "mismatch"}


# ───────────────────────────────────────────────────────── 题面选择（可复算）
def selection_seed(node_id: str, model: str, run_id: Any) -> str:
    """选题种子：``node:model:run_id`` —— 每条运行不同，且可由 run 行原样复算。"""
    return f"{node_id}:{model}:{run_id}"


def pick_prompt_key(node_id: str, model: str, seed: Any,
                    prompt_keys: Sequence[str]) -> str:
    """确定性题面选择：sha256(``node:model:seed``) 取模（排序后取下标）。

    ``seed`` 用 :func:`selection_seed`（含 run_id）：**每次运行题目不同**，避免客户端
    在一个时间窗内反复看到同一题；事后任何人可用 run 行里的 id 复算出当时选的题面。
    """
    keys = sorted(str(key) for key in prompt_keys)
    if not keys:
        raise Conflict("没有可用的 canary 题面", reason="no_active_prompt")
    digest = hashlib.sha256(f"{node_id}:{model}:{seed}".encode("utf-8")).hexdigest()
    return keys[int(digest[:8], 16) % len(keys)]


# ───────────────────────────────────────────────────────── 载荷
def prompt_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": str(row["id"]), "prompt_key": row["prompt_key"],
            "prompt": row["prompt"], "expected_kind": row["expected_kind"],
            "max_tokens": int(row["max_tokens"]), "state": row["state"]}


def run_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    score = row.get("score")
    return {
        "id": str(row["id"]),
        "node_id": row["node_id"],
        "upstream_id": row.get("upstream_id"),
        "model": row["model"],
        "prompt_id": str(row["prompt_id"]),
        "status": row["status"],
        "response_hash": row.get("response_hash"),
        "score": (float(score) if score is not None else None),
        "detail": dict(row.get("detail") or {}),
        "created_at": clock.iso(row["created_at"]),
        "deadline_at": clock.iso(row["deadline_at"]),
        "resolved_at": clock.iso(row.get("resolved_at")),
    }


def event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"event_id": str(row["event_id"]), "run_id": str(row["run_id"]),
            "event": row["event"], "created_at": clock.iso(row["created_at"])}


# ───────────────────────────────────────────────────────── SQL（本模块私有）
def _parse_uuid(value: Any, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise BadRequest(f"{field} 非法", field=field) from exc


def _active_prompts(conn: Any) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.CANARY_COLUMNS_PROMPT} FROM canary_prompts"
            " WHERE state = 'active' ORDER BY prompt_key")
        return [dict(row) for row in cur.fetchall()]


def _get_prompt_by_id(conn: Any, prompt_id: uuid.UUID) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.CANARY_COLUMNS_PROMPT} FROM canary_prompts WHERE id = %s",
            (prompt_id,))
        return cur.fetchone()


def _get_prompt(conn: Any, prompt_key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.CANARY_COLUMNS_PROMPT} FROM canary_prompts"
            " WHERE prompt_key = %s AND state = 'active'", (prompt_key,))
        return cur.fetchone()


def _insert_run(conn: Any, *, run_id: uuid.UUID, node_id: str, upstream_id: str | None,
                model: str, prompt_id: uuid.UUID, nonce: str, created_at: datetime,
                deadline_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO canary_runs
              (id, node_id, upstream_id, model, prompt_id, nonce, status, response_hash,
               score, detail, created_at, deadline_at, resolved_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'issued', NULL, NULL, '{{}}'::jsonb, %s, %s, NULL)
            RETURNING {facts.CANARY_COLUMNS_RUN}
            """,
            (run_id, node_id, upstream_id, model, prompt_id, nonce, created_at, deadline_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _insert_event(conn: Any, *, run_id: uuid.UUID, event: str,
                  detail: dict[str, Any], now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO canary_events (event_id, run_id, event, detail, created_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING {facts.CANARY_COLUMNS_EVENT}
            """, (uuid7(), run_id, event, Jsonb(detail), now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _detail(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _resolve_run(conn: Any, run_id: uuid.UUID, *, status: str,
                 response_hash: str | None, score: float | None,
                 detail: dict[str, Any], now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE canary_runs
               SET status = %s, response_hash = %s, score = %s, detail = %s, resolved_at = %s
             WHERE id = %s AND status = 'issued'
            RETURNING {facts.CANARY_COLUMNS_RUN}
            """, (status, response_hash, score, Jsonb(detail), now, run_id))
        row = cur.fetchone()
    if row is None:                                    # pragma: no cover - FOR UPDATE 后不应发生
        raise Conflict("canary 运行状态已变化，请重试", reason="conflict")
    return dict(row)


# ───────────────────────────────────────────────────────── 1) 发题
def issue_run(conn: Any, *, node_id: Any, model: Any, upstream_id: Any = None,
              now: datetime | None = None) -> dict[str, Any]:
    """发一条 canary：可复算选题 + 运行 nonce；同一 (node, model) 只能有 1 条 issued。"""
    require_feature()
    moment = now or clock.utcnow()
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    upstream = models.normalize_text(upstream_id, field="upstream_id", max_len=128,
                                     required=False)
    prompts = _active_prompts(conn)
    if not prompts:
        raise Conflict("没有可用的 canary 题面", reason="no_active_prompt")
    run_id = uuid7()
    seed = selection_seed(node, model_id, run_id)
    prompt_key = pick_prompt_key(node, model_id, seed,
                                 [row["prompt_key"] for row in prompts])
    prompt = _get_prompt(conn, prompt_key)
    if prompt is None:                                 # pragma: no cover - 竞态下题面被 retire
        raise Conflict("canary 题面已下线，请重试", reason="no_active_prompt")
    nonce = secrets.token_hex(facts.CANARY_NONCE_BYTES)
    issued_prompt = str(prompt["prompt"]) + "\n\ncanary nonce: " + nonce
    try:
        row = _insert_run(conn, run_id=run_id, node_id=node, upstream_id=upstream,
                          model=model_id, prompt_id=uuid.UUID(str(prompt["id"])),
                          nonce=nonce, created_at=moment,
                          deadline_at=moment + facts.CANARY_DEADLINE)
    except pg_errors.UniqueViolation as exc:
        raise Conflict("该 (node, model) 已有未回填的 canary，请先回填或等待过期",
                       reason="run_pending") from exc
    _insert_event(conn, run_id=run_id, event="issued",
                  detail=_detail(prompt_key=prompt_key, selection=seed,
                                 max_tokens=int(prompt["max_tokens"]),
                                 deadline_at=clock.iso(moment + facts.CANARY_DEADLINE)),
                  now=moment)
    return {
        "run_id": str(run_id),
        "node_id": node,
        "upstream_id": upstream,
        "model": model_id,
        "prompt_key": prompt_key,
        "selection": seed,
        "prompt": issued_prompt,
        "nonce": nonce,
        "max_tokens": int(prompt["max_tokens"]),
        "issued_at": clock.iso(moment),
        "deadline_at": clock.iso(moment + facts.CANARY_DEADLINE),
        "status": "issued",
    }


# ───────────────────────────────────────────────────────── 2) 回填 / 匹配
def submit_response(conn: Any, *, run_id: Any, node_id: Any, response_text: Any,
                    usage_prompt_tokens: Any = None, latency_ms: Any = None,
                    now: datetime | None = None) -> dict[str, Any]:
    """回填响应：只比对、只存 hash/score；同 run 重复提交 → 409（40919）。"""
    require_feature()
    moment = now or clock.utcnow()
    identifier = _parse_uuid(run_id, field="id")
    node = models.validate_node_id(node_id)
    if not isinstance(response_text, str):
        raise BadRequest("response_text 必须是字符串", field="response_text")
    if len(response_text) > facts.CANARY_RESPONSE_MAX_LEN:
        raise BadRequest("response_text 超过上限", field="response_text")
    usage = _optional_int(usage_prompt_tokens, field="usage_prompt_tokens")
    latency = _optional_int(latency_ms, field="latency_ms")

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {facts.CANARY_COLUMNS_RUN} FROM canary_runs"
                    " WHERE id = %s FOR UPDATE", (identifier,))
        run = cur.fetchone()
    if run is None or str(run["node_id"]) != node:
        raise NotFound("canary 运行不存在", reason="not_found")
    if run["status"] != "issued":
        raise Conflict("canary 运行已有结果，不可重复提交", reason="run_resolved")
    if run["deadline_at"] <= moment:
        missed = _resolve_run(conn, identifier, status="missed", response_hash=None,
                              score=None, detail={"reason": "deadline_elapsed"},
                              now=moment)
        _insert_event(conn, run_id=identifier, event="missed",
                      detail={"reason": "deadline_elapsed"}, now=moment)
        raise Conflict("canary 已过期（deadline 已过）", reason="run_expired")

    prompt = _get_prompt_by_id(conn, uuid.UUID(str(run["prompt_id"])))
    if prompt is None:                                 # pragma: no cover - 题面被删（DB 禁止）
        raise Conflict("canary 题面不可用", reason="no_active_prompt")
    match = match_response(prompt["expected_kind"], prompt["expected_value"], response_text)
    response_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
    status = "passed" if match["passed"] else "failed"
    detail = _detail(match=match["match"], reason=match["reason"],
                     answer_len=len(response_text), usage_prompt_tokens=usage,
                     latency_ms=latency, prompt_key=prompt["prompt_key"])
    resolved = _resolve_run(conn, identifier, status=status, response_hash=response_hash,
                            score=float(match["score"]), detail=detail, now=moment)
    _insert_event(conn, run_id=identifier, event=status,
                  detail=_detail(match=match["match"], score=match["score"],
                                 response_hash=response_hash),
                  now=moment)
    return {"run": run_payload(resolved),
            "match": {"passed": match["passed"], "score": match["score"],
                      "match": match["match"], "reason": match["reason"],
                      "response_hash": response_hash}}


def _optional_int(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequest(f"{field} 必须是整数", field=field)
    if value < 0:
        raise BadRequest(f"{field} 不能为负", field=field)
    return int(value)


def _prompt_key_of(conn: Any, prompt_id: uuid.UUID) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT prompt_key FROM canary_prompts WHERE id = %s", (prompt_id,))
        row = cur.fetchone()
    return str(row[0]) if row else ""


# ───────────────────────────────────────────────────────── 3) 过期
def expire_due(conn: Any, *, now: datetime | None = None) -> dict[str, int]:
    """issued 超 deadline → missed + 事件（只改本模块表，不碰账本）。"""
    require_feature()
    moment = now or clock.utcnow()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE canary_runs
               SET status = 'missed', detail = '{{"reason": "deadline_elapsed"}}'::jsonb,
                   resolved_at = %s
             WHERE status = 'issued' AND deadline_at <= %s
            RETURNING {facts.CANARY_COLUMNS_RUN}
            """, (moment, moment))
        rows = [dict(row) for row in cur.fetchall()]
    for row in rows:
        _insert_event(conn, run_id=uuid.UUID(str(row["id"])), event="missed",
                      detail={"reason": "deadline_elapsed"}, now=moment)
    return {"runs": len(rows)}


# ───────────────────────────────────────────────────────── 4) 统计 / L4 线索
def stats(conn: Any, *, node_id: Any, model: Any, window: Any = None) -> dict[str, Any]:
    """最近 N 次已定结果运行的 pass / fail / missed 与通过率。"""
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    if window is None:
        size = facts.CANARY_STATS_DEFAULT_WINDOW
    else:
        try:
            size = int(window)
        except (TypeError, ValueError) as exc:
            raise BadRequest("window 必须是整数", field="window") from exc
    if not 1 <= size <= facts.CANARY_STATS_MAX_WINDOW:
        raise BadRequest(f"window 必须在 1–{facts.CANARY_STATS_MAX_WINDOW}", field="window")
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT status, COUNT(*) FROM (
              SELECT status FROM canary_runs
               WHERE node_id = %s AND model = %s AND status <> 'issued'
               ORDER BY created_at DESC, id DESC LIMIT %s
            ) recent GROUP BY status
            """, (node, model_id, size))
        counts = {str(row[0]): int(row[1]) for row in cur.fetchall()}
    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0)
    missed = counts.get("missed", 0)
    total = passed + failed + missed
    return {"node_id": node, "model": model_id, "window": size, "total": total,
            "passed": passed, "failed": failed, "missed": missed,
            "pass_rate": round(passed / total, 3) if total else None}


def behavioral_evidence(conn: Any, *, node_id: Any, model: Any, now: datetime | None = None,
                        streak: int = facts.CANARY_L4_STREAK) -> dict[str, Any]:
    """连续 N 次 pass → L4 线索（**不写定级**，留给 C12 / 风控裁决）。"""
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    need = max(1, int(streak))
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT status FROM canary_runs
             WHERE node_id = %s AND model = %s AND status <> 'issued'
             ORDER BY created_at DESC, id DESC LIMIT %s
            """, (node, model_id, need))
        recent = [str(row[0]) for row in cur.fetchall()]
    if len(recent) < need:
        return {"level": None, "pass": False, "streak": len(recent), "required": need,
                "source": "canary", "reason": "insufficient_runs",
                "note": "canary 线索：定级由 C12 / 风控决定"}
    if all(status == "passed" for status in recent):
        return {"level": "L4", "pass": True, "streak": need, "required": need,
                "source": "canary", "reason": "consecutive_passes",
                "note": "canary 线索：定级由 C12 / 风控决定"}
    leading = 0
    for status in recent:
        if status != "passed":
            break
        leading += 1
    return {"level": None, "pass": False, "streak": leading, "required": need,
            "source": "canary", "reason": "streak_broken",
            "note": "canary 线索：定级由 C12 / 风控决定"}


# ───────────────────────────────────────────────────────── 5) 查询
def list_runs(conn: Any, *, node_id: Any = None, model: Any = None, status: Any = None,
              limit: Any = None, cursor: str | None = None) -> dict[str, Any]:
    conditions: list[str] = []
    params: list[Any] = []
    if node_id:
        conditions.append("node_id = %s")
        params.append(models.validate_node_id(node_id))
    if model:
        conditions.append("model = %s")
        params.append(models.validate_model(model))
    if status:
        value = str(status).strip().lower()
        if value not in facts.CANARY_STATUSES:
            raise BadRequest("status 必须是 issued / passed / failed / missed", field="status")
        conditions.append("status = %s")
        params.append(value)
    page_limit = models.page_limit(limit)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        conditions.append("(created_at < %s OR (created_at = %s AND id::text < %s))")
        params.extend([moment, moment, identity])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(page_limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.CANARY_COLUMNS_RUN} FROM canary_runs{where}"
            " ORDER BY created_at DESC, id DESC LIMIT %s", tuple(params))
        rows = [dict(row) for row in cur.fetchall()]
    has_more = len(rows) > page_limit
    rows = rows[:page_limit]
    next_cursor = None
    if has_more and rows:
        next_cursor = models.encode_cursor(rows[-1]["created_at"], str(rows[-1]["id"]))
    return {"items": [run_payload(row) for row in rows], "has_more": has_more,
            "next_cursor": next_cursor}


def get_run(conn: Any, run_id: Any) -> dict[str, Any] | None:
    identifier = _parse_uuid(run_id, field="id")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {facts.CANARY_COLUMNS_RUN} FROM canary_runs WHERE id = %s",
                    (identifier,))
        row = cur.fetchone()
    if row is None:
        return None
    payload = run_payload(row)
    prompt_key = _prompt_key_of(conn, uuid.UUID(str(row["prompt_id"])))
    payload["prompt_key"] = prompt_key
    payload["events"] = _events_of(conn, identifier)
    return payload


def _events_of(conn: Any, run_id: uuid.UUID) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.CANARY_COLUMNS_EVENT} FROM canary_events"
            " WHERE run_id = %s ORDER BY created_at DESC, event_id DESC LIMIT 20",
            (run_id,))
        return [event_payload(dict(row)) for row in cur.fetchall()]
