# SPDX-License-Identifier: Apache-2.0
"""审计链存储层（只碰 ``audit_log`` / ``audit_anchors`` / ``m16_outbox``，不读任何业务表）。

并发（关键设计，见证据文件「并发与锁」）：**每个 schema 一把事务级 advisory lock**::

    SELECT pg_advisory_xact_lock(hashtext('djb.audit.append:' || current_schema())::bigint)

为什么选它，而不是"锁最后一行"（``SELECT … FOR UPDATE``）：

* 空表时**没有行可锁**，行锁方案在第一条就会退化（要么加锁失败，要么两个写入者都读到空表）；
* advisory lock 与"哪一行是尾"无关，天然覆盖"空表 → 第一条"这个边界；
* 事务级（``xact``）锁在 COMMIT / ROLLBACK 自动释放，不需要额外解锁路径，也不会出现
  "进程崩了锁还在"（对比文件锁 / 会话锁）；
* 锁 key 里带 ``current_schema()``：测试与多 schema 演练互不阻塞，同一 schema 内严格串行。

拿到锁之后再 ``SELECT seq, hash ORDER BY seq DESC LIMIT 1`` → 分配 ``seq = tail.seq + 1``
（**不用序列**：序列会留空洞，而链要求 seq 连续可验；回滚/幂等重放也不该消耗序号）。

事务边界（M16 §6）：审计条目与 ``m16_outbox`` 同一事务写入；本模块不自开事务、不提交——
由调用方（router / CLI）的连接上下文统一提交或回滚。
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Mapping, Sequence

from psycopg.types.json import Jsonb

from . import canonical, clock, errors, events, facts, keys, models

#: 事务级 advisory lock：同一 schema 内串行化 append（见模块 docstring 的取舍说明）
ADVISORY_LOCK_SQL = (
    "SELECT pg_advisory_xact_lock(hashtext('djb.audit.append:' || current_schema())::bigint)"
)

#: 条目列（顺序即 ``_row_to_entry`` 的取值顺序）
ENTRY_COLUMNS: tuple[str, ...] = (
    "seq", "entry_id", "ts", "actor", "actor_type", "role", "action", "target",
    "before", "after", "reason_code", "ticket", "evidence", "approval_chain",
    "status", "alg", "prev_hash", "hash", "idempotency_key",
)

_SELECT_ENTRY = "SELECT " + ", ".join(ENTRY_COLUMNS) + " FROM audit_log"

_INSERT_ENTRY = """
    INSERT INTO audit_log
        (seq, entry_id, ts, actor, actor_type, role, action, target, before, after,
         reason_code, ticket, evidence, approval_chain, status, alg, prev_hash, hash,
         idempotency_key)
    VALUES
        (%(seq)s, %(entry_id)s, %(ts)s, %(actor)s, %(actor_type)s, %(role)s, %(action)s,
         %(target)s, %(before)s, %(after)s, %(reason_code)s, %(ticket)s, %(evidence)s,
         %(approval_chain)s, %(status)s, %(alg)s, %(prev_hash)s, %(hash)s,
         %(idempotency_key)s)
"""

_INSERT_OUTBOX = """
    INSERT INTO m16_outbox
        (event_id, type, version, occurred_at, producer, aggregate_type, aggregate_id,
         correlation_id, causation_id, trace_id, idempotency_key, payload)
    VALUES
        (%(event_id)s, %(type)s, %(version)s, %(occurred_at)s, %(producer)s,
         %(aggregate_type)s, %(aggregate_id)s, %(correlation_id)s, %(causation_id)s,
         %(trace_id)s, %(idempotency_key)s, %(payload)s)
"""


# --------------------------------------------------------------------------- 行 → 条目
def _row_to_entry(row: Sequence[Any]) -> dict[str, Any]:
    return {column: row[index] for index, column in enumerate(ENTRY_COLUMNS)}


def _core_key(entry: Mapping[str, Any]) -> str:
    """幂等比对用的规范字符串（业务内容，不含链字段）。"""
    return canonical.canonical_json(models.request_core(entry))


def _normalise(cur: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
    """让 payload 与数据库 jsonb **同字节**：先 ``::jsonb`` 再读回，再序列化。

    这样 append 写的 hash 与 verify 重算的 hash 不会因为"Python 侧序列化细节"
    （键序、数字形态、转义）出现假警报。
    """
    row = cur.execute("SELECT (%s::jsonb)::text", (Jsonb(dict(payload)),)).fetchone()
    return json.loads(row[0])


def _insert_outbox(cur: Any, entry: Mapping[str, Any], *, trace_id: str,
                   occurred_at: Any) -> dict[str, Any]:
    envelope = events.audit_appended_envelope(entry, trace_id=trace_id, occurred_at=occurred_at)
    cur.execute(_INSERT_OUTBOX, {
        "event_id": envelope["event_id"],
        "type": envelope["type"],
        "version": envelope["version"],
        "occurred_at": envelope["occurred_at"],
        "producer": envelope["producer"],
        "aggregate_type": envelope["aggregate_type"],
        "aggregate_id": envelope["aggregate_id"],
        "correlation_id": envelope["correlation_id"],
        "causation_id": envelope["causation_id"],
        "trace_id": envelope["trace_id"],
        "idempotency_key": envelope["idempotency_key"],
        "payload": Jsonb(envelope["payload"]),
    })
    return envelope


# --------------------------------------------------------------------------- 查询
def fetch_by_idempotency(cur: Any, idempotency_key: str) -> dict[str, Any] | None:
    row = cur.execute(f"{_SELECT_ENTRY} WHERE idempotency_key = %s",
                      (idempotency_key,)).fetchone()
    return _row_to_entry(row) if row else None


def fetch_all(c: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    """整条链（seq 升序）；``limit`` 给定时只取前 N 条（演练 / 大链分段用）。"""
    sql = f"{_SELECT_ENTRY} ORDER BY seq"
    params: tuple[Any, ...] = ()
    if limit is not None:
        sql += " LIMIT %s"
        params = (int(limit),)
    with c.cursor() as cur:
        return [_row_to_entry(row) for row in cur.execute(sql, params).fetchall()]


def list_page(c: Any, *, from_seq: int | None = None, action: str | None = None,
              target: str | None = None, limit: int | None = None) -> dict[str, Any]:
    """只读分页（spec ``listAuditEntries``：按 seq 升序，``has_more`` + ``next_cursor``）。"""
    page_size = facts.DEFAULT_PAGE_SIZE if limit is None else int(limit)
    if page_size < 1 or page_size > facts.MAX_PAGE_SIZE:
        raise errors.InvalidArgument(f"limit 必须是 1..{facts.MAX_PAGE_SIZE}", field="limit")
    where: list[str] = []
    params: dict[str, Any] = {"limit": page_size + 1}
    if from_seq is not None:
        where.append("seq >= %(from_seq)s")
        params["from_seq"] = int(from_seq)
    if action:
        where.append("action = %(action)s")
        params["action"] = action
    if target:
        where.append("target = %(target)s")
        params["target"] = target
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with c.cursor() as cur:
        rows = [_row_to_entry(row) for row in cur.execute(
            f"{_SELECT_ENTRY}{clause} ORDER BY seq LIMIT %(limit)s", params).fetchall()]
    has_more = len(rows) > page_size
    data = rows[:page_size]
    next_cursor = str(data[-1]["seq"] + 1) if has_more and data else None
    return {"data": data,
            "page": {"cursor": None, "has_more": has_more, "next_cursor": next_cursor}}


# --------------------------------------------------------------------------- 追加
def append(c: Any, draft: Mapping[str, Any], *, key_provider: Any,
           now: Any = None, trace_id: str | None = None,
           idempotency_key: str | None = None) -> dict[str, Any]:
    """追加一条审计条目（同事务写 outbox）。返回 ``{"entry", "duplicate"}``。

    fail-closed：密钥不可用 → :class:`app.audit.errors.ChainLocked`（423 / 42301），一行都不写。
    幂等：同键重复提交返回**首次结果**（``duplicate=True``）；同键不同内容 → 409。
    """
    if getattr(c, "autocommit", False):
        # autocommit 连接下 advisory lock 会在语句结束时立即释放，串行化失效 → 直接拒绝
        raise errors.ServiceUnavailable(
            "审计追加必须在事务内执行（连接处于 autocommit，串行化取 seq 会失效）",
            reason="autocommit_not_allowed")
    key = keys.read_key(key_provider)
    if key is None:
        raise errors.ChainLocked(
            "审计链 HMAC 密钥不可用（DJB_AUDIT_HMAC_KEY_FILE 未配置）：拒绝写入（fail-closed）",
            reason="audit_key_missing")
    moment = clock.as_utc(now or clock.utcnow())
    trace = (trace_id or "").strip() or str(models.uuid7(moment))

    with c.cursor() as cur:
        cur.execute(ADVISORY_LOCK_SQL)

        if idempotency_key:
            existing = fetch_by_idempotency(cur, idempotency_key)
            if existing is not None:
                if _core_key(existing) != _core_key(draft):
                    raise errors.Conflict(
                        "幂等键已用于不同的审计内容（拒绝改写历史事实）",
                        reason="idempotency_key_reused",
                        entry_id=str(existing["entry_id"]), seq=existing["seq"])
                return {"entry": existing, "duplicate": True}

        tail = cur.execute(
            "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        entry: dict[str, Any] = dict(draft)
        entry.update({
            "seq": (int(tail[0]) + 1) if tail else 1,
            "entry_id": str(models.uuid7(moment)),
            "ts": moment,
            "alg": facts.ALG,
            "prev_hash": str(tail[1]) if tail else facts.GENESIS,
        })

        payload = _normalise(cur, canonical.entry_payload(entry))
        entry_hash = canonical.compute_hash_payload(key, entry["prev_hash"], payload)
        entry["hash"] = entry_hash

        cur.execute(_INSERT_ENTRY, {
            "seq": entry["seq"],
            "entry_id": entry["entry_id"],
            "ts": entry["ts"],
            "actor": entry["actor"],
            "actor_type": entry["actor_type"],
            "role": entry["role"],
            "action": entry["action"],
            "target": entry["target"],
            "before": Jsonb(entry["before"]) if entry.get("before") is not None else None,
            "after": Jsonb(entry["after"]) if entry.get("after") is not None else None,
            "reason_code": entry.get("reason_code"),
            "ticket": entry.get("ticket"),
            "evidence": entry.get("evidence"),
            "approval_chain": Jsonb(entry.get("approval_chain") or []),
            "status": entry["status"],
            "alg": entry["alg"],
            "prev_hash": entry["prev_hash"],
            "hash": entry_hash,
            "idempotency_key": idempotency_key,
        })
        _insert_outbox(cur, entry, trace_id=trace, occurred_at=moment)

    return {"entry": entry, "duplicate": False}


# --------------------------------------------------------------------------- 日根
def get_anchor(c: Any, period: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        row = cur.execute(
            """SELECT period, merkle_root, sealed_at, alg, evidence_ref, entry_count,
                      first_seq, last_seq
                 FROM audit_anchors WHERE period = %s""", (period,)).fetchone()
    if row is None:
        return None
    return {"period": row[0], "merkle_root": row[1], "sealed_at": row[2], "alg": row[3],
            "evidence_ref": row[4], "entry_count": row[5], "first_seq": row[6],
            "last_seq": row[7]}


def insert_anchor(c: Any, *, period: str, merkle_root: str, sealed_at: Any,
                  alg: str = facts.ALG, evidence_ref: str | None = None,
                  entry_count: int = 0, first_seq: int | None = None,
                  last_seq: int | None = None) -> tuple[dict[str, Any], bool]:
    """幂等封盘：同一天只写一行；已存在则返回既有行（``created=False``）。"""
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO audit_anchors
                   (period, merkle_root, sealed_at, alg, evidence_ref, entry_count,
                    first_seq, last_seq)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (period) DO NOTHING""",
            (period, merkle_root, sealed_at, alg, evidence_ref, int(entry_count),
             first_seq, last_seq))
        created = cur.rowcount == 1
    anchor = get_anchor(c, period)
    if anchor is None:                              # pragma: no cover - 并发删除不可能（只追加）
        raise errors.ServiceUnavailable("审计锚点写入后不可读：请重试", reason="anchor_unreadable")
    return anchor, created


__all__ = [
    "ADVISORY_LOCK_SQL",
    "ENTRY_COLUMNS",
    "append",
    "fetch_all",
    "fetch_by_idempotency",
    "get_anchor",
    "insert_anchor",
    "list_page",
]
