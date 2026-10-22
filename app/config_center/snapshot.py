# SPDX-License-Identifier: Apache-2.0
"""快照与回放（T4，INV-08）。

M10 §6 事务边界：**active 切换与快照写入同事务**；§7：快照缺失要阻止转 active。
本模块只做三件事：

1. :func:`write_snapshot` —— 把「当前全部 active 版本」落成一行不可变快照
   （entries 覆盖全部 active key；``policy_version = left(snapshot_digest, 12)`` 由 1003 的生成列保证）；
2. :func:`assert_snapshot_consistent` —— **落库 digest 必须等于事件里携带的 digest**（R-14），
   不一致即抛 47001，让外层事务整体回滚；
3. :func:`replay_snapshot` / :func:`verify_snapshot` —— 回放与复算（T5 的只读 CLI 复用）。

快照表只追加（1003 触发器拒绝 UPDATE/DELETE），同一内容重复落库按唯一 digest 幂等返回既有行。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

import psycopg
from psycopg.types.json import Jsonb

from . import canonical, store
from .errors import ValidationFailed

__all__ = [
    "snapshot_entries",
    "write_snapshot",
    "verify_snapshot",
    "assert_snapshot_consistent",
    "replay_snapshot",
    "list_snapshots",
]


def _one(conn: psycopg.Connection, sql: str, params: Any = ()) -> dict[str, Any] | None:
    cur = conn.execute(sql, params)
    columns = [desc.name for desc in cur.description or ()]
    rows = [dict(zip(columns, row)) for row in cur.fetchall()]
    return rows[0] if rows else None


def snapshot_entries(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """快照 entries：全部 active 版本（INV-08「覆盖全部 active key」）。"""
    return store.active_entries(conn)


def write_snapshot(
    conn: psycopg.Connection,
    *,
    period: str,
    publish_request_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """落一行不可变快照；同 digest 幂等（返回既有行）。"""
    if not isinstance(period, str) or not 1 <= len(period) <= 64:
        raise ValidationFailed(f"period 非法：{period!r}")
    entries = snapshot_entries(conn)
    if not entries:
        raise ValidationFailed("没有 active 配置，拒绝落快照（INV-08：entries 必须覆盖全部 active key）")
    digest = canonical.snapshot_digest(entries)
    moment = now or datetime.now(timezone.utc)
    row = _one(
        conn,
        """INSERT INTO config_snapshots
             (snapshot_digest, period, entries, entries_count, publish_request_id, created_at)
           VALUES (%s, %s, %s, %s, %s, %s)
           ON CONFLICT (snapshot_digest) DO NOTHING
           RETURNING *""",
        (digest, period, Jsonb(entries), len(entries), publish_request_id, moment),
    )
    if row is None:                       # 同一内容已有快照：幂等返回既有行
        row = _one(conn, "SELECT * FROM config_snapshots WHERE snapshot_digest = %s", (digest,))
    if row is None:                       # pragma: no cover - 唯一约束后必然存在
        raise ValidationFailed(f"快照写入后读不到：{digest}")
    return row


def verify_snapshot(row: Mapping[str, Any]) -> bool:
    """复算快照 digest（entries 与库内 digest 必须一致）。"""
    entries = row["entries"]
    if not isinstance(entries, list) or not entries:
        return False
    try:
        return canonical.snapshot_digest(entries) == row["snapshot_digest"]
    except (TypeError, ValueError):
        return False


def assert_snapshot_consistent(row: Mapping[str, Any], *, expected_digest: str) -> None:
    """R-14：落库快照 digest 必须等于事件将携带的 digest，不一致即拒绝（外层回滚）。"""
    actual = row.get("snapshot_digest")
    if actual != expected_digest:
        raise ValidationFailed(
            f"快照 digest 与事件 digest 不一致：snapshot={actual!r} event={expected_digest!r}"
            "（INV-08 / R-14，拒绝转 active）")
    if not verify_snapshot(row):
        raise ValidationFailed(
            f"快照 entries 无法复算出 digest：{actual!r}（快照内容被改写？）")
    if canonical.policy_version(actual) != row.get("policy_version"):
        raise ValidationFailed(
            f"policy_version 与 digest 前 12 位不一致：{row.get('policy_version')!r} vs {actual[:12]}")


def replay_snapshot(conn: psycopg.Connection, *, snapshot_digest: str | None = None,
                    period: str | None = None) -> dict[str, Any] | None:
    """按 digest 或 period 取快照（``djb-config replay`` 的存储层）。"""
    if snapshot_digest is not None:
        return _one(conn, "SELECT * FROM config_snapshots WHERE snapshot_digest = %s",
                    (snapshot_digest,))
    if period is not None:
        return _one(conn, """SELECT * FROM config_snapshots WHERE period = %s
                              ORDER BY created_at DESC LIMIT 1""", (period,))
    raise ValidationFailed("replay_snapshot 需要 snapshot_digest 或 period")


def list_snapshots(conn: psycopg.Connection, *, limit: int = 50) -> list[dict[str, Any]]:
    if not 1 <= limit <= 200:
        raise ValidationFailed(f"limit 越界 1..200：{limit}")
    cur = conn.execute("""SELECT * FROM config_snapshots ORDER BY created_at DESC LIMIT %s""",
                       (limit,))
    columns = [desc.name for desc in cur.description or ()]
    return [dict(zip(columns, row)) for row in cur.fetchall()]
