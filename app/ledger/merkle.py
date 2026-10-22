# SPDX-License-Identifier: Apache-2.0
"""Merkle 期间根（journal / daily_close）：计算 → 锚定（写入即发布）→ 读回 → 可复现校验。

口径（INV-13 / M06 §4.2 / spec 1.2.1 MerkleCommitment）：
  · 叶子 = 当期凭证的 ``journal_entry.hash``（已经是内容哈希，见 hashchain）；
  · 内部节点 = ``sha256(0x01 ‖ left ‖ right)``；奇数个节点时最后一个**上提**到下一层
    （不复制自己，避免 CVE-2012-2459 那类"重复叶子"歧义）；
  · 空期间 = ``sha256(b"M06:MERKLE:EMPTY")``（有明确定义的根，不是 0 或 NULL）；
  · 期间归属：``journal_entry.merkle_period`` 优先；为空时按 ``ts``（UTC）落桶：
    月 ``YYYY-MM`` / 日 ``YYYY-MM-DD`` / 时 ``YYYY-MM-DDTHH`` —— 由调用方给的 period 形状决定；
  · **写入即发布**：锚定 = INSERT merkle_commitments（603 的只追加表）；
    同期间同类别重算得到不同根 → 40920（发布后不可改，人工查因，不自动覆盖）。

投递：锚定成功后发 ``merkle.anchored``（02-events §3），与锚定同事务。
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Iterable

from . import hashchain, outbox
from .constants import (HASH_ALGO, HEX_PREVIEW_LEN, MERKLE_KINDS_OWNED, PERIOD_LEN_DAY,
                        PERIOD_LEN_HOUR, PERIOD_LEN_MONTH)
from .errors import LedgerError

_EMPTY_SEED = b"M06:MERKLE:EMPTY"
_PERIOD_FORMATS = {PERIOD_LEN_HOUR: "YYYY-MM-DD\"T\"HH24", PERIOD_LEN_DAY: "YYYY-MM-DD",
                   PERIOD_LEN_MONTH: "YYYY-MM"}   # 时 / 日 / 月
_PERIOD_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])(-([0-2][0-9]|3[01])(T([01][0-9]|2[0-3]))?)?$")


class MerkleError(LedgerError):
    """期间 / 类别不合法（CR-L1 的 42222 段）。"""

    code = "42222"


class MerklePublishedImmutable(LedgerError):
    """期内根已发布且与重算不一致：发布后不可改，人工查因（40920）。"""

    code = "40920"


def period_format(period: str) -> str:
    """根据 period 形状决定落桶粒度；不认识的形状直接拒绝（不猜）。"""
    fmt = _PERIOD_FORMATS.get(len(period))
    if fmt is None or not _PERIOD_RE.match(period):
        raise MerkleError(f"period {period!r} 必须是 YYYY-MM / YYYY-MM-DD / YYYY-MM-DDTHH")
    return fmt


def leaf_hashes(conn, *, period: str) -> list[bytes]:
    """期间内的凭证哈希（按 seq 升序；merkle_period 优先，否则按 ts 落桶）。"""
    fmt = period_format(period)
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT hash FROM journal_entry
                 WHERE merkle_period = %s
                    OR (merkle_period IS NULL
                        AND to_char(ts AT TIME ZONE 'UTC', '{fmt}') = %s)
                 ORDER BY seq""", (period, period))
        return [bytes(row[0]) for row in cur.fetchall()]


def merkle_root(leaves: Iterable[bytes]) -> bytes:
    """Merkle 根：叶子已是哈希；奇数节点上提；空期间返回定义好的空根。"""
    level = [bytes(leaf) for leaf in leaves]
    if not level:
        return hashlib.new(HASH_ALGO, _EMPTY_SEED).digest()
    while len(level) > 1:
        nxt: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else None
            nxt.append(hashlib.new(HASH_ALGO, b"\x01" + left + right).digest() if right is not None
                       else left)
        level = nxt
    return level[0]


def compute(conn, *, kind: str, period: str) -> dict:
    """重算期间根（只读）：返回 root(hex) / entry_count / leaves。"""
    if kind not in MERKLE_KINDS_OWNED:
        raise MerkleError(f"kind {kind!r} 不属于 M06（只允许 {MERKLE_KINDS_OWNED}）")
    leaves = leaf_hashes(conn, period=period)
    return {"kind": kind, "period": period, "root": merkle_root(leaves).hex(),
            "entry_count": len(leaves)}


def anchor(conn, *, kind: str, period: str, trace_id: str | None = None,
           occurred_at: datetime | None = None) -> dict:
    """锚定 = 写入即发布：INSERT merkle_commitments + merkle.anchored（同一事务）。"""
    computed = compute(conn, kind=kind, period=period)
    anchored_at = occurred_at or datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO merkle_commitments (period, kind, root, entry_count,
                                               anchored_at, published_at)
               VALUES (%s, %s, %s, %s, %s, now())
               ON CONFLICT (period, kind) DO NOTHING
               RETURNING root, entry_count, published_at""",
            (period, kind, computed["root"], computed["entry_count"], anchored_at))
        inserted = cur.fetchone()
        if inserted is None:                        # 已发布过：根必须一致，否则 40920
            cur.execute(
                """SELECT root, entry_count, published_at FROM merkle_commitments
                    WHERE period = %s AND kind = %s""", (period, kind))
            existing = cur.fetchone()
            if existing is None:                    # 理论上不可达（冲突必有行）
                raise MerkleError(f"锚定失败：{kind}/{period}")
            if existing[0] != computed["root"]:
                raise MerklePublishedImmutable(
                    f"{kind}/{period} 已发布 root={existing[0][:HEX_PREVIEW_LEN]}…，"
                    f"重算 root={computed['root'][:HEX_PREVIEW_LEN]}… 不一致",
                    detail={"period": period, "kind": kind,
                            "published_root": existing[0], "recomputed_root": computed["root"]})
            return {"period": period, "kind": kind, "root": existing[0],
                    "entry_count": int(existing[1]), "published_at": existing[2].isoformat(),
                    "created": False, "event_ids": ()}

    event = outbox.merkle_anchored_event(
        root=computed["root"], kind=kind, period=period, anchored_at=anchored_at,
        trace_id=trace_id)
    event_ids = (outbox.append_event(conn, event),)
    return {"period": period, "kind": kind, "root": inserted[0],
            "entry_count": int(inserted[1]), "published_at": inserted[2].isoformat(),
            "created": True, "event_ids": event_ids}


def get(conn, *, kind: str, period: str) -> dict | None:
    """读回已发布根，并给出 ``reproducible``（重算是否一致；False 即 P0）。"""
    if kind not in MERKLE_KINDS_OWNED:
        raise MerkleError(f"kind {kind!r} 不属于 M06（只允许 {MERKLE_KINDS_OWNED}）")
    period_format(period)
    with conn.cursor() as cur:
        cur.execute(
            """SELECT root, entry_count, published_at, anchored_at, algorithm
                 FROM merkle_commitments WHERE period = %s AND kind = %s""",
            (period, kind))
        row = cur.fetchone()
    if row is None:
        return None
    root, entry_count, published_at, anchored_at, algorithm = row
    recomputed = compute(conn, kind=kind, period=period)
    return {
        "period": period,
        "kind": kind,
        "root": root,
        "entry_count": int(entry_count),
        "published_at": published_at.astimezone(timezone.utc).isoformat(),
        "anchored_at": anchored_at.astimezone(timezone.utc).isoformat(),
        "algorithm": algorithm,
        "reproducible": recomputed["root"] == root,
        "recomputed_root": recomputed["root"],
        "verify_hint": f"POST /api/v1/admin/ledger/recompute (period={period})",
    }


def anchor_period(conn, *, kind: str, period: str, trace_id: str | None = None) -> dict:
    """定时 job ``merkle_anchor`` 的入口别名（M06 §4.2：job 按期间调用本函数）。"""
    return anchor(conn, kind=kind, period=period, trace_id=trace_id)


def verify_commitment(conn, *, kind: str, period: str) -> bool:
    """最小验证入口（T4 契约测试与运维用）：根是否可由当期分录复现。"""
    record = get(conn, kind=kind, period=period)
    return bool(record and record["reproducible"])
