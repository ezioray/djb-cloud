# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 §5.10 / §5.11 可验证随机抽检（C14b）：commit-reveal + 贡献加权。

流程
====

1. :func:`open_epoch` —— **先承诺**：调用方给抽样框快照 ``contributions``
   （``[{node_id, model, weight}]``，来自 M05 用量快照，本模块不查账本）与 ``draw_count``；
   服务端生成 32 字节 seed，只把 ``sha256(seed)`` 写进库（``seed_commit``），
   **seed 本体不落库**，仅返回给调用方保管（揭示时用）。
2. :func:`reveal_epoch` —— **后揭晓**：校验 ``sha256(seed) == seed_commit``（否则 409），
   写 ``seed_reveal`` + ``state=revealed``，然后**确定性**重算抽签：
   ``HMAC-SHA256(seed, f"{epoch_no}:{node}:{model}:{i}")`` 给每个候选排序/取值，
   按 ``score = -ln(u) / weight`` 做**加权无放回**抽样（Efraimidis–Spirakis 指数竞赛），
   权重 0 不参与；每个命中调用 :func:`attest.issue_challenge` 建 C12 挑战（status=pending）。
3. :func:`record_result` —— 回填：调用 :func:`attest.submit_evidence` 消费挑战并定级，
   ``L3+ → passed``、``L2/L1/L0 → failed``；挑战过期 / 不存在 → ``missed``（由
   :func:`expire_due` 或本函数就近翻转）。
4. :func:`expire_due` —— pending 且挑战已过 TTL → ``missed`` + 事件。
5. :func:`escalate` —— 按最近 24h / 7d 的 failed+missed 次数**只给建议**（I0/I1/I2），
   不建 hold；调用方可用 C14 ``holds.create_or_escalate`` 落地。
6. :func:`verify_epoch` —— 任何人可用 ``seed_reveal + contributions + draw_count`` 复算，
   返回 ``consistent`` / ``commit_ok``；**同 seed 重算 100% 一致**。

不变量
======

* **客户端不可选择 / 不可跳过**：抽样框、seed、命中都由服务端在 epoch 内定；
  本卡不下发 C10 帧（执行由 C13 接线），只做服务端核心；
* **seed 不落库**：库里只有 ``seed_commit``（承诺）与 ``seed_reveal``（揭示后）；
  ``sampling_events.detail`` 有 DB 黑名单禁止出现 ``seed`` / 正文 / 凭据；
* **不碰账本**：没有任何 ledger / account_balances / loss_pool 写路径；
* **开关默认关闭**：``supply.sampling.enabled`` 默认 False，S2 测试网 ``DJB_SAMPLING=1``
  显式激活；关闭时写接口 503 / 50001，读接口只读。
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import attest, clock, facts, features, models
from .errors import BadRequest, Conflict, FeatureUnavailable, IntegrityError, NotFound
from .ids import uuid7

__all__ = [
    "Contribution", "normalize_contributions", "seed_commit", "drawing",
    "compare_drawings", "feature_enabled", "require_feature", "open_epoch",
    "reveal_epoch", "record_result", "expire_due", "escalate", "list_epochs",
    "get_epoch", "list_draws", "verify_epoch", "epoch_payload", "draw_payload",
    "event_payload",
]


# ───────────────────────────────────────────────────────── 开关（fail-closed）
def feature_enabled() -> bool:
    """只读开关：``supply.sampling.enabled``（默认 False；S2 测试网 ``DJB_SAMPLING=1``）。"""
    return features.enabled(facts.SAMPLING_FLAG) or os.environ.get(facts.SAMPLING_ENV) == "1"


def require_feature() -> None:
    if not feature_enabled():
        raise FeatureUnavailable(
            "可验证随机抽检未启用（supply.sampling.enabled=false，默认关闭；"
            "S2 测试网用 DJB_SAMPLING=1 激活）：写接口 fail-closed；已存轮次只读",
            reason="feature_disabled")


# ───────────────────────────────────────────────────────── 抽样框 / 纯函数
@dataclass(frozen=True)
class Contribution:
    node_id: str
    model: str
    weight: int

    def as_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "model": self.model, "weight": self.weight}


def normalize_contributions(raw: Any) -> list[Contribution]:
    """校验抽样框：``[{node_id, model, weight}]``；去重（重复即 400，不静默合并）。"""
    if not isinstance(raw, (list, tuple)):
        raise BadRequest("contributions 必须是数组", field="contributions")
    if not raw:
        raise BadRequest("contributions 不能为空", field="contributions")
    if len(raw) > facts.SAMPLING_MAX_CONTRIBUTIONS:
        raise BadRequest("contributions 超过上限", field="contributions")
    out: list[Contribution] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise BadRequest("contributions 每项必须是对象", field="contributions")
        extra = set(str(key) for key in item) - set(facts.SAMPLING_CONTRIBUTION_KEYS)
        if extra:
            raise BadRequest("contributions 只允许 node_id / model / weight",
                             field="contributions")
        node = models.validate_node_id(item.get("node_id"))
        model = models.validate_model(item.get("model"))
        weight = item.get("weight")
        if isinstance(weight, bool) or not isinstance(weight, int):
            raise BadRequest("weight 必须是整数", field="contributions")
        if weight < 0 or weight > facts.SAMPLING_WEIGHT_MAX:
            raise BadRequest("weight 超出范围（0..上限）", field="contributions")
        marker = (node, model)
        if marker in seen:
            raise BadRequest("contributions 存在重复的 (node_id, model)",
                             field="contributions")
        seen.add(marker)
        out.append(Contribution(node, model, int(weight)))
    return out


def seed_commit(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


def _hmac_hex(seed: bytes, message: str) -> str:
    return hmac.new(seed, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _unit_interval(hexdigest: str) -> float:
    """取 HMAC 前 64 bit → (0, 1) 的开区间均匀值（避免 0 导致 log 爆炸）。"""
    value = int(hexdigest[:16], 16)
    return (value + 1) / float(1 << 64)


def drawing(seed_hex: str, epoch_no: int, contributions: Sequence[Contribution],
            draw_count: int) -> list[dict[str, Any]]:
    """确定性抽签（纯函数，可被任何人复算）。

    * 排序键：``HMAC-SHA256(seed, f"{epoch_no}:{node}:{model}:{index}")``（index = 抽样框下标 + 1）；
    * 选择：``score = -ln(u) / weight`` 升序取前 ``draw_count``（加权**无放回**）；
      权重 0 不参与；
    * ``rank``：命中集合内按排序键升序的 1..k 位次。

    返回 ``[{node_id, model, weight, rank, order_key}]``（按 rank 升序）。
    """
    try:
        seed = bytes.fromhex(seed_hex)
    except (ValueError, TypeError) as exc:
        raise BadRequest("seed 必须是十六进制", field="seed") from exc
    if not seed:
        raise BadRequest("seed 不能为空", field="seed")
    eligible = [(index, item) for index, item in enumerate(contributions, start=1)
                if item.weight > 0]
    if draw_count <= 0 or not eligible:
        return []
    scored: list[tuple[float, str, int, Contribution]] = []
    for index, item in eligible:
        order_key = _hmac_hex(seed, f"{epoch_no}:{item.node_id}:{item.model}:{index}")
        score = -math.log(_unit_interval(order_key)) / float(item.weight)
        scored.append((score, order_key, index, item))
    scored.sort(key=lambda entry: (entry[0], entry[1]))
    selected = scored[:min(draw_count, len(scored))]
    ordered = sorted(selected, key=lambda entry: (entry[1], entry[3].node_id,
                                                  entry[3].model))
    return [{"node_id": item.node_id, "model": item.model, "weight": int(item.weight),
             "rank": rank, "order_key": order_key}
            for rank, (_score, order_key, _index, item) in enumerate(ordered, start=1)]


def compare_drawings(expected: Sequence[Mapping[str, Any]],
                     actual: Sequence[Mapping[str, Any]]) -> bool:
    """复算比对：``(node_id, model, rank)`` 序列必须完全一致（含顺序）。"""
    def _key(rows: Iterable[Mapping[str, Any]]) -> list[tuple[str, str, int]]:
        return [(str(row["node_id"]), str(row["model"]), int(row["rank"])) for row in rows]

    return _key(expected) == _key(actual)


# ───────────────────────────────────────────────────────── 载荷
def epoch_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "epoch_no": int(row["epoch_no"]),
        "seed_commit": row["seed_commit"],
        "seed_reveal": row.get("seed_reveal"),
        "contributions": list(row.get("contributions") or []),
        "state": row["state"],
        "draw_count": int(row["draw_count"]),
        "committed_at": clock.iso(row["committed_at"]),
        "revealed_at": clock.iso(row.get("revealed_at")),
        "created_at": clock.iso(row.get("created_at")),
    }


def draw_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "epoch_id": str(row["epoch_id"]),
        "node_id": row["node_id"],
        "model": row["model"],
        "weight": int(row["weight"]),
        "rank": int(row["rank"]),
        "challenge_id": str(row["challenge_id"]) if row.get("challenge_id") else None,
        "status": row["status"],
        "level": row.get("level"),
        "detail": dict(row.get("detail") or {}),
        "created_at": clock.iso(row["created_at"]),
        "resolved_at": clock.iso(row.get("resolved_at")),
    }


def event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"event_id": str(row["event_id"]), "epoch_id": str(row["epoch_id"])
            if row.get("epoch_id") else None,
            "draw_id": str(row["draw_id"]) if row.get("draw_id") else None,
            "event": row["event"], "created_at": clock.iso(row["created_at"])}


# ───────────────────────────────────────────────────────── SQL（本模块私有）
def _load_epoch(conn: Any, epoch_id: uuid.UUID, *, for_update: bool = False
                ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.SAMPLING_EPOCH_COLUMNS} FROM sampling_epochs"
            f" WHERE id = %s{suffix}", (epoch_id,))
        return cur.fetchone()


def _insert_epoch(conn: Any, *, epoch_id: uuid.UUID, epoch_no: int, commit: str,
                  contributions: list[Contribution], draw_count: int, now: datetime
                  ) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO sampling_epochs
              (id, epoch_no, seed_commit, seed_reveal, contributions, state,
               committed_at, revealed_at, draw_count, created_at)
            VALUES (%s, %s, %s, NULL, %s, 'committed', %s, NULL, %s, %s)
            RETURNING {facts.SAMPLING_EPOCH_COLUMNS}
            """,
            (epoch_id, epoch_no, commit,
             Jsonb([item.as_dict() for item in contributions]), now, draw_count, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _mark_revealed(conn: Any, epoch_id: uuid.UUID, *, seed_hex: str, now: datetime
                   ) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE sampling_epochs
               SET seed_reveal = %s, state = 'revealed', revealed_at = %s
             WHERE id = %s AND state = 'committed'
            RETURNING {facts.SAMPLING_EPOCH_COLUMNS}
            """, (seed_hex, now, epoch_id))
        row = cur.fetchone()
    if row is None:                                    # pragma: no cover - FOR UPDATE 后不应发生
        raise Conflict("轮次状态已变化，请重试", reason="conflict")
    return dict(row)


def _insert_draw(conn: Any, *, epoch_id: uuid.UUID, item: Contribution, rank: int,
                 challenge_id: uuid.UUID, now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO sampling_draws
              (id, epoch_id, node_id, model, weight, rank, challenge_id, status, level,
               detail, created_at, resolved_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', NULL,
                    '{{}}'::jsonb, %s, NULL)
            RETURNING {facts.SAMPLING_DRAW_COLUMNS}
            """,
            (uuid7(), epoch_id, item.node_id, item.model, int(item.weight), rank,
             challenge_id, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _insert_event(conn: Any, *, epoch_id: uuid.UUID | None, draw_id: uuid.UUID | None,
                  event: str, detail: dict[str, Any], actor: str, now: datetime
                  ) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO sampling_events (event_id, epoch_id, draw_id, event, detail,
                                         actor, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING {facts.SAMPLING_EVENT_COLUMNS}
            """,
            (uuid7(), epoch_id, draw_id, event, Jsonb(detail), actor, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _detail(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _parse_uuid(value: Any, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise BadRequest(f"{field} 非法", field=field) from exc


# ───────────────────────────────────────────────────────── 1) 开轮次（承诺）
def open_epoch(conn: Any, *, epoch_no: Any, contributions: Any, draw_count: Any,
               now: datetime | None = None, actor: str = facts.SAMPLING_ACTOR_SYSTEM
               ) -> dict[str, Any]:
    """承诺轮次：只写 ``sha256(seed)``，**seed 不落库**，仅在本返回值的 ``seed`` 字段给出。

    调用方必须把 seed 保存在安全位置（S2 测试网：运维内存/密钥库），揭示时回传。
    """
    require_feature()
    moment = now or clock.utcnow()
    if isinstance(epoch_no, bool) or not isinstance(epoch_no, int) or epoch_no < 1:
        raise BadRequest("epoch_no 必须是 ≥1 的整数", field="epoch_no")
    if isinstance(draw_count, bool) or not isinstance(draw_count, int):
        raise BadRequest("draw_count 必须是整数", field="draw_count")
    if not 0 <= draw_count <= facts.SAMPLING_MAX_DRAW_COUNT:
        raise BadRequest(f"draw_count 必须在 0–{facts.SAMPLING_MAX_DRAW_COUNT}",
                         field="draw_count")
    items = normalize_contributions(contributions)
    seed = secrets.token_bytes(facts.SAMPLING_SEED_BYTES)
    epoch_id = uuid7()
    try:
        row = _insert_epoch(conn, epoch_id=epoch_id, epoch_no=epoch_no,
                            commit=seed_commit(seed), contributions=items,
                            draw_count=draw_count, now=moment)
    except pg_errors.UniqueViolation as exc:
        raise Conflict("epoch_no 已存在（轮次唯一递增）", reason="epoch_exists") from exc
    _insert_event(conn, epoch_id=epoch_id, draw_id=None, event="committed",
                  detail=_detail(epoch_no=epoch_no, draw_count=draw_count,
                                 contributions=len(items),
                                 eligible=sum(1 for item in items if item.weight > 0),
                                 seed_commit=row["seed_commit"]),
                  actor=actor, now=moment)
    # seed 只在承诺时返回给调用方保管（库里没有）；响应形状与 reveal/verify 一致
    return {"epoch": epoch_payload(row), "seed": seed.hex()}


# ───────────────────────────────────────────────────────── 2) 揭示 + 抽签
def reveal_epoch(conn: Any, *, epoch_id: Any, seed: Any, now: datetime | None = None,
                 actor: str = facts.SAMPLING_ACTOR_SYSTEM) -> dict[str, Any]:
    """揭示 seed 并执行确定性抽签；重复揭示同 seed 幂等，不同 seed → 409。"""
    require_feature()
    moment = now or clock.utcnow()
    identifier = _parse_uuid(epoch_id, field="id")
    seed_hex = str(seed or "").strip().lower()
    if len(seed_hex) != facts.SAMPLING_SEED_BYTES * 2 or any(
            char not in "0123456789abcdef" for char in seed_hex):
        raise BadRequest("seed 必须是 64 位十六进制（32 字节）", field="seed")

    epoch = _load_epoch(conn, identifier, for_update=True)
    if epoch is None:
        raise NotFound("轮次不存在", reason="not_found")
    if seed_commit(bytes.fromhex(seed_hex)) != str(epoch["seed_commit"]):
        raise Conflict("seed 与承诺不一致（sha256 不匹配）", reason="seed_mismatch")
    if epoch["state"] == "revealed":
        if str(epoch["seed_reveal"]) != seed_hex:
            raise Conflict("轮次已用另一 seed 揭示（承诺不可改）", reason="seed_mismatch")
        return {"epoch": epoch_payload(epoch),
                "draws": list_draws(conn, epoch_id=identifier)["items"],
                "idempotent": True}
    if epoch["state"] == "expired":
        raise Conflict("轮次已过期，不能揭示", reason="epoch_expired")

    items = [Contribution(str(item["node_id"]), str(item["model"]), int(item["weight"]))
             for item in (epoch["contributions"] or [])]
    selected = drawing(seed_hex, int(epoch["epoch_no"]), items, int(epoch["draw_count"]))
    updated = _mark_revealed(conn, identifier, seed_hex=seed_hex, now=moment)
    draws: list[dict[str, Any]] = []
    for entry in selected:
        challenge = attest.issue_challenge(conn, node_id=entry["node_id"],
                                           model=entry["model"], now=moment)
        item = Contribution(entry["node_id"], entry["model"], int(entry["weight"]))
        draw = _insert_draw(conn, epoch_id=identifier, item=item, rank=int(entry["rank"]),
                            challenge_id=uuid.UUID(challenge["challenge_id"]), now=moment)
        _insert_event(conn, epoch_id=identifier, draw_id=uuid.UUID(str(draw["id"])),
                      event="drawn",
                      detail=_detail(rank=entry["rank"], weight=entry["weight"],
                                     challenge_id=challenge["challenge_id"]),
                      actor=actor, now=moment)
        draws.append(draw_payload(draw))
    _insert_event(conn, epoch_id=identifier, draw_id=None, event="revealed",
                  detail=_detail(draw_count=int(updated["draw_count"]),
                                 selected=len(draws),
                                 seed_commit=updated["seed_commit"]),
                  actor=actor, now=moment)
    return {"epoch": epoch_payload(updated), "draws": draws, "idempotent": False}


# ───────────────────────────────────────────────────────── 3) 回填结果
def record_result(conn: Any, *, draw_id: Any, evidence: Mapping[str, Any],
                  now: datetime | None = None,
                  actor: str = facts.SAMPLING_ACTOR_SYSTEM) -> dict[str, Any]:
    """回填一次抽检结果：L3+ → passed；L2/L1/L0 → failed；挑战过期/缺失 → missed。"""
    require_feature()
    moment = now or clock.utcnow()
    identifier = _parse_uuid(draw_id, field="id")
    if not isinstance(evidence, Mapping):
        raise BadRequest("evidence 必须是对象", field="evidence")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.SAMPLING_DRAW_COLUMNS} FROM sampling_draws"
            f" WHERE id = %s FOR UPDATE", (identifier,))
        draw = cur.fetchone()
    if draw is None:
        raise NotFound("抽检记录不存在", reason="not_found")
    if draw["status"] != "pending":
        raise Conflict("抽检结果已确定，不可重复回填", reason="draw_resolved")

    challenge_id = str(draw["challenge_id"]) if draw["challenge_id"] else None
    submitted = str(evidence.get("challenge_id") or "")
    if not challenge_id or submitted != challenge_id:
        raise BadRequest("evidence.challenge_id 必须等于该抽检的挑战", field="challenge_id")
    if str(evidence.get("model") or "") != str(draw["model"]):
        raise BadRequest("evidence.model 必须等于抽检模型", field="model")

    status = "failed"
    level: str | None = None
    reason: str | None = None
    attestation: dict[str, Any] | None = None
    try:
        result = attest.submit_evidence(conn, node_id=str(draw["node_id"]),
                                        payload=dict(evidence), now=moment)
        attestation = result["attestation"]
        level = str(attestation["level"])
        if facts.ATTEST_LEVEL_RANK[level] >= facts.ATTEST_LEVEL_RANK["L3"]:
            status = "passed"
        else:
            status = "failed"
            reason = "tokenizer_mismatch" if level == "L2" else "level_below_l3"
    except Conflict as exc:
        if exc.reason == "challenge_expired":
            status, reason = "missed", "challenge_expired"
        else:
            status, reason = "failed", str(exc.reason or "conflict")
    except NotFound:
        status, reason = "missed", "challenge_missing"

    resolved = _resolve_draw(conn, identifier, status=status, level=level,
                             detail=_detail(level=level, reason=reason,
                                            attestation_id=(attestation or {}).get("id")),
                             now=moment)
    _insert_event(conn, epoch_id=uuid.UUID(str(draw["epoch_id"])),
                  draw_id=identifier, event=status,
                  detail=_detail(level=level, reason=reason),
                  actor=actor, now=moment)
    return {"draw": draw_payload(resolved), "attestation": attestation}


def _resolve_draw(conn: Any, draw_id: uuid.UUID, *, status: str, level: str | None,
                  detail: dict[str, Any], now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE sampling_draws
               SET status = %s, level = %s, detail = %s, resolved_at = %s
             WHERE id = %s AND status = 'pending'
            RETURNING {facts.SAMPLING_DRAW_COLUMNS}
            """, (status, level, Jsonb(detail), now, draw_id))
        row = cur.fetchone()
    if row is None:                                    # pragma: no cover - FOR UPDATE 后不应发生
        raise Conflict("抽检状态已变化，请重试", reason="conflict")
    return dict(row)


# ───────────────────────────────────────────────────────── 4) 过期 → missed
def expire_due(conn: Any, *, now: datetime | None = None,
               actor: str = facts.SAMPLING_ACTOR_SYSTEM) -> dict[str, int]:
    """pending 抽检的挑战已过 TTL → ``missed`` + 事件（只改本模块表）。"""
    require_feature()
    moment = now or clock.utcnow()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE sampling_draws d
               SET status = 'missed', resolved_at = %s,
                   detail = '{{"reason": "challenge_ttl_elapsed"}}'::jsonb
              FROM attestation_challenges c
             WHERE d.challenge_id = c.id
               AND d.status = 'pending'
               AND c.expires_at <= %s
            RETURNING d.*
            """, (moment, moment))
        rows = [dict(row) for row in cur.fetchall()]
    for row in rows:
        _insert_event(conn, epoch_id=uuid.UUID(str(row["epoch_id"])),
                      draw_id=uuid.UUID(str(row["id"])), event="missed",
                      detail=_detail(reason="challenge_ttl_elapsed"),
                      actor=actor, now=moment)
    return {"draws": len(rows)}


# ───────────────────────────────────────────────────────── 5) 升级建议（不建 hold）
def escalate(conn: Any, *, node_id: Any, model: Any, now: datetime | None = None
             ) -> dict[str, Any]:
    """按最近 24h / 7d 的 failed+missed 次数给 I0/I1/I2 **建议**（不建 hold、不改账本）。

    阈值对齐 M17 §6.1：24h 内 1 次 → I0；24h 内 2 次 → I1；7d 内 3 次 → I2。
    """
    moment = now or clock.utcnow()
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
              COUNT(*) FILTER (WHERE resolved_at >= %s) AS c24,
              COUNT(*) FILTER (WHERE resolved_at >= %s) AS c7
              FROM sampling_draws
             WHERE node_id = %s AND model = %s
               AND status IN ('failed', 'missed')
               AND resolved_at IS NOT NULL
            """,
            (moment - facts.SAMPLING_ESCALATION_24H,
             moment - facts.SAMPLING_ESCALATION_7D, node, model_id))
        row = cur.fetchone()
    failures_24h = int(row[0] or 0)
    failures_7d = int(row[1] or 0)
    suggested: str | None = None
    if failures_7d >= facts.SAMPLING_LEVEL_7D_I2:
        suggested = "I2"
    elif failures_24h >= facts.SAMPLING_LEVEL_24H_I1:
        suggested = "I1"
    elif failures_24h >= facts.SAMPLING_LEVEL_24H_I0:
        suggested = "I0"
    return {
        "node_id": node,
        "model": model_id,
        "failures_24h": failures_24h,
        "failures_7d": failures_7d,
        "suggested_level": suggested,
        "basis": ("7d>=3 → I2 / 24h>=2 → I1 / 24h>=1 → I0（M17 §6.1）"
                  if suggested else "未达建议阈值"),
        "note": "只给建议：是否建 hold 由 C14 holds.create_or_escalate 的调用方决定",
    }


# ───────────────────────────────────────────────────────── 6) 查询 / 复算
def list_epochs(conn: Any, *, state: Any = None, limit: Any = None,
                cursor: str | None = None) -> dict[str, Any]:
    state_value = None
    if state:
        state_value = str(state).strip().lower()
        if state_value not in facts.SAMPLING_EPOCH_STATES:
            raise BadRequest("state 必须是 committed / revealed / expired", field="state")
    page_limit = models.page_limit(limit)
    conditions: list[str] = []
    params: list[Any] = []
    if state_value:
        conditions.append("state = %s")
        params.append(state_value)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        conditions.append("(created_at < %s OR (created_at = %s AND id::text < %s))")
        params.extend([moment, moment, identity])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(page_limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.SAMPLING_EPOCH_COLUMNS} FROM sampling_epochs{where}"
            " ORDER BY epoch_no DESC, id DESC LIMIT %s", tuple(params))
        rows = [dict(row) for row in cur.fetchall()]
    has_more = len(rows) > page_limit
    rows = rows[:page_limit]
    next_cursor = None
    if has_more and rows:
        next_cursor = models.encode_cursor(rows[-1]["created_at"], str(rows[-1]["id"]))
    return {"items": [epoch_payload(row) for row in rows], "has_more": has_more,
            "next_cursor": next_cursor}


def list_draws(conn: Any, *, epoch_id: Any = None, node_id: Any = None,
               model: Any = None, status: Any = None, limit: Any = None,
               cursor: str | None = None) -> dict[str, Any]:
    conditions: list[str] = []
    params: list[Any] = []
    if epoch_id:
        conditions.append("epoch_id = %s")
        params.append(_parse_uuid(epoch_id, field="epoch_id"))
    if node_id:
        conditions.append("node_id = %s")
        params.append(models.validate_node_id(node_id))
    if model:
        conditions.append("model = %s")
        params.append(models.validate_model(model))
    if status:
        value = str(status).strip().lower()
        if value not in facts.SAMPLING_DRAW_STATUSES:
            raise BadRequest("status 必须是 pending / passed / failed / missed",
                             field="status")
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
            f"SELECT {facts.SAMPLING_DRAW_COLUMNS} FROM sampling_draws{where}"
            " ORDER BY created_at DESC, id DESC LIMIT %s", tuple(params))
        rows = [dict(row) for row in cur.fetchall()]
    has_more = len(rows) > page_limit
    rows = rows[:page_limit]
    next_cursor = None
    if has_more and rows:
        next_cursor = models.encode_cursor(rows[-1]["created_at"], str(rows[-1]["id"]))
    return {"items": [draw_payload(row) for row in rows], "has_more": has_more,
            "next_cursor": next_cursor}


def get_epoch(conn: Any, epoch_id: Any) -> dict[str, Any] | None:
    """轮次详情（含 draws，按 rank 升序）；不存在返回 None。"""
    identifier = _parse_uuid(epoch_id, field="id")
    row = _load_epoch(conn, identifier)
    if row is None:
        return None
    payload = epoch_payload(row)
    payload["draws"] = list_draws(conn, epoch_id=identifier)["items"]
    return payload


def verify_epoch(conn: Any, epoch_id: Any) -> dict[str, Any]:
    """复算验证：``sha256(seed_reveal)==seed_commit`` 且抽签结果与重算完全一致。"""
    identifier = _parse_uuid(epoch_id, field="id")
    epoch = _load_epoch(conn, identifier)
    if epoch is None:
        raise NotFound("轮次不存在", reason="not_found")
    if epoch["state"] != "revealed" or not epoch.get("seed_reveal"):
        raise Conflict("轮次尚未揭示，无法复算", reason="epoch_not_revealed")
    seed_hex = str(epoch["seed_reveal"])
    commit_ok = seed_commit(bytes.fromhex(seed_hex)) == str(epoch["seed_commit"])
    items = [Contribution(str(item["node_id"]), str(item["model"]), int(item["weight"]))
             for item in (epoch["contributions"] or [])]
    expected = drawing(seed_hex, int(epoch["epoch_no"]), items, int(epoch["draw_count"]))
    actual = [{"node_id": item["node_id"], "model": item["model"], "rank": item["rank"]}
              for item in list_draws(conn, epoch_id=identifier)["items"]]
    actual.sort(key=lambda item: int(item["rank"]))
    consistent = bool(commit_ok and compare_drawings(expected, actual))
    return {
        "epoch_id": str(identifier),
        "consistent": consistent,
        "commit_ok": bool(commit_ok),
        "draw_count": int(epoch["draw_count"]),
        "expected": expected,
        "actual": actual,
    }
