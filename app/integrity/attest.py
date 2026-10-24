# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 §5.1–5.3 / §5.7 模型身份证明服务端核心（C12；**服务端自己验证，不信任客户端**）。

做什么
======

1. **签发挑战**（:func:`issue_challenge`）：从合成 prompt 池取一条 + 随机 nonce，
   用服务端注入的 tokenizer 计数，TTL 5 分钟，落 ``attestation_challenges``；
2. **接收证据**（:func:`submit_evidence`）：校验挑战归属（node/model/upstream）、未过期、
   未消费；**一次性消费**（SQL 条件更新 + DB 触发器双保险），然后由服务端比对
   ``usage_prompt_tokens`` 与签发时的 ``prompt_tokens``：

   ==========================  ==================================================
   usage                       判定（服务端唯一口径）
   ==========================  ==================================================
   缺省 / ≤0                    L2（客户端自称 inference_ok 时）或 L1；事件 evidence_submitted
   |差| ≤ max(1, ceil(1%))     **L3**（tokenizer 匹配），事件 level_up / evidence_submitted
   |差| > 容差                 L2 + ``tokenizer_mismatch`` 事件（**不判作弊**，不暂停）
   result=failed               等级不变（无记录时登记 L0），事件 failed
   ==========================  ==================================================

3. **定级只升不降**：同一 ``(node_id, upstream_id, model)`` 只保留 1 条 active；
   只有更高等级才更新记录与 TTL（L1/L2 24h、L3 7d）；降级/清零属于 C13 风控与复核流程，
   本模块只给证据，不下处罚结论；
4. **查询**：:func:`attestation_level` / :func:`is_attested` / :func:`list_attestations`
   给调度、公告、结算与后台用；:func:`expire_due` 负责 TTL 翻转（只改本表 + 事件）。

不变量
======

* **证据不落正文**：只存 prompt_tokens / usage / diff / tolerance / response_hash（64 hex）/
  latency_ms / error_class；合成 prompt 本身只留在 ``attestation_challenges``（探针文本，
  不含用户数据，DB 长度受限 + detail 键黑名单兜底）；
* **不碰账本**：本模块没有任何 ledger / account_balances / loss_pool 写路径；
* **开关默认关闭**：``supply.attestation.enabled`` 默认 False；S2 测试网用 ``DJB_ATTEST=1``
  显式激活（代码默认仍关）；关闭时写接口 503 / 50001，读接口只读。
"""
from __future__ import annotations

import math
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import clock, facts, features, models, providers
from .errors import (BadRequest, Conflict, FeatureUnavailable, IntegrityError, NotFound,
                     TokenizerUnavailable)
from .ids import uuid7

__all__ = [
    "EvidenceInput", "parse_evidence", "feature_enabled", "require_feature",
    "tolerance_for", "compare_tokens", "issue_challenge", "submit_evidence",
    "attestation_level", "is_attested", "list_attestations", "get_attestation",
    "expire_due", "attestation_payload", "event_payload",
    "normalize_attest_level",
]


# ───────────────────────────────────────────────────────── 开关（fail-closed）
def feature_enabled() -> bool:
    """只读开关：``supply.attestation.enabled``（默认 False；S2 测试网 ``DJB_ATTEST=1``）。"""
    return features.enabled(facts.ATTEST_FLAG) or os.environ.get(facts.ATTEST_ENV) == "1"


def require_feature() -> None:
    if not feature_enabled():
        raise FeatureUnavailable(
            "模型身份证明未启用（supply.attestation.enabled=false，默认关闭；"
            "S2 测试网用 DJB_ATTEST=1 激活）：写接口 fail-closed；已存证明只读",
            reason="feature_disabled")


# ───────────────────────────────────────────────────────── 纯函数
def tolerance_for(prompt_tokens: int) -> int:
    """§5.1 容差：``max(1, ceil(prompt_tokens × 1%))``（整数化，边界可复算）。"""
    tokens = int(prompt_tokens)
    if tokens <= 0:
        raise BadRequest("prompt_tokens 必须为正整数", field="prompt_tokens")
    return max(facts.TOKENIZER_MIN_TOLERANCE,
               int(math.ceil(tokens * facts.TOKENIZER_TOLERANCE_PCT / 100.0)))


def compare_tokens(expected: int, usage: int | None) -> dict[str, Any]:
    """服务端比对（唯一口径）：返回 ``{match, expected, usage, diff, tolerance}``。

    ``usage`` 缺省 / ≤0 → ``match=False, diff=None``（证据不足，调用方降到 L2）。
    """
    allowed = tolerance_for(expected)
    if usage is None or int(usage) <= 0:
        return {"match": False, "insufficient": True, "expected": int(expected),
                "usage": None, "diff": None, "tolerance": allowed}
    actual = int(usage)
    diff = abs(actual - int(expected))
    return {"match": diff <= allowed, "insufficient": False, "expected": int(expected),
            "usage": actual, "diff": diff, "tolerance": allowed}


@dataclass(frozen=True)
class EvidenceInput:
    """客户端上报形状（Lead 1.2.11 定稿；等级由服务端判，不采信 result）。"""

    challenge_id: uuid.UUID
    model: str
    result: str
    upstream_id: str | None = None
    usage_prompt_tokens: int | None = None
    response_hash: str | None = None
    latency_ms: int | None = None
    error_class: str | None = None


def _parse_uuid(value: Any, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise BadRequest(f"{field} 非法", field=field) from exc


def parse_evidence(body: Mapping[str, Any]) -> EvidenceInput:
    if not isinstance(body, Mapping):
        raise BadRequest("请求体必须是 JSON 对象", field="body")
    challenge_id = _parse_uuid(body.get("challenge_id"), field="challenge_id")
    model = models.validate_model(body.get("model"))
    result = str(body.get("result") or "").strip().lower()
    if result not in facts.EVIDENCE_RESULTS:
        raise BadRequest("result 必须是 " + " / ".join(facts.EVIDENCE_RESULTS), field="result")
    upstream = models.normalize_text(body.get("upstream_id"), field="upstream_id",
                                     max_len=128, required=False)
    usage = body.get("usage_prompt_tokens")
    if usage is not None:
        if isinstance(usage, bool) or not isinstance(usage, int):
            raise BadRequest("usage_prompt_tokens 必须是整数", field="usage_prompt_tokens")
        if usage < 0:
            raise BadRequest("usage_prompt_tokens 不能为负", field="usage_prompt_tokens")
        usage = int(usage)
    response_hash = models.normalize_text(body.get("response_hash"), field="response_hash",
                                          max_len=facts.RESPONSE_HASH_MAX_LEN[1],
                                          required=False)
    if response_hash is not None:
        text = response_hash
        if text.startswith("sha256:"):
            text = text.split(":", 1)[1]
        if len(text) != 64 or any(char not in "0123456789abcdef" for char in text.lower()):
            raise BadRequest("response_hash 必须是 sha256 十六进制（64 位）",
                             field="response_hash")
        response_hash = text.lower()
    latency = body.get("latency_ms")
    if latency is not None:
        if isinstance(latency, bool) or not isinstance(latency, int):
            raise BadRequest("latency_ms 必须是整数", field="latency_ms")
        if latency < 0 or latency > facts.LATENCY_MAX_MS:
            raise BadRequest("latency_ms 超出范围", field="latency_ms")
        latency = int(latency)
    error_class = models.normalize_text(body.get("error_class"), field="error_class",
                                        max_len=facts.ERROR_CLASS_MAX_LEN, required=False)
    return EvidenceInput(challenge_id=challenge_id, model=model, result=result,
                         upstream_id=upstream, usage_prompt_tokens=usage,
                         response_hash=response_hash, latency_ms=latency,
                         error_class=error_class)


# ───────────────────────────────────────────────────────── 载荷
def attestation_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """证明记录对外形状（Lead 1.2.11 定稿字段，一个不多一个不少）。"""
    return {
        "id": str(row["id"]),
        "node_id": row["node_id"],
        "upstream_id": row.get("upstream_id"),
        "model": row["model"],
        "level": row["level"],
        "state": row["state"],
        "source": row["source"],
        "tokenizer_version": row.get("tokenizer_version"),
        "evidence_ref": row["evidence_ref"],
        "verified_at": clock.iso(row.get("verified_at")),
        "expires_at": clock.iso(row.get("expires_at")),
    }


def event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"event_id": str(row["event_id"]), "event": row["event"],
            "level": row.get("level"), "created_at": clock.iso(row["created_at"])}


# ───────────────────────────────────────────────────────── SQL（本模块私有）
ACTIVE_PREDICATE = "state = 'active' AND (level = 'L0' OR expires_at > %s)"


def _load_challenge(conn: Any, challenge_id: uuid.UUID, *, for_update: bool = False
                    ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.CHALLENGE_COLUMNS} FROM attestation_challenges"
            f" WHERE id = %s{suffix}", (challenge_id,))
        return cur.fetchone()


def _insert_challenge(conn: Any, *, challenge_id: uuid.UUID, node_id: str,
                      upstream_id: str | None, model: str, prompt: str,
                      prompt_tokens: int, nonce: str, created_at: datetime,
                      expires_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO attestation_challenges
              (id, node_id, upstream_id, model, prompt, prompt_tokens, nonce, state,
               expires_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'issued', %s, %s)
            RETURNING {facts.CHALLENGE_COLUMNS}
            """,
            (challenge_id, node_id, upstream_id, model, prompt, prompt_tokens, nonce,
             expires_at, created_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _consume_challenge(conn: Any, challenge_id: uuid.UUID, now: datetime
                       ) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE attestation_challenges
               SET state = 'consumed', consumed_at = %s
             WHERE id = %s AND state = 'issued'
            RETURNING {facts.CHALLENGE_COLUMNS}
            """, (now, challenge_id))
        row = cur.fetchone()
    return dict(row) if row else None


def _expire_challenge(conn: Any, challenge_id: uuid.UUID, now: datetime) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE attestation_challenges SET state = 'expired'"
            " WHERE id = %s AND state = 'issued'", (challenge_id,))
        return cur.rowcount > 0


def _find_active_attestation(conn: Any, *, node_id: str, upstream_id: str | None,
                             model: str, now: datetime, for_update: bool = False
                             ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.ATTESTATION_COLUMNS} FROM model_attestations"
            f" WHERE node_id = %s AND COALESCE(upstream_id, '') = COALESCE(%s::text, '')"
            f" AND model = %s AND {ACTIVE_PREDICATE}{suffix}",
            (node_id, upstream_id, model, now))
        return cur.fetchone()


def _insert_attestation(conn: Any, *, attestation_id: uuid.UUID, node_id: str,
                        upstream_id: str | None, model: str, level: str, source: str,
                        tokenizer_version: str | None, evidence_ref: str,
                        verified_at: datetime | None, expires_at: datetime | None,
                        created_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO model_attestations
              (id, node_id, upstream_id, model, level, state, source, tokenizer_version,
               evidence_ref, verified_at, expires_at, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, 'active', %s, %s, %s, %s, %s, %s, %s)
            RETURNING {facts.ATTESTATION_COLUMNS}
            """,
            (attestation_id, node_id, upstream_id, model, level, source,
             tokenizer_version, evidence_ref, verified_at, expires_at, created_at,
             created_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def _upgrade_attestation(conn: Any, attestation_id: uuid.UUID, *, level: str,
                         tokenizer_version: str | None, evidence_ref: str,
                         verified_at: datetime, expires_at: datetime,
                         updated_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE model_attestations
               SET level = %s, tokenizer_version = %s, evidence_ref = %s,
                   verified_at = %s, expires_at = %s, updated_at = %s
             WHERE id = %s AND state = 'active'
            RETURNING {facts.ATTESTATION_COLUMNS}
            """,
            (level, tokenizer_version, evidence_ref, verified_at, expires_at,
             updated_at, attestation_id))
        row = cur.fetchone()
    if row is None:                                     # pragma: no cover - FOR UPDATE 串行化后不应发生
        raise Conflict("证明记录状态已变化，请重试", reason="conflict")
    return dict(row)


def _insert_event(conn: Any, *, attestation_id: uuid.UUID | None,
                  challenge_id: uuid.UUID | None, node_id: str, model: str, event: str,
                  level: str | None, detail: dict[str, Any], actor: str,
                  created_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO attestation_events
              (event_id, attestation_id, challenge_id, node_id, model, event, level,
               detail, actor, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {facts.ATTEST_EVENT_COLUMNS}
            """,
            (uuid7(), attestation_id, challenge_id, node_id, model, event, level,
             Jsonb(detail), actor, created_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def normalize_attest_level(value: Any) -> str:
    """证明等级校验（L0–L5）；与冻结段 I0–I4 是两套枚举，不复用 models.normalize_level。"""
    text = str(value or "").strip().upper()
    if text not in facts.ATTEST_LEVELS:
        raise BadRequest("level 必须是 L0–L5 之一", field="level")
    return text


def _detail(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _ttl_for(level: str) -> Any:
    return facts.ATTEST_LEVEL_TTL[level]


# ───────────────────────────────────────────────────────── 签发挑战
def _compose_prompt() -> tuple[str, str]:
    """合成 prompt + 一次性 nonce（非用户数据；nonce 保证不可预缓存）。"""
    nonce = secrets.token_hex(facts.CHALLENGE_NONCE_BYTES)
    base = secrets.choice(facts.SYNTHETIC_PROMPTS)
    return base + "\n\nchallenge nonce: " + nonce, nonce


def issue_challenge(conn: Any, *, node_id: Any, upstream_id: Any = None, model: Any,
                    now: datetime | None = None) -> dict[str, Any]:
    """签发 L1–L3 探针挑战（TTL 5 min；prompt 为合成探针，不含用户正文）。"""
    require_feature()
    moment = now or clock.utcnow()
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    upstream = models.normalize_text(upstream_id, field="upstream_id", max_len=128,
                                     required=False)
    prompt, nonce = _compose_prompt()
    prompt_tokens = providers.count_prompt_tokens(prompt, model_id)   # 未接线 → 503
    challenge_id = uuid7()
    expires_at = moment + facts.CHALLENGE_TTL
    row = _insert_challenge(conn, challenge_id=challenge_id, node_id=node,
                            upstream_id=upstream, model=model_id, prompt=prompt,
                            prompt_tokens=prompt_tokens, nonce=nonce, created_at=moment,
                            expires_at=expires_at)
    _insert_event(conn, attestation_id=None, challenge_id=challenge_id, node_id=node,
                  model=model_id, event="challenge_issued", level=None,
                  detail=_detail(prompt_tokens=prompt_tokens, expires_at=clock.iso(expires_at),
                                 upstream_id=upstream),
                  actor=f"node:{node}", created_at=moment)
    return {
        "challenge_id": str(row["id"]),
        "model": model_id,
        "upstream_id": upstream,
        "prompt": prompt,
        "nonce": nonce,
        "expires_at": clock.iso(expires_at),
    }


# ───────────────────────────────────────────────────────── 接收证据 / 定级
def submit_evidence(conn: Any, *, node_id: Any, payload: EvidenceInput | Mapping[str, Any],
                    now: datetime | None = None) -> dict[str, Any]:
    """消费一次挑战并定级（服务端自己比对；**不信任客户端 result**）。

    返回 ``{"attestation": {...}, "event": {...}}``（Lead 1.2.11 定稿形状）。
    """
    require_feature()
    moment = now or clock.utcnow()
    node = models.validate_node_id(node_id)
    evidence = payload if isinstance(payload, EvidenceInput) else parse_evidence(payload)
    model_id = evidence.model

    challenge = _load_challenge(conn, evidence.challenge_id, for_update=True)
    if challenge is None or str(challenge["node_id"]) != node:
        raise NotFound("挑战不存在", reason="not_found")
    if str(challenge["model"]) != model_id:
        raise Conflict("挑战与 model 不匹配", reason="challenge_model_mismatch")
    if evidence.upstream_id and challenge.get("upstream_id") \
            and evidence.upstream_id != challenge["upstream_id"]:
        raise Conflict("挑战与 upstream 不匹配", reason="challenge_upstream_mismatch")
    if challenge["state"] == "consumed":
        raise Conflict("挑战已消费（重放拒绝）", reason="challenge_consumed")
    if challenge["state"] == "expired" or challenge["expires_at"] <= moment:
        _expire_challenge(conn, evidence.challenge_id, moment)
        raise Conflict("挑战已过期", reason="challenge_expired")

    consumed = _consume_challenge(conn, evidence.challenge_id, moment)
    if consumed is None:                                # 并发下的第二发：重放
        raise Conflict("挑战已消费（重放拒绝）", reason="challenge_consumed")

    expected = int(challenge["prompt_tokens"])
    usage = evidence.usage_prompt_tokens
    check = compare_tokens(expected, usage)

    target: str | None
    event: str
    reason: str | None = None
    if evidence.result == "failed":
        target = None
        event = "failed"
        reason = evidence.error_class or "probe_failed"
    elif check["insufficient"]:
        target = "L2" if evidence.result in ("inference_ok", "tokenizer_match") else "L1"
        event = "evidence_submitted"
        reason = "usage_missing"
    elif check["match"]:
        target = "L3"
        event = "evidence_submitted"                    # 若无等级提升，事件名保持中立
    else:
        target = "L2"
        event = "tokenizer_mismatch"                    # 只记事件，不判作弊、不暂停
        reason = "tokenizer_mismatch"

    record = _find_active_attestation(conn, node_id=node, upstream_id=evidence.upstream_id,
                                      model=model_id, now=moment, for_update=True)
    tokenizer_version = providers.tokenizer_version()
    evidence_ref = "challenge:" + str(evidence.challenge_id)
    action = "unchanged"
    current_rank = facts.ATTEST_LEVEL_RANK[str(record["level"])] if record else -1

    if target is None:
        if record is None:                              # 失败也登记 L0（declared），不接单
            record = _insert_attestation(
                conn, attestation_id=uuid7(), node_id=node,
                upstream_id=evidence.upstream_id, model=model_id, level="L0",
                source="server_challenge", tokenizer_version=None,
                evidence_ref=evidence_ref, verified_at=None, expires_at=None,
                created_at=moment)
            action = "created"
    elif facts.ATTEST_LEVEL_RANK[target] > current_rank:   # 只升不降
        verified_at = moment
        expires_at = moment + _ttl_for(target)
        if record is None:
            record = _insert_attestation(
                conn, attestation_id=uuid7(), node_id=node,
                upstream_id=evidence.upstream_id, model=model_id, level=target,
                source="server_challenge", tokenizer_version=tokenizer_version,
                evidence_ref=evidence_ref, verified_at=verified_at,
                expires_at=expires_at, created_at=moment)
            action = "created"
        else:
            record = _upgrade_attestation(
                conn, uuid.UUID(str(record["id"])), level=target,
                tokenizer_version=tokenizer_version, evidence_ref=evidence_ref,
                verified_at=verified_at, expires_at=expires_at, updated_at=moment)
            action = "upgraded"
        if event == "evidence_submitted":
            event = "level_up"

    detail = _detail(
        result=evidence.result, prompt_tokens=expected, usage_prompt_tokens=usage,
        diff=check["diff"], tolerance=check["tolerance"], insufficient=check["insufficient"],
        response_hash=evidence.response_hash, latency_ms=evidence.latency_ms,
        error_class=evidence.error_class, reason=reason, action=action,
        tokenizer_version=tokenizer_version)
    event_row = _insert_event(
        conn, attestation_id=uuid.UUID(str(record["id"])) if record else None,
        challenge_id=evidence.challenge_id, node_id=node, model=model_id, event=event,
        level=str(record["level"]) if record else None, detail=detail,
        actor=f"node:{node}", created_at=moment)
    assert record is not None
    return {"attestation": attestation_payload(record),
            "event": event_payload(event_row)}


# ───────────────────────────────────────────────────────── 查询
def attestation_level(conn: Any, node_id: Any, model: Any, *, upstream_id: Any = None,
                      now: datetime | None = None) -> str | None:
    """当前生效等级；无记录 / 已过期 → ``None``（调用方按 L0 处理）。"""
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    upstream = models.normalize_text(upstream_id, field="upstream_id", max_len=128,
                                     required=False)
    row = _find_active_attestation(conn, node_id=node, upstream_id=upstream,
                                   model=model_id, now=now or clock.utcnow())
    return str(row["level"]) if row else None


def is_attested(conn: Any, node_id: Any, model: Any, *, upstream_id: Any = None,
                min_level: str = facts.ATTEST_SERVICE_MIN_LEVEL,
                now: datetime | None = None) -> bool:
    """调度 / 公告 / 结算门控：等级 ≥ ``min_level``（默认 L3）且未过期。"""
    level = attestation_level(conn, node_id, model, upstream_id=upstream_id, now=now)
    if level is None:
        return False
    return facts.ATTEST_LEVEL_RANK[level] >= facts.ATTEST_LEVEL_RANK[
        normalize_attest_level(min_level)]


def get_attestation(conn: Any, attestation_id: Any, *, now: datetime | None = None
                    ) -> dict[str, Any] | None:
    identifier = _parse_uuid(attestation_id, field="id")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {facts.ATTESTATION_COLUMNS} FROM model_attestations"
                    " WHERE id = %s", (identifier,))
        row = cur.fetchone()
    if row is None:
        return None
    payload = attestation_payload(row)
    payload["fresh"] = str(row["state"]) == "active" and (
        row["level"] == "L0" or row["expires_at"] > (now or clock.utcnow()))
    return payload


def list_attestations(conn: Any, *, node_id: Any = None, model: Any = None,
                      level: Any = None, limit: Any = None, cursor: str | None = None,
                      now: datetime | None = None) -> dict[str, Any]:
    """管理面列表（node / model / level 过滤 + 游标分页）。"""
    node = models.normalize_text(node_id, field="node_id", max_len=128, required=False)
    model_id = models.normalize_text(model, field="model", max_len=128, required=False)
    level_value = normalize_attest_level(level) if level else None
    page_limit = models.page_limit(limit)
    moment = now or clock.utcnow()
    if feature_enabled():
        _expire_attestations(conn, moment)               # 读前翻转，口径一致；关开关时纯只读

    conditions: list[str] = []
    params: list[Any] = []
    if node:
        conditions.append("node_id = %s")
        params.append(node)
    if model_id:
        conditions.append("model = %s")
        params.append(model_id)
    if level_value:
        conditions.append("level = %s")
        params.append(level_value)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment_cursor, identity = parsed
        conditions.append("(created_at < %s OR (created_at = %s AND id::text < %s))")
        params.extend([moment_cursor, moment_cursor, identity])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(page_limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.ATTESTATION_COLUMNS} FROM model_attestations{where}"
            " ORDER BY created_at DESC, id DESC LIMIT %s", tuple(params))
        rows = [dict(row) for row in cur.fetchall()]
    has_more = len(rows) > page_limit
    rows = rows[:page_limit]
    next_cursor = None
    if has_more and rows:
        next_cursor = models.encode_cursor(rows[-1]["created_at"], str(rows[-1]["id"]))
    return {"items": [attestation_payload(row) for row in rows],
            "has_more": has_more, "next_cursor": next_cursor}


# ───────────────────────────────────────────────────────── TTL 翻转
def _expire_attestations(conn: Any, now: datetime) -> int:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE model_attestations
               SET state = 'expired', updated_at = %s
             WHERE state = 'active' AND level <> 'L0' AND expires_at <= %s
            RETURNING {facts.ATTESTATION_COLUMNS}
            """, (now, now))
        rows = [dict(row) for row in cur.fetchall()]
    for row in rows:
        _insert_event(conn, attestation_id=uuid.UUID(str(row["id"])), challenge_id=None,
                      node_id=str(row["node_id"]), model=str(row["model"]),
                      event="expired", level=str(row["level"]),
                      detail=_detail(reason="ttl_elapsed"), actor="system:ttl",
                      created_at=now)
    return len(rows)


def _expire_challenges(conn: Any, now: datetime) -> int:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE attestation_challenges
               SET state = 'expired'
             WHERE state = 'issued' AND expires_at <= %s
            RETURNING {facts.CHALLENGE_COLUMNS}
            """, (now,))
        rows = [dict(row) for row in cur.fetchall()]
    for row in rows:
        _insert_event(conn, attestation_id=None, challenge_id=uuid.UUID(str(row["id"])),
                      node_id=str(row["node_id"]), model=str(row["model"]),
                      event="expired", level=None,
                      detail=_detail(reason="challenge_ttl_elapsed", challenge=True),
                      actor="system:ttl", created_at=now)
    return len(rows)


def expire_due(conn: Any, *, now: datetime | None = None) -> dict[str, int]:
    """TTL 翻转（证明 + 挑战）；只改本模块两张表并追加事件，不碰账本。"""
    require_feature()
    moment = now or clock.utcnow()
    return {"attestations": _expire_attestations(conn, moment),
            "challenges": _expire_challenges(conn, moment)}
