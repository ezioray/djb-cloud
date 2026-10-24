# SPDX-License-Identifier: AGPL-3.0-or-later
"""上游申报与本地体检回执（M02 §6.3 / §3 NodeUpstream / INV-02 / INV-04 / H1）。

铁律：

* **凭据永不上行**（H1）：只登记 ``credential_handle``（本地句柄），不解析、不明文回显；
  疑似凭据字段由 ``security.scan_credentials`` 在路由层拦掉（400 + 只记字段名）。
* **服务端不探测**：``POST /node/upstream/probe`` 只收**本地结论**（reachable / latency /
  粗粒度 error_class / 每模型 ok），不收上游响应正文。
* 状态机（M02 §3）：``declared → probing → verified | rejected``；
  重复体检允许改变结论（上游会坏也会好），每次变化都写 ``node_events`` 并发
  ``node.upstream.changed``；``probing`` 是本地探测期间的瞬态，由「首个体检回执」隐式经过。
* 上限（§8.2）：单节点 16 个上游、单上游 200 个模型、端点不得带 userinfo。
"""
from __future__ import annotations

import dataclasses
import logging
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from psycopg.types.json import Jsonb

from . import clock, events, facts, models, state as state_machine
from .errors import InvalidArgument, UpstreamNotFound

log = logging.getLogger("djb.supply.upstream")

_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_ALLOWED_SCHEMES = ("http", "https")
_ERROR_CLASS_MAX = 64

PROBE_HINT = "probe_locally_then_report:/api/v1/node/upstream/probe"

#: 上游状态迁移（M02 §3 的声明式状态机 + 允许重复体检改变结论）
UPSTREAM_TRANSITIONS: dict[str, frozenset[str]] = {
    "declared": frozenset({"probing", "verified", "rejected"}),
    "probing": frozenset({"verified", "rejected"}),
    "verified": frozenset({"probing", "rejected"}),
    "rejected": frozenset({"probing", "verified"}),
}


@dataclasses.dataclass(frozen=True)
class Upstream:
    id: uuid.UUID
    node_id: str
    access_type: str
    base_url: str
    models: tuple[str, ...]
    protocol: str | None
    credential_handle: str | None
    state: str
    verified_at: datetime | None
    rejected_reason_code: str | None
    created_at: datetime
    updated_at: datetime


def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else clock.utcnow()


def _row(row: Mapping[str, Any]) -> Upstream:
    return Upstream(id=row["id"], node_id=row["node_id"], access_type=row["access_type"],
                    base_url=row["base_url"],
                    models=tuple(str(item) for item in (row["models"] or [])),
                    protocol=row["protocol"], credential_handle=row["credential_handle"],
                    state=row["state"], verified_at=row["verified_at"],
                    rejected_reason_code=row["rejected_reason_code"],
                    created_at=row["created_at"], updated_at=row["updated_at"])


def validate_base_url(value: Any) -> str:
    """端点校验：合法绝对 URL、只允许 http/https、**禁 userinfo**（M02 §6.3）。"""
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgument("base_url 必填", field="base_url")
    text = value.strip()
    if len(text) > 2048:
        raise InvalidArgument("base_url 超长（≤2048）", field="base_url")
    if not _URL_RE.match(text):
        raise InvalidArgument("base_url 必须是绝对 URL", field="base_url")
    parts = urlsplit(text)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise InvalidArgument("base_url 只允许 http/https", field="base_url")
    if not parts.hostname:
        raise InvalidArgument("base_url 缺少主机", field="base_url")
    if parts.username or parts.password or "@" in parts.netloc:
        raise InvalidArgument("base_url 不得带用户名 / 口令（H1）", field="base_url")
    return text


def validate_models(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise InvalidArgument("models 必须是非空数组", field="models")
    if len(values) > facts.MAX_MODELS_PER_UPSTREAM:
        raise InvalidArgument(f"models 最多 {facts.MAX_MODELS_PER_UPSTREAM} 个", field="models")
    result: list[str] = []
    for index, item in enumerate(values):
        if not isinstance(item, str) or not item.strip():
            raise InvalidArgument(f"models[{index}] 必须是非空字符串", field=f"models[{index}]")
        text = item.strip()
        if len(text) > 128:
            raise InvalidArgument(f"models[{index}] 超长（≤128）", field=f"models[{index}]")
        result.append(text)
    return tuple(dict.fromkeys(result))


def _count(c, node_id: str) -> int:
    with c.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM node_upstreams WHERE node_id = %s", (node_id,))
        row = models._one(cur)
    return int(row["n"]) if row else 0


def _load(c, *, upstream_id: uuid.UUID | None = None, node_id: str | None = None,
          access_type: str | None = None, base_url: str | None = None,
          for_update: bool = False) -> Upstream | None:
    sql = ("SELECT id, node_id, access_type, base_url, models, protocol, credential_handle, "
           "state, verified_at, rejected_reason_code, created_at, updated_at FROM node_upstreams")
    params: tuple[Any, ...]
    if upstream_id is not None:
        sql += " WHERE id = %s"
        params = (upstream_id,)
    else:
        sql += " WHERE node_id = %s AND access_type = %s AND base_url = %s"
        params = (node_id, access_type, base_url)
    with c.cursor() as cur:
        cur.execute(sql + (" FOR UPDATE" if for_update else ""), params)
        row = models._one(cur)
    return _row(row) if row else None


def get_upstream(c, upstream_id: uuid.UUID, *, node_id: str, for_update: bool = False) -> Upstream:
    upstream = _load(c, upstream_id=upstream_id, for_update=for_update)
    if upstream is None or upstream.node_id != node_id:
        raise UpstreamNotFound("上游不存在", upstream_id=str(upstream_id))
    return upstream


def list_upstreams(c, node_id: str) -> list[Upstream]:
    with c.cursor() as cur:
        cur.execute(
            """SELECT id, node_id, access_type, base_url, models, protocol, credential_handle,
                      state, verified_at, rejected_reason_code, created_at, updated_at
                 FROM node_upstreams WHERE node_id = %s ORDER BY created_at, id""", (node_id,))
        return [_row(row) for row in models._rows(cur)]


def declare(c, *, node, access_type: Any, base_url: Any, models_list: Any,
            upstream_protocol: Any = None, credential_handle: Any = None,
            now: datetime | None = None, trace_id: str = "") -> tuple[Upstream, bool]:
    """申报 A1/A2/B 端点与模型（幂等：``(node_id, access_type, base_url)`` 命中即更新）。"""
    moment = _now(now)
    state_machine.require_active(node.state, action="declare_upstream")     # INV-02 → 40305
    if access_type not in facts.ACCESS_TYPES:
        raise InvalidArgument(f"access_type 必须是 {'/'.join(facts.ACCESS_TYPES)} 之一",
                              field="access_type")
    url = validate_base_url(base_url)
    declared_models = validate_models(models_list)
    upstream_protocol_text = None
    if upstream_protocol is not None:
        if not isinstance(upstream_protocol, str) or len(upstream_protocol.strip()) > 64:
            raise InvalidArgument("protocol 必须是 ≤64 字符的字符串", field="protocol")
        upstream_protocol_text = upstream_protocol.strip() or None
    handle = None
    if credential_handle is not None:
        if not isinstance(credential_handle, str) or not credential_handle.strip():
            raise InvalidArgument("credential_handle 必须是非空字符串", field="credential_handle")
        handle = credential_handle.strip()
        if len(handle) > 200:
            raise InvalidArgument("credential_handle 超长（≤200）", field="credential_handle")

    existing = _load(c, node_id=node.id, access_type=access_type, base_url=url, for_update=True)
    if existing is not None:
        with c.cursor() as cur:
            cur.execute(
                """UPDATE node_upstreams
                      SET models = %s, protocol = %s, credential_handle = %s, updated_at = %s
                    WHERE id = %s""",
                (Jsonb(list(declared_models)), upstream_protocol_text,
                 handle if handle is not None else existing.credential_handle, moment,
                 existing.id))
        upstream = _load(c, upstream_id=existing.id)
        return upstream, False

    if _count(c, node.id) >= facts.MAX_UPSTREAMS_PER_NODE:
        raise InvalidArgument(
            f"单节点最多 {facts.MAX_UPSTREAMS_PER_NODE} 个上游", field="access_type")

    identifier = models.uuid7(int(moment.timestamp() * 1_000_000))
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO node_upstreams
                   (id, node_id, access_type, base_url, models, protocol, credential_handle,
                    state, created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'declared', %s, %s)""",
            (identifier, node.id, access_type, url, Jsonb(list(declared_models)),
             upstream_protocol_text, handle, moment, moment))
    # node_events 的 from_state/to_state 只承载**节点生命周期**四态；上游状态放 payload
    _history(c, node_id=node.id, kind="upstream_declared", from_state=None, to_state=None,
             reason_code="declared", actor="self",
             payload={"upstream_id": str(identifier), "access_type": access_type,
                      "upstream_state": "declared"}, now=moment)
    models.emit_upstream_changed(c, node_id=node.id, upstream_type=access_type,
                                 state="declared", trace_id=trace_id, moment=moment,
                                 causation_id=identifier)
    log.info("supply.upstream.declared", extra={"event": "node.upstream.declared",
                                                "node_id": node.id, "upstream_id": str(identifier),
                                                "trace_id": trace_id})
    return _load(c, upstream_id=identifier), True


def _history(c, *, node_id: str, kind: str, from_state: str | None, to_state: str | None,
             reason_code: str | None, actor: str, payload: Mapping[str, Any],
             now: datetime) -> uuid.UUID:
    return models.append_node_event(c, node_id=node_id, kind=kind, from_state=from_state,
                                    to_state=to_state, reason_code=reason_code, actor=actor,
                                    payload=payload, now=now)


def _probe_verdict(reachable: Any, model_checks: Any) -> tuple[str, str | None]:
    """本地回执 → (目标状态, 拒绝原因码)。"""
    if not isinstance(reachable, bool):
        raise InvalidArgument("reachable 必须是布尔值", field="reachable")
    checks: list[dict[str, Any]] = []
    if model_checks is not None:
        if not isinstance(model_checks, (list, tuple)):
            raise InvalidArgument("model_checks 必须是数组", field="model_checks")
        if len(model_checks) > facts.MAX_MODELS_PER_UPSTREAM:
            raise InvalidArgument(f"model_checks 最多 {facts.MAX_MODELS_PER_UPSTREAM} 项",
                                  field="model_checks")
        for index, item in enumerate(model_checks):
            if not isinstance(item, Mapping):
                raise InvalidArgument(f"model_checks[{index}] 必须是对象",
                                      field=f"model_checks[{index}]")
            model = item.get("model")
            ok = item.get("ok")
            if not isinstance(model, str) or not model.strip():
                raise InvalidArgument(f"model_checks[{index}].model 必填",
                                      field=f"model_checks[{index}].model")
            if not isinstance(ok, bool):
                raise InvalidArgument(f"model_checks[{index}].ok 必须是布尔值",
                                      field=f"model_checks[{index}].ok")
            error_class = item.get("error_class")
            if error_class is not None and (not isinstance(error_class, str)
                                            or len(error_class) > _ERROR_CLASS_MAX):
                raise InvalidArgument(f"model_checks[{index}].error_class 不合法",
                                      field=f"model_checks[{index}].error_class")
            checks.append({"model": model.strip(), "ok": ok, "error_class": error_class})
    if not reachable:
        return "rejected", "unreachable"
    failing = next((item for item in checks if not item["ok"]), None)
    if failing is not None:
        return "rejected", (failing.get("error_class") or "model_check_failed")
    return "verified", None


def report_probe(c, *, node, upstream_id: Any, reachable: Any, latency_ms: Any = None,
                 error_class: Any = None, model_checks: Any = None,
                 checked_at: Any = None, now: datetime | None = None,
                 trace_id: str = "") -> Upstream:
    """上报**本地**体检结论（服务端不探测；只收结论与耗时）。"""
    moment = _now(now)
    state_machine.require_active(node.state, action="report_probe")          # INV-02 → 40305
    try:
        identifier = upstream_id if isinstance(upstream_id, uuid.UUID) else uuid.UUID(str(upstream_id))
    except (ValueError, TypeError) as exc:
        raise InvalidArgument("upstream_id 必须是 UUID", field="upstream_id") from exc

    if latency_ms is not None:
        if isinstance(latency_ms, bool) or not isinstance(latency_ms, (int, float)) \
                or not math.isfinite(float(latency_ms)) or float(latency_ms) < 0:
            raise InvalidArgument("latency_ms 必须是非负数字", field="latency_ms")
    if error_class is not None and (not isinstance(error_class, str)
                                    or len(error_class) > _ERROR_CLASS_MAX):
        raise InvalidArgument("error_class 不合法", field="error_class")
    if checked_at is not None:
        if not isinstance(checked_at, str) or not checked_at.strip():
            raise InvalidArgument("checked_at 必须是 RFC 3339 字符串", field="checked_at")

    target, reason = _probe_verdict(reachable, model_checks)
    upstream = get_upstream(c, identifier, node_id=node.id, for_update=True)
    if target not in UPSTREAM_TRANSITIONS.get(upstream.state, frozenset()):
        raise InvalidArgument(f"上游状态 {upstream.state} 不允许再体检", field="upstream_id")

    verified_at = moment if target == "verified" else None
    with c.cursor() as cur:
        cur.execute(
            """UPDATE node_upstreams
                  SET state = %s, verified_at = %s, rejected_reason_code = %s, updated_at = %s
                WHERE id = %s""",
            (target, verified_at, reason, moment, upstream.id))
    _history(c, node_id=node.id, kind="upstream_probed", from_state=None, to_state=None,
             reason_code=target, actor="self",
             payload={"upstream_id": str(upstream.id), "from": upstream.state,
                      "to": target, "reachable": reachable,
                      "latency_ms": latency_ms, "reason_code": reason}, now=moment)
    models.emit_upstream_changed(c, node_id=node.id, upstream_type=upstream.access_type,
                                 state=target, trace_id=trace_id, moment=moment,
                                 causation_id=upstream.id)
    log.info("supply.upstream.probed", extra={"event": "node.upstream.probed",
                                              "node_id": node.id, "upstream_id": str(upstream.id),
                                              "state": target, "trace_id": trace_id})
    return _load(c, upstream_id=upstream.id)


def upstream_payload(upstream: Upstream) -> dict[str, Any]:
    """spec ``NodeUpstreamResponse``（+ 只加字段）。"""
    return {
        "upstream_id": str(upstream.id),
        "state": upstream.state,
        "models_declared": list(upstream.models),
        "probe_hint": PROBE_HINT,
        "access_type": upstream.access_type,
        "protocol": upstream.protocol,
        "verified_at": models.iso(upstream.verified_at),
        "rejected_reason_code": upstream.rejected_reason_code,
        "credential_registered": upstream.credential_handle is not None,
    }


def probe_ack_payload(upstream: Upstream, recorded_at: datetime) -> dict[str, Any]:
    """spec ``NodeProbeAck``（+ 只加字段；不回显任何凭据）。"""
    return {
        "upstream_id": str(upstream.id),
        "state": upstream.state,
        "rejected_reason_code": upstream.rejected_reason_code,
        "recorded_at": models.iso(recorded_at),
    }


__all__ = ["Upstream", "UPSTREAM_TRANSITIONS", "PROBE_HINT", "validate_base_url",
           "validate_models", "declare", "report_probe", "get_upstream", "list_upstreams",
           "upstream_payload", "probe_ack_payload"]
