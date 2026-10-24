# SPDX-License-Identifier: AGPL-3.0-or-later
"""M10 管理面 router（T4）：``/api/v1/admin/config/*``，operationId 对齐 spec 1.2.1。

**不接线**：本文件只提供 ``create_router(...)``，由 Lead 在 ``app/api.py`` 合并窗口接线
（写域禁止改 api.py）。生产部署必须注入两个依赖：

    router = create_router(
        principal_resolver=identity 侧的会话解析（返回 publish.Principal，含 roles / step-up），
        connection_factory=连接池取出的事务型连接（commit/rollback 由 router 管），
    )

S1 实现的端点（spec 1.2.1）：

| operationId | 方法 / 路径 | 说明 |
| --- | --- | --- |
| listConfigItems | GET /items | 元数据检索（敏感项脱敏） |
| listConfigDrifts | GET /drifts | 三源漂移清单 |
| listConfigNamespaces | GET /namespaces | 十域命名空间（S1 只读三项之一） |
| getConfigItem | GET /{key} | 单键 / 历史版本 |
| createConfigDraft | POST /{key} | 建草稿（201） |
| publishConfigItem | POST /{key}/publish | 发起发布单（202） |
| approveConfigPublish | POST /publish-requests/{id}/approve | 复核（200） |
| rollbackConfigItem | POST /{key}/rollback | 回滚（200） |
| killSwitchConfigItem | POST /{key}/kill-switch | 紧急收紧（200） |
| getConfigDiff | GET /{key}/diff | 字段级 diff（只读） |
| getConfigImpact | GET /{key}/impact | 影响面（只读） |

S2/S3 端点（``promoteConfigPublish`` 灰度推进、``listConfigAudit`` 审计聚合）**不实现**：
CR-1 裁决 S1 只交只读三项；且审计事实源是 M16（T5 接 audit API）。

错误信封对齐 spec ``Error``：``{"error": {type, code, message, request_id}}``；
step-up 缺失返回 424 + ``42401``（spec 1.2.1 已登记）；其余码值见 ``errors.ERROR_CODES``。
"""
from __future__ import annotations

import base64
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, ContextManager, Iterator, Mapping

import psycopg
from fastapi import APIRouter, Body, Header, Query, Request, Response
from fastapi.responses import JSONResponse

from . import audit as audit_mod
from . import drift, migrate, publish, registry, snapshot, store
from .errors import (
    ApproverNotAllowed,
    CooldownActive,
    DangerousKeyForbidden,
    GrayPlanInvalid,
    IdempotencyConflict,
    KeyLocked,
    OutsidePublishWindow,
    SelfApprovalForbidden,
    StateConflict,
    StepUpRequired,
    UnknownKey,
    ValidationFailed,
    VersionNotFound,
)
from .registry import ConfigKey, Registry, load as load_registry

__all__ = ["create_router", "default_principal_resolver", "default_connection_factory"]

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


# ───────────────────────────────────────────────────────────── 依赖默认实现
class _Unauthorized(Exception):
    """未认证（401）：默认解析器没拿到主体时抛。"""


def default_principal_resolver(request: Request, *,
                              now: datetime | None = None) -> publish.Principal:
    """本地 / 测试用的主体解析（**生产必须覆盖**：由 M01 会话 + step-up 校验注入）。

    头约定：``X-Admin-Actor``（必填）、``X-Admin-Roles``（逗号分隔，如 ``FIN,AUDIT``）、
    ``X-Admin-Step-Up``（step-up ref，可选）、``X-Admin-Step-Up-At``（RFC3339，可选；
    缺省视为「刚刚完成二次认证」）。
    """
    actor = request.headers.get("X-Admin-Actor")
    if not actor:
        raise _Unauthorized(
            "缺少 X-Admin-Actor：默认解析器仅用于本地/测试，生产由接线层注入 M01 会话解析")
    roles = frozenset(
        part.strip().upper()
        for part in (request.headers.get("X-Admin-Roles") or "").split(",")
        if part.strip())
    step_up_ref = request.headers.get("X-Admin-Step-Up")
    raw_at = request.headers.get("X-Admin-Step-Up-At")
    step_up_at: datetime | None = None
    if step_up_ref:
        if raw_at:
            try:
                step_up_at = datetime.fromisoformat(raw_at.replace("Z", "+00:00"))
            except ValueError:
                raise ValidationFailed(f"X-Admin-Step-Up-At 不是 RFC3339：{raw_at!r}") from None
        else:
            step_up_at = now or datetime.now(timezone.utc)
    return publish.Principal(actor=actor, roles=roles,
                             step_up_at=step_up_at, step_up_ref=step_up_ref)


@contextmanager
def default_connection_factory() -> Iterator[psycopg.Connection]:
    """默认连接：一条连接一个事务；成功 commit，异常 rollback。"""
    conn = psycopg.connect(migrate.dsn())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ───────────────────────────────────────────────────────────── 小工具
def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-Id") or str(uuid.uuid4())


def _error_response(exc: Exception, request_id: str) -> JSONResponse:
    """领域错误 → spec Error 信封。"""
    if isinstance(exc, StepUpRequired):
        status, code, kind = 424, 42401, "permission_error"
    elif isinstance(exc, (SelfApprovalForbidden, ApproverNotAllowed)):
        status, code, kind = 403, 47002, "permission_error"
    elif isinstance(exc, DangerousKeyForbidden):
        status, code, kind = 403, 47004, "permission_error"
    elif isinstance(exc, VersionNotFound):
        status, code, kind = 404, 47006, "not_found_error"
    elif isinstance(exc, UnknownKey):
        status, code, kind = 404, 47006, "not_found_error"
    elif isinstance(exc, (StateConflict, IdempotencyConflict)):
        status, code, kind = 409, 40919, "conflict_error"
    elif isinstance(exc, KeyLocked):
        status, code, kind = 409, 47003, "conflict_error"
    elif isinstance(exc, CooldownActive):
        status, code, kind = 409, 47005, "conflict_error"
    elif isinstance(exc, OutsidePublishWindow):
        status, code, kind = 409, 47008, "conflict_error"
    elif isinstance(exc, GrayPlanInvalid):
        status, code, kind = 400, 47007, "validation_error"
    elif isinstance(exc, _Unauthorized):
        # spec 1.2.x：Error.code 必须是已登记数字码；40101 = 未认证 / 会话缺失
        status, code, kind = 401, 40101, "authentication_error"
    elif isinstance(exc, ValidationFailed):
        status, code, kind = 400, exc.code, "validation_error"
    else:                                              # pragma: no cover - 兜底
        status, code, kind = 500, 0, "server_error"
    return JSONResponse(
        status_code=status,
        content={"error": {"type": kind, "code": code, "message": str(exc),
                           "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _reject_unknown(body: Mapping[str, Any], allowed: tuple[str, ...]) -> None:
    extra = sorted(set(body) - set(allowed))
    if extra:
        raise ValidationFailed(
            f"请求体含未定义字段：{', '.join(extra)}",
            details=[{"field": field} for field in extra])


def _require_body(body: Any) -> Mapping[str, Any]:
    if not isinstance(body, Mapping):
        raise ValidationFailed("请求体必须是 JSON 对象")
    return body


def _limit(limit: int) -> int:
    if not 1 <= int(limit) <= MAX_LIMIT:
        raise ValidationFailed(f"limit 越界 1..{MAX_LIMIT}：{limit}")
    return int(limit)


def _encode_cursor(key: str) -> str:
    return base64.urlsafe_b64encode(key.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> str | None:
    if not cursor:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        return base64.urlsafe_b64decode(cursor + padding).decode("utf-8")
    except Exception:                                  # noqa: BLE001
        raise ValidationFailed(f"cursor 非法：{cursor!r}") from None


def _scope(value: str | None) -> str:
    scope = value or "global"
    if scope not in ("global", "region", "tenant"):
        raise ValidationFailed(f"scope 非法：{scope!r}")
    if scope != "global":
        raise ValidationFailed(f"S1 只支持 global scope（收到 {scope}）")
    return scope


def _public_state(version_status: str | None, item_state: str) -> str:
    if version_status is None:
        return "retired" if item_state == "tombstoned" else "draft"
    return {"draft": "draft", "active": "active", "rolled_back": "rolled_back",
            "superseded": "active", "rejected": "retired",
            "tombstoned": "retired"}.get(version_status, "retired")


def _masked_ref(secret_ref: Any) -> str | None:
    if not isinstance(secret_ref, Mapping):
        return None
    scheme = secret_ref.get("scheme") or "secret"
    path = secret_ref.get("path") or ""
    return f"{scheme}://{path}"


def _item_payload(item: ConfigKey, item_row: Mapping[str, Any],
                  version_row: Mapping[str, Any] | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "key": item.key,
        "scope": version_row["scope"] if version_row else "global",
        "version": version_row["version"] if version_row else 0,
        "value_type": item.value_type,
        "state": _public_state(version_row["status"] if version_row else None, item_row["state"]),
        "description": item.description,
        "risk_level": item.risk,
        "unit": item.unit,
        "updated_at": (version_row["updated_at"] if version_row else item_row["updated_at"]).isoformat(),
        "updated_by": version_row["created_by"] if version_row else "registry",
    }
    if item.sensitive or item.secret_ref_only:
        payload["secret_ref"] = _masked_ref(version_row["secret_ref"] if version_row else None)
        payload["masked"] = True
    else:
        payload["value"] = version_row["value"] if version_row else None
        payload["secret_ref"] = None
        payload["masked"] = False
    if version_row is not None:
        payload["content_digest"] = version_row["content_digest"]
    return payload


def _ack_payload(request_row: Mapping[str, Any],
                 *, version: int | None = None) -> dict[str, Any]:
    risk = request_row["risk_level"]
    approved = list(request_row["approved_by"] or [])
    effective = request_row["effective_at"]
    return {
        "request_id": str(request_row["publish_request_id"]),
        "state": request_row["status"],
        "version": version,
        "effective_at": effective.isoformat() if effective else None,
        "approvals_required": publish.APPROVALS_REQUIRED[risk],
        "approvals_received": len(approved),
        "risk_level": risk,
    }


def _latest_version(conn: psycopg.Connection, key: str, scope: str = "global",
                    version: int | None = None) -> dict[str, Any] | None:
    return store.get_version(conn, key=key, version=version, scope=scope)


def _item_row(conn: psycopg.Connection, key: str) -> dict[str, Any]:
    cur = conn.execute("SELECT * FROM config_items WHERE key = %s", (key,))
    columns = [desc.name for desc in cur.description or ()]
    row = cur.fetchone()
    if row is None:
        raise UnknownKey(f"未注册的配置键：{key!r}", key=key)
    return dict(zip(columns, row))


def _json_diff(before: Any, after: Any, prefix: str = "") -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        for key in sorted(set(before) | set(after)):
            path = f"{prefix}/{key}" if prefix else f"/{key}"
            if before.get(key) == after.get(key):
                continue
            changes.extend(_json_diff(before.get(key), after.get(key), path))
        return changes
    if before != after:
        changes.append({"path": prefix or "", "before": before, "after": after, "masked": False})
    return changes


# ───────────────────────────────────────────────────────────── Router 工厂
def create_router(
    *,
    principal_resolver: Callable[[Request], publish.Principal] | None = None,
    connection_factory: Callable[[], ContextManager[psycopg.Connection]] | None = None,
    registry_provider: Callable[[], Registry] | None = None,
    now_provider: Callable[[], datetime] | None = None,
    audit_sink: "audit_mod.AuditSink | None" = None,
) -> APIRouter:
    clock = now_provider or (lambda: datetime.now(timezone.utc))
    resolve = principal_resolver or (lambda req: default_principal_resolver(req, now=clock()))
    connect = connection_factory or default_connection_factory
    reg_of = registry_provider or load_registry
    audit = audit_sink

    def _maybe_activate(conn, request_row, *, version: int | None) -> tuple[dict[str, Any], int | None]:
        """S1 接线：复核/创建后若已 approved 且生效时间已到，立即生效（窗口内）。

        effective_at 在未来的单保持 approved（调度器在 T5 接；S1 很少用）。
        """
        if request_row["status"] != "approved":
            return request_row, version
        effective = request_row["effective_at"]
        moment = clock()
        if effective is not None and effective > moment:
            return request_row, version
        result = publish.activate_request(
            conn, request_row["publish_request_id"], now=moment, audit=audit)
        return result["request"], result["version"]["version"]
    router = APIRouter(prefix="/api/v1/admin/config", tags=["admin"])

    def guard(request: Request, fn: Callable[[], Any]) -> Any:
        rid = _request_id(request)
        try:
            return fn()
        except Exception as exc:                        # noqa: BLE001 - 统一映射
            return _error_response(exc, rid)

    # ── 读：items / drifts / namespaces（不能与 /{key} 冲突，先声明）
    @router.get("/items", operation_id="listConfigItems")
    def list_config_items(
        request: Request, response: Response,
        prefix: str | None = Query(None), scope: str | None = Query(None),
        limit: int = Query(DEFAULT_LIMIT), cursor: str | None = Query(None),
    ):
        def run():
            resolve(request)
            _limit(limit)
            scope_value = _scope(scope)
            after = _decode_cursor(cursor)
            with connect() as conn:
                sql = """SELECT i.*, v.version AS version_no, v.status AS version_status,
                                v.value, v.secret_ref, v.content_digest,
                                v.updated_at AS version_updated_at, v.created_by AS version_by
                           FROM config_items i
                           LEFT JOIN LATERAL (
                                SELECT * FROM config_versions v
                                 WHERE v.key = i.key AND v.scope = %s
                                 ORDER BY v.version DESC LIMIT 1) v ON TRUE
                          WHERE (%s::text IS NULL OR i.key LIKE %s::text)
                            AND (%s::text IS NULL OR i.key > %s::text)
                          ORDER BY i.key LIMIT %s"""
                pattern = f"{prefix}%" if prefix else None
                rows = conn.execute(sql, (scope_value, prefix, pattern, after, after, limit + 1))
                columns = [desc.name for desc in rows.description or ()]
                data = [dict(zip(columns, row)) for row in rows.fetchall()]
            has_more = len(data) > limit
            data = data[:limit]
            items = []
            for row in data:
                item = reg_of().require(row["key"])
                version_row = None
                if row["version_no"] is not None:
                    version_row = {"scope": scope_value, "version": row["version_no"],
                                   "status": row["version_status"], "value": row["value"],
                                   "secret_ref": row["secret_ref"],
                                   "content_digest": row["content_digest"],
                                   "updated_at": row["version_updated_at"],
                                   "created_by": row["version_by"]}
                items.append(_item_payload(item, row, version_row))
            next_cursor = _encode_cursor(data[-1]["key"]) if has_more and data else None
            response.headers["X-Request-Id"] = _request_id(request)
            return {"data": items,
                    "page": {"cursor": cursor or "", "has_more": has_more,
                             "next_cursor": next_cursor}}
        return guard(request, run)

    @router.get("/drifts", operation_id="listConfigDrifts")
    def list_config_drifts(
        request: Request, response: Response,
        limit: int = Query(DEFAULT_LIMIT), cursor: str | None = Query(None),
    ):
        def run():
            resolve(request)
            _limit(limit)
            with connect() as conn:
                rows = drift.list_drifts(conn, resolved=False, limit=limit)
            response.headers["X-Request-Id"] = _request_id(request)
            data = [{
                "key": row["key"], "scope": row["scope"], "scope_id": row["scope_id"],
                "desired_version": row["desired_version"],
                "effective_version": row["effective_version"],
                "running_version": row["running_version"],
                "detected_at": row["detected_at"].isoformat(),
            } for row in rows]
            return {"data": data,
                    "page": {"cursor": cursor or "", "has_more": False, "next_cursor": None}}
        return guard(request, run)

    @router.get("/namespaces", operation_id="listConfigNamespaces")
    def list_config_namespaces(request: Request, response: Response,
                               limit: int = Query(DEFAULT_LIMIT)):
        def run():
            resolve(request)
            _limit(limit)
            reg = reg_of()
            data = []
            for domain in reg.domains:
                keys = [item for item in reg.keys if item.domain == domain.code]
                data.append({
                    "namespace": domain.namespaces[0],
                    "item_count": len(keys),
                    "prefixes": list(domain.namespaces),
                    "consumers": sorted({c for item in keys for c in item.consumers}),
                    "dangerous_keys": [item.key for item in keys if item.dangerous],
                })
            for aux in reg.aux:
                keys = [item for item in reg.keys if item.domain == aux.namespace]
                data.append({
                    "namespace": aux.namespace,
                    "item_count": len(keys),
                    "prefixes": [aux.namespace],
                    "consumers": sorted({c for item in keys for c in item.consumers}),
                    "dangerous_keys": [item.key for item in keys if item.dangerous],
                })
            response.headers["X-Request-Id"] = _request_id(request)
            return {"data": data,
                    "page": {"cursor": "", "has_more": False, "next_cursor": None}}
        return guard(request, run)

    # ── 读：单键 / diff / impact
    @router.get("/{key}", operation_id="getConfigItem")
    def get_config_item(
        request: Request, response: Response, key: str,
        version: int | None = Query(None), scope: str | None = Query(None),
    ):
        def run():
            resolve(request)
            scope_value = _scope(scope)
            with connect() as conn:
                item = reg_of().require(key)
                item_row = _item_row(conn, key)
                row = _latest_version(conn, key, scope_value, version)
                if version is not None and row is None:
                    raise VersionNotFound(f"{key} v{version} 不存在", key=key)
                payload = _item_payload(item, item_row, row)
            response.headers["X-Request-Id"] = _request_id(request)
            return payload
        return guard(request, run)

    @router.get("/{key}/diff", operation_id="getConfigDiff")
    def get_config_diff(
        request: Request, response: Response, key: str,
        from_version: int | None = Query(None), to_version: int | None = Query(None),
        scope: str | None = Query(None),
    ):
        def run():
            resolve(request)
            scope_value = _scope(scope)
            with connect() as conn:
                item = reg_of().require(key)
                latest = _latest_version(conn, key, scope_value)
                if latest is None:
                    raise VersionNotFound(f"{key} 没有任何版本", key=key)
                to_no = to_version or latest["version"]
                from_no = from_version or max(1, to_no - 1)
                before = _latest_version(conn, key, scope_value, from_no)
                after = _latest_version(conn, key, scope_value, to_no)
                if before is None or after is None:
                    raise VersionNotFound(
                        f"{key} 的版本不存在（from={from_no} to={to_no}）", key=key)
                before_value = before["value"] if before["value"] is not None else before["secret_ref"]
                after_value = after["value"] if after["value"] is not None else after["secret_ref"]
                if item.sensitive or item.secret_ref_only:
                    changes = [{"path": "", "before": "***", "after": "***", "masked": True}]
                else:
                    changes = _json_diff(before_value, after_value)
                payload = {
                    "key": key, "scope": scope_value,
                    "from_version": from_no, "to_version": to_no,
                    "changes": changes,
                    "digest_before": before["content_digest"],
                    "digest_after": after["content_digest"],
                }
            response.headers["X-Request-Id"] = _request_id(request)
            return payload
        return guard(request, run)

    @router.get("/{key}/impact", operation_id="getConfigImpact")
    def get_config_impact(
        request: Request, response: Response, key: str,
        version: int | None = Query(None), scope: str | None = Query(None),
    ):
        def run():
            resolve(request)
            scope_value = _scope(scope)
            with connect() as conn:
                item = reg_of().require(key)
                impact = publish.impact_analysis(conn, item, scope=scope_value)
                row = _latest_version(conn, key, scope_value, version)
                if version is not None and row is None:
                    raise VersionNotFound(f"{key} v{version} 不存在", key=key)
            payload = {
                "key": key, "scope": scope_value, "risk_level": item.risk,
                "consumers": impact["consumers"],
                "affected_modules": impact["consumers"],
                "requires_restart": False,
                "effective_on": "immediate",
                "gray_buckets": [],
                "notes": f"影响面基于注册表 consumers 声明；版本 {row['version'] if row else 'n/a'}",
            }
            response.headers["X-Request-Id"] = _request_id(request)
            return payload
        return guard(request, run)

    # ── S2：灰度推进（spec 1.2.1 已登记；S1 开关关闭 → 409 + 47007）
    @router.post("/publish-requests/{request_id}/promote", status_code=200,
                 operation_id="promoteConfigPublish")
    def promote_config_publish(
        request: Request, response: Response, request_id: str,
        body: Mapping[str, Any] = Body(...),
        idempotency_key: str | None = Header(None, alias="X-DJB-Idempotency-Key"),
    ):
        def run():
            principal = resolve(request)
            body_checked = _require_body(body)
            _reject_unknown(body_checked, ("target_stage",))
            target_stage = body_checked.get("target_stage")
            if target_stage not in ("next_bucket", "full"):
                raise ValidationFailed("target_stage 必须是 next_bucket / full")
            try:
                with connect() as conn:
                    result = publish.promote_request(
                        conn, request_id, principal=principal, target_stage=target_stage,
                        now=clock(), audit=audit)
                    row = result["request"]
            except GrayPlanInvalid as exc:
                # spec promote：观测窗/灰度非法 → 409 + 47007（其它端点仍是 400）
                rid = _request_id(request)
                return JSONResponse(
                    status_code=409,
                    content={"error": {"type": "conflict_error", "code": 47007,
                                       "message": str(exc), "request_id": rid}},
                    headers={"X-Request-Id": rid})
            versions = row["versions"] or {}
            ack = _ack_payload(row, version=versions.get(row["key"])
                               if isinstance(versions, dict) else None)
            ack["bucket"] = result["bucket"]
            ack["activated"] = result["activated"]
            response.headers["X-Request-Id"] = _request_id(request)
            return ack
        return guard(request, run)

    # ── M16 审计只读聚合（事实源在 M16；注入的 sink 提供 query 时返回最近事件）
    @router.get("/{key}/audit", operation_id="listConfigAudit")
    def list_config_audit(request: Request, response: Response, key: str,
                          limit: int = Query(DEFAULT_LIMIT)):
        def run():
            resolve(request)
            _limit(limit)
            reg_of().require(key)
            rows: list[dict[str, Any]] = []
            source = "m16"
            if audit is not None and hasattr(audit, "query"):
                rows = list(audit.query(key, limit=limit))  # type: ignore[attr-defined]
                source = "m16-injected"
            response.headers["X-Request-Id"] = _request_id(request)
            return {"data": rows,
                    "page": {"cursor": "", "has_more": False, "next_cursor": None},
                    "source": source}

        return guard(request, run)

    # ── 写：草稿 / 发布 / 复核 / 回滚 / kill switch
    @router.post("/{key}", status_code=201, operation_id="createConfigDraft")
    def create_config_draft(
        request: Request, response: Response, key: str,
        body: Mapping[str, Any] = Body(...),
        idempotency_key: str | None = Header(None, alias="X-DJB-Idempotency-Key"),
    ):
        def run():
            principal = resolve(request)
            body_checked = _require_body(body)
            _reject_unknown(body_checked, ("value", "secret_ref", "value_type", "reason",
                                           "ticket", "effective_at"))
            if "value_type" not in body_checked:
                raise ValidationFailed("value_type 必填（spec ConfigDraftRequest）")
            if len(body_checked.get("reason") or "") < 4:
                raise ValidationFailed("reason 必填且至少 4 个字符")
            if idempotency_key is not None and not 16 <= len(idempotency_key) <= 128:
                raise ValidationFailed("X-DJB-Idempotency-Key 长度必须 16..128")
            with connect() as conn:
                row = store.create_draft(
                    conn, key=key, value=body_checked.get("value"),
                    secret_ref=body_checked.get("secret_ref"),
                    value_type=body_checked.get("value_type"),
                    reason=body_checked["reason"], actor=principal.actor,
                    effective_at=body_checked.get("effective_at"),
                    ticket=body_checked.get("ticket"),
                    idempotency_key=idempotency_key, registry=reg_of(), now=clock())
                item = reg_of().require(key)
                audit_mod.emit(audit, audit_mod.build_event(
                    "config.draft.created", actor=principal.actor, key=key,
                    version=row["version"], reason=body_checked["reason"],
                    occurred_at=clock(),
                    metadata={"value_type": item.value_type, "status": row["status"]}))
                item_row = _item_row(conn, key)
                payload = _item_payload(item, item_row, row)
            response.headers["X-Request-Id"] = _request_id(request)
            return payload
        return guard(request, run)

    @router.post("/{key}/publish", status_code=202, operation_id="publishConfigItem")
    def publish_config_item(
        request: Request, response: Response, key: str,
        body: Mapping[str, Any] = Body(...),
        idempotency_key: str | None = Header(None, alias="X-DJB-Idempotency-Key"),
    ):
        def run():
            principal = resolve(request)
            body_checked = _require_body(body)
            _reject_unknown(body_checked, ("version", "reason", "effective_at", "ticket",
                                           "gray_plan"))
            if "version" not in body_checked or "reason" not in body_checked:
                raise ValidationFailed("version 与 reason 必填（spec ConfigPublishRequest）")
            with connect() as conn:
                row = publish.create_request(
                    conn, key=key, version=int(body_checked["version"]), principal=principal,
                    reason=body_checked["reason"], effective_at=body_checked.get("effective_at"),
                    gray_plan=body_checked.get("gray_plan"), ticket=body_checked.get("ticket"),
                    idempotency_key=idempotency_key, registry=reg_of(), now=clock(),
                    audit=audit)
                row, activated_version = _maybe_activate(
                    conn, row, version=int(body_checked["version"]))
                ack = _ack_payload(row, version=activated_version)
            response.headers["X-Request-Id"] = _request_id(request)
            return ack
        return guard(request, run)

    @router.post("/publish-requests/{request_id}/approve", status_code=200,
                 operation_id="approveConfigPublish")
    def approve_config_publish(
        request: Request, response: Response, request_id: str,
        body: Mapping[str, Any] = Body(...),
        idempotency_key: str | None = Header(None, alias="X-DJB-Idempotency-Key"),
    ):
        def run():
            principal = resolve(request)
            body_checked = _require_body(body)
            _reject_unknown(body_checked, ("decision", "reason"))
            if body_checked.get("decision") not in ("approve", "reject"):
                raise ValidationFailed("decision 必须是 approve / reject")
            if len(body_checked.get("reason") or "") < 4:
                raise ValidationFailed("reason 必填且至少 4 个字符")
            with connect() as conn:
                row = publish.approve_request(
                    conn, request_id, principal=principal,
                    decision=body_checked["decision"], reason=body_checked["reason"],
                    now=clock(), audit=audit)
                versions = row["versions"] or {}
                target_version = versions.get(row["key"]) if isinstance(versions, dict) else None
                row, activated_version = _maybe_activate(
                    conn, row, version=target_version)
                ack = _ack_payload(row, version=activated_version)
            response.headers["X-Request-Id"] = _request_id(request)
            return ack
        return guard(request, run)

    @router.post("/{key}/rollback", status_code=200, operation_id="rollbackConfigItem")
    def rollback_config_item(
        request: Request, response: Response, key: str,
        body: Mapping[str, Any] = Body(...),
        idempotency_key: str | None = Header(None, alias="X-DJB-Idempotency-Key"),
    ):
        def run():
            principal = resolve(request)
            body_checked = _require_body(body)
            _reject_unknown(body_checked, ("target_version", "reason", "ticket"))
            if "target_version" not in body_checked or "reason" not in body_checked:
                raise ValidationFailed("target_version 与 reason 必填（spec ConfigRollbackRequest）")
            with connect() as conn:
                row = publish.rollback(
                    conn, key=key, target_version=int(body_checked["target_version"]),
                    principal=principal, reason=body_checked["reason"],
                    ticket=body_checked.get("ticket"), idempotency_key=idempotency_key,
                    registry=reg_of(), now=clock(), audit=audit)
                new_version = row.get("new_version")
                row, activated_version = _maybe_activate(conn, row, version=new_version)
                ack = _ack_payload(row, version=activated_version)
            response.headers["X-Request-Id"] = _request_id(request)
            return ack
        return guard(request, run)

    @router.post("/{key}/kill-switch", status_code=200, operation_id="killSwitchConfigItem")
    def kill_switch_config_item(
        request: Request, response: Response, key: str,
        body: Mapping[str, Any] = Body(...),
        idempotency_key: str | None = Header(None, alias="X-DJB-Idempotency-Key"),
    ):
        def run():
            principal = resolve(request)
            body_checked = _require_body(body)
            _reject_unknown(body_checked, ("value", "reason", "ttl_seconds", "tighten_only"))
            if "ttl_seconds" not in body_checked or "reason" not in body_checked:
                raise ValidationFailed("ttl_seconds 与 reason 必填（spec ConfigKillSwitchRequest）")
            if body_checked.get("tighten_only") is False:
                raise ValidationFailed("tighten_only 只能为 true（kill switch 只收紧）")
            with connect() as conn:
                result = publish.kill_switch(
                    conn, key=key, value=body_checked.get("value"),
                    ttl_seconds=int(body_checked["ttl_seconds"]), principal=principal,
                    reason=body_checked["reason"], registry=reg_of(), now=clock(), audit=audit)
                version = result["version"]
                ack = {
                    # kill switch 不是发布单：用版本 id 作为可回查的 request_id
                    "request_id": str(version["version_id"]),
                    "state": "active",
                    "version": version["version"],
                    "effective_at": (version["effective_at"].isoformat()
                                     if version["effective_at"] else None),
                    "approvals_required": 0,
                    "approvals_received": 0,
                    "risk_level": reg_of().require(key).risk,
                    "expires_at": result["expires_at"].isoformat() if result["expires_at"] else None,
                    "emergency": True,
                }
            response.headers["X-Request-Id"] = _request_id(request)
            return ack
        return guard(request, run)

    return router
