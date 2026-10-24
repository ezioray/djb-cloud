# SPDX-License-Identifier: AGPL-3.0-or-later
"""/healthz（spec-1.2.2 ``HealthStatus``；M16 §4.1「只返回状态与版本，不暴露拓扑」）。

约定：

* 200 + ``{"status": "ok"|"degraded", "version", "checked_at", "checks"}``；
* DB 不可用 → **500** + spec ``Error`` 信封（spec 明写 500 = 依赖不可用）；
* 审计密钥缺失 / 不可读 → 200 + ``status=degraded`` + ``checks.audit_key``：
  服务仍然活着（只读 / 校验结论照常返回），但写入会 fail-closed（423/42301）。
  这样探针不会把"只读可用"判成死，同时把密钥状态显式暴露给值班；
* ``checks`` 只给状态字符串（ok / down / missing / locked），不给地址、凭据、拓扑。

handler 供 Lead 在 ``app/api.py`` 里替换 legacy ``/healthz`` 使用（本模块不改 api.py）。
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from . import clock, errors, facts, keys


def _error_body(message: str, request_id: str | None) -> dict[str, Any]:
    return {"error": {"type": errors.error_type_for(500), "code": 50001,
                      "message": message, "request_id": request_id or ""}}


def create_health_handler(*, connection_factory: Callable[[], Any],
                          key_provider: Any = None, version: str | None = None,
                          now: Callable[[], Any] | None = None) -> Callable[[], JSONResponse]:
    """构造 ``GET /healthz`` 的 handler（依赖注入，不读全局状态）。"""
    moment_source = now or clock.utcnow
    service_version = version or facts.SERVICE_VERSION

    def healthz() -> JSONResponse:
        moment = clock.as_utc(moment_source())
        checks: dict[str, str] = {}

        database_ok = True
        try:
            with connection_factory() as connection:
                connection.execute("SELECT 1")
            checks["db"] = "ok"
        except Exception:                                  # pragma: no cover - 依赖不可用
            database_ok = False
            checks["db"] = "down"

        key_state = "ok"
        try:
            if keys.read_key(key_provider) is None:
                key_state = "missing"
        except errors.AuditError:
            key_state = "locked"
        checks["audit_key"] = key_state

        if not database_ok:
            return JSONResponse(_error_body("依赖不可用：数据库连接失败", None), status_code=500)

        status = "ok" if key_state == "ok" else "degraded"
        return JSONResponse({"status": status, "version": service_version,
                             "checked_at": clock.iso_micros(moment), "checks": checks})

    return healthz


def create_health_router(*, connection_factory: Callable[[], Any], key_provider: Any = None,
                         version: str | None = None,
                         now: Callable[[], Any] | None = None) -> APIRouter:
    """把 /healthz 包成 APIRouter（由 Lead 在 api.py include / 替换 legacy handler）。"""
    router = APIRouter(tags=["ops"])
    handler = create_health_handler(connection_factory=connection_factory,
                                    key_provider=key_provider, version=version, now=now)
    router.add_api_route("/healthz", handler, methods=["GET"], name="getHealthz")
    return router


__all__ = ["create_health_handler", "create_health_router"]
