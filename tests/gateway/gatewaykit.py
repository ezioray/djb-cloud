# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/gateway 测试工具：迁移执行、结构指纹、注入 provider 的假实现。

只读契约：

* 迁移文件是唯一 DDL 来源，测试只用 ``psql -f`` 执行（与 CI / 生产同一条路径），
  不在 Python 里手写建表语句；
* 每个测试进程用独立 schema（默认 ``m03_t12_<pid>_<hex>``，``M03_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不读写 public，也不碰别人的 schema；
* 缺 ``DJB_DSN`` 或库不可达时 DB 用例 skip（纯函数用例照跑）；
* 上游模块一律用**假 provider**（M01 / M04 / M05 / 节点通道 / 模型目录），
  测试不 import 任何其它业务模块。
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

import psycopg

from app.gateway import models

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

#: 本模块的迁移（301–307，数字序）
M03_MIGRATIONS = (
    "301_api_request_log.sql",
    "302_batch_jobs.sql",
    "303_batch_items.sql",
    "304_m03_outbox.sql",
    "305_m03_idempotency.sql",
    "306_batch_webhook_state.sql",
    "307_api_request_log_usage_source_dual.sql",
)

#: M03 拥有的表（01-ownership §2 + M03 §5；``m03_outbox`` 按 01-ownership §2「每模块自己的 outbox」；
#: ``m03_idempotency`` 是 M03 §3.1 的 ``idempotency_record`` 聚合，交付证据里已作为 CR 上报 Lead）
M03_TABLES = ("api_request_log", "batch_jobs", "batch_items", "m03_outbox", "m03_idempotency")

#: 本模块新增的函数（触发器 / 护栏）
M03_FUNCTIONS = ("m03_forbid_truncate", "m03_request_log_guard", "m03_batch_state_guard",
                 "m03_batch_item_guard", "m03_outbox_guard", "m03_outbox_insert_guard",
                 "m03_idempotency_guard")

#: 前置段（编号 < 300）里必须存在的对象（升级测试要在这些对象上证明「只加不改」）
BASE_TABLES = ("users", "user_accounts", "api_keys", "sessions", "tenant_quotas", "nodes",
               "node_upstreams", "capacity_announcements")
"""前置段（<300：001–006 / M01 1xx / M02 2xx）里必须存在的对象；3xx 不得改动它们。"""

NOW = datetime(2026, 10, 23, 4, 0, tzinfo=timezone.utc)
"""固定时钟（00-conventions §10）：所有用例显式传 ``now=NOW`` / ``now=NOW + Δ``。"""


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    from tests.pgdsn import safe_dsn
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 W1-EXECUTION-PLAN §3）")
    return safe_dsn(value)


def connect(schema: str, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m03-t12-tests",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


@contextmanager
def session(schema: str):
    """autocommit 只读 / 单语句会话；退出即 close。"""
    conn = connect(schema, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def create_schema(name: str) -> None:
    conn = psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m03-t12-tests")
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{name}"')
    finally:
        conn.close()


def drop_schema(name: str) -> None:
    conn = psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m03-t12-tests")
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '15s'")
            cur.execute("SET statement_timeout = '180s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        conn.close()


def migration_number(path: pathlib.Path) -> int:
    return int(path.name.split("_", 1)[0])


def migration_files(order: str = "numeric") -> list[pathlib.Path]:
    """默认按**数字**排序（CI 用 ``sort -V``；字典序另有用例覆盖）。"""
    files = list(MIGRATIONS_DIR.glob("*.sql"))
    if order == "numeric":
        return sorted(files, key=migration_number)
    if order == "lexicographic":
        return sorted(files)
    raise ValueError(f"未知排序：{order}")


def m03_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M03_MIGRATIONS]


def prerequisite_files(to: int = 299) -> list[pathlib.Path]:
    """前置段：编号 ≤ ``to`` 的全部迁移（空库三跑用）。"""
    return [path for path in migration_files() if migration_number(path) <= to]


def run_migrations(paths: Sequence[pathlib.Path], schema: str) -> subprocess.CompletedProcess:
    """一个 psql 进程按序执行多个文件（同一连接），省掉每文件一次进程启动。"""
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    args = ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q"]
    for path in paths:
        args += ["-f", str(path)]
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=300)


def apply_migrations(schema: str, files: Sequence[pathlib.Path] | None = None) -> list[dict]:
    """顺序执行迁移，返回 [{name, rc, stderr}]；失败立刻断言。"""
    paths = list(files if files is not None else migration_files())
    result = run_migrations(paths, schema)
    out = [{"name": p.name, "rc": result.returncode,
            "stderr": (result.stderr or "").strip()} for p in paths]
    assert result.returncode == 0, f"迁移失败（rc={result.returncode}）：\n{result.stderr}"
    return out


# ─────────────────────────────────────────────────────── 结构查询
def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[tuple]:
    return list(conn.execute(sql, params).fetchall())


def table_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))}


def column_names(schema: str, table: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT column_name FROM information_schema.columns"
                  " WHERE table_schema = %s AND table_name = %s", (schema, table))}


def function_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, """SELECT p.proname FROM pg_proc p
                       JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = %s""", (schema,))}


def index_names(schema: str, table: str | None = None) -> set[str]:
    with session(schema) as conn:
        if table is None:
            rows = _rows(conn, "SELECT indexname FROM pg_indexes WHERE schemaname = %s",
                         (schema,))
        else:
            rows = _rows(conn, "SELECT indexname FROM pg_indexes"
                               " WHERE schemaname = %s AND tablename = %s", (schema, table))
    return {row[0] for row in rows}


# ─────────────────────────────────────────────────────── 假 provider（扮演上游模块）
class FakeAuth:
    """M01 ``verify_api_key`` 的投影：按明文 Key 查表返回主体 / 抛异常。"""

    def __init__(self, *, account_id: uuid.UUID | None = None,
                 tenant_id: uuid.UUID | None = None, api_key_id: int | None = 1,
                 accounts: dict[str, dict[str, Any]] | None = None,
                 qps: int | None = None, daily_cap_minor: int | None = None,
                 daily_spend_minor: int | None = None, state: str = "normal",
                 ip_allowlist: Sequence[str] = ()) -> None:
        self.account_id = account_id or uuid.uuid4()
        self.tenant_id = tenant_id or uuid.uuid4()
        self.api_key_id = api_key_id
        self.accounts = accounts or {}
        self.qps = qps
        self.daily_cap_minor = daily_cap_minor
        self.daily_spend_minor = daily_spend_minor
        self.state = state
        self.ip_allowlist = tuple(ip_allowlist)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, raw_key: str, *, now: Any, client_ip: str | None,
                 trace_id: str) -> dict[str, Any]:
        self.calls.append({"raw_key": raw_key, "client_ip": client_ip, "trace_id": trace_id})
        if raw_key in self.accounts:
            return self.accounts[raw_key]
        if raw_key.startswith("revoked"):
            exc = RuntimeError("Key 哈希未命中")
            exc.status_code = 401                     # M01 IdentityError 的两属性口径
            exc.code = "40101"
            exc.reason = "api_key_invalid"
            raise exc
        return principal_dict(account_id=self.account_id, tenant_id=self.tenant_id,
                              api_key_id=self.api_key_id, qps=self.qps,
                              daily_cap_minor=self.daily_cap_minor,
                              daily_spend_minor=self.daily_spend_minor,
                              state=self.state, ip_allowlist=self.ip_allowlist)


def principal_dict(*, account_id: uuid.UUID | None = None, tenant_id: uuid.UUID | None = None,
                   api_key_id: int | None = 1, state: str = "normal",
                   qps: int | None = None, daily_cap_minor: int | None = None,
                   daily_spend_minor: int | None = None, ip_allowlist: Sequence[str] = (),
                   policy_version: str = "pv-1") -> dict[str, Any]:
    """构造 M01 ``AuthContext`` 风格的 provider 返回值（Mapping 形态）。"""
    effective: dict[str, int] = {}
    if qps is not None:
        effective["qps"] = int(qps)
    if daily_cap_minor is not None:
        effective["daily_usd_minor"] = int(daily_cap_minor)
    quotas: dict[str, Any] = {"policy_version": policy_version, "effective": effective}
    if daily_spend_minor is not None:
        quotas["spend"] = {"daily_spend_minor": int(daily_spend_minor)}
    return {"account_id": str(account_id or uuid.uuid4()),
            "tenant_id": str(tenant_id or uuid.uuid4()),
            "api_key_id": api_key_id, "api_key_prefix": "djb_abc1",
            "account_state": state, "quotas": quotas,
            "ip_allowlist": list(ip_allowlist), "policy_version": policy_version}


class FakeRoute:
    """M04 ``/api/v1/schedule/route`` 的投影：按顺序返回决策，可注入失败。"""

    def __init__(self, *, node_id: str = "n_001", node_qps: int | None = None,
                 price_minor: int = 250, fail_times: int = 0,
                 eta_seconds: int = 1) -> None:
        self.node_id = node_id
        self.node_qps = node_qps
        self.price_minor = price_minor
        self.fail_times = fail_times
        self.eta_seconds = eta_seconds
        self.requests: list[models.RouteRequest] = []

    def route(self, request: models.RouteRequest) -> dict[str, Any]:
        self.requests.append(request)
        if len(self.requests) <= self.fail_times:
            from app.gateway import providers

            raise providers.NoRoute("无可用节点（45001）")
        return {"decision_id": str(uuid.uuid4()),
                "chosen": {"node_id": self.node_id, "upstream_id": "up_001",
                           "access": "A1", "model": request.model},
                "quote_version": "v1", "policy_version": "pv-1",
                "eta_seconds": self.eta_seconds,
                "price": {"amount": f"{self.price_minor / 100:.2f}", "unit": "token"},
                "node_qps": self.node_qps}


class FakeNode:
    """上游节点通道：可注入超时 / 异常 / 正常结果。"""

    def __init__(self, *, content: str = "hello", tokens_in: int = 3, tokens_out: int = 2,
                 finish_reason: str = "stop", timeouts: int = 0, failures: int = 0,
                 latency_ms: int = 12, first_byte_ms: int = 9,
                 usage_source: str = "actual") -> None:
        self.content = content
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.finish_reason = finish_reason
        self.timeouts = timeouts
        self.failures = failures
        self.latency_ms = latency_ms
        self.first_byte_ms = first_byte_ms
        self.usage_source = usage_source
        self.calls: list[models.NodeCall] = []

    def complete(self, call: models.NodeCall) -> models.NodeResult:
        from app.gateway import providers

        self.calls.append(call)
        if self.timeouts > 0:
            self.timeouts -= 1
            raise providers.UpstreamTimeout("上游超时")
        if self.failures > 0:
            self.failures -= 1
            raise providers.UpstreamFailure("上游 502")
        return models.NodeResult(content=self.content, finish_reason=self.finish_reason,
                                 model=call.model, tokens_in=self.tokens_in,
                                 tokens_out=self.tokens_out, usage_source=self.usage_source,
                                 latency_ms=self.latency_ms, first_byte_ms=self.first_byte_ms)


class FakeStream:
    """上游**流式**通道：可注入首字节前失败、流中中断、token 上报。"""

    def __init__(self, chunks: Sequence[str] = ("hello", " world"), *,
                 tokens_in: int | None = 3, tokens_out: int | None = 2,
                 timeouts: int = 0, failures: int = 0, fail_after: int | None = None,
                 finish_reason: str = "stop", first_byte_ms: int = 5) -> None:
        self.chunks = list(chunks)
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.timeouts = timeouts
        self.failures = failures
        self.fail_after = fail_after
        self.finish_reason = finish_reason
        self.first_byte_ms = first_byte_ms
        self.calls: list[models.NodeCall] = []

    def stream(self, call: models.NodeCall):
        from app.gateway import providers

        self.calls.append(call)
        if self.timeouts > 0:
            self.timeouts -= 1
            raise providers.UpstreamTimeout("上游超时")
        if self.failures > 0:
            self.failures -= 1
            raise providers.UpstreamFailure("上游 502")
        return self._generate()

    def _generate(self):
        from app.gateway import models as gateway_models, providers

        total = len(self.chunks)
        for index, text in enumerate(self.chunks):
            if self.fail_after is not None and index >= self.fail_after:
                raise providers.UpstreamFailure("上游中途断开")
            last = index == total - 1
            yield gateway_models.StreamChunk(
                delta=text, role="assistant" if index == 0 else None,
                finish_reason=self.finish_reason if last else None,
                model="m1",
                tokens_in=self.tokens_in if last else None,
                tokens_out=self.tokens_out if last else None,
                first_byte_ms=self.first_byte_ms if index == 0 else None)


class FakeWebhookSender:
    """对外 webhook 投递桩：记录请求，可按序列返回状态码 / 抛异常。"""

    def __init__(self, statuses: Sequence[int | None] | None = None, *,
                 raises: int = 0) -> None:
        self.statuses = list(statuses or [200])
        self.raises = raises
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, body: bytes, headers: Mapping[str, str]) -> Any:
        self.calls.append({"url": url, "body": body, "headers": dict(headers)})
        if self.raises > 0:
            self.raises -= 1
            raise RuntimeError("connection refused")
        if not self.statuses:
            return 500
        return self.statuses.pop(0)


class FakeSigner:
    """批次结果签名 URL 签发桩。"""

    def __init__(self, base: str = "https://files.example") -> None:
        self.base = base
        self.calls: list[tuple[str, Any]] = []

    def __call__(self, batch_id: str, expires_at: Any) -> str:
        self.calls.append((batch_id, expires_at))
        stamp = int(expires_at.timestamp())
        return f"{self.base}/{batch_id}?exp={stamp}&sig=deadbeef"


class FakeUsage:
    """M05 用量写入口：记录 draft（按 request_id 去重，模拟幂等）。"""

    def __init__(self, *, fail: bool = False) -> None:
        self.drafts: list[models.UsageDraft] = []
        self.fail = fail

    def record(self, draft: models.UsageDraft) -> models.UsageReceipt:
        if self.fail:
            raise RuntimeError("M05 不可用")
        self.drafts.append(draft)
        return models.UsageReceipt(usage_id=f"u_{draft.request_id[:8]}",
                                   amount_minor=draft.amount_minor)


class FakeCatalog:
    """M04 ``model_catalog`` 只读投影。"""

    def __init__(self, items: Iterable[dict[str, Any]] | None = None) -> None:
        self.items = list(items or [
            {"id": "m1", "owned_by": "djb", "context_window": 8192, "unit": "token",
             "price": {"amount": "0.02", "unit": "token"}},
            {"id": "m2", "owned_by": "djb"},
        ])

    def list_models(self) -> list[dict[str, Any]]:
        return list(self.items)


# ─────────────────────────────────────────────────────── 断言辅助
def reload_now(seconds: int = 0) -> datetime:
    return NOW + timedelta(seconds=seconds)


__all__ = [
    "NOW", "M03_MIGRATIONS", "M03_TABLES", "M03_FUNCTIONS", "BASE_TABLES", "ROOT",
    "dsn", "connect", "session", "create_schema", "drop_schema", "migration_files",
    "m03_migration_files", "prerequisite_files", "run_migrations", "apply_migrations",
    "table_names", "column_names", "function_names", "index_names",
    "FakeAuth", "FakeRoute", "FakeNode", "FakeStream", "FakeUsage", "FakeCatalog",
    "FakeWebhookSender", "FakeSigner", "principal_dict", "reload_now",
]
