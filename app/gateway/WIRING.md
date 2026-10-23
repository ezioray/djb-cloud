# M03 gateway-protocol · 合并接线说明（WIRING）

> 本文件是给 **Lead 合并时**用的接线清单。M03 自身**不 import** 任何其它业务模块，
> 所有跨模块依赖都走 `app/gateway/providers.py` 与 `app/gateway/config_source.py`
> 的注入点；**默认 fail-closed**（未注入时鉴权 / 路由 / 上游一律 503）。

## 1 五个 provider（缺一不可）

```python
from app.gateway import providers, config_source

# ① M01 鉴权：Bearer Key → 主体（AuthContext / Mapping 均可，网关侧 coerce 成 Principal）
def auth_provider(raw_key: str, *, now, client_ip, trace_id):
    from app.identity import api_keys          # ← 由 Lead 的接线层 import（不在 M03 里）
    with app_db_conn() as c:
        ctx = api_keys.verify_api_key(c, raw_key, now=now, require_writable=True,
                                      require_quota=True, trace_id=trace_id)
    # AuthContext 已带 account / api_key_id / quotas（policy_version + effective）
    return {"account_id": str(ctx.account.id),
            "tenant_id": str(ctx.tenant_id),
            "api_key_id": ctx.api_key_id,
            "api_key_prefix": ctx.api_key_prefix,
            "account_state": ctx.account.state,
            "quotas": ctx.quotas or {},
            "ip_allowlist": (),          # Key 级白名单：由 M01 读侧给出（未实现前留空）
            "policy_version": (ctx.quotas or {}).get("policy_version")}
providers.set_auth_provider(auth_provider)

# ② M04 路由：RouteRequest → 决策（decision_id / chosen / price / node_qps）
def route_provider(request):                    # request: models.RouteRequest
    from app.scheduling import router as scheduling_router   # 或内部 HTTP 客户端
    ...                                          # 返回 dict 或 M04 Decision 对象
providers.set_route_provider(RouteProvider(route_provider))

# ③ 上游节点通道：NodeCall → NodeResult（超时抛 providers.UpstreamTimeout）
providers.set_node_client(node_client)          # M02 节点通道（A1/A2 直连 / B 中继）

# ④ M05 计量：UsageDraft → UsageReceipt（按 request_id 幂等）
providers.set_usage_provider(usage_provider)

# ⑤ M04 模型目录：/v1/models
providers.set_model_catalog_provider(catalog_provider)

# ⑥ M10 配置（可选）：gateway.rate_limit_qps / gateway.stream_timeout_s
config_source.set_provider(lambda: m10_snapshot(namespace="gateway."))
```

**provider 契约要点**

| provider | 入参 | 返回 | 异常约定 |
| --- | --- | --- | --- |
| `set_auth_provider` | `(raw_key, *, now, client_ip, trace_id)` | Mapping / 对象（`coerce_principal` 可吃 M01 `AuthContext`） | M01 `IdentityError`（带 `status_code`/`code`/`reason`）会被 `providers.translate_error` 翻成 M03 码 |
| `set_route_provider` | `.route(RouteRequest)` | Mapping / M04 `Decision` | 无路由抛 `providers.NoRoute` → 503/50901 |
| `set_node_client` | `.complete(NodeCall)` | `NodeResult` / Mapping | 超时抛 `UpstreamTimeout`（→504/50902）、其它抛 `UpstreamFailure`（→502/50903）；未分类异常自动归为上游异常 |
| `set_usage_provider` | `.record(UsageDraft)` | `UsageReceipt` / Mapping | 异常不阻塞 2xx（`request.completed` 由 outbox 至少一次补偿） |
| `set_model_catalog_provider` | `.list_models()` | `[Model, ...]` | 异常 → 503/45001 |

## 2 路由接线（`app/api.py` 由 Lead 统一 include）

```python
from app.gateway.router import router as gateway_router
app.include_router(gateway_router)        # /v1/chat/completions、/v1/models
```

* 生产连接：`app/gateway/router.py::_connection` 默认走 `app.db.conn`（成功提交 / 异常回滚），
  Lead 无需改动。
* 客户端 IP：默认取 `request.client.host`。只有在**确认受信代理**时才注入
  `router.set_client_ip_resolver(fn)` 解析 `X-Forwarded-For`（否则白名单可被伪造）。

## 3 数据库

* 迁移段 **300–399**（`301_api_request_log` / `302_batch_jobs` / `303_batch_items` /
  `304_m03_outbox` / `305_m03_idempotency`），执行器：`python -m app.gateway.migrate --up|--down|--status`。
* 表清单：`api_request_log`、`batch_jobs`、`batch_items`、`m03_outbox`、`m03_idempotency`。
  `m03_idempotency` 是 M03 §3.1 `idempotency_record` 聚合的落库形态，**01-ownership §2 尚未登记**
  → 已在交付证据里作为 CR 上报 Lead（与 CR-1 同类）。
* **只加不改**：3xx 不建 / 不改任何前置对象；回滚只删本模块对象（`tests/gateway/test_migrations.py` 三跑覆盖）。

## 4 后台作业（建议由 M16 调度）

```python
from app.gateway import outbox, idempotency
outbox.set_publisher(lambda event_type, envelope: message_bus.publish(event_type, envelope))
outbox.dispatch_once(c, now=now)                 # 每秒 or 每 5 秒一批（≤100 行，SKIP LOCKED）
idempotency.delete_expired(c, now=now)           # 每小时一次（过期幂等 / 指纹行）
```

* 投递失败按 1s/5s/30s/5min/30min 退避，8 次后留在表里等人工重放（DLQ 语义）。
* `api_request_log` 保留 7 天：由 M14 的保留作业 `DELETE ... WHERE created_at < now() - 7 days`
  （DB 触发器只允许删 7 天以上的行）。

## 5 多实例

* `ratelimit.LIMITER` 是**进程内**滑动窗口。多实例部署时，全局一致限流由 M16 入口层负责；
  M03 的作用域键（`key:<id>` / `tenant:<id>` / `node:<id>`）与 1 秒窗口口径保持不变。
* `m03_outbox` 的 `FOR UPDATE SKIP LOCKED` 已保证多 worker 不抢同一行。

## 6 本任务（T1+T2）未做项

| 项 | 归属 | 现状 |
| --- | --- | --- |
| SSE 流式（`stream=true`） | T3 | 显式 400/40001（开关 `gateway.stream_sse` 默认关） |
| 流式中断计费（44101 / `usage_source=estimated`） | T3 | 错误码已登记，未接线 |
| `/v1/batches*` 提交 / 轮询 / 取消 / webhook | T4 | 表已建（302/303），端点未实现 |
| 协议版本 426/42601、`Sunset` 头 | T4 | `facts.PROTOCOL_VERSION_CURRENT` 已登记 |
| 节点层限流 | 开关 `gateway.node_layer_rate_limit` | 默认关；打开后按决策的 `node_qps` 二次限流 |
