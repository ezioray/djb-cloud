# M03 gateway-protocol · 合并接线说明（WIRING）

> 本文件是给 **Lead 合并时**用的接线清单。M03 自身**不 import** 任何其它业务模块，
> 所有跨模块依赖都走 `app/gateway/providers.py` 与 `app/gateway/config_source.py`
> 的注入点；**默认 fail-closed**（未注入时鉴权 / 路由 / 上游一律 503）。

## 1 provider 清单（T1–T4 共 9 个）

必需（缺 → 503 fail-closed）：`auth` / `route` / `node` / `stream` / `model_catalog` /
`usage`（用量写失败不阻塞 2xx）。可选（缺 → 该能力降级，不影响主链路）：
`webhook_sender` + `webhook_secret`（批次回调）、`result_signer`（批次结果 URL）。

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

# ④b 上游流式通道（T3）：NodeCall → 分块迭代器（每块 StreamChunk / Mapping / 文本增量）
providers.set_stream_client(stream_client)

# ⑦ 批次结果签名 URL（T4，可选）：(batch_id, expires_at) -> url（TTL ≤15 分钟）
providers.set_result_signer(result_signer)

# ⑧ 对外 webhook（T4，可选）：sender(url, body, headers) -> status；secret(account_id) -> 密钥引用
providers.set_webhook_sender(http_sender)
providers.set_webhook_secret_provider(secret_lookup)   # 密钥本体不得进日志

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
| `set_stream_client` | `.stream(NodeCall)` | 分块迭代器 | 首字节前 `UpstreamTimeout` → 504/50902、`UpstreamFailure` → 502/50903（≤2 次重路由）；首字节后异常 → interrupted + 44101 |
| `set_result_signer` | `(batch_id, expires_at)` | URL 字符串 / None | 未接线 → 响应里不给 `results_ref` |
| `set_webhook_sender` | `(url, body, headers)` | HTTP 状态码 | 抛异常 → 计一次失败并退避重试（≤3 次） |
| `set_webhook_secret_provider` | `(account_id)` | 密钥字符串 / None | None → 不投递（skipped），**绝不发未签名回调** |

## 2 路由接线（`app/api.py` 由 Lead 统一 include）

```python
from app.gateway.router import router as gateway_router
app.include_router(gateway_router)
# /v1/chat/completions（JSON / SSE）、/v1/models、/v1/batches、/v1/batches/{id}、
# /v1/batches/{id}/cancel
```

* 生产连接：`app/gateway/router.py::_connection` 默认走 `app.db.conn`（成功提交 / 异常回滚），
  Lead 无需改动。
* 客户端 IP：默认取 `request.client.host`。只有在**确认受信代理**时才注入
  `router.set_client_ip_resolver(fn)` 解析 `X-Forwarded-For`（否则白名单可被伪造）。

## 3 数据库

* 迁移段 **300–399**（`301_api_request_log` / `302_batch_jobs` / `303_batch_items` /
  `304_m03_outbox` / `305_m03_idempotency` / `306_batch_webhook_state`），
  执行器：`python -m app.gateway.migrate --up|--down|--status`。
* `306` 给 `batch_jobs` 加 4 个 webhook 台账列，并把状态机护栏的「终态可变列」放宽到
  投递台账（业务列仍冻结）；回滚会恢复 302 的护栏。
* 表清单：`api_request_log`、`batch_jobs`、`batch_items`、`m03_outbox`、`m03_idempotency`。
  `m03_idempotency` 是 M03 §3.1 `idempotency_record` 聚合的落库形态，**01-ownership §2 尚未登记**
  → 已在交付证据里作为 CR 上报 Lead（与 CR-1 同类）。
* **只加不改**：3xx 不建 / 不改任何前置对象；回滚只删本模块对象（`tests/gateway/test_migrations.py` 三跑覆盖）。

## 4 批次执行 worker（T4 交付的**内部 API**，不是 HTTP 端点）

```python
from app.gateway import batches
batches.advance(c, batch_id=bid, status="running", now=now)                 # queued → running
batches.advance(c, batch_id=bid, status="running", checkpoint_resumes=1)    # 检查点恢复
batches.advance(c, batch_id=bid, status="succeeded", completed=n,
                cost_actual_minor=minor, now=now)                            # 终态 + 签发 results_ref
```

* 终态不可逆（`succeeded` / `failed` / `canceled`）；重复推进同状态不报错。
* 终态会按闸门 `gateway.batch_webhook_delivery` 投递 `batch.completed` / `batch.failed`。
* **item 级执行循环不在本任务范围**（T4 交付提交/轮询/取消/状态机/webhook；worker 的
  per-item 派发与检查点实现由 M16 调度接 `advance` 驱动，登记为未做项）。

## 5 后台作业（建议由 M16 调度）

```python
from app.gateway import outbox, idempotency
outbox.set_publisher(lambda event_type, envelope: message_bus.publish(event_type, envelope))
outbox.dispatch_once(c, now=now)                 # 每秒 or 每 5 秒一批（≤100 行，SKIP LOCKED）
idempotency.delete_expired(c, now=now)           # 每小时一次（过期幂等 / 指纹行）
```

* 投递失败按 1s/5s/30s/5min/30min 退避，8 次后留在表里等人工重放（DLQ 语义）。
* `api_request_log` 保留 7 天：由 M14 的保留作业 `DELETE ... WHERE created_at < now() - 7 days`
  （DB 触发器只允许删 7 天以上的行）。

## 6 对外 webhook 契约（客户侧实现依据）

```
POST <webhook_url>
X-DJB-Event: batch.queued | batch.started | batch.checkpoint_restored | batch.completed | batch.failed | batch.eta_updated
X-DJB-Timestamp: <unix 秒>
X-DJB-Signature: hmac-sha256=<hex(hmac_sha256(secret, f"{timestamp}." + raw_body))>
Content-Type: application/json

{ "event": "...", "batch_id": "...", "account_id": "...", "status": "...",
  "progress": {"completed": 0, "total": 3}, "eta_seconds": 42, "checkpoint_resumes": 0,
  "cost": {"estimated": {"amount": "5.00", "unit": "USD"}}, "occurred_at": "...Z" }
```

客户端必须：① 校验签名（密钥按账户下发，**不经 M03 保管**）；② 校验时间窗 ±300s 防重放；
③ 幂等处理（同一事件可能重投，最多 3 次）。M03 侧台账在 `batch_jobs.webhook_*` 四列。

## 7 多实例

* `ratelimit.LIMITER` 是**进程内**滑动窗口。多实例部署时，全局一致限流由 M16 入口层负责；
  M03 的作用域键（`key:<id>` / `tenant:<id>` / `node:<id>`）与 1 秒窗口口径保持不变。
* `m03_outbox` 的 `FOR UPDATE SKIP LOCKED` 已保证多 worker 不抢同一行。

## 8 未做项与开关（T1–T4 收口时）

| 项 | 归属 | 现状 |
| --- | --- | --- |
| 批次 item 级执行 / 检查点持久化 | M16 调度（T4+） | 只提供 `batches.advance` worker API；per-item 派发未实现 |
| 结果分片存储（`results_ref` 指向的对象） | M14/M16 存储 | 网关只签发 URL（注入 `result_signer`），不存结果体 |
| webhook 按次投递审计表 | CR（未批准） | 台账暂存 `batch_jobs.webhook_*` 四列 |
| 节点层限流 | 开关 `gateway.node_layer_rate_limit` | 默认关；打开后按决策 `node_qps` 二次限流 |
| 流式中断后由网关写估算用量 | 开关 `gateway.stream_estimated_usage_sync` | 默认关：只标记 interrupted + 事件，M05 用收据/账单校正 |
| 批次 webhook 实际投递 | 开关 `gateway.batch_webhook_delivery` | 默认关：状态变化只落库，可重放 |
| 协议版本严格模式（426） | 开关 `gateway.protocol_version_strict` | 默认关：不兼容版本只记日志 |
| `Sunset` 弃用头 | M03（预留） | `protocol.sunset_header()` 已实现，S1 无弃用版本 |
