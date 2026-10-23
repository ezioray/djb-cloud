# 02 事件契约（跨模块异步通信）

> 事件只用于“已经发生的事实”，不用于命令。需要同步结果时走 API；需要别人跟进时发事件。
> 生产事件前先在本文登记；未登记的事件不得上线。

---

## 1 事件信封

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| event_id | uuid | 是 | UUIDv7；全局唯一；消费幂等键 |
| type | string | 是 | 领域.对象.动作（过去式），见 §3 目录 |
| version | int | 是 | 从 1 开始；破坏性变更 +1 |
| occurred_at | timestamptz | 是 | 事实发生时间（UTC） |
| producer | string | 是 | 模块 ID，如 M08 |
| aggregate_type | string | 是 | 聚合根类型，如 payment_order |
| aggregate_id | string | 是 | 聚合根 ID；用于分区与顺序 |
| correlation_id | string | 否 | 关联的业务单号（order_no / batch_no） |
| causation_id | string | 否 | 触发本事件的上一条 event_id |
| trace_id | string | 是 | 全链路追踪 |
| idempotency_key | string | 是 | 生产侧业务幂等键，如 payment_order:paid:<id> |
| payload | object | 是 | 只放事实字段；schema 见 §3 |

**硬规则**：payload 不放大段正文、不放 prompt/response、不放密钥/PII；金额用 amount_minor + currency。

---

## 2 投递语义

1. **至少一次**：生产侧本地事务 + outbox；投递可能重复，消费侧必须按 event_id 幂等。
2. **顺序**：同一 aggregate_id 内有序；跨聚合不保证顺序。
3. **重试**：指数退避 1s/5s/30s/5min/30min，最多 8 次；之后进死信（DLQ）并告警。
4. **死信**：只能人工重放；重放前先确认消费幂等与业务状态。
5. **回放**：按 type + 时间范围回放；回放事件保留原 event_id（消费侧不会重复落账）。
6. **不阻塞主链路**：事件投递失败不得回滚已提交的业务事务；由 outbox 补偿。

---

## 3 事件目录（首批）

| 事件 | 生产者 | 关键 payload | 主要消费者 |
| --- | --- | --- | --- |
| account.created | M01 | account_id, type, tenant_id | M08 M11 M12 |
| account.state.changed | M01 | account_id, from, to, frozen_until | M03 M08 M11 |
| apikey.created / apikey.revoked | M01 | api_key_id, account_id, prefix | M03 M11 |
| session.revoked | M01 | session_id, account_id, epoch, reason | M03 M08 M11 M12 M14 |
| node.registered | M02 | node_id, account_id, protocols, region | M04 M11 |
| node.state.changed | M02 | node_id, from, to, reason | M03 M04 M11 |
| node.upstream.changed | M02 | node_id, upstream_type, state | M04 |
| capacity.announced | M02 | node_id, models, gpu, ram, expires_at | M04 |
| request.completed | M03 | request_id, model, tokens_in/out, latency_ms, node_id | M05 M11 |
| request.failed | M03 | request_id, error_code, upstream_error_class | M05 M11 |
| batch.queued / batch.started / batch.checkpoint_restored / batch.completed / batch.failed / batch.eta_updated | M03 | batch_id, account_id, status, progress, eta_seconds, cost_estimate/actual | 外部 webhook · M14 |
| quote.created / quote.expired | M04 | quote_id, model, price, ttl_s | M03 |
| booking.created / booking.expired | M04 | booking_id, node_id, request_id, expires_at | M03 M05 |
| routing.decided | M04 | request_id, node_id, reason_codes, snapshot_id | M03 M16 |
| usage.recorded | M05 | usage_id, account_id, request_id, amount_minor, source | M06 M07 M09 |
| receipt.signed | M05 | receipt_id, usage_id, node_id, signature_ref | M06 M09 |
| usage.settled | M05 | usage_id, final_amount_minor, correction_id | M06 M07 |
| journal.posted | M06 | journal_id, event_type, amount_minor, ref_id | M08 M09 M14 |
| ledger.reversed | M06 | journal_id, reverse_of, reason_code | M08 M09 |
| merkle.anchored | M06 | root, kind, period, anchored_at | M09 M16 |
| reputation.changed | M07 | account_id, score, tier, reasons | M04 M08 |
| cop.earned / cop.spent | M07 | account_id, amount, source, ref_id | M04 M08 M12 |
| invite.bound | M07 | inviter_id, invitee_id, code | M08 |
| payment.created | M08 | order_no, amount_minor, method | M09 M12 |
| payment.paid | M08 | order_no, paid_at, provider_ref | M06 M09 M12 |
| payment.failed | M08 | order_no, error_code | M09 M12 |
| wallet.switched | M08 | pool_id, from_wallet, to_wallet, reason | M09 M14 |
| sweep.completed | M08 | batch_no, from_wallet, to_wallet, amount_minor, txid | M09 |
| payout.paid | M08 | batch_no, item_count, total_minor, txid | M06 M09 M12 |
| refund.completed | M08 | refund_no, order_no, amount_minor, method | M06 M09 M12 |
| signing.requested / signing.signed | M08 | intent_id, signer_type, signed_at | M09 M14 |
| recon.completed | M09 | run_id, period, p0/p1/p2 counts | M08 M14 |
| exception.opened / exception.closed | M09 | exception_id, severity, amount_minor | M08 M11 M14 |
| por.published | M09 | snapshot_id, coverage_pct, merkle_root | M14 M12 |
| config.published / config.rolled_back | M10 | namespace, key, version, risk_level | 全部 |
| config.drift_detected | M10 | namespace, key, expected, actual | M14 M16 |
| risk.case.opened / risk.case.closed | M11 | case_id, subject_id, risk_type, severity | M03 M04 M08 M12 |
| risk.limit.hit | M11 | subject_id, limit_type, value | M03 M04 M08 |
| risk.action.requested | M11 | case_id, subject_type, subject_id, action, reason_code | M01 M02 M08 |
| risk.action.executed | M01/M02/M08 | case_id, subject_id, action, result | M11 M14 |
| ticket.created / ticket.updated / ticket.closed | M14 | ticket_id, severity, state, assignee | M12 M14 |
| notification.requested | M12 | notification_id, template, recipients | 站内/邮件/Webhook |
| notification.delivered / notification.failed | M12 | notification_id, channel, attempt | M14 |
| data.export.completed | M14 | export_id, requester, rows | M16 |
| retention.executed | M14 | job_id, object, deleted_count | M16 |
| audit.appended | M16 | audit_id, actor, action, hash | M14 |
| deploy.completed / backup.completed | M16 | run_id, env, status | M14 M12 |

> 新增事件必须同时在 01-ownership 与本文登记；payload 字段以模块规格为准，但必须遵守信封规则。
>
> **node.registered 的 account_id 允许为 null**：S1 先注册（pending_review）后网页绑定，首次注册事件无归属账户；
> 归属以随后的 `node.state.changed(reason=bound)` 为准。消费方（M04/M11）不得用 node.registered.account_id 建非空索引。

---

## 4 版本与兼容

1. 只加字段、不删字段、不改类型；新增必填字段 = 破坏性变更，必须升 version 并双写至少一个周期。
2. 消费方必须容忍未知字段（tolerant reader）；不得因未知字段失败。
3. 事件 schema 放在 contracts/events/<type>.v<version>.json；CI 校验生产/消费双方。
4. 废弃事件保留 ≥2 个 MAJOR 周期，并在 02-events 标注 deprecated。

---

## 5 消费方要求

- 幂等：event_id 唯一索引 + 业务幂等键。
- 事务：消费与本地状态在同一事务；失败重试不产生半成品。
- 毒消息：解析失败进 DLQ，不阻塞分区。
- 可观测：消费延迟、失败率、DLQ 数量必须有指标与告警。
- 测试：每个事件至少一条 schema 测试 + 一条幂等重放测试。
