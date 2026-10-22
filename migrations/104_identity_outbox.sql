-- 104 · M01 事件 outbox（01-ownership §2：每个模块自己的 <module>_outbox，不共用全局表）
-- 信封字段对齐 02-events §1；生产事件目录见 M01 §4.2 与 02-events §3。
-- 本地事务 + outbox：状态 / Key / 角色 / 配额的每次写都在同事务落一条事件（M01 §6 事务边界）。
-- 幂等：idempotency_key 唯一 —— 到期解冻 job 重放两次只产生一条 account.state.changed（A2）。
-- 回滚：见 app/identity/migrate.py 的 DOWN_SQL。
BEGIN;

CREATE TABLE IF NOT EXISTS identity_outbox (
  seq             BIGSERIAL PRIMARY KEY,
  event_id        UUID NOT NULL,
  type            TEXT NOT NULL,
  version         INTEGER NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  producer        TEXT NOT NULL DEFAULT 'M01',
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload         JSONB NOT NULL,
  published_at    TIMESTAMPTZ,
  CONSTRAINT identity_outbox_event_uq UNIQUE (event_id),
  CONSTRAINT identity_outbox_idem_uq UNIQUE (idempotency_key),
  CONSTRAINT identity_outbox_producer_chk CHECK (producer = 'M01'),
  CONSTRAINT identity_outbox_version_chk CHECK (version >= 1),
  CONSTRAINT identity_outbox_type_chk CHECK (type IN (
    'account.created', 'account.state.changed',
    'apikey.created', 'apikey.revoked', 'session.revoked')),
  CONSTRAINT identity_outbox_payload_chk CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS identity_outbox_unpublished_idx ON identity_outbox (seq)
  WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS identity_outbox_aggregate_idx
  ON identity_outbox (aggregate_type, aggregate_id, seq);

COMMIT;
