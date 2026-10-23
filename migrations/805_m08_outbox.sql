-- 805 · M08 事件发件箱（m08_outbox）
-- 规格：M08 §4.2 事件表 · 02-events.md §1（信封）/ §2（本地事务 + outbox，至少一次）/
--       §3（事件目录）/ §5（按 event_id 幂等）
--
-- 说明：
--   1) m08_outbox 是**基础设施表**（02-events §2）：业务写入与事件入队同事务；
--   2) type 只允许 02-events §3 已登记的 9 个 M08 事件（未登记事件写不进来）；
--   3) 信封不可改写；投递状态机 pending → published / dead；重试 1s/5s/30s/5m/30m，8 次进 dead；
--   4) payload 禁止出现正文 / 密钥 / 完整签名 / 卡号 / 助记词（库层 CHECK 兜底）。
BEGIN;

CREATE TABLE IF NOT EXISTS m08_outbox (
  id              BIGSERIAL PRIMARY KEY,
  event_id        UUID NOT NULL UNIQUE,                   -- 信封 event_id（UUIDv7；消费幂等键）
  type            TEXT NOT NULL,
  version         INTEGER NOT NULL DEFAULT 1,
  producer        TEXT NOT NULL DEFAULT 'M08',
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT,
  idempotency_key TEXT NOT NULL UNIQUE,                   -- 生产侧业务幂等键
  payload         JSONB NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ,
  published_at    TIMESTAMPTZ,
  last_error      TEXT,
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT m08_outbox_type_ck CHECK (type IN
    ('payment.created', 'payment.paid', 'payment.failed', 'wallet.switched', 'sweep.completed',
     'payout.paid', 'refund.completed', 'signing.requested', 'signing.signed')),
  CONSTRAINT m08_outbox_status_ck CHECK (status IN ('pending', 'published', 'dead')),
  CONSTRAINT m08_outbox_version_ck CHECK (version >= 1),
  CONSTRAINT m08_outbox_attempts_ck CHECK (attempts BETWEEN 0 AND 8),
  CONSTRAINT m08_outbox_aggregate_ck CHECK (char_length(aggregate_id) BETWEEN 1 AND 128),
  -- 零密钥 / 零正文 / 零完整签名（02-events §1 / 05-security §1 S6-S7）
  CONSTRAINT m08_outbox_payload_ck CHECK (
    NOT (payload ?| ARRAY['card', 'card_no', 'pan', 'cvv', 'secret', 'private_key', 'mnemonic',
                          'seed', 'signature', 'prompt', 'response', 'email', 'phone',
                          'raw_body']))
);

CREATE INDEX IF NOT EXISTS m08_outbox_pending_idx
  ON m08_outbox (status, next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS m08_outbox_aggregate_idx
  ON m08_outbox (aggregate_type, aggregate_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS m08_outbox_type_idx
  ON m08_outbox (type, occurred_at DESC);

COMMENT ON TABLE m08_outbox IS
  'M08 事件发件箱：只允许 02-events 已登记的 9 个 M08 事件；与业务写入同事务；payload 零密钥/正文';

CREATE OR REPLACE FUNCTION m08_outbox_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'm08_outbox 只追加：禁止 DELETE（投递失败进 dead，人工重放）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.type IS DISTINCT FROM OLD.type
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.payload IS DISTINCT FROM OLD.payload
     OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at THEN
    RAISE EXCEPTION 'm08_outbox 信封不可改写（02-events §1）' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_outbox_guard ON m08_outbox;
CREATE TRIGGER m08_outbox_guard BEFORE UPDATE OR DELETE ON m08_outbox
  FOR EACH ROW EXECUTE FUNCTION m08_outbox_guard();

DROP TRIGGER IF EXISTS m08_outbox_no_truncate ON m08_outbox;
CREATE TRIGGER m08_outbox_no_truncate BEFORE TRUNCATE ON m08_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

COMMIT;
