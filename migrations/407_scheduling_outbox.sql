-- 407 · M04 scheduler-pricing · 事件出站（scheduling_outbox）
-- 规格：M04 §4.2 事件（quote.created / quote.expired / booking.created / booking.expired /
--       routing.decided）· §5 数据所有权（CR-4 已裁决：登记为 M04 辅助表）
--       02-events §1 信封 / §2 至少一次（本地事务 + outbox）/ §3 事件目录
--       01-ownership §2「每个模块自己的 outbox 表」
--
-- 设计（与 205 supply_outbox / 604 m06_outbox / 1005 config_outbox 同款）：
--   1) 写入只追加：DELETE 拒绝；唯一允许的变化是投递状态列
--      （published_at / attempts / next_attempt_at / last_error）。
--   2) 事件契约在库里兜底：type 白名单（本模块只生产这 5 个）、producer 固定 M04、
--      aggregate_type 与 type 对应、payload 必含 02-events §3 的业务键（缺键即写入失败）。
--   3) 幂等：idempotency_key 唯一（消费侧按 event_id 幂等，生产侧按业务键去重）。
--   4) 退避：1s / 5s / 30s / 5min / 30min，最多 8 次（02-events §2.3），由 app/scheduling/outbox.py 计算。
BEGIN;

CREATE TABLE IF NOT EXISTS scheduling_outbox (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- 消费侧幂等键（02-events §1）
  type            TEXT NOT NULL,
  version         INT  NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  producer        TEXT NOT NULL DEFAULT 'M04',
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,                               -- 同 aggregate 内有序
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload         JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at    TIMESTAMPTZ,                                 -- NULL = 待投递
  attempts        INT NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error      TEXT,

  CONSTRAINT scheduling_outbox_idem_uq UNIQUE (idempotency_key),
  CONSTRAINT scheduling_outbox_version_ck CHECK (version >= 1),
  CONSTRAINT scheduling_outbox_producer_ck CHECK (producer = 'M04'),
  CONSTRAINT scheduling_outbox_attempts_ck CHECK (attempts BETWEEN 0 AND 8),
  CONSTRAINT scheduling_outbox_type_ck CHECK (
    type IN ('quote.created', 'quote.expired', 'booking.created', 'booking.expired',
             'routing.decided')),
  CONSTRAINT scheduling_outbox_aggregate_type_ck CHECK (
    (type IN ('quote.created', 'quote.expired') AND aggregate_type = 'quote')
    OR (type IN ('booking.created', 'booking.expired') AND aggregate_type = 'booking')
    OR (type = 'routing.decided' AND aggregate_type = 'routing_decision')),
  CONSTRAINT scheduling_outbox_aggregate_id_ck CHECK (char_length(aggregate_id) BETWEEN 1 AND 128),
  CONSTRAINT scheduling_outbox_trace_ck CHECK (char_length(trace_id) BETWEEN 1 AND 128),
  CONSTRAINT scheduling_outbox_idem_len_ck CHECK (char_length(idempotency_key) BETWEEN 1 AND 200),
  CONSTRAINT scheduling_outbox_payload_object_ck CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT scheduling_outbox_error_len_ck
    CHECK (last_error IS NULL OR char_length(last_error) <= 500),
  -- 02-events §3：每个事件的必含业务键（值可为 null，但键必须在）
  CONSTRAINT scheduling_outbox_payload_ck CHECK (
    (type IN ('quote.created', 'quote.expired')
       AND payload ?& ARRAY['quote_id', 'node_id', 'model', 'price_minor', 'ttl_s'])
    OR (type IN ('booking.created', 'booking.expired')
       AND payload ?& ARRAY['booking_id', 'node_id', 'request_id', 'expires_at'])
    OR (type = 'routing.decided'
       AND payload ?& ARRAY['request_id', 'node_id', 'reason_codes', 'snapshot_id'])
  )
);

CREATE INDEX IF NOT EXISTS scheduling_outbox_pending_idx
  ON scheduling_outbox (next_attempt_at, created_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS scheduling_outbox_aggregate_idx
  ON scheduling_outbox (aggregate_type, aggregate_id, created_at);

-- 投递状态是唯一可变部分；DELETE 永久拒绝（事件不可消失）
CREATE OR REPLACE FUNCTION m04_outbox_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'scheduling_outbox 只追加：禁止 DELETE（02-events §2）';
  END IF;

  IF NEW.event_id <> OLD.event_id
     OR NEW.type <> OLD.type
     OR NEW.version <> OLD.version
     OR NEW.occurred_at <> OLD.occurred_at
     OR NEW.producer <> OLD.producer
     OR NEW.aggregate_type <> OLD.aggregate_type
     OR NEW.aggregate_id <> OLD.aggregate_id
     OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
     OR NEW.causation_id IS DISTINCT FROM OLD.causation_id
     OR NEW.trace_id <> OLD.trace_id
     OR NEW.idempotency_key <> OLD.idempotency_key
     OR NEW.payload IS DISTINCT FROM OLD.payload
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'scheduling_outbox 只追加：只有投递状态列可变';
  END IF;

  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scheduling_outbox_guard_trg ON scheduling_outbox;
CREATE TRIGGER scheduling_outbox_guard_trg
  BEFORE UPDATE OR DELETE ON scheduling_outbox
  FOR EACH ROW EXECUTE FUNCTION m04_outbox_guard();

COMMENT ON TABLE scheduling_outbox IS
  'M04 事件出站（CR-4 登记）：本地事务内写入，至少一次投递，消费侧按 event_id 幂等';
COMMENT ON COLUMN scheduling_outbox.published_at IS 'NULL = 待投递；非 NULL = 已投递（只允许单向置位）';
COMMENT ON COLUMN scheduling_outbox.attempts IS '已投递尝试次数（0–8；超限进 DLQ 人工重放）';

COMMIT;
