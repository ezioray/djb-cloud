-- 205 · M02 node-supply · 事件出站（supply_outbox）
-- 规格：M02 §4.2 事件（生产 4 个：node.registered / node.state.changed /
--       node.upstream.changed / capacity.announced）· §5 数据所有权（保留 7 天）
--       02-events §1 信封 / §2 至少一次（本地事务 + outbox）/ §3 事件目录
--       01-ownership §2「每个模块自己的 outbox 表」
--
-- 设计（与 604 m06_outbox / 1005 config_outbox 同款）：
--   1) 写入只追加：DELETE 拒绝；唯一允许的变化是 published_at 由 NULL 置为投递完成时刻。
--   2) 事件契约在库里兜底：type 白名单（本模块只生产这四个）、producer 固定 M02、
--      aggregate_type 固定 node、payload 必含 02-events §3 的业务键（缺键即写入失败）。
--   3) 投递失败不得回滚已提交的业务事务（02-events §2.6），由 outbox 补偿。
BEGIN;

CREATE TABLE IF NOT EXISTS supply_outbox (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- 消费侧幂等键（02-events §1）
  type            TEXT NOT NULL,
  version         INT  NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  producer        TEXT NOT NULL DEFAULT 'M02',
  aggregate_type  TEXT NOT NULL DEFAULT 'node',
  aggregate_id    TEXT NOT NULL,                               -- node_id（同 node 内有序）
  correlation_id  TEXT,
  causation_id    UUID,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload         JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at    TIMESTAMPTZ,                                 -- NULL = 待投递

  CONSTRAINT supply_outbox_idem_uq UNIQUE (idempotency_key),
  CONSTRAINT supply_outbox_version_ck CHECK (version >= 1),
  CONSTRAINT supply_outbox_producer_ck CHECK (producer = 'M02'),
  CONSTRAINT supply_outbox_aggregate_type_ck CHECK (aggregate_type = 'node'),
  CONSTRAINT supply_outbox_type_ck CHECK (
    type IN ('node.registered', 'node.state.changed',
             'node.upstream.changed', 'capacity.announced')),
  CONSTRAINT supply_outbox_aggregate_id_ck CHECK (char_length(aggregate_id) BETWEEN 1 AND 128),
  CONSTRAINT supply_outbox_trace_ck CHECK (char_length(trace_id) BETWEEN 1 AND 128),
  CONSTRAINT supply_outbox_idem_len_ck CHECK (char_length(idempotency_key) BETWEEN 1 AND 200),
  CONSTRAINT supply_outbox_payload_object_ck CHECK (jsonb_typeof(payload) = 'object'),
  -- 02-events §3：每个事件的必含业务键（值可为 null，但键必须在）
  CONSTRAINT supply_outbox_payload_ck CHECK (
    (type = 'node.registered'
       AND payload ?& ARRAY['node_id', 'account_id', 'protocols', 'region'])
    OR (type = 'node.state.changed'
       AND payload ?& ARRAY['node_id', 'from', 'to', 'reason'])
    OR (type = 'node.upstream.changed'
       AND payload ?& ARRAY['node_id', 'upstream_type', 'state'])
    OR (type = 'capacity.announced'
       AND payload ?& ARRAY['node_id', 'models', 'gpu', 'ram', 'expires_at'])
  )
);

CREATE INDEX IF NOT EXISTS supply_outbox_pending_idx
  ON supply_outbox (created_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS supply_outbox_aggregate_idx
  ON supply_outbox (aggregate_type, aggregate_id, created_at);

-- 投递标记：只允许 published_at 由 NULL 变非 NULL；DELETE 永远拒绝
CREATE OR REPLACE FUNCTION m02_outbox_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'supply_outbox 只追加：禁止 DELETE（02-events §2）';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.published_at IS NULL AND NEW.published_at IS NOT NULL
       AND NEW.event_id = OLD.event_id
       AND NEW.type = OLD.type
       AND NEW.version = OLD.version
       AND NEW.occurred_at = OLD.occurred_at
       AND NEW.producer = OLD.producer
       AND NEW.aggregate_type = OLD.aggregate_type
       AND NEW.aggregate_id = OLD.aggregate_id
       AND NEW.correlation_id IS NOT DISTINCT FROM OLD.correlation_id
       AND NEW.causation_id IS NOT DISTINCT FROM OLD.causation_id
       AND NEW.trace_id = OLD.trace_id
       AND NEW.idempotency_key = OLD.idempotency_key
       AND NEW.payload = OLD.payload
       AND NEW.created_at = OLD.created_at
    THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'supply_outbox 只允许把 published_at 由 NULL 置为投递时刻';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS supply_outbox_guard_trg ON supply_outbox;
CREATE TRIGGER supply_outbox_guard_trg
  BEFORE UPDATE OR DELETE ON supply_outbox
  FOR EACH ROW EXECUTE FUNCTION m02_outbox_guard();

COMMIT;
