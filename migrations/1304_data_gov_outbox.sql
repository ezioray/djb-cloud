-- 1304 · M14 admin-data · 事件 outbox（data_gov_outbox）
-- 规格：02-events §1/§2（本地事务 + outbox；至少一次；event_id 幂等）
--       M14 §6 事务边界（自有 3 表本地事务 + outbox；禁止跨模块事务）
--       01-ownership §2（每个模块自己的 outbox，不共用全局 outbox）
--
-- 说明：这是**事件基础设施表**，不是第 4 张业务表（M14 §5 的三张业务表是
-- data_export_requests / retention_jobs / admin_saved_views）。与 M10/M11/M12/M16 同构。
BEGIN;

CREATE TABLE IF NOT EXISTS data_gov_outbox (
  id              BIGSERIAL PRIMARY KEY,
  event_id        UUID NOT NULL,
  type            TEXT NOT NULL,
  version         INTEGER NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL,
  producer        TEXT NOT NULL DEFAULT 'M14',
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    TEXT,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload         JSONB NOT NULL,
  state           TEXT NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ,
  last_error      TEXT,
  published_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE data_gov_outbox DROP CONSTRAINT IF EXISTS data_gov_outbox_shape_ck;
ALTER TABLE data_gov_outbox ADD CONSTRAINT data_gov_outbox_shape_ck
  CHECK (type IN ('data.export.completed', 'retention.executed')
     AND producer = 'M14'
     AND version >= 1
     AND state IN ('pending', 'published', 'failed')
     AND attempts BETWEEN 0 AND 8
     AND char_length(trace_id) BETWEEN 1 AND 128
     AND char_length(idempotency_key) BETWEEN 16 AND 128
     AND char_length(aggregate_type) BETWEEN 1 AND 64
     AND char_length(aggregate_id) BETWEEN 1 AND 128
     AND jsonb_typeof(payload) = 'object') NOT VALID;

-- 02-events §1：payload 只放事实字段（M14 两条事件的字段白名单，库层兜底）
CREATE OR REPLACE FUNCTION m14_outbox_payload_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  allowed TEXT[];
BEGIN
  allowed := CASE NEW.type
    WHEN 'data.export.completed' THEN ARRAY['export_id', 'requester', 'rows']
    WHEN 'retention.executed' THEN ARRAY['job_id', 'object', 'deleted_count']
    ELSE NULL END;
  IF allowed IS NULL THEN
    RAISE EXCEPTION '未登记事件类型 %（02-events §3）', NEW.type USING ERRCODE = '23514';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.payload) AS k
       WHERE k <> ALL(allowed)) > 0 THEN
    RAISE EXCEPTION '事件 payload 含未登记字段（02-events §1）' USING ERRCODE = '23514';
  END IF;
  IF (SELECT count(*) FROM unnest(allowed) AS a WHERE NOT (NEW.payload ? a)) > 0 THEN
    RAISE EXCEPTION '事件 payload 缺字段（02-events §1）' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

-- 信封不可改：只允许投递状态字段（state / attempts / next_attempt_at / last_error / published_at）
CREATE OR REPLACE FUNCTION m14_outbox_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.type IS DISTINCT FROM OLD.type
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
     OR NEW.producer IS DISTINCT FROM OLD.producer
     OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
     OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
     OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
     OR NEW.causation_id IS DISTINCT FROM OLD.causation_id
     OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.payload IS DISTINCT FROM OLD.payload THEN
    RAISE EXCEPTION 'outbox 事件信封不可改（02-events §1）' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS data_gov_outbox_payload_guard ON data_gov_outbox;
CREATE TRIGGER data_gov_outbox_payload_guard BEFORE INSERT ON data_gov_outbox
  FOR EACH ROW EXECUTE FUNCTION m14_outbox_payload_guard();
DROP TRIGGER IF EXISTS data_gov_outbox_guard ON data_gov_outbox;
CREATE TRIGGER data_gov_outbox_guard BEFORE UPDATE ON data_gov_outbox
  FOR EACH ROW EXECUTE FUNCTION m14_outbox_guard();
DROP TRIGGER IF EXISTS data_gov_outbox_no_delete ON data_gov_outbox;
CREATE TRIGGER data_gov_outbox_no_delete BEFORE DELETE ON data_gov_outbox
  FOR EACH ROW EXECUTE FUNCTION m14_forbid_delete();
DROP TRIGGER IF EXISTS data_gov_outbox_no_truncate ON data_gov_outbox;
CREATE TRIGGER data_gov_outbox_no_truncate BEFORE TRUNCATE ON data_gov_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m14_forbid_truncate();

DROP INDEX IF EXISTS uq_data_gov_outbox_event_id;
CREATE UNIQUE INDEX uq_data_gov_outbox_event_id ON data_gov_outbox (event_id);
DROP INDEX IF EXISTS uq_data_gov_outbox_idempotency;
CREATE UNIQUE INDEX uq_data_gov_outbox_idempotency ON data_gov_outbox (idempotency_key);
DROP INDEX IF EXISTS idx_data_gov_outbox_pending;
CREATE INDEX idx_data_gov_outbox_pending ON data_gov_outbox (state, next_attempt_at);
DROP INDEX IF EXISTS idx_data_gov_outbox_aggregate;
CREATE INDEX idx_data_gov_outbox_aggregate ON data_gov_outbox (aggregate_type, aggregate_id);

DO $$
DECLARE
  missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO missing
    FROM unnest(ARRAY['id','event_id','type','version','occurred_at','producer',
                      'aggregate_type','aggregate_id','correlation_id','causation_id',
                      'trace_id','idempotency_key','payload','state','attempts',
                      'next_attempt_at','last_error','published_at','created_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'data_gov_outbox' AND column_name = c);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'data_gov_outbox 结构与 1304 不符，缺列：%', missing;
  END IF;
END;
$$;

COMMIT;
