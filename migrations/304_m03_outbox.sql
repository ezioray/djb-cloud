-- 304 · M03 网关 · 事件 outbox（m03_outbox）+ 投递护栏
-- 规格：product/v4/modules/M03-gateway-protocol.md §4.2（request.completed / request.failed）
--       §5「outbox：按 01-ownership §2，生产事件经本模块的 m03_outbox 投递」· §6 事务边界
--       product/v4/modules/02-events.md §1 信封 / §2（本地事务 + outbox / 至少一次 / 退避 / 死信）
--       01-ownership §2「每个模块自己的 outbox 表：<module>_outbox」
--
-- 语义：
--   1) **同事务**：``api_request_log`` 与事件在同一事务里写，事务失败则事件不存在；
--   2) **至少一次**：投递由派发器重试（1s/5s/30s/5min/30min，最多 8 次 → 死信），
--      投递失败不回滚业务（02-events §2.6）；
--   3) **幂等**：``idempotency_key`` 唯一——同一事实重复入队不会产生两条事件；
--   4) **保留**：只有已发布且超过 30 天的行可被清理；未发布行任何 DELETE 一律拒绝。
BEGIN;

CREATE TABLE IF NOT EXISTS m03_outbox (
  event_id        UUID PRIMARY KEY,
  type            TEXT NOT NULL,                 -- 02-events §3（本模块只发 2 个）
  version         INTEGER NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL,
  producer        TEXT NOT NULL,                 -- 'M03'
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    TEXT,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,                 -- 生产侧业务幂等键（唯一）
  payload         JSONB NOT NULL,                -- 只放元数据，不放正文/凭据
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL,
  published_at    TIMESTAMPTZ,                   -- NULL = 待投递
  last_error      TEXT,                          -- 截断后不含堆栈
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE m03_outbox DROP CONSTRAINT IF EXISTS m03_outbox_type_ck;
ALTER TABLE m03_outbox ADD CONSTRAINT m03_outbox_type_ck
  CHECK (type IN ('request.completed', 'request.failed')) NOT VALID;

ALTER TABLE m03_outbox DROP CONSTRAINT IF EXISTS m03_outbox_producer_ck;
ALTER TABLE m03_outbox ADD CONSTRAINT m03_outbox_producer_ck
  CHECK (producer = 'M03') NOT VALID;

ALTER TABLE m03_outbox DROP CONSTRAINT IF EXISTS m03_outbox_attempts_ck;
ALTER TABLE m03_outbox ADD CONSTRAINT m03_outbox_attempts_ck
  CHECK (attempts >= 0 AND attempts <= 8) NOT VALID;

ALTER TABLE m03_outbox DROP CONSTRAINT IF EXISTS m03_outbox_text_ck;
ALTER TABLE m03_outbox ADD CONSTRAINT m03_outbox_text_ck
  CHECK (char_length(type) BETWEEN 1 AND 64
     AND char_length(aggregate_type) BETWEEN 1 AND 64
     AND char_length(aggregate_id) BETWEEN 1 AND 128
     AND char_length(trace_id) BETWEEN 1 AND 128
     AND char_length(idempotency_key) BETWEEN 1 AND 200
     AND version >= 1
     AND (correlation_id IS NULL OR char_length(correlation_id) BETWEEN 1 AND 128)
     AND (causation_id IS NULL OR char_length(causation_id) BETWEEN 1 AND 128)
     AND (last_error IS NULL OR char_length(last_error) <= 200)) NOT VALID;

DROP INDEX IF EXISTS m03_outbox_idempotency_uq;
CREATE UNIQUE INDEX m03_outbox_idempotency_uq ON m03_outbox (idempotency_key);

DROP INDEX IF EXISTS m03_outbox_pending_idx;
CREATE INDEX m03_outbox_pending_idx ON m03_outbox (next_attempt_at) WHERE published_at IS NULL;

DROP INDEX IF EXISTS m03_outbox_aggregate_idx;
CREATE INDEX m03_outbox_aggregate_idx ON m03_outbox (aggregate_id, occurred_at DESC);

DROP INDEX IF EXISTS m03_outbox_published_idx;
CREATE INDEX m03_outbox_published_idx ON m03_outbox (published_at) WHERE published_at IS NOT NULL;

-- ────────────────────────────────────────────────────────── 投递护栏
CREATE OR REPLACE FUNCTION m03_outbox_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['attempts', 'next_attempt_at', 'published_at', 'last_error'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.published_at IS NULL OR OLD.published_at > now() - INTERVAL '30 days' THEN
      RAISE EXCEPTION 'm03_outbox: only published rows older than retention may be deleted'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'm03_outbox: envelope is immutable, only delivery columns may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS NULL THEN
    RAISE EXCEPTION 'm03_outbox: published_at cannot be cleared' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS m03_outbox_guard ON m03_outbox;
CREATE TRIGGER m03_outbox_guard BEFORE UPDATE OR DELETE ON m03_outbox
  FOR EACH ROW EXECUTE FUNCTION m03_outbox_guard();

DROP TRIGGER IF EXISTS m03_outbox_no_truncate ON m03_outbox;
CREATE TRIGGER m03_outbox_no_truncate BEFORE TRUNCATE ON m03_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m03_forbid_truncate();

CREATE OR REPLACE FUNCTION m03_outbox_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.published_at IS NOT NULL OR NEW.attempts <> 0 THEN
    RAISE EXCEPTION 'm03_outbox: new rows must be pending (published_at NULL, attempts 0)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS m03_outbox_insert_guard ON m03_outbox;
CREATE TRIGGER m03_outbox_insert_guard BEFORE INSERT ON m03_outbox
  FOR EACH ROW EXECUTE FUNCTION m03_outbox_insert_guard();

COMMENT ON TABLE m03_outbox IS
  'M03 事件 outbox（迁移 304）：与 api_request_log 同事务写入；至少一次投递；已发布保留 30 天';
COMMENT ON COLUMN m03_outbox.payload IS
  '只放元数据（request_id / model / tokens / latency / node_id / usage_source），不放正文与凭据';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'm03_outbox' AND column_name = 'idempotency_key') THEN
    RAISE EXCEPTION '304: m03_outbox 缺列 idempotency_key';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'm03_outbox_pending_idx') THEN
    RAISE EXCEPTION '304: 缺待投递索引 m03_outbox_pending_idx';
  END IF;
END
$$;

COMMIT;
