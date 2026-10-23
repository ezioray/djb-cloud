-- 506 · M05 计量收据 · 事件 outbox（metering_outbox）+ 投递护栏
-- 规格：product/v4/modules/M05-metering-receipt.md §5 数据所有权（metering_outbox，迁移 506，
--       保留「已发布 30 天」）· §4.2 事件 · §6 流程 1 第 4 步
--       product/v4/modules/02-events.md §2（本地事务 + outbox / 至少一次 / 退避 / 死信）
--       CR-5 已批准：事件与 usage/receipt 同事务写 outbox
--
-- 语义：
--   1) **同事务**：受理收据 / 落 usage 的那个事务里一起写 outbox，事务失败则事件也不存在；
--   2) **至少一次**：投递由派发器重试（1s/5s/30s/5min/30min，最多 8 次 → 死信），
--      投递失败不回滚业务（02-events §2.6）；
--   3) **幂等**：``idempotency_key`` 唯一——同一事实重复入队不会产生两条事件；
--      消费侧再按 event_id 幂等（02-events §2.1）；
--   4) **保留**：只有已发布且超过 30 天的行可被清理（append-only 语义下的唯一 DELETE 例外），
--      未发布行任何 DELETE 一律拒绝。
BEGIN;

CREATE TABLE IF NOT EXISTS metering_outbox (
  event_id        UUID PRIMARY KEY,
  type            TEXT NOT NULL,                 -- 02-events §3（本模块只发 3 个）
  version         INTEGER NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL,
  producer        TEXT NOT NULL,                 -- 'M05'
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT NOT NULL,
  correlation_id  TEXT,
  causation_id    TEXT,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,                 -- 生产侧业务幂等键（唯一）
  payload         JSONB NOT NULL,                -- 只放事实与金额，不放正文/凭据
  attempts        INTEGER NOT NULL DEFAULT 0,    -- 已尝试投递次数
  next_attempt_at TIMESTAMPTZ NOT NULL,          -- 下次重试时刻（退避）
  published_at    TIMESTAMPTZ,                   -- 投递成功时刻（NULL = 待投递）
  last_error      TEXT,                          -- 最近一次失败原因（截断，不含堆栈）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 事件白名单：本模块只发 02-events §3 里登记的三个事件
ALTER TABLE metering_outbox DROP CONSTRAINT IF EXISTS metering_outbox_type_ck;
ALTER TABLE metering_outbox ADD CONSTRAINT metering_outbox_type_ck
  CHECK (type IN ('receipt.signed', 'usage.recorded', 'usage.settled')) NOT VALID;

ALTER TABLE metering_outbox DROP CONSTRAINT IF EXISTS metering_outbox_producer_ck;
ALTER TABLE metering_outbox ADD CONSTRAINT metering_outbox_producer_ck
  CHECK (producer = 'M05') NOT VALID;

ALTER TABLE metering_outbox DROP CONSTRAINT IF EXISTS metering_outbox_attempts_ck;
ALTER TABLE metering_outbox ADD CONSTRAINT metering_outbox_attempts_ck
  CHECK (attempts >= 0 AND attempts <= 8) NOT VALID;

ALTER TABLE metering_outbox DROP CONSTRAINT IF EXISTS metering_outbox_version_ck;
ALTER TABLE metering_outbox ADD CONSTRAINT metering_outbox_version_ck
  CHECK (version >= 1) NOT VALID;

-- 信封长度（02-events §1 / facts.MAX_* 对齐）
ALTER TABLE metering_outbox DROP CONSTRAINT IF EXISTS metering_outbox_text_ck;
ALTER TABLE metering_outbox ADD CONSTRAINT metering_outbox_text_ck
  CHECK (char_length(type) BETWEEN 1 AND 64
     AND char_length(aggregate_type) BETWEEN 1 AND 64
     AND char_length(aggregate_id) BETWEEN 1 AND 128
     AND char_length(trace_id) BETWEEN 1 AND 128
     AND char_length(idempotency_key) BETWEEN 1 AND 200
     AND (correlation_id IS NULL OR char_length(correlation_id) BETWEEN 1 AND 128)
     AND (causation_id IS NULL OR char_length(causation_id) BETWEEN 1 AND 128)
     AND (last_error IS NULL OR char_length(last_error) <= 200)) NOT VALID;

-- 幂等（02-events §2.1）：同一业务事实只有一条事件
DROP INDEX IF EXISTS metering_outbox_idempotency_uq;
CREATE UNIQUE INDEX metering_outbox_idempotency_uq
  ON metering_outbox (idempotency_key);

-- 待投递队列：按 next_attempt_at 取（部分索引，发布后不再参与扫描）
DROP INDEX IF EXISTS metering_outbox_pending_idx;
CREATE INDEX metering_outbox_pending_idx
  ON metering_outbox (next_attempt_at) WHERE published_at IS NULL;

-- 聚合顺序 / 排障：同一聚合内按发生时间
DROP INDEX IF EXISTS metering_outbox_aggregate_idx;
CREATE INDEX metering_outbox_aggregate_idx
  ON metering_outbox (aggregate_id, occurred_at DESC);

-- 保留期清理（已发布 30 天）走这条索引
DROP INDEX IF EXISTS metering_outbox_published_idx;
CREATE INDEX metering_outbox_published_idx
  ON metering_outbox (published_at) WHERE published_at IS NOT NULL;

-- ────────────────────────────────────────────────────────── 投递护栏
-- 写入即不可改信封（type / payload / idempotency_key / aggregate_id …），
-- 只有投递记账四列可改：attempts / next_attempt_at / published_at / last_error。
CREATE OR REPLACE FUNCTION m05_outbox_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['attempts', 'next_attempt_at', 'published_at', 'last_error'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- 唯一允许的删除：已发布且超过保留期（M05 §5「已发布 30 天」）
    IF OLD.published_at IS NULL OR OLD.published_at > now() - INTERVAL '30 days' THEN
      RAISE EXCEPTION 'metering_outbox: only published rows older than retention may be deleted'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'metering_outbox: envelope is immutable, only delivery columns may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS NULL THEN
    RAISE EXCEPTION 'metering_outbox: published_at cannot be cleared' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS metering_outbox_guard ON metering_outbox;
CREATE TRIGGER metering_outbox_guard BEFORE UPDATE OR DELETE ON metering_outbox
  FOR EACH ROW EXECUTE FUNCTION m05_outbox_guard();

DROP TRIGGER IF EXISTS metering_outbox_no_truncate ON metering_outbox;
CREATE TRIGGER metering_outbox_no_truncate BEFORE TRUNCATE ON metering_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m05_forbid_truncate();

-- 新行必须待投递（published_at IS NULL）且 attempts = 0
CREATE OR REPLACE FUNCTION m05_outbox_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.published_at IS NOT NULL OR NEW.attempts <> 0 THEN
    RAISE EXCEPTION 'metering_outbox: new rows must be pending (published_at NULL, attempts 0)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS metering_outbox_insert_guard ON metering_outbox;
CREATE TRIGGER metering_outbox_insert_guard BEFORE INSERT ON metering_outbox
  FOR EACH ROW EXECUTE FUNCTION m05_outbox_insert_guard();

COMMENT ON TABLE metering_outbox IS
  'M05 事件 outbox（M05 §5 / 迁移 506）：与业务同事务写入；至少一次投递；已发布保留 30 天';
COMMENT ON COLUMN metering_outbox.payload IS
  '只放事实字段与金额（amount_minor），不放 prompt / response / 凭据（INV-10 / 02-events §1）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'metering_outbox_pending_idx') THEN
    RAISE EXCEPTION '506: 缺待投递索引 metering_outbox_pending_idx';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'metering_outbox' AND column_name = 'idempotency_key') THEN
    RAISE EXCEPTION '506: metering_outbox 缺列 idempotency_key';
  END IF;
END
$$;

COMMIT;
