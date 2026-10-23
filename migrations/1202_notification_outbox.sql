-- 1202 · M12 本模块事件 outbox（notification_outbox）
-- 规格：product/v4/modules/M12-notification.md §5（notification_outbox，迁移 1202，保留 30 天）
--       §4.2 事件（notification.requested / delivered / failed）· §6 流程 6.1（同事务）
--       product/v4/modules/02-events.md §2（本地事务 + outbox / 至少一次 / 退避 8 次 → DLQ）
--
-- 语义：
--   1) **同事务**：通知与 outbox 在同一个库事务里写；事务失败则事件也不存在（INV-08）。
--   2) **至少一次**：投递由派发器重试（1s/5s/30s/5min/30min，最多 8 次 → 死信），
--      投递失败不回滚业务（02-events §2.6）。
--   3) **幂等**：UNIQUE(event_id)——同一事实重复入队不会产生两条事件。
--   4) **保留**：只有已发布且超过 30 天的行可被清理；未发布行任何 DELETE 一律拒绝。
BEGIN;

CREATE TABLE IF NOT EXISTS notification_outbox (
  id              UUID PRIMARY KEY,                 -- 行 id（与 event_id 分开：event_id 是契约键）
  event_id        UUID NOT NULL,                    -- 02-events §1 信封
  type            TEXT NOT NULL,                    -- notification.requested / delivered / failed
  version         INTEGER NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL,
  producer        TEXT NOT NULL DEFAULT 'M12',
  aggregate_type  TEXT NOT NULL,                    -- notification
  aggregate_id    TEXT NOT NULL,                    -- notification_id
  correlation_id  TEXT,
  causation_id    TEXT,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,                    -- 生产侧业务幂等键（如 notification.requested:<id>）
  payload         JSONB NOT NULL,                   -- 只放 id / 渠道 / 尝试号 / 原因码（INV-07）
  attempts        INTEGER NOT NULL DEFAULT 0,       -- 已尝试投递次数（≤ 8，02-events §2.3）
  next_attempt_at TIMESTAMPTZ NOT NULL,             -- 下次重试时刻（退避）
  published_at    TIMESTAMPTZ,                      -- 投递成功时刻（NULL = 待投递）
  last_error      TEXT,                             -- 最近一次失败原因（短码，不含堆栈）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 事件白名单：本模块只发 02-events §3 里登记的三个事件
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_type_ck;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_type_ck
  CHECK (type IN ('notification.requested', 'notification.delivered',
                  'notification.failed')) NOT VALID;

ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_producer_ck;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_producer_ck
  CHECK (producer = 'M12') NOT VALID;

ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_attempts_ck;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_attempts_ck
  CHECK (attempts >= 0 AND attempts <= 8) NOT VALID;

ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_version_ck;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_version_ck
  CHECK (version >= 1) NOT VALID;

-- 零 PII（INV-07）：事件 payload 同样不得出现邮箱 / 手机 / 正文 / 密钥
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_payload_ck;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_payload_ck
  CHECK (jsonb_typeof(payload) = 'object'
     AND NOT (payload ?| ARRAY['email', 'phone', 'msisdn', 'secret', 'password',
                               'body', 'content', 'html', 'text', 'token'])) NOT VALID;

ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_text_ck;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_text_ck
  CHECK (char_length(type) BETWEEN 1 AND 64
     AND char_length(aggregate_type) BETWEEN 1 AND 64
     AND char_length(aggregate_id) BETWEEN 1 AND 128
     AND char_length(trace_id) BETWEEN 1 AND 128
     AND char_length(idempotency_key) BETWEEN 1 AND 200) NOT VALID;

-- 事件幂等（唯一键）
DROP INDEX IF EXISTS notification_outbox_event_uq;
CREATE UNIQUE INDEX notification_outbox_event_uq ON notification_outbox (event_id);

-- 派发器扫描：只看未发布且到点的行
DROP INDEX IF EXISTS notification_outbox_pending_idx;
CREATE INDEX notification_outbox_pending_idx
  ON notification_outbox (next_attempt_at) WHERE published_at IS NULL;

-- ────────────────────────────────────────────────────────── 护栏
-- 单独重跑本文件也成立：TRUNCATE 拦截函数与 1201 同定义（CREATE OR REPLACE 幂等）
CREATE OR REPLACE FUNCTION m12_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M12 §5)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION m12_outbox_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['attempts', 'next_attempt_at', 'published_at', 'last_error'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.published_at IS NULL OR OLD.published_at > now() - INTERVAL '30 days' THEN
      RAISE EXCEPTION 'notification_outbox: only published rows older than retention may be deleted'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'notification_outbox: envelope is immutable, only delivery columns may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS NULL THEN
    RAISE EXCEPTION 'notification_outbox: published_at cannot be cleared' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notification_outbox_guard ON notification_outbox;
CREATE TRIGGER notification_outbox_guard BEFORE UPDATE OR DELETE ON notification_outbox
  FOR EACH ROW EXECUTE FUNCTION m12_outbox_guard();

DROP TRIGGER IF EXISTS notification_outbox_no_truncate ON notification_outbox;
CREATE TRIGGER notification_outbox_no_truncate BEFORE TRUNCATE ON notification_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

-- 新行必须待投递（published_at IS NULL）且 attempts = 0
CREATE OR REPLACE FUNCTION m12_outbox_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.published_at IS NOT NULL OR NEW.attempts <> 0 THEN
    RAISE EXCEPTION 'notification_outbox: new rows must be pending (published_at NULL, attempts 0)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notification_outbox_insert_guard ON notification_outbox;
CREATE TRIGGER notification_outbox_insert_guard BEFORE INSERT ON notification_outbox
  FOR EACH ROW EXECUTE FUNCTION m12_outbox_insert_guard();

COMMENT ON TABLE notification_outbox IS
  'M12 事件 outbox（M12 §5 / 迁移 1202）：与通知同事务写入；至少一次投递；已发布保留 30 天';
COMMENT ON COLUMN notification_outbox.payload IS
  '只放 notification_id / channel / attempt / error_code 等短字段（INV-07）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'notification_outbox_pending_idx') THEN
    RAISE EXCEPTION '1202: 缺待投递索引 notification_outbox_pending_idx';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'notification_outbox_event_uq') THEN
    RAISE EXCEPTION '1202: 缺事件幂等唯一索引 notification_outbox_event_uq';
  END IF;
END
$$;

COMMIT;
