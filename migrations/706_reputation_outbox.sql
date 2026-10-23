-- 706 · M07 本模块事件 outbox（reputation_outbox）
-- 规格：product/v4/modules/M07-reputation-cop.md §4.2（生产 reputation.changed / cop.earned / cop.spent / invite.bound）
--       §5（reputation_outbox，迁移 706，保留 30 天）· §6（「本模块内 cop_ledger + outbox 同事务」）
--       §7（事件重复 / 乱序 → 幂等丢弃）· 02-events §2（本地事务 + outbox；至少一次；退避 8 次 → DLQ）
--
-- 语义：
--   1) **同事务**：业务写入与 outbox 在同一库事务内；事务失败则事件也不存在。
--   2) **至少一次**：投递由派发器重试（1s/5s/30s/5min/30min，最多 8 次 → 死信）。
--   3) **幂等**：UNIQUE(event_id)——同一事实重复入队不会产生两条事件。
--   4) **保留 30 天**：只有已发布且超过 30 天的行可被清理；未发布行 DELETE 一律拒绝。
--   5) 只放事实（account_id / amount / source / ref_id / tier / reasons），不放阈值、不放 PII。
BEGIN;

CREATE TABLE IF NOT EXISTS reputation_outbox (
  id              UUID PRIMARY KEY,                 -- 行 id（与 event_id 分开：event_id 是契约键）
  event_id        UUID NOT NULL,                    -- 02-events §1 信封
  type            TEXT NOT NULL,                    -- reputation.changed / cop.earned / cop.spent / invite.bound
  version         INTEGER NOT NULL DEFAULT 1,
  occurred_at     TIMESTAMPTZ NOT NULL,
  producer        TEXT NOT NULL DEFAULT 'M07',
  aggregate_type  TEXT NOT NULL,                    -- account
  aggregate_id    TEXT NOT NULL,                    -- account_id（invite.bound 用 inviter_id）
  correlation_id  TEXT,
  causation_id    TEXT,
  trace_id        TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,                    -- 生产侧业务幂等键（如 cop.earned:<journal_id>）
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  attempts        INTEGER NOT NULL DEFAULT 0,       -- ≤ 8（02-events §2.3）
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at    TIMESTAMPTZ,                      -- NULL = 待投递
  last_error      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 事件白名单：本模块只发 02-events §3 里登记的四个事件（只加不改：新增事件走新迁移放宽）
ALTER TABLE reputation_outbox DROP CONSTRAINT IF EXISTS reputation_outbox_type_ck;
ALTER TABLE reputation_outbox ADD CONSTRAINT reputation_outbox_type_ck
  CHECK (type IN ('reputation.changed', 'cop.earned', 'cop.spent', 'invite.bound')) NOT VALID;

ALTER TABLE reputation_outbox DROP CONSTRAINT IF EXISTS reputation_outbox_producer_ck;
ALTER TABLE reputation_outbox ADD CONSTRAINT reputation_outbox_producer_ck
  CHECK (producer = 'M07') NOT VALID;

ALTER TABLE reputation_outbox DROP CONSTRAINT IF EXISTS reputation_outbox_attempts_ck;
ALTER TABLE reputation_outbox ADD CONSTRAINT reputation_outbox_attempts_ck
  CHECK (attempts >= 0 AND attempts <= 8) NOT VALID;

ALTER TABLE reputation_outbox DROP CONSTRAINT IF EXISTS reputation_outbox_version_ck;
ALTER TABLE reputation_outbox ADD CONSTRAINT reputation_outbox_version_ck
  CHECK (version >= 1) NOT VALID;

ALTER TABLE reputation_outbox DROP CONSTRAINT IF EXISTS reputation_outbox_payload_ck;
ALTER TABLE reputation_outbox ADD CONSTRAINT reputation_outbox_payload_ck
  CHECK (jsonb_typeof(payload) = 'object'
     AND NOT (payload ?| ARRAY['email', 'phone', 'msisdn', 'secret', 'password',
                               'token', 'threshold', 'limit'])) NOT VALID;

ALTER TABLE reputation_outbox DROP CONSTRAINT IF EXISTS reputation_outbox_text_ck;
ALTER TABLE reputation_outbox ADD CONSTRAINT reputation_outbox_text_ck
  CHECK (char_length(type) BETWEEN 1 AND 64
     AND char_length(aggregate_type) BETWEEN 1 AND 64
     AND char_length(aggregate_id) BETWEEN 1 AND 128
     AND char_length(trace_id) BETWEEN 1 AND 128
     AND char_length(idempotency_key) BETWEEN 1 AND 200) NOT VALID;

DROP INDEX IF EXISTS reputation_outbox_event_uq;
CREATE UNIQUE INDEX reputation_outbox_event_uq ON reputation_outbox (event_id);

-- 业务幂等：(type, idempotency_key) 唯一 —— 重放 / 重试不会产生第二条事件
DROP INDEX IF EXISTS reputation_outbox_dedupe_uq;
CREATE UNIQUE INDEX reputation_outbox_dedupe_uq
  ON reputation_outbox (type, idempotency_key);

DROP INDEX IF EXISTS reputation_outbox_pending_idx;
CREATE INDEX reputation_outbox_pending_idx
  ON reputation_outbox (next_attempt_at) WHERE published_at IS NULL;

-- ────────────────────────────────────────────────────────── 护栏
CREATE OR REPLACE FUNCTION m07_outbox_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['attempts', 'next_attempt_at', 'published_at', 'last_error'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.published_at IS NULL OR OLD.published_at > now() - INTERVAL '30 days' THEN
      RAISE EXCEPTION 'reputation_outbox: only published rows older than retention may be deleted'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'reputation_outbox: envelope is immutable, only delivery columns may change'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS NULL THEN
    RAISE EXCEPTION 'reputation_outbox: published_at cannot be cleared' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reputation_outbox_guard ON reputation_outbox;
CREATE TRIGGER reputation_outbox_guard BEFORE UPDATE OR DELETE ON reputation_outbox
  FOR EACH ROW EXECUTE FUNCTION m07_outbox_guard();

DROP TRIGGER IF EXISTS reputation_outbox_no_truncate ON reputation_outbox;
CREATE TRIGGER reputation_outbox_no_truncate BEFORE TRUNCATE ON reputation_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION m07_forbid_truncate();

CREATE OR REPLACE FUNCTION m07_outbox_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.published_at IS NOT NULL OR NEW.attempts <> 0 THEN
    RAISE EXCEPTION 'reputation_outbox: new rows must be pending (published_at NULL, attempts 0)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reputation_outbox_insert_guard ON reputation_outbox;
CREATE TRIGGER reputation_outbox_insert_guard BEFORE INSERT ON reputation_outbox
  FOR EACH ROW EXECUTE FUNCTION m07_outbox_insert_guard();

COMMENT ON TABLE reputation_outbox IS
  'M07 事件 outbox（M07 §5 / 迁移 706，保留 30 天）：与业务同事务写入；至少一次投递';
COMMENT ON COLUMN reputation_outbox.payload IS
  '只放 account_id / amount / source / ref_id / tier / reasons 等事实字段（不含阈值与 PII）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'reputation_outbox_event_uq') THEN
    RAISE EXCEPTION '706: 缺事件幂等唯一索引 reputation_outbox_event_uq';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'reputation_outbox_guard') THEN
    RAISE EXCEPTION '706: 缺 outbox 护栏触发器 reputation_outbox_guard';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'reputation_outbox_dedupe_uq') THEN
    RAISE EXCEPTION '706: 缺业务幂等唯一索引 reputation_outbox_dedupe_uq';
  END IF;
END
$$;

COMMIT;
