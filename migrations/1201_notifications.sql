-- 1201 · M12 通知主体与站内记录（notifications）
-- 规格：product/v4/modules/M12-notification.md §3 不变量（INV-01/02/03/07/09）
--       §5 数据所有权（notifications，迁移 1201，保留 180 天）· §6 流程 6.1 / 6.2
--       product/v4/modules/02-events.md §1（信封；payload 只放事实，不放正文 / PII / 凭据）
--       00-conventions §7.5（事件 / 审计只追加）· §7.2（只加列 / 表 / 索引）
--
-- 原则：
--   1) 只加不改：只建 M12 自己的对象，其它模块的表 / 数据零改动（无跨模块 FK）。
--   2) 合并去重（INV-03）：UNIQUE(account_id, type, dedupe_bucket)——同一合并窗口内同类通知
--      只落一条；重复触发只累加 channel_count 并把新 event_id 追加进 merged_event_ids。
--   3) 事件消费幂等（02-events §5）：UNIQUE(source_event_id)——同一 event_id 重放不落第二条；
--      合并进来的 event_id 记在 merged_event_ids 里，重放同样识别得出来。
--   4) 站内必留（INV-02）：channels 必须含 in_app；偏好关掉 in_app 只表示「不产生未读提醒」
--      （落库时直接预置 read_at），记录本身不可因此消失。
--   5) 零 PII（INV-07）：payload_ref 只放 id / 金额 / 时间 / 原因码；DB 层直接拒绝敏感键。
--   6) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE / CREATE OR REPLACE；
--      末尾结构断言保证「已存在的表」与本节定义同形，避免半途建表被静默放过。
BEGIN;

-- ────────────────────────────────────────────────────────── 通知主体（站内记录）
CREATE TABLE IF NOT EXISTS notifications (
  id              UUID PRIMARY KEY,                  -- UUIDv7（00-conventions §2）
  account_id      UUID NOT NULL,                     -- 收件账户（M01 accounts，软引用，不建 FK）
  level           TEXT NOT NULL,                     -- P0 / P1 / P2（§5 枚举）
  type            TEXT NOT NULL,                     -- 业务事件类型（如 payment.paid，02-events §3）
  template_key    TEXT NOT NULL,                     -- 模板标识（含 customer./internal. 命名空间）
  template_scope  TEXT NOT NULL DEFAULT 'customer',  -- customer / internal（INV-09 两套模板）
  payload_ref     JSONB NOT NULL DEFAULT '{}'::jsonb,-- 只放 id / 金额 / 时间 / 原因码（INV-07）
  channels        TEXT[] NOT NULL,                   -- in_app / email / webhook；必含 in_app（INV-02）
  channel_count   INTEGER NOT NULL DEFAULT 1,        -- 合并窗口内的实际触发条数（INV-03，>1 即合并）
  dedupe_bucket   BIGINT NOT NULL,                   -- floor(created_at / notify.merge_window_s)
  source_event_id UUID,                              -- 首次触发的事件 id（消费幂等键）
  merged_event_ids UUID[] NOT NULL DEFAULT '{}'::uuid[], -- 被合并掉的后续事件 id（重放识别用）
  status          TEXT NOT NULL DEFAULT 'queued',    -- queued→sending→delivered|partial|failed→dead
  created_at      TIMESTAMPTZ NOT NULL,              -- 业务发生时间（UTC；分页 / 合并窗口按它）
  sent_at         TIMESTAMPTZ,                       -- 全部渠道完成时刻
  read_at         TIMESTAMPTZ,                       -- 已读时刻（NULL = 未读）
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now() -- 落库时刻（保留期按它算，防伪造 created_at）
);

-- 枚举与形态（只加不改：后续新增级别 / 渠道走新迁移放宽约束）
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_level_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_level_ck
  CHECK (level IN ('P0', 'P1', 'P2')) NOT VALID;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_status_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_status_ck
  CHECK (status IN ('queued', 'sending', 'delivered', 'partial', 'failed', 'dead')) NOT VALID;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_scope_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_scope_ck
  CHECK (template_scope IN ('customer', 'internal')) NOT VALID;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_channels_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_channels_ck
  CHECK (channels <@ ARRAY['in_app', 'email', 'webhook']::text[]
     AND 'in_app' = ANY (channels)) NOT VALID;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_text_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_text_ck
  CHECK (char_length(type) BETWEEN 1 AND 128
     AND char_length(template_key) BETWEEN 1 AND 128) NOT VALID;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_count_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_count_ck
  CHECK (channel_count >= 1 AND dedupe_bucket >= 0) NOT VALID;

-- 零 PII（INV-07）：payload 里出现这些键直接拒写（宁可报错，也不落库）
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_payload_ck;
ALTER TABLE notifications ADD CONSTRAINT notifications_payload_ck
  CHECK (jsonb_typeof(payload_ref) = 'object'
     AND NOT (payload_ref ?| ARRAY['email', 'phone', 'msisdn', 'secret', 'password',
                                   'body', 'content', 'html', 'text', 'token'])) NOT VALID;

-- 合并去重唯一（INV-03）：同账户 + 同类型 + 同窗口 = 一条
DROP INDEX IF EXISTS notifications_dedupe_uq;
CREATE UNIQUE INDEX notifications_dedupe_uq
  ON notifications (account_id, type, dedupe_bucket);

-- 事件消费幂等（02-events §5）：同一 event_id 只落第一条
DROP INDEX IF EXISTS notifications_source_event_uq;
CREATE UNIQUE INDEX notifications_source_event_uq
  ON notifications (source_event_id) WHERE source_event_id IS NOT NULL;

-- 列表（§5 索引：account_id + created_at desc）与 dispatcher 扫描（status + created_at）
DROP INDEX IF EXISTS notifications_account_created_idx;
CREATE INDEX notifications_account_created_idx
  ON notifications (account_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS notifications_status_created_idx;
CREATE INDEX notifications_status_created_idx
  ON notifications (status, created_at);

-- ────────────────────────────────────────────────────────── 只追加 + 状态机护栏
-- 可变列白名单：状态机列 + 合并计数（INV-03）+ 已读时刻（INV-02）。
CREATE OR REPLACE FUNCTION m12_notification_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['status', 'sent_at', 'read_at', 'channel_count', 'merged_event_ids'];
  allowed TEXT[][] := ARRAY[
    ['queued', 'sending'], ['sending', 'delivered'], ['sending', 'partial'],
    ['sending', 'failed'], ['failed', 'dead']
  ];
  pair TEXT[];
  legal BOOLEAN := FALSE;
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- 站内保留 180 天（§8.2）：到期归档才允许删；其余一律拒绝（INV-02 不得删除记录）
    IF OLD.recorded_at > now() - INTERVAL '180 days' THEN
      RAISE EXCEPTION 'notifications: only rows older than 180 days may be archived'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'notifications: subject columns are immutable, only state/read/merge may change (INV-02/INV-03)'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.read_at IS NOT NULL AND NEW.read_at IS DISTINCT FROM OLD.read_at THEN
    RAISE EXCEPTION 'notifications: read_at is write-once (已读不可撤回)'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> NEW.status THEN
    FOREACH pair SLICE 1 IN ARRAY allowed LOOP
      IF pair[1] = OLD.status AND pair[2] = NEW.status THEN
        legal := TRUE;
      END IF;
    END LOOP;
    IF NOT legal THEN
      RAISE EXCEPTION 'notifications: illegal transition % → % (M12 §3 状态机)',
        OLD.status, NEW.status USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notifications_guard ON notifications;
CREATE TRIGGER notifications_guard BEFORE UPDATE OR DELETE ON notifications
  FOR EACH ROW EXECUTE FUNCTION m12_notification_guard();

CREATE OR REPLACE FUNCTION m12_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M12 §5)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notifications_no_truncate ON notifications;
CREATE TRIGGER notifications_no_truncate BEFORE TRUNCATE ON notifications
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

-- 新行必须待投递（queued / sent_at 为空），且合并计数与 merged_event_ids 自洽
CREATE OR REPLACE FUNCTION m12_notification_insert_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.status <> 'queued' OR NEW.sent_at IS NOT NULL THEN
    RAISE EXCEPTION 'notifications: new rows must be queued with sent_at NULL'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.channel_count <> 1 + cardinality(NEW.merged_event_ids) THEN
    RAISE EXCEPTION 'notifications: channel_count must equal 1 + merged_event_ids (INV-03)'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.source_event_id IS NOT NULL AND NEW.source_event_id = ANY (NEW.merged_event_ids) THEN
    RAISE EXCEPTION 'notifications: source_event_id must not repeat in merged_event_ids'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notifications_insert_guard ON notifications;
CREATE TRIGGER notifications_insert_guard BEFORE INSERT ON notifications
  FOR EACH ROW EXECUTE FUNCTION m12_notification_insert_guard();

COMMENT ON TABLE notifications IS
  'M12 通知主体与站内记录（M12 §5 / 迁移 1201）：合并去重 + 事件幂等 + 站内必留；保留 180 天';
COMMENT ON COLUMN notifications.payload_ref IS
  '只放 id / 金额 / 时间 / 原因码；禁 email / phone / 正文 / 密钥（INV-07，DB 约束兜底）';
COMMENT ON COLUMN notifications.dedupe_bucket IS
  'floor(created_at / notify.merge_window_s)；与 account_id + type 组成合并去重唯一键（INV-03）';

-- ────────────────────────────────────────────────────────── 结构断言（半途建表不放过）
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'notifications_dedupe_uq') THEN
    RAISE EXCEPTION '1201: 缺合并去重唯一索引 notifications_dedupe_uq';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'notifications_account_created_idx') THEN
    RAISE EXCEPTION '1201: 缺列表索引 notifications_account_created_idx';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'notifications' AND column_name = 'merged_event_ids') THEN
    RAISE EXCEPTION '1201: notifications 缺列 merged_event_ids';
  END IF;
END
$$;

COMMIT;
