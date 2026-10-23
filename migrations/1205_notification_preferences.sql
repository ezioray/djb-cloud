-- 1205 · M12 通知偏好（notification_preferences）
-- 规格：product/v4/modules/M12-notification.md §3 INV-01（P0 不可退订：p0_opt_out 只能为 false，
--       写入 true 返回 40902；quiet_hours 与 digest 对 P0 无效）· INV-02（偏好不能删记录）
--       §4.1 GET|PUT /api/v1/user/notifications/preferences
--       §5 数据所有权第 5 张表（CR-3 已批准；迁移 1205）· spec 1.2.3 NotificationPreferences
--
-- 语义：
--   1) **P0 不可退订**：DB 层 CHECK(p0_opt_out = false)——应用层先返回 409 / 40902，
--      数据库这层是兜底：任何绕过 API 的写入同样写不进 true（INV-01）。
--   2) **覆盖式更新**：PUT 是整行覆盖（不是增量合并），本表按 account_id 一行。
--   3) **偏好不删记录**：本表只有「开关」，不持有任何通知 / 站内记录；删偏好行最多回到默认值。
--   4) **静默时段 / 摘要不影响 P0**：判定在应用层（app/notify/preferences.py），DB 只存原始值。
BEGIN;

CREATE TABLE IF NOT EXISTS notification_preferences (
  account_id   UUID PRIMARY KEY,                        -- 一账户一行（M01 accounts，软引用）
  email        BOOLEAN NOT NULL DEFAULT true,           -- 邮件渠道（§8.2「邮件必有」的默认开）
  in_app       BOOLEAN NOT NULL DEFAULT true,           -- false 只表示不产生未读提醒（INV-02）
  webhook      BOOLEAN NOT NULL DEFAULT false,          -- Webhook 可选（§8.2），默认关
  quiet_hours  JSONB,                                   -- {start,end,timezone}；NULL = 无静默时段
  digest       TEXT NOT NULL DEFAULT 'realtime',        -- realtime / daily / weekly（§8.1 默认）
  p0_opt_out   BOOLEAN NOT NULL DEFAULT false,          -- 恒 false（INV-01）
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INV-01（数据库兜底）：p0_opt_out 只能为 false
ALTER TABLE notification_preferences DROP CONSTRAINT IF EXISTS notification_preferences_p0_ck;
ALTER TABLE notification_preferences ADD CONSTRAINT notification_preferences_p0_ck
  CHECK (p0_opt_out = false) NOT VALID;

ALTER TABLE notification_preferences DROP CONSTRAINT IF EXISTS notification_preferences_digest_ck;
ALTER TABLE notification_preferences ADD CONSTRAINT notification_preferences_digest_ck
  CHECK (digest IN ('realtime', 'daily', 'weekly')) NOT VALID;

-- 静默时段形态（spec NotificationPreferences.quiet_hours）：HH:MM + 时区名
ALTER TABLE notification_preferences DROP CONSTRAINT IF EXISTS notification_preferences_quiet_ck;
ALTER TABLE notification_preferences ADD CONSTRAINT notification_preferences_quiet_ck
  CHECK (quiet_hours IS NULL
      OR (jsonb_typeof(quiet_hours) = 'object'
          AND quiet_hours ? 'start' AND quiet_hours ? 'end'
          AND (quiet_hours->>'start') ~ '^[0-2][0-9]:[0-5][0-9]$'
          AND (quiet_hours->>'end') ~ '^[0-2][0-9]:[0-5][0-9]$'
          AND ((quiet_hours->>'timezone') IS NULL
               OR char_length(quiet_hours->>'timezone') BETWEEN 1 AND 64))) NOT VALID;

CREATE OR REPLACE FUNCTION m12_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M12 §5)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notification_preferences_no_truncate ON notification_preferences;
CREATE TRIGGER notification_preferences_no_truncate BEFORE TRUNCATE ON notification_preferences
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

COMMENT ON TABLE notification_preferences IS
  'M12 通知偏好（M12 §5 / 迁移 1205，CR-3）：P0 不可退订在 DB 层兜底（INV-01）';
COMMENT ON COLUMN notification_preferences.in_app IS
  'false 只表示不产生未读提醒；站内记录仍然保留（INV-02）';
COMMENT ON COLUMN notification_preferences.quiet_hours IS
  '静默时段只对 P1/P2 生效；P0 立即投递（INV-01，判定在 app/notify/preferences.py）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'notification_preferences' AND column_name = 'p0_opt_out') THEN
    RAISE EXCEPTION '1205: notification_preferences 缺列 p0_opt_out';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conname = 'notification_preferences_p0_ck' AND connamespace = current_schema()::regnamespace) THEN
    RAISE EXCEPTION '1205: 缺 INV-01 兜底约束 notification_preferences_p0_ck';
  END IF;
END
$$;

COMMIT;
