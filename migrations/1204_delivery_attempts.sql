-- 1204 · M12 投递尝试（delivery_attempts）
-- 规格：product/v4/modules/M12-notification.md §3 INV-04（每次尝试只追加一条、历史不改写、
--       重试复用同一 notification_id）· INV-06（重试与降级）· §5 数据所有权（保留 180 天）
--       §6.2 分派与投递（每次尝试写 delivery_attempts）
--
-- 语义：
--   1) **只追加**：UPDATE / DELETE / TRUNCATE 一律拒绝（INV-04「历史不改写」）。
--   2) **尝试唯一**：UNIQUE(notification_id, channel, attempt_no)——重试复用同一通知，只递增尝试号。
--   3) **每渠道最多 3 次**（§8.2「每通知最大尝试」）：attempt_no 1–3，超过即降级不再重试。
BEGIN;

CREATE TABLE IF NOT EXISTS delivery_attempts (
  id              UUID PRIMARY KEY,                 -- 尝试 id（UUIDv7）
  notification_id UUID NOT NULL,                    -- 复用同一 notification_id（INV-04）
  channel         TEXT NOT NULL,                    -- in_app / email / webhook
  attempt_no      INTEGER NOT NULL,                 -- 1..3（§8.2）
  status          TEXT NOT NULL,                    -- pending 之外的终态：success / retryable / permanent
  error_code      TEXT,                             -- 短码（如 http_500 / timeout / smtp_5xx），不含正文
  provider_ref    TEXT,                             -- 供应方引用（消息 id / HTTP 响应 id），只存引用
  latency_ms      INTEGER,                          -- 本次耗时（毫秒）
  occurred_at     TIMESTAMPTZ NOT NULL,             -- 尝试发生时间（UTC）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 同模块 FK（通知主体在本模块内，允许强引用）；跨模块不建 FK
ALTER TABLE delivery_attempts DROP CONSTRAINT IF EXISTS delivery_attempts_notification_fk;
ALTER TABLE delivery_attempts ADD CONSTRAINT delivery_attempts_notification_fk
  FOREIGN KEY (notification_id) REFERENCES notifications (id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE delivery_attempts DROP CONSTRAINT IF EXISTS delivery_attempts_channel_ck;
ALTER TABLE delivery_attempts ADD CONSTRAINT delivery_attempts_channel_ck
  CHECK (channel IN ('in_app', 'email', 'webhook')) NOT VALID;

ALTER TABLE delivery_attempts DROP CONSTRAINT IF EXISTS delivery_attempts_status_ck;
ALTER TABLE delivery_attempts ADD CONSTRAINT delivery_attempts_status_ck
  CHECK (status IN ('success', 'retryable', 'permanent')) NOT VALID;

ALTER TABLE delivery_attempts DROP CONSTRAINT IF EXISTS delivery_attempts_attempt_ck;
ALTER TABLE delivery_attempts ADD CONSTRAINT delivery_attempts_attempt_ck
  CHECK (attempt_no BETWEEN 1 AND 3 AND (latency_ms IS NULL OR latency_ms >= 0)) NOT VALID;

ALTER TABLE delivery_attempts DROP CONSTRAINT IF EXISTS delivery_attempts_error_ck;
ALTER TABLE delivery_attempts ADD CONSTRAINT delivery_attempts_error_ck
  CHECK ((status = 'success' AND error_code IS NULL)
      OR (status <> 'success' AND error_code IS NOT NULL AND char_length(error_code) BETWEEN 2 AND 64))
  NOT VALID;

-- 尝试唯一（INV-04）+ 详情索引（§5 索引：notification_id 供详情）
DROP INDEX IF EXISTS delivery_attempts_channel_attempt_uq;
CREATE UNIQUE INDEX delivery_attempts_channel_attempt_uq
  ON delivery_attempts (notification_id, channel, attempt_no);

DROP INDEX IF EXISTS delivery_attempts_notification_idx;
CREATE INDEX delivery_attempts_notification_idx
  ON delivery_attempts (notification_id, occurred_at DESC);

-- ────────────────────────────────────────────────────────── 只追加护栏
CREATE OR REPLACE FUNCTION m12_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M12 §5)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION m12_attempt_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'delivery_attempts is append-only: % not allowed (INV-04)', TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS delivery_attempts_immutable ON delivery_attempts;
CREATE TRIGGER delivery_attempts_immutable BEFORE UPDATE OR DELETE ON delivery_attempts
  FOR EACH ROW EXECUTE FUNCTION m12_attempt_immutable();

DROP TRIGGER IF EXISTS delivery_attempts_no_truncate ON delivery_attempts;
CREATE TRIGGER delivery_attempts_no_truncate BEFORE TRUNCATE ON delivery_attempts
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

COMMENT ON TABLE delivery_attempts IS
  'M12 每次投递尝试（M12 §5 / 迁移 1204）：只追加；重试复用同一 notification_id（INV-04）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'delivery_attempts_channel_attempt_uq') THEN
    RAISE EXCEPTION '1204: 缺尝试唯一索引 delivery_attempts_channel_attempt_uq';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = current_schema()
                    AND table_name = 'delivery_attempts' AND column_name = 'attempt_no') THEN
    RAISE EXCEPTION '1204: delivery_attempts 缺列 attempt_no';
  END IF;
END
$$;

COMMIT;
