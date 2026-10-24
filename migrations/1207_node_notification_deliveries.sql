-- 1207 · M12 · 节点通知投递记录（node_notification_deliveries）
-- 规格：M12a node_push §「投递状态」· 00-conventions §7.5（审计类表只追加）
--
-- 语义：
--   1) 每次把通知**交给节点**（long_poll 帧 / pull 拉取）都追加一行，用于投递可观测；
--   2) **只追加**：UPDATE / DELETE / TRUNCATE 一律拒绝（同 1204 delivery_attempts 口径）；
--   3) 不存正文：只有 notification_id / channel / attempt / status / error_class。
BEGIN;

CREATE TABLE IF NOT EXISTS node_notification_deliveries (
  id              UUID PRIMARY KEY,
  notification_id UUID NOT NULL,                          -- node_notifications.id（软引用）
  channel         TEXT NOT NULL,                          -- long_poll / pull
  attempt         INTEGER NOT NULL DEFAULT 1,
  status          TEXT NOT NULL,                          -- success / failed
  error_class     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE node_notification_deliveries DROP CONSTRAINT IF EXISTS node_notification_deliveries_channel_ck;
ALTER TABLE node_notification_deliveries ADD CONSTRAINT node_notification_deliveries_channel_ck
  CHECK (channel IN ('long_poll', 'pull')) NOT VALID;

ALTER TABLE node_notification_deliveries DROP CONSTRAINT IF EXISTS node_notification_deliveries_status_ck;
ALTER TABLE node_notification_deliveries ADD CONSTRAINT node_notification_deliveries_status_ck
  CHECK (status IN ('success', 'failed')) NOT VALID;

ALTER TABLE node_notification_deliveries DROP CONSTRAINT IF EXISTS node_notification_deliveries_meta_ck;
ALTER TABLE node_notification_deliveries ADD CONSTRAINT node_notification_deliveries_meta_ck
  CHECK (attempt >= 1
     AND (error_class IS NULL OR char_length(error_class) BETWEEN 1 AND 64)) NOT VALID;

CREATE INDEX IF NOT EXISTS node_notification_deliveries_notification_idx
  ON node_notification_deliveries (notification_id, attempt DESC);

CREATE INDEX IF NOT EXISTS node_notification_deliveries_created_idx
  ON node_notification_deliveries (created_at DESC);

CREATE OR REPLACE FUNCTION m12_node_delivery_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'node_notification_deliveries is append-only: % not allowed (M12a)',
    TG_OP USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS node_notification_deliveries_guard ON node_notification_deliveries;
CREATE TRIGGER node_notification_deliveries_guard
  BEFORE UPDATE OR DELETE ON node_notification_deliveries
  FOR EACH ROW EXECUTE FUNCTION m12_node_delivery_immutable();

DROP TRIGGER IF EXISTS node_notification_deliveries_no_truncate ON node_notification_deliveries;
CREATE TRIGGER node_notification_deliveries_no_truncate
  BEFORE TRUNCATE ON node_notification_deliveries
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

COMMENT ON TABLE node_notification_deliveries IS
  'M12a 节点通知投递记录（迁移 1207）：每次交给节点追加一行，只追加、可审计';

COMMIT;
