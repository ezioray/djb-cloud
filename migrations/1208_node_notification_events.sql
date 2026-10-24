-- 1208 · M12 · 节点通知状态事件（node_notification_events）
-- 规格：M12a node_push §「投递状态」· 00-conventions §7.5（只追加）
--
-- 语义：
--   1) 通知状态机每走一步追加一条：queued / delivered / acked / read / expired；
--   2) 只追加：UPDATE / TRUNCATE 拒绝，DELETE 只允许 180 天前的行（保留期与通知一致）；
--   3) detail 只放原因码 / 短码（≤200 字符），不放正文。
BEGIN;

CREATE TABLE IF NOT EXISTS node_notification_events (
  id              UUID PRIMARY KEY,
  notification_id UUID NOT NULL,                          -- node_notifications.id（软引用）
  event           TEXT NOT NULL,                          -- queued / delivered / acked / read / expired
  detail          TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE node_notification_events DROP CONSTRAINT IF EXISTS node_notification_events_event_ck;
ALTER TABLE node_notification_events ADD CONSTRAINT node_notification_events_event_ck
  CHECK (event IN ('queued', 'delivered', 'acked', 'read', 'expired')) NOT VALID;

ALTER TABLE node_notification_events DROP CONSTRAINT IF EXISTS node_notification_events_detail_ck;
ALTER TABLE node_notification_events ADD CONSTRAINT node_notification_events_detail_ck
  CHECK (detail IS NULL OR char_length(detail) <= 200) NOT VALID;

CREATE INDEX IF NOT EXISTS node_notification_events_notification_idx
  ON node_notification_events (notification_id, created_at);

CREATE INDEX IF NOT EXISTS node_notification_events_event_idx
  ON node_notification_events (event, created_at DESC);

CREATE OR REPLACE FUNCTION m12_node_event_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.created_at > now() - INTERVAL '180 days' THEN
      RAISE EXCEPTION 'node_notification_events: only rows older than 180 days may be deleted'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'node_notification_events is append-only: UPDATE not allowed (M12a)'
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS node_notification_events_guard ON node_notification_events;
CREATE TRIGGER node_notification_events_guard
  BEFORE UPDATE OR DELETE ON node_notification_events
  FOR EACH ROW EXECUTE FUNCTION m12_node_event_guard();

DROP TRIGGER IF EXISTS node_notification_events_no_truncate ON node_notification_events;
CREATE TRIGGER node_notification_events_no_truncate
  BEFORE TRUNCATE ON node_notification_events
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

COMMENT ON TABLE node_notification_events IS
  'M12a 节点通知状态事件（迁移 1208）：queued/delivered/acked/read/expired，只追加';

COMMIT;
