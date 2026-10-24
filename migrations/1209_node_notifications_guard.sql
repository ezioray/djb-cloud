-- 1209 · M12 · 节点通知的「不可变 + 保留 + 观测」（node_notifications 护栏与视图）
-- 规格：00-conventions §7.5（审计类只追加）· M12 §5（保留 180 天）· M12a node_push
--
-- 为什么单独一个文件：1206 建表时只放「行内取值约束」，跨行的生命周期护栏
-- （UPDATE 白名单 / DELETE 保留期 / 观测视图）集中在这里，回滚时先撤护栏再删表。
BEGIN;

-- 只允许状态列变化：业务列（node_id / severity / category / template_key / payload /
-- dedupe_key / source_event_id / created_at / expires_at）一旦写入即冻结。
CREATE OR REPLACE FUNCTION m12_node_notification_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['state', 'delivered_at', 'read_at'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.created_at > now() - INTERVAL '180 days' THEN
      RAISE EXCEPTION 'node_notifications: only rows older than 180 days may be deleted (retention)'
        USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'node_notifications: only state/delivered_at/read_at may change (M12a)'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS node_notifications_guard ON node_notifications;
CREATE TRIGGER node_notifications_guard
  BEFORE UPDATE OR DELETE ON node_notifications
  FOR EACH ROW EXECUTE FUNCTION m12_node_notification_guard();

DROP TRIGGER IF EXISTS node_notifications_no_truncate ON node_notifications;
CREATE TRIGGER node_notifications_no_truncate
  BEFORE TRUNCATE ON node_notifications
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

-- 观测：每节点「待拉取且未过期」的条数（运维看板用；不含正文）
CREATE OR REPLACE VIEW v_node_notifications_pending AS
  SELECT node_id,
         count(*) FILTER (WHERE severity = 'P0') AS p0,
         count(*) FILTER (WHERE severity = 'P1') AS p1,
         count(*) FILTER (WHERE severity = 'P2') AS p2,
         count(*)                                AS total
    FROM node_notifications
   WHERE state IN ('queued', 'delivered')
     AND (expires_at IS NULL OR expires_at > now())
   GROUP BY node_id;

COMMENT ON VIEW v_node_notifications_pending IS
  'M12a 观测视图（迁移 1209）：每节点未读且未过期的通知条数（按级别分桶，无正文）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = current_schema() AND c.relname = 'node_notifications'
                    AND t.tgname = 'node_notifications_guard') THEN
    RAISE EXCEPTION '1209: node_notifications 缺不可变护栏触发器';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.views
                  WHERE table_schema = current_schema()
                    AND table_name = 'v_node_notifications_pending') THEN
    RAISE EXCEPTION '1209: 缺观测视图 v_node_notifications_pending';
  END IF;
END
$$;

COMMIT;
