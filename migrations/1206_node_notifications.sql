-- 1206 · M12 · 节点通知队列（node_notifications）
-- 规格：product/v4/modules/M12-notification.md（M12a node_push）· spec 1.2.13 通知形状
--       01-ownership §2（每模块自己的表）· 00-conventions §7.5（只追加）· INV-07（零正文/零 PII）
--
-- 语义：
--   1) 服务端为节点排队通知（告警 / 分润 / 冻结 / 维护 / 活动 / 系统）；节点离线时保留，
--      上线后按 (created_at, id) keyset 游标拉取（不返回已 read 的）；
--   2) `dedupe_key` 在同一节点内唯一、`source_event_id` 全局唯一 —— 应用层幂等 + DB 兜底；
--   3) payload **只允许 id / 金额 / 时间 / 原因码**：应用层白名单，DB 层用
--      `m12_node_payload_bad_key()` 递归检查 PII / 正文 / 凭据键名兜底（INV-07）；
--   4) P0 必须有 `expires_at`（不可长期悬挂），且 `expires_at > created_at`；
--   5) 保留 180 天、只允许状态列变更 —— 护栏在 1209。
BEGIN;

CREATE TABLE IF NOT EXISTS node_notifications (
  id              UUID PRIMARY KEY,
  node_id         TEXT NOT NULL,                          -- M02 节点 id（软引用，不建 FK）
  severity        TEXT NOT NULL,                          -- P0 / P1 / P2（M12 §5 级别）
  category        TEXT NOT NULL,                          -- alert / earnings / freeze / maintenance / campaign / system
  template_key    TEXT NOT NULL,                          -- 模板键（不含正文）
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,     -- 只放 id / 金额 / 时间 / 原因码
  dedupe_key      TEXT,                                   -- 应用层去重键（同节点内唯一）
  state           TEXT NOT NULL DEFAULT 'queued',         -- queued / delivered / read / expired
  source_event_id UUID,                                   -- 上游事件幂等键（全局唯一）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ,                            -- P0 必填；过期即不再投递
  delivered_at    TIMESTAMPTZ,
  read_at         TIMESTAMPTZ
);

-- payload 守卫（INV-07 的 DB 兜底）：返回第一个违规键名，NULL = 合规
CREATE OR REPLACE FUNCTION m12_node_payload_bad_key(payload JSONB) RETURNS TEXT AS $$
DECLARE
  forbidden TEXT[] := ARRAY['email', 'email_address', 'phone', 'phone_number', 'mobile',
                            'msisdn', 'secret', 'password', 'token', 'api_key', 'private_key',
                            'authorization', 'cookie', 'signature', 'body', 'content', 'html',
                            'text', 'message', 'subject', 'attachment', 'prompt', 'response'];
  entry RECORD;
  element JSONB;
BEGIN
  IF payload IS NULL THEN
    RETURN NULL;
  END IF;
  IF jsonb_typeof(payload) <> 'object' THEN
    RETURN 'payload';
  END IF;
  FOR entry IN SELECT key, value FROM jsonb_each(payload) LOOP
    IF lower(entry.key) = ANY (forbidden) THEN
      RETURN entry.key;
    END IF;
    IF jsonb_typeof(entry.value) = 'object' THEN
      IF m12_node_payload_bad_key(entry.value) IS NOT NULL THEN
        RETURN entry.key;
      END IF;
    ELSIF jsonb_typeof(entry.value) = 'array' THEN
      FOR element IN SELECT jsonb_array_elements(entry.value) LOOP
        IF jsonb_typeof(element) = 'object'
           AND m12_node_payload_bad_key(element) IS NOT NULL THEN
          RETURN entry.key;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_severity_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_severity_ck
  CHECK (severity IN ('P0', 'P1', 'P2')) NOT VALID;

ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_category_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_category_ck
  CHECK (category IN ('alert', 'earnings', 'freeze', 'maintenance', 'campaign', 'system'))
  NOT VALID;

ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_state_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_state_ck
  CHECK (state IN ('queued', 'delivered', 'read', 'expired')) NOT VALID;

-- 元数据边界：列宽受限 → 正文 / 堆栈不可能塞进来
ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_meta_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_meta_ck
  CHECK (char_length(node_id) BETWEEN 1 AND 128
     AND char_length(template_key) BETWEEN 1 AND 64
     AND (dedupe_key IS NULL OR char_length(dedupe_key) BETWEEN 1 AND 200)
     AND jsonb_typeof(payload) = 'object') NOT VALID;

-- INV-07：payload 不得出现 PII / 正文 / 凭据键（DB 兜底）
ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_payload_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_payload_ck
  CHECK (m12_node_payload_bad_key(payload) IS NULL) NOT VALID;

-- P0 必须带过期时间（不允许长期悬挂），且过期时间必须晚于创建时间
ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_p0_expiry_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_p0_expiry_ck
  CHECK (severity <> 'P0' OR expires_at IS NOT NULL) NOT VALID;

ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_expiry_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_expiry_ck
  CHECK (expires_at IS NULL OR expires_at > created_at) NOT VALID;

-- read 蕴含 delivered（read_at 存在 → delivered_at 必须存在）
ALTER TABLE node_notifications DROP CONSTRAINT IF EXISTS node_notifications_read_order_ck;
ALTER TABLE node_notifications ADD CONSTRAINT node_notifications_read_order_ck
  CHECK (read_at IS NULL OR delivered_at IS NOT NULL) NOT VALID;

-- 幂等：同节点 dedupe_key 唯一（NULL 不冲突）；source_event_id 全局唯一
CREATE UNIQUE INDEX IF NOT EXISTS node_notifications_dedupe_uq
  ON node_notifications (node_id, dedupe_key);

CREATE UNIQUE INDEX IF NOT EXISTS node_notifications_source_event_uq
  ON node_notifications (source_event_id);

-- 拉取索引：按节点 + keyset 游标，只扫「未读且未过期」的行
CREATE INDEX IF NOT EXISTS node_notifications_pull_idx
  ON node_notifications (node_id, created_at, id)
  WHERE state IN ('queued', 'delivered');

CREATE INDEX IF NOT EXISTS node_notifications_expiry_idx
  ON node_notifications (expires_at)
  WHERE state IN ('queued', 'delivered');

CREATE INDEX IF NOT EXISTS node_notifications_node_state_idx
  ON node_notifications (node_id, state, created_at DESC);

COMMENT ON TABLE node_notifications IS
  'M12a 节点通知队列（迁移 1206）：服务端排队、节点离线拉取；payload 只放 id/金额/时间/原因码';
COMMENT ON COLUMN node_notifications.dedupe_key IS
  '应用层去重键：同节点内唯一（重复入队返回既有行，不产生第二条通知）';
COMMENT ON COLUMN node_notifications.source_event_id IS
  '上游事件幂等键：全局唯一（同一事件重复投递只落一条通知）';
COMMENT ON COLUMN node_notifications.payload IS
  '只允许 id / 金额 / 时间 / 原因码：不得出现 PII、正文或凭据（INV-07，DB 约束兜底）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = current_schema() AND p.proname = 'm12_node_payload_bad_key') THEN
    RAISE EXCEPTION '1206: 缺 payload 守卫函数 m12_node_payload_bad_key';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'node_notifications_dedupe_uq') THEN
    RAISE EXCEPTION '1206: 缺去重唯一索引 node_notifications_dedupe_uq';
  END IF;
END
$$;

COMMIT;
