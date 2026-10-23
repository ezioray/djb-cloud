-- 1203 · M12 Webhook 订阅（webhook_subscriptions）
-- 规格：product/v4/modules/M12-notification.md §3 INV-05（签名 / secret 只返回一次、只存哈希）
--       §5 数据所有权（webhook_subscriptions，迁移 1203，随账户）· §6 流程 6.3
--       §4.1 POST/GET/DELETE /api/v1/user/webhooks · spec 1.2.3 WebhookSubscription*
--
-- 语义：
--   1) **只存哈希**：secret_hash = sha256(secret) 十六进制；DB 层 CHECK 形状，明文永不落库。
--   2) **订阅唯一**：UNIQUE(account_id, url)——同账户同一 URL 只能有一条订阅（§3 幂等与唯一）。
--   3) **幂等键**：UNIQUE(account_id, idempotency_key)（部分索引）——同一幂等键重复提交不产生第二条；
--      回放时服务端**无法**再给出 secret（只存哈希），只能返回冲突，详见 app/notify/webhooks.py。
--   4) **https-only**：DB 层兜底只接受 https://（§6.3「仅 https」）；SSRF 私网判定在应用层（需解析主机）。
--   5) **注销**：DELETE 行是取消订阅的正常路径（非账本类表），但不允许 TRUNCATE。
BEGIN;

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id                  UUID PRIMARY KEY,                -- 订阅 id（UUIDv7）
  account_id          UUID NOT NULL,                   -- 订阅账户（M01 accounts，软引用）
  url                 TEXT NOT NULL,                   -- 回调地址（含路径；查询串不写日志，见 INV-07）
  url_host            TEXT NOT NULL,                   -- 冗余主机名（审计 / 日志用，不含查询串）
  events              TEXT[] NOT NULL,                 -- 事件白名单（spec 枚举，至少 1 个）
  description         TEXT,                            -- 备注（≤200，不参与投递）
  secret_hash         TEXT NOT NULL,                   -- sha256(secret) 十六进制；明文永不落库（INV-05）
  secret_alg          TEXT NOT NULL DEFAULT 'sha256',  -- 哈希算法标识（只加不改）
  status              TEXT NOT NULL DEFAULT 'active',  -- active ⇄ paused → disabled
  paused_until        TIMESTAMPTZ,                     -- paused 的自动恢复时刻（NULL = 人工恢复）
  failure_count       INTEGER NOT NULL DEFAULT 0,      -- 连续失败计数（4xx 永久失败 → paused）
  idempotency_key     TEXT,                            -- 创建时的 X-DJB-Idempotency-Key（24h 语义）
  request_fingerprint TEXT,                            -- 幂等键对应的请求指纹（不含 secret）
  created_at          TIMESTAMPTZ NOT NULL,
  updated_at          TIMESTAMPTZ NOT NULL
);

ALTER TABLE webhook_subscriptions DROP CONSTRAINT IF EXISTS webhook_subscriptions_status_ck;
ALTER TABLE webhook_subscriptions ADD CONSTRAINT webhook_subscriptions_status_ck
  CHECK (status IN ('active', 'paused', 'disabled')) NOT VALID;

ALTER TABLE webhook_subscriptions DROP CONSTRAINT IF EXISTS webhook_subscriptions_events_ck;
ALTER TABLE webhook_subscriptions ADD CONSTRAINT webhook_subscriptions_events_ck
  CHECK (cardinality(events) BETWEEN 1 AND 5
     AND events <@ ARRAY['task.completed', 'task.failed', 'payment.settled',
                         'payout.sent', 'security.alert']::text[]) NOT VALID;

-- 只接受 https（§6.3）；长度上限防止把超长字符串塞进日志 / 审计
ALTER TABLE webhook_subscriptions DROP CONSTRAINT IF EXISTS webhook_subscriptions_url_ck;
ALTER TABLE webhook_subscriptions ADD CONSTRAINT webhook_subscriptions_url_ck
  CHECK (url LIKE 'https://%' AND char_length(url) BETWEEN 9 AND 2048
     AND char_length(url_host) BETWEEN 1 AND 255) NOT VALID;

-- 只存哈希（INV-05）：形状不对直接拒写，避免有人把明文塞进 secret_hash
ALTER TABLE webhook_subscriptions DROP CONSTRAINT IF EXISTS webhook_subscriptions_hash_ck;
ALTER TABLE webhook_subscriptions ADD CONSTRAINT webhook_subscriptions_hash_ck
  CHECK (secret_alg = 'sha256' AND secret_hash ~ '^[0-9a-f]{64}$') NOT VALID;

ALTER TABLE webhook_subscriptions DROP CONSTRAINT IF EXISTS webhook_subscriptions_desc_ck;
ALTER TABLE webhook_subscriptions ADD CONSTRAINT webhook_subscriptions_desc_ck
  CHECK (description IS NULL OR char_length(description) <= 200) NOT VALID;

ALTER TABLE webhook_subscriptions DROP CONSTRAINT IF EXISTS webhook_subscriptions_failure_ck;
ALTER TABLE webhook_subscriptions ADD CONSTRAINT webhook_subscriptions_failure_ck
  CHECK (failure_count >= 0) NOT VALID;

-- 订阅唯一（§3）：同账户 + 同 URL 只一条
DROP INDEX IF EXISTS webhook_subscriptions_account_url_uq;
CREATE UNIQUE INDEX webhook_subscriptions_account_url_uq
  ON webhook_subscriptions (account_id, url);

-- 幂等键唯一（部分索引：未带幂等键的旧行不参与）
DROP INDEX IF EXISTS webhook_subscriptions_idem_uq;
CREATE UNIQUE INDEX webhook_subscriptions_idem_uq
  ON webhook_subscriptions (account_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- 列表（同账户按创建时间倒序）与派发前扫描（启用中的订阅）
DROP INDEX IF EXISTS webhook_subscriptions_account_created_idx;
CREATE INDEX webhook_subscriptions_account_created_idx
  ON webhook_subscriptions (account_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS webhook_subscriptions_status_idx;
CREATE INDEX webhook_subscriptions_status_idx
  ON webhook_subscriptions (status, paused_until);

-- ────────────────────────────────────────────────────────── 护栏
CREATE OR REPLACE FUNCTION m12_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M12 §5)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

-- 不可变列：id / account_id / url / secret_hash / created_at；secret_hash 连「换密钥」都不允许，
-- 换密钥必须重建订阅（S1 无轮换接口）。可变列：status / paused_until / failure_count / updated_at。
CREATE OR REPLACE FUNCTION m12_webhook_guard() RETURNS trigger AS $$
DECLARE
  mutable TEXT[] := ARRAY['status', 'paused_until', 'failure_count', 'updated_at'];
BEGIN
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'webhook_subscriptions: url/secret_hash are immutable (INV-05)'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS webhook_subscriptions_guard ON webhook_subscriptions;
CREATE TRIGGER webhook_subscriptions_guard BEFORE UPDATE ON webhook_subscriptions
  FOR EACH ROW EXECUTE FUNCTION m12_webhook_guard();

DROP TRIGGER IF EXISTS webhook_subscriptions_no_truncate ON webhook_subscriptions;
CREATE TRIGGER webhook_subscriptions_no_truncate BEFORE TRUNCATE ON webhook_subscriptions
  FOR EACH STATEMENT EXECUTE FUNCTION m12_forbid_truncate();

COMMENT ON TABLE webhook_subscriptions IS
  'M12 Webhook 订阅（M12 §5 / 迁移 1203）：secret 只存哈希、只返回一次（INV-05）；仅 https';
COMMENT ON COLUMN webhook_subscriptions.secret_hash IS
  'sha256(secret) 十六进制；明文永不落库、永不写日志（INV-05 / INV-07）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'webhook_subscriptions_account_url_uq') THEN
    RAISE EXCEPTION '1203: 缺订阅唯一索引 webhook_subscriptions_account_url_uq';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'webhook_subscriptions_idem_uq') THEN
    RAISE EXCEPTION '1203: 缺幂等键唯一索引 webhook_subscriptions_idem_uq';
  END IF;
END
$$;

COMMIT;
