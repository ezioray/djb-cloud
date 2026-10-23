-- 305 · M03 网关 · 幂等 / 请求体指纹（m03_idempotency）
-- 规格：product/v4/modules/M03-gateway-protocol.md §3.1（idempotency_record 聚合：(scope, key) 唯一，
--       24h 后过期）· §3.2 INV-M03-03（同键返回第一次结果，不重复落账/扣费）
--       §8.2（idempotency_ttl_s=86400 / fingerprint_window_s=300 / stream_dedup_window_s=60）
--       00-conventions §6.1（写接口必须支持幂等键）
--
-- 口径：
--   1) **一条记录 = 一次首次结果**：(scope, key) 唯一，scope 含「方法 + 路径 + 账户 + Key」，
--      同键不同账户互不回放；
--   2) **窗口**：带 X-DJB-Idempotency-Key 的行 TTL 24h（expires_at 由应用层算）；
--      请求体指纹行 TTL = 300s（非流式）/ 60s（流式），同样落在 expires_at；
--   3) **只追加后覆盖**：过期行可被同键新结果替换（应用层 ON CONFLICT DO UPDATE），
--      未过期行绝不被覆盖（应用层先判 409）；行本身不做 UPDATE 触发器拦截，因为覆盖是
--      唯一允许的写路径且只能由应用层触发（见 m03_idempotency_guard：只允许同 scope/key）。
--   4) 保留：过期后由应用层小批量 DELETE（``purge_idempotency``），不参与 7 天审计保留。
BEGIN;

CREATE TABLE IF NOT EXISTS m03_idempotency (
  id           UUID PRIMARY KEY,                  -- UUIDv7（行标识）
  scope        TEXT NOT NULL,                     -- idem:<METHOD>:<path>:<account>:<key_id> / fp:...
  key          TEXT NOT NULL,                     -- 幂等键 或 请求体 sha256
  request_hash TEXT NOT NULL,                     -- 规范化报文 sha256（判定「同键不同载荷」）
  status_code  INTEGER NOT NULL,                  -- 首次响应的 HTTP 状态
  response     JSONB NOT NULL,                    -- 首次响应体（**不含**正文持久化语义）
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL
);

ALTER TABLE m03_idempotency DROP CONSTRAINT IF EXISTS m03_idempotency_scope_ck;
ALTER TABLE m03_idempotency ADD CONSTRAINT m03_idempotency_scope_ck
  CHECK (char_length(scope) BETWEEN 1 AND 256
     AND char_length(key) BETWEEN 1 AND 256
     AND char_length(request_hash) = 64
     AND status_code BETWEEN 100 AND 599
     AND expires_at > created_at) NOT VALID;

CREATE UNIQUE INDEX IF NOT EXISTS m03_idempotency_scope_key_uq
  ON m03_idempotency (scope, key);
CREATE INDEX IF NOT EXISTS m03_idempotency_expires_idx ON m03_idempotency (expires_at);

-- 覆盖护栏：同 (scope, key) 的 UPDATE 只允许「过期后重写」，不允许改 scope/key 本体。
-- 注意：过期判定用 **NEW.created_at（应用时钟）** 而不是 now()，保证测试固定时钟下
-- 与应用层的判定同源（00-conventions §10「测试必须确定性」）。
CREATE OR REPLACE FUNCTION m03_idempotency_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.created_at < OLD.expires_at THEN
      RAISE EXCEPTION 'm03_idempotency: unexpired record must not be overwritten (INV-M03-03)'
        USING ERRCODE = '42501';
    END IF;
    IF NEW.scope IS DISTINCT FROM OLD.scope OR NEW.key IS DISTINCT FROM OLD.key THEN
      RAISE EXCEPTION 'm03_idempotency: scope/key is immutable' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS m03_idempotency_guard ON m03_idempotency;
CREATE TRIGGER m03_idempotency_guard BEFORE UPDATE ON m03_idempotency
  FOR EACH ROW EXECUTE FUNCTION m03_idempotency_guard();

COMMENT ON TABLE m03_idempotency IS
  'M03 幂等/指纹（迁移 305）：(scope,key) 唯一；幂等键 24h、指纹 300s/60s；过期才可覆盖';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'm03_idempotency_scope_key_uq') THEN
    RAISE EXCEPTION '305: 缺幂等唯一索引 m03_idempotency_scope_key_uq';
  END IF;
END
$$;

COMMIT;
