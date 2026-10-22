-- 206 · M02 node-supply · 幂等键（supply_idempotency）
-- 规格：M02 §3 幂等段（pair / binding / review 按 X-DJB-Idempotency-Key 24 h）·
--       00-conventions §6.1（同一键重复请求返回第一次结果，不重复落账）
--
-- 形态与 M01 的 identity_idempotency 一致：**只存响应体，不存任何明文凭据**。
-- pair / register 的响应含一次性明文 client_key，落表前必须剔除（否则等于凭据落库）。
BEGIN;

CREATE TABLE IF NOT EXISTS supply_idempotency (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope        TEXT NOT NULL,                     -- 方法 + 归一化路径（≤64 字符）
  idem_key     TEXT NOT NULL,                     -- X-DJB-Idempotency-Key（≤128 字符）
  request_hash TEXT NOT NULL,                     -- sha256(canonical_json(body))
  status_code  INTEGER NOT NULL,
  response     JSONB NOT NULL,                    -- 首次响应体（已剔明文）
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,              -- 24 h 窗口

  CONSTRAINT supply_idempotency_uq UNIQUE (scope, idem_key),
  CONSTRAINT supply_idempotency_scope_chk CHECK (char_length(scope) BETWEEN 1 AND 64),
  CONSTRAINT supply_idempotency_key_chk CHECK (char_length(idem_key) BETWEEN 1 AND 128),
  CONSTRAINT supply_idempotency_ttl_chk CHECK (expires_at > created_at),
  CONSTRAINT supply_idempotency_response_ck CHECK (jsonb_typeof(response) = 'object')
);

CREATE INDEX IF NOT EXISTS supply_idempotency_expiry_idx
  ON supply_idempotency (expires_at);

COMMIT;
