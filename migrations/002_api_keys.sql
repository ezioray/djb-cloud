-- 002 · 用方 API Key（只存哈希，明文只显示一次）与幂等键
BEGIN;

CREATE TABLE IF NOT EXISTS api_keys (
  id         BIGSERIAL PRIMARY KEY,
  user_id    TEXT NOT NULL,
  key_prefix TEXT NOT NULL,              -- 前 8 位便于排障，不可用于鉴权
  key_hash   TEXT NOT NULL UNIQUE,       -- sha256(明文)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id);

ALTER TABLE receipts ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS receipts_idem_uq ON receipts(idempotency_key) WHERE idempotency_key IS NOT NULL;

COMMIT;
