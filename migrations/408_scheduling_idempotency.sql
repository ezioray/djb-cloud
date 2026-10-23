-- 408 · M04 scheduler-pricing · 幂等键（scheduling_idempotency）
-- 规格：M04 §3 幂等段「写接口以 (scope, X-DJB-Idempotency-Key) 唯一 24 h」
--       00-conventions §6.1 / spec 1.2.0（同键不同载荷 → 40919）
--       CR-5 已裁决：登记为 M04 辅助表
--
-- 设计：
--   1) 唯一键 (scope, idem_key)：scope = 「方法 + 归一化路径」（路径参数折成 {id}）；
--   2) 同键同载荷 → 回放首次响应（状态码与响应体都回放，**字节级一致**）；
--      同键不同载荷 → 应用层返回 409/40919，不做猜测性覆盖；
--   3) 24 h 窗口（expires_at），过期由清理作业删除——这是**缓存**不是审计表，
--      允许 DELETE，但禁止 UPDATE（重放必须是首次响应，不能被改）。
BEGIN;

CREATE TABLE IF NOT EXISTS scheduling_idempotency (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope        TEXT NOT NULL,
  idem_key     TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status_code  INT  NOT NULL,
  response     JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,

  CONSTRAINT scheduling_idempotency_uq UNIQUE (scope, idem_key),
  CONSTRAINT scheduling_idempotency_scope_ck CHECK (char_length(scope) BETWEEN 1 AND 64),
  CONSTRAINT scheduling_idempotency_key_ck CHECK (char_length(idem_key) BETWEEN 1 AND 128),
  CONSTRAINT scheduling_idempotency_hash_ck CHECK (char_length(request_hash) = 64),
  CONSTRAINT scheduling_idempotency_status_ck CHECK (status_code BETWEEN 100 AND 599),
  CONSTRAINT scheduling_idempotency_response_ck CHECK (jsonb_typeof(response) = 'object'),
  CONSTRAINT scheduling_idempotency_expiry_ck CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS scheduling_idempotency_expiry_idx
  ON scheduling_idempotency (expires_at);

-- 只允许删除过期行；响应体与载荷哈希不可改（回放必须是首次响应）
CREATE OR REPLACE FUNCTION m04_idempotency_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'scheduling_idempotency 禁止 UPDATE：回放必须是首次响应（00-conventions §6.1）';
  END IF;
  RETURN OLD;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scheduling_idempotency_guard_trg ON scheduling_idempotency;
CREATE TRIGGER scheduling_idempotency_guard_trg
  BEFORE UPDATE ON scheduling_idempotency
  FOR EACH ROW EXECUTE FUNCTION m04_idempotency_guard();

COMMENT ON TABLE scheduling_idempotency IS
  'M04 幂等键（CR-5 登记）：(scope, key) 唯一 24 h；同键同载荷回放首次响应，异载荷 40919';
COMMENT ON COLUMN scheduling_idempotency.scope IS '方法 + 归一化路径（路径参数折成 {id}，≤64 字符）';

COMMIT;
