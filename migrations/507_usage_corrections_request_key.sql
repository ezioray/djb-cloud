-- 507 · M05 计量收据 · 校正幂等键（usage_corrections.request_key）
-- 规格：product/v4/modules/M05-metering-receipt.md §4.1（POST /admin/usage/corrections「必带」幂等键）
--       00-conventions §5（写接口必须支持幂等键）· §6.1（同键重复请求返回第一次结果）
--       spec 1.2.0 `POST /api/v1/admin/usage/corrections` 的参数 IdempotencyKey
--
-- 为什么加列：人工校正没有 ``upstream_bill_id`` 时，``(usage_id, upstream_bill_id)`` 唯一键
-- 无法覆盖「同一请求重复提交」；按「只加不改」新增 ``request_key``（客户端幂等键原样存）+
-- 部分唯一索引，重复提交直接返回首次结果（不新增校正、不改历史）。
BEGIN;

ALTER TABLE usage_corrections ADD COLUMN IF NOT EXISTS request_key TEXT;

ALTER TABLE usage_corrections DROP CONSTRAINT IF EXISTS usage_corrections_request_key_ck;
ALTER TABLE usage_corrections ADD CONSTRAINT usage_corrections_request_key_ck
  CHECK (request_key IS NULL OR char_length(request_key) BETWEEN 1 AND 200) NOT VALID;

-- 幂等：同一幂等键只允许一条校正（空值不参与唯一）
DROP INDEX IF EXISTS usage_corrections_request_key_uq;
CREATE UNIQUE INDEX usage_corrections_request_key_uq
  ON usage_corrections (request_key) WHERE request_key IS NOT NULL;

COMMENT ON COLUMN usage_corrections.request_key IS
  'X-DJB-Idempotency-Key 原样（1..200）；重复提交返回首次结果（00-conventions §6.1）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'usage_corrections_request_key_uq') THEN
    RAISE EXCEPTION '507: 缺幂等索引 usage_corrections_request_key_uq';
  END IF;
END
$$;

COMMIT;
