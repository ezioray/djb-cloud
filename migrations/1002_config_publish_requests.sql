-- 1002 · M10 配置中心 · 发布单（config_publish_requests）
-- 规格：M10 §3（发布单状态机 / 禁迁移）· §5 数据所有权（迁移 1002；uq_requests / idx_requests_status）
--       §6 事务边界（version + publish_request + outbox 同事务）· INV-03（自批自核）
--       product/v4/src/21-config-management.md §21.4.1（九步）· §21.4.2（状态机）
--
-- 本文件的边界（T2 只做存储，不做流程）：
--   · 建表 + 枚举 + 结构性约束 + INV-03 的库层断点；
--   · **状态机触发器留给 T3**（发布单九步、CAS 切换、4h 过期、冷却期都在 T3 实现）；
--   · 不做任何「自动放行」：expired 只是状态，不产生版本（§21.4.2）。
BEGIN;

CREATE TABLE IF NOT EXISTS config_publish_requests (
  publish_request_id UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
  key             TEXT        NOT NULL,              -- S1 单 key；key_set 冗余保存，便于演进多 key
  namespace       TEXT        NOT NULL,
  key_set         TEXT[]      NOT NULL,
  versions        JSONB       NOT NULL,              -- {"<key>": <version>} 或 [{"key":..,"version":..}]
  risk_level      TEXT        NOT NULL,
  scope           TEXT        NOT NULL DEFAULT 'global',
  scope_id        TEXT        NOT NULL DEFAULT '',
  status          TEXT        NOT NULL DEFAULT 'draft',
  proposed_by     TEXT        NOT NULL,              -- 发起人（≠ 复核人，INV-03）
  approved_by     TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
  decision        TEXT,                              -- approve / reject（终态时写）
  gray_plan       JSONB,                             -- {"buckets":[..],"observation_seconds":N}
  snapshot_before TEXT,                              -- 发布前快照 digest（64 hex）
  snapshot_after  TEXT,                              -- 发布后快照 digest（发布成功必填，T4 落）
  requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ,                       -- pending_approval 4h 过期
  effective_at    TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  reason          TEXT        NOT NULL,
  ticket          TEXT,
  idempotency_key TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT config_publish_requests_status_ck CHECK (status IN (
    'draft', 'pending_approval', 'approved', 'scheduled', 'rolling_out', 'active',
    'closed', 'rejected', 'expired', 'cancelled', 'failed', 'rolled_back')),
  CONSTRAINT config_publish_requests_risk_ck CHECK (risk_level IN ('P0', 'P1', 'P2')),
  CONSTRAINT config_publish_requests_scope_ck CHECK (scope IN ('global', 'region', 'tenant')),
  CONSTRAINT config_publish_requests_scope_id_ck CHECK (
    (scope = 'global' AND scope_id = '')
    OR (scope IN ('region', 'tenant') AND scope_id <> '')),
  CONSTRAINT config_publish_requests_key_set_ck CHECK (
    array_length(key_set, 1) BETWEEN 1 AND 16 AND key = ANY (key_set)),
  CONSTRAINT config_publish_requests_versions_ck CHECK (jsonb_typeof(versions) IN ('object', 'array')),
  CONSTRAINT config_publish_requests_decision_ck CHECK (
    decision IS NULL OR decision IN ('approve', 'reject')),
  CONSTRAINT config_publish_requests_reason_ck CHECK (char_length(reason) BETWEEN 4 AND 512),
  CONSTRAINT config_publish_requests_idem_ck CHECK (
    idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 8 AND 128),
  CONSTRAINT config_publish_requests_digest_ck CHECK (
    (snapshot_before IS NULL OR snapshot_before ~ '^[0-9a-f]{64}$')
    AND (snapshot_after IS NULL OR snapshot_after ~ '^[0-9a-f]{64}$')),
  CONSTRAINT config_publish_requests_closed_ck CHECK (status <> 'closed' OR closed_at IS NOT NULL),
  -- INV-03（库层断点）：发起人不得出现在复核人列表里
  CONSTRAINT config_publish_requests_sod_ck CHECK (NOT (proposed_by = ANY (approved_by)))
);

CREATE INDEX IF NOT EXISTS config_publish_requests_status_idx
  ON config_publish_requests (status, requested_at);
CREATE INDEX IF NOT EXISTS config_publish_requests_key_idx
  ON config_publish_requests (key, scope, scope_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS config_publish_requests_idem_uq
  ON config_publish_requests (scope, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- ───────────────────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['publish_request_id','key','namespace','key_set','versions','risk_level','scope',
                      'scope_id','status','proposed_by','approved_by','decision','gray_plan',
                      'snapshot_before','snapshot_after','requested_at','expires_at','effective_at',
                      'closed_at','reason','ticket','idempotency_key','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'config_publish_requests'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'config_publish_requests 结构与 1002 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
