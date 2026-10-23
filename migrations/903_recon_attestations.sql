-- 903 · M09 对账 · 复核凭证（reconciliation_attestations）+ INV-05 唯一 valid
-- 规格：M09-recon-reports.md §3.1 / §3.2 状态机 / §3.3 INV-05
--       「同一 (period_start, period_end, batch_hash) 只能一个 valid attestation；
--        签名覆盖 ledger_root + batch_hash + balances + payable_total；复核人 ≠ 制单人」
--       §5 数据所有权（reconciliation_attestations，保留 5 年及以上）
--
-- 原则：
--   1) 只追加（§3.2「valid attestation 被 UPDATE」禁止）：除 valid -> superseded / revoked
--      的状态流转外，任何列不得变化；DELETE 一律拒绝。
--   2) 唯一性用**部分唯一索引**表达（只约束 status='valid' 的行），重复提交由应用层
--      转成 409 + 49205；索引是最后一道防线。
--   3) 只存引用与摘要：私钥在复核人设备，本表不存签名原文 / 私钥 / 口令（M09 §1 非责任）。
BEGIN;

CREATE TABLE IF NOT EXISTS reconciliation_attestations (
  attestation_id     UUID PRIMARY KEY,                -- UUIDv7
  period_start       TIMESTAMPTZ NOT NULL,
  period_end         TIMESTAMPTZ NOT NULL,
  ledger_root        TEXT NOT NULL,                   -- M06 Merkle 根（hex64）
  chain_snapshot_ref TEXT,                            -- 链上快照引用（不存正文）
  bank_snapshot_ref  TEXT,                            -- 银行快照引用
  balances_ref       TEXT,                            -- 余额快照引用（INV-05 签名覆盖面之一）
  payable_total_minor BIGINT NOT NULL,                -- 应付合计（整数最小单位）
  batch_hash         TEXT NOT NULL,                   -- 批次哈希（M08 出款批次）
  reviewer_id        TEXT,                            -- 复核人（≠ 制单人）
  reviewer_pubkey_ref TEXT,                           -- 复核人公钥引用（不存公钥正文）
  maker_id           TEXT,                            -- 制单人（追加列，用于 INV-05 比对）
  signature_ref      TEXT NOT NULL,                   -- 签名引用（设备侧签名，不存原文）
  hsm_verified_at    TIMESTAMPTZ,
  status             TEXT NOT NULL DEFAULT 'valid',
  tenant_id          TEXT,                            -- 追加列（NULL = 平台级）
  idempotency_key    TEXT,                            -- 提交幂等键（24h；追加列）
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT reconciliation_attestations_period_ck CHECK (period_end > period_start),
  CONSTRAINT reconciliation_attestations_root_ck CHECK (ledger_root ~ '^[0-9a-f]{64}$'),
  CONSTRAINT reconciliation_attestations_batch_ck CHECK (batch_hash ~ '^[0-9a-f]{16,128}$'),
  CONSTRAINT reconciliation_attestations_payable_ck CHECK (payable_total_minor >= 0),
  CONSTRAINT reconciliation_attestations_status_ck CHECK (
    status IN ('valid', 'superseded', 'revoked')),
  -- INV-05：复核人 ≠ 制单人（同人提交直接进不来）
  CONSTRAINT reconciliation_attestations_dual_ck CHECK (
    maker_id IS NULL OR reviewer_id IS NULL OR maker_id <> reviewer_id),
  CONSTRAINT reconciliation_attestations_sig_ck CHECK (char_length(signature_ref) BETWEEN 1 AND 256)
);

-- INV-05：同一 (period_start, period_end, batch_hash) 只能一个 valid（部分唯一）
CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_attestations_valid_uq
  ON reconciliation_attestations (period_start, period_end, batch_hash)
  WHERE status = 'valid';

-- 同键重放（24h）返回首次结果
CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_attestations_idem_uq
  ON reconciliation_attestations (idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS reconciliation_attestations_period_idx
  ON reconciliation_attestations (period_end DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS reconciliation_attestations_tenant_idx
  ON reconciliation_attestations (tenant_id, created_at DESC) WHERE tenant_id IS NOT NULL;

-- ────────────────────────────────────────────── 只追加 + 状态流转护栏
CREATE OR REPLACE FUNCTION m09_attestations_guard() RETURNS trigger AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['valid->superseded', 'valid->revoked'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'reconciliation_attestations is append-only: DELETE not allowed (M09 §3.2)'
      USING ERRCODE = '42501';
  END IF;

  -- 除 status / updated_at 外一律不可变（valid 只能 revoke 后新件替代，§3.2）
  IF (to_jsonb(NEW) - ARRAY['status', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'updated_at']) THEN
    RAISE EXCEPTION 'reconciliation_attestations: only status may change (M09 §3.2)'
      USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'reconciliation_attestations: illegal transition % -> % (M09 §3.2)',
      OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reconciliation_attestations_guard ON reconciliation_attestations;
CREATE TRIGGER reconciliation_attestations_guard BEFORE UPDATE OR DELETE
  ON reconciliation_attestations FOR EACH ROW EXECUTE FUNCTION m09_attestations_guard();
DROP TRIGGER IF EXISTS reconciliation_attestations_no_truncate ON reconciliation_attestations;
CREATE TRIGGER reconciliation_attestations_no_truncate BEFORE TRUNCATE
  ON reconciliation_attestations FOR EACH STATEMENT EXECUTE FUNCTION m09_forbid_truncate();

-- ────────────────────────────────────────────── 只读视图
CREATE OR REPLACE VIEW v_m09_valid_attestations AS
  SELECT attestation_id, period_start, period_end, ledger_root, payable_total_minor, batch_hash,
         reviewer_id, maker_id, signature_ref, hsm_verified_at, tenant_id, created_at
    FROM reconciliation_attestations
   WHERE status = 'valid';

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['attestation_id','period_start','period_end','ledger_root',
                      'chain_snapshot_ref','bank_snapshot_ref','balances_ref',
                      'payable_total_minor','batch_hash','reviewer_id','reviewer_pubkey_ref',
                      'maker_id','signature_ref','hsm_verified_at','status','tenant_id',
                      'idempotency_key','created_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'reconciliation_attestations'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'reconciliation_attestations 结构与 903 不符，缺列：%', v_missing;
  END IF;
  IF to_regclass('reconciliation_attestations_valid_uq') IS NULL THEN
    RAISE EXCEPTION 'reconciliation_attestations 缺 INV-05 部分唯一索引（903）';
  END IF;
END;
$$;

COMMIT;
