-- 904 · M09 对账 · 储备证明快照（por_snapshots）
-- 规格：M09-recon-reports.md §3.1 / §3.2（computed -> published（日根）-> month_proof）/
--       §3.3 INV-06（分子只计确认数达标入账；出方向在途扣减；冻结资产剔除；
--                     覆盖率低于 100% 不得 published 为正常态）
--       §5 数据所有权（por_snapshots，保留 5 年及以上）
--
-- 本轮（T1–T3）**只建表与视图**，不实现 PoR 计算与发布（T4）。表在这里一次建好，
-- 是为了 901–905 的迁移段完整、T4 不再改 9xx 编号；本模块代码不写这张表。
BEGIN;

CREATE TABLE IF NOT EXISTS por_snapshots (
  snapshot_id        UUID PRIMARY KEY,                -- UUIDv7
  granularity        TEXT NOT NULL,                   -- daily / monthly（§3.1「日 / 月各一条」）
  cutoff_at          TIMESTAMPTZ NOT NULL,            -- 截止时刻（同粒度唯一）
  block_height       BIGINT,                          -- 截止高度（scope=chain 口径）
  assets_minor       BIGINT NOT NULL DEFAULT 0,       -- 确认数达标入账的资产
  liabilities_minor  BIGINT NOT NULL DEFAULT 0,       -- 负债（出方向在途已扣减）
  coverage_bps       INTEGER,                         -- 覆盖率（万分比；10000 = 100%）
  gap_minor          BIGINT,                          -- 缺口（负值 = 超额覆盖）
  psp_recovery_bps   INTEGER,                         -- PSP 可回收比例（M09 §8.1 por.psp_recovery_bps）
  fx_rate_id         BIGINT,                          -- 汇率引用（不存汇率数值）
  merkle_root        TEXT,                            -- 叶子 = H(account|unit|balance|salt)（§8.2）
  status             TEXT NOT NULL DEFAULT 'computed',
  self_proof_ref     TEXT,                            -- 月根自证引用
  tenant_id          TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at       TIMESTAMPTZ,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT por_snapshots_granularity_ck CHECK (granularity IN ('daily', 'monthly')),
  CONSTRAINT por_snapshots_status_ck CHECK (
    status IN ('computed', 'published', 'month_proof')),
  CONSTRAINT por_snapshots_amounts_ck CHECK (assets_minor >= 0 AND liabilities_minor >= 0),
  CONSTRAINT por_snapshots_coverage_ck CHECK (
    coverage_bps IS NULL OR (coverage_bps >= 0 AND coverage_bps <= 100000)),
  CONSTRAINT por_snapshots_root_ck CHECK (
    merkle_root IS NULL OR merkle_root ~ '^[0-9a-f]{64}$'),
  -- INV-06：覆盖率低于 100% 不得 published / month_proof
  CONSTRAINT por_snapshots_inv06_ck CHECK (
    status = 'computed'
    OR (coverage_bps IS NOT NULL AND coverage_bps >= 10000)),
  CONSTRAINT por_snapshots_published_ck CHECK (
    (status = 'computed' AND published_at IS NULL)
    OR (status <> 'computed' AND published_at IS NOT NULL))
);

-- §5「快照 cutoff_at」：同粒度同一截止时刻只有一条
CREATE UNIQUE INDEX IF NOT EXISTS por_snapshots_granularity_cutoff_uq
  ON por_snapshots (granularity, cutoff_at);
CREATE INDEX IF NOT EXISTS por_snapshots_cutoff_idx
  ON por_snapshots (cutoff_at DESC);
CREATE INDEX IF NOT EXISTS por_snapshots_tenant_idx
  ON por_snapshots (tenant_id, cutoff_at DESC) WHERE tenant_id IS NOT NULL;

CREATE OR REPLACE FUNCTION m09_por_guard() RETURNS trigger AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['computed->published', 'published->month_proof'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'por_snapshots is append-only: DELETE not allowed (M09 §3.1)'
      USING ERRCODE = '42501';
  END IF;

  -- 快照数字只读：状态之外只允许回填发布痕迹（published_at / self_proof_ref / updated_at）
  IF (to_jsonb(NEW) - ARRAY['status', 'published_at', 'self_proof_ref', 'updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'published_at', 'self_proof_ref', 'updated_at']) THEN
    RAISE EXCEPTION 'por_snapshots: only status/publish fields may change (M09 §3.1)'
      USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'por_snapshots: illegal transition % -> % (M09 §3.2)',
      OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS por_snapshots_guard ON por_snapshots;
CREATE TRIGGER por_snapshots_guard BEFORE UPDATE OR DELETE ON por_snapshots
  FOR EACH ROW EXECUTE FUNCTION m09_por_guard();
DROP TRIGGER IF EXISTS por_snapshots_no_truncate ON por_snapshots;
CREATE TRIGGER por_snapshots_no_truncate BEFORE TRUNCATE ON por_snapshots
  FOR EACH STATEMENT EXECUTE FUNCTION m09_forbid_truncate();

-- 只读视图：每粒度最新一条（报表 / 出款前查询口径）
CREATE OR REPLACE VIEW v_m09_latest_por AS
  SELECT DISTINCT ON (granularity)
         snapshot_id, granularity, cutoff_at, block_height, assets_minor, liabilities_minor,
         coverage_bps, gap_minor, psp_recovery_bps, fx_rate_id, merkle_root, status,
         published_at, tenant_id
    FROM por_snapshots
   ORDER BY granularity, cutoff_at DESC;

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['snapshot_id','granularity','cutoff_at','block_height','assets_minor',
                      'liabilities_minor','coverage_bps','gap_minor','psp_recovery_bps',
                      'fx_rate_id','merkle_root','status','self_proof_ref','tenant_id',
                      'created_at','published_at','updated_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'por_snapshots'
        AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'por_snapshots 结构与 904 不符，缺列：%', v_missing;
  END IF;
  IF to_regclass('por_snapshots_granularity_cutoff_uq') IS NULL THEN
    RAISE EXCEPTION 'por_snapshots 缺 (granularity, cutoff_at) 唯一索引（904 / §5）';
  END IF;
END;
$$;

COMMIT;
