-- 801 · M08 钱包与钱包池扩展（wallet 追加列 / wallet_transfers / 预生成批次扩展）
-- 规格：M08 §3（wallet / wallet_pool / provision_batch 状态机）· §5 数据所有权（迁移 801）
--       · INV-01（一钱包一池一 fund_class）· INV-02（激活批次不夹带转账）· INV-03（standby 余额 0；
--       ready = active ∧ gas_ok）· INV-04（cap × 在用只数 ≤ 池上限；cap 下限 1,000 USD）
--       · INV-05（max_active 只升不降）· 产品 §19.4.10（扩容 / 激活 / 切换 / 退休四步 / 池空摊量）
--       · 03-facts §2（min_spare 3 / max_active 8|4 / 70% / 每批 4 / 24h TTL / 50,000 USD / +4→20）
--
-- 前置：004 已建 wallet_pool / wallet / wallet_provision_batch / wallet_activation /
--       wallet_pool_event（旧表名保持单数，01-ownership §7）。本迁移**只加不改**：
--       · wallet 追加 cap_minor（单钱包 cap，分）/ policy_version / last_switched_at 等；
--       · provision_batch 追加 batch_no / created_by / idempotency_key / signing_request_id，
--         并把 status CHECK 放宽为规格的 draft → pending_sign → signed → activated
--         （004 没有 draft；放宽枚举值是加法，不改既有语义）；
--       · 新建 wallet_transfers（归集 / 调拨 / 出款执行）。
-- 可重复执行：IF NOT EXISTS / ADD COLUMN IF NOT EXISTS / DO 块先删后加约束。
BEGIN;

-- ────────────────────────────────────────────────────────────── wallet 追加列
ALTER TABLE wallet ADD COLUMN IF NOT EXISTS cap_minor        BIGINT;
ALTER TABLE wallet ADD COLUMN IF NOT EXISTS policy_version   TEXT;
ALTER TABLE wallet ADD COLUMN IF NOT EXISTS last_switched_at TIMESTAMPTZ;
ALTER TABLE wallet ADD COLUMN IF NOT EXISTS retired_reason   TEXT;
ALTER TABLE wallet ADD COLUMN IF NOT EXISTS updated_at       TIMESTAMPTZ NOT NULL DEFAULT now();

-- cap 正数（下限 1,000 USD 由应用层判：cap 被池上限压低时仍不得低于 1,000 USD）
ALTER TABLE wallet DROP CONSTRAINT IF EXISTS wallet_cap_ck;
ALTER TABLE wallet ADD CONSTRAINT wallet_cap_ck CHECK (cap_minor IS NULL OR cap_minor > 0);

-- INV-03：standby 钱包余额必须为 0（库层兜底；应用层切 standby 前先归零）
ALTER TABLE wallet DROP CONSTRAINT IF EXISTS wallet_standby_balance_ck;
ALTER TABLE wallet ADD CONSTRAINT wallet_standby_balance_ck CHECK (
  switch_state IS DISTINCT FROM 'standby' OR COALESCE(balance_minor, 0) = 0
);

CREATE INDEX IF NOT EXISTS wallet_fund_class_idx ON wallet (chain_id, fund_class, status);

COMMENT ON COLUMN wallet.cap_minor IS
  'M08 单钱包 cap（USD 分）：min(10,000 USD, 5 天预测)；被池上限压低时不低于 1,000 USD（INV-04）';

-- wallet 追加列同样禁止改池归属（004 触发器已拦 pool_id / chain_id / fund_class）
CREATE OR REPLACE FUNCTION m08_wallet_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'wallet 不可删除：地址与 wallet_id 永久可解析（§19.4.10(5)）'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.status = 'retired' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'wallet 已 retired，不可复活或重新激活（只能新建一只）' USING ERRCODE = '23514';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_wallet_guard ON wallet;
CREATE TRIGGER m08_wallet_guard BEFORE UPDATE OR DELETE ON wallet
  FOR EACH ROW EXECUTE FUNCTION m08_wallet_guard();

DROP TRIGGER IF EXISTS wallet_no_truncate ON wallet;
CREATE TRIGGER wallet_no_truncate BEFORE TRUNCATE ON wallet
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 预生成批次（追加列 + 放宽状态）
ALTER TABLE wallet_provision_batch ADD COLUMN IF NOT EXISTS batch_no TEXT;
ALTER TABLE wallet_provision_batch ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE wallet_provision_batch ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE wallet_provision_batch ADD COLUMN IF NOT EXISTS signing_request_id UUID;
ALTER TABLE wallet_provision_batch ADD COLUMN IF NOT EXISTS policy_version TEXT;
ALTER TABLE wallet_provision_batch ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- 004 的状态枚举没有 draft（规格 §3 是 draft → pending_sign → signed → activated）。
-- 放宽是加法：先按定义删掉既有 status CHECK，再按 7 值重建（幂等）。
DO $$
DECLARE
  bad TEXT;
BEGIN
  FOR bad IN
    SELECT conname FROM pg_constraint c
      JOIN pg_class r ON r.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = r.relnamespace
     WHERE n.nspname = current_schema()
       AND r.relname = 'wallet_provision_batch'
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%pending_sign%'
  LOOP
    EXECUTE format('ALTER TABLE wallet_provision_batch DROP CONSTRAINT IF EXISTS %I', bad);
  END LOOP;
END $$;

ALTER TABLE wallet_provision_batch DROP CONSTRAINT IF EXISTS wallet_provision_batch_status_m08_ck;
ALTER TABLE wallet_provision_batch ADD CONSTRAINT wallet_provision_batch_status_m08_ck CHECK (
  status IN ('draft', 'pending_sign', 'signed', 'activated', 'expired', 'failed', 'cancelled'));

-- batch_no 唯一（旧批次为 NULL 不参与）
CREATE UNIQUE INDEX IF NOT EXISTS wallet_provision_batch_no_uq
  ON wallet_provision_batch (batch_no) WHERE batch_no IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS wallet_provision_batch_idem_uq
  ON wallet_provision_batch (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- 激活批次不得夹带转账指令（INV-02）：004 的 CHECK (contains_transfer = FALSE) 保留；
-- 这里再拦「批次上出现 transfer 类字段」的结构性风险（列级断言）。
DO $$
DECLARE
  bad TEXT;
BEGIN
  SELECT string_agg(column_name, ', ') INTO bad
    FROM information_schema.columns
   WHERE table_schema = current_schema()
     AND table_name = 'wallet_provision_batch'
     AND column_name ~ '(transfer_instruction|transfer_data|calldata|to_address|recipient)';
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'INV-02 违规：wallet_provision_batch 出现转账指令列（%）', bad;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION m08_batch_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_allowed TEXT[] := ARRAY['draft->pending_sign', 'draft->cancelled', 'draft->expired',
                            'pending_sign->signed', 'pending_sign->expired',
                            'pending_sign->cancelled', 'pending_sign->failed',
                            'signed->activated', 'signed->expired'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'wallet_provision_batch 只追加：禁止 DELETE' USING ERRCODE = '42501';
  END IF;
  IF OLD.status = 'activated' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'wallet_provision_batch 已激活，不可回退（§3）' USING ERRCODE = '23514';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status || '->' || NEW.status) = ANY (v_allowed)) THEN
    RAISE EXCEPTION 'wallet_provision_batch 非法状态迁移：% -> %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_batch_guard ON wallet_provision_batch;
CREATE TRIGGER m08_batch_guard BEFORE UPDATE OR DELETE ON wallet_provision_batch
  FOR EACH ROW EXECUTE FUNCTION m08_batch_guard();

DROP TRIGGER IF EXISTS wallet_provision_batch_no_truncate ON wallet_provision_batch;
CREATE TRIGGER wallet_provision_batch_no_truncate BEFORE TRUNCATE ON wallet_provision_batch
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 钱包转账（归集 / 调拨 / 出款执行）
CREATE TABLE IF NOT EXISTS wallet_transfers (
  transfer_id     UUID PRIMARY KEY,
  batch_no        TEXT,                                   -- 归集批次号（SW-...）/ 出款批次号
  kind            TEXT NOT NULL,                          -- sweep / rebalance / payout / gas_topup
  chain_id        TEXT NOT NULL DEFAULT 'polygon',
  from_wallet_id  TEXT REFERENCES wallet (wallet_id),
  to_wallet_id    TEXT REFERENCES wallet (wallet_id),
  from_address    TEXT,
  to_address      TEXT,
  qty_minor       BIGINT NOT NULL DEFAULT 0,              -- USDT micro（6 位）
  amount_minor    BIGINT NOT NULL DEFAULT 0,              -- USD micro（账本口径）
  gas_fee_minor   BIGINT NOT NULL DEFAULT 0,              -- gas（USD micro）
  gas_reserve_pol BIGINT NOT NULL DEFAULT 0,              -- 归集时预留的原生 gas（wei 级）
  status          TEXT NOT NULL DEFAULT 'planned',
  intent_id       UUID,                                   -- treasury_intents.intent_id
  nonce           BIGINT,
  policy_version  TEXT NOT NULL,
  chain_tx_id     TEXT,
  failure_reason  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  confirmed_at    TIMESTAMPTZ,
  CONSTRAINT wallet_transfers_kind_ck CHECK
    (kind IN ('sweep', 'rebalance', 'payout', 'gas_topup')),
  CONSTRAINT wallet_transfers_status_ck CHECK
    (status IN ('planned', 'signed', 'broadcast', 'confirmed', 'failed')),
  CONSTRAINT wallet_transfers_amounts_ck CHECK
    (qty_minor >= 0 AND amount_minor >= 0 AND gas_fee_minor >= 0),
  -- 归集 / 调拨必须有源与目的；gas_topup 只补源钱包
  CONSTRAINT wallet_transfers_wallets_ck CHECK (from_wallet_id IS NOT NULL OR to_wallet_id IS NOT NULL),
  CONSTRAINT wallet_transfers_sweep_ck CHECK
    (kind <> 'sweep' OR (from_wallet_id IS NOT NULL AND to_wallet_id IS NOT NULL
                         AND from_wallet_id <> to_wallet_id))
);

CREATE UNIQUE INDEX IF NOT EXISTS wallet_transfers_tx_uq
  ON wallet_transfers (chain_id, chain_tx_id) WHERE chain_tx_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS wallet_transfers_status_idx
  ON wallet_transfers (status, created_at DESC);
CREATE INDEX IF NOT EXISTS wallet_transfers_batch_idx
  ON wallet_transfers (batch_no, created_at);

COMMENT ON TABLE wallet_transfers IS
  'M08 归集 / 调拨 / 出款执行：只记录链上事实与批次关联；不存私钥、签名原文';

CREATE OR REPLACE FUNCTION m08_transfers_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'wallet_transfers 只追加：禁止 DELETE' USING ERRCODE = '42501';
  END IF;
  IF NEW.transfer_id IS DISTINCT FROM OLD.transfer_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.from_wallet_id IS DISTINCT FROM OLD.from_wallet_id
     OR NEW.to_wallet_id IS DISTINCT FROM OLD.to_wallet_id
     OR NEW.qty_minor IS DISTINCT FROM OLD.qty_minor
     OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'wallet_transfers 身份字段不可变（金额 / 源 / 目的 / 批次）'
      USING ERRCODE = '42501';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m08_transfers_guard ON wallet_transfers;
CREATE TRIGGER m08_transfers_guard BEFORE UPDATE OR DELETE ON wallet_transfers
  FOR EACH ROW EXECUTE FUNCTION m08_transfers_guard();

DROP TRIGGER IF EXISTS wallet_transfers_no_truncate ON wallet_transfers;
CREATE TRIGGER wallet_transfers_no_truncate BEFORE TRUNCATE ON wallet_transfers
  FOR EACH STATEMENT EXECUTE FUNCTION m08_forbid_truncate();

-- ────────────────────────────────────────────────────────────── 平台收款地址追加列
-- 005 的 deposit_address 已归 M08；publish 需要 reason / ticket 留痕（spec 1.2.5 DepositAddressRequest）
ALTER TABLE deposit_address ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE deposit_address ADD COLUMN IF NOT EXISTS ticket_id TEXT;
ALTER TABLE deposit_address ADD COLUMN IF NOT EXISTS monitoring_until TIMESTAMPTZ;

-- ────────────────────────────────────────────────────────────── 只读视图（后台 / M09 读）
CREATE OR REPLACE VIEW v_m08_pool_depth AS
  SELECT p.pool_id, p.chain_id, p.role, p.fund_class, p.status AS pool_status,
         p.min_spare_count, p.max_active_count, p.switch_threshold_pct,
         count(*) FILTER (WHERE w.status = 'active' AND w.gas_ok) AS depth_ready,
         count(*) FILTER (WHERE w.status = 'active' AND w.gas_ok)
           + count(*) FILTER (WHERE w.status = 'provisioning')       AS depth_available,
         count(*) FILTER (WHERE w.status = 'active' AND w.switch_state = 'in_service')
           AS in_service_count,
         COALESCE(sum(w.balance_minor) FILTER (WHERE w.status = 'active'), 0)
           AS active_balance_minor
    FROM wallet_pool p
    LEFT JOIN wallet w ON w.pool_id = p.pool_id
   GROUP BY p.pool_id;

COMMENT ON VIEW v_m08_pool_depth IS
  'M08 只读视图：池深度（depth_ready = active ∧ gas_ok；depth_available 含 provisioning）';

COMMIT;
