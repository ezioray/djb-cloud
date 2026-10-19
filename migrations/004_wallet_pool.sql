-- 004 · 钱包池与自动扩容（设计 v4 §19.4.3 / §19.4.10，决策 K5）
-- 原则：
--   1) 扩容只开容量，不动钱：本迁移不建任何账本表、不写任何账本分录（ledger_entries / accounts 零改动）。
--   2) 批次（WALLET_PROVISION）内不得携带转账指令：DB 层用 CHECK (contains_transfer = FALSE) 硬拦。
--   3) 幂等可重复执行：全部 IF NOT EXISTS / ADD COLUMN IF NOT EXISTS / ON CONFLICT DO NOTHING。
--   4) 池键三元组（chain_id, role, fund_class）与 wallet 的池归属创建后不可改（触发器硬拦）。
BEGIN;

-- ---------------------------------------------------------------- 池
CREATE TABLE IF NOT EXISTS wallet_pool (
  pool_id               TEXT PRIMARY KEY,               -- 约定 <chain>:<role>:<fund_class>
  chain_id              TEXT NOT NULL,
  role                  TEXT NOT NULL CHECK (role IN ('hot', 'warm')),
  fund_class            TEXT NOT NULL CHECK (fund_class IN ('customer', 'platform')),
  min_spare_count       INT    NOT NULL DEFAULT 3  CHECK (min_spare_count BETWEEN 0 AND 8),
  max_active_count      INT    NOT NULL DEFAULT 8  CHECK (max_active_count BETWEEN 1 AND 20),
  switch_threshold_pct  INT    NOT NULL DEFAULT 70 CHECK (switch_threshold_pct BETWEEN 50 AND 95),
  activate_batch_size   INT    NOT NULL DEFAULT 4  CHECK (activate_batch_size BETWEEN 1 AND 8),
  provision_lead_time_h INT    NOT NULL DEFAULT 12 CHECK (provision_lead_time_h BETWEEN 1 AND 48),
  pool_cap_minor        BIGINT NOT NULL DEFAULT 5000000 CHECK (pool_cap_minor > 0),  -- 50,000 USD（USD 分）
  switch_policy         TEXT   NOT NULL DEFAULT 'least_utilized',
  status                TEXT   NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'retired')),
  policy_version        TEXT   NOT NULL DEFAULT 'v4.0',
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT wallet_pool_key_uq UNIQUE (chain_id, role, fund_class),
  -- max_active 硬上限 20（§19.4.10(4) 自动上调硬顶），DB 层兜底
  CONSTRAINT wallet_pool_max_active_hard_cap CHECK (max_active_count <= 20)
);

-- ---------------------------------------------------------------- 钱包
-- 一只钱包只属一个池；pool_id / chain_id / fund_class 一经写入不可变更。
CREATE TABLE IF NOT EXISTS wallet (
  wallet_id       TEXT PRIMARY KEY,
  chain_id        TEXT NOT NULL,
  address         TEXT NOT NULL,
  pool_id         TEXT REFERENCES wallet_pool(pool_id),
  pool_role       TEXT CHECK (pool_role IN ('hot', 'warm')),
  fund_class      TEXT CHECK (fund_class IN ('customer', 'platform')),
  custody_kind    TEXT CHECK (custody_kind IN ('self_custody_hot', 'self_custody_warm', 'external_owner_cold')),
  -- 七值 + 预生成失败（§19.4.10(2)(5)）
  status          TEXT NOT NULL DEFAULT 'provisioning'
                  CHECK (status IN ('provisioning', 'active', 'paused', 'draining',
                                    'zero', 'frozen', 'retired', 'provisioning_failed')),
  switch_state    TEXT CHECK (switch_state IN ('standby', 'in_service', 'switching_out', 'draining')),
  signer_set_ref  TEXT,                                  -- 签名人集合引用（决策人 / 复核人 / HSM）
  descriptor_hash TEXT,                                  -- 描述符哈希，激活批次内可复算
  balance_minor   BIGINT NOT NULL DEFAULT 0 CHECK (balance_minor >= 0),   -- 备用钱包余额必须为 0
  gas_ok          BOOLEAN NOT NULL DEFAULT FALSE,        -- ready = active AND gas_ok（激活 ≠ 可用）
  provisioned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at    TIMESTAMPTZ,
  retired_at      TIMESTAMPTZ,
  CONSTRAINT wallet_chain_address_uq UNIQUE (chain_id, address)
);

CREATE INDEX IF NOT EXISTS wallet_pool_status_idx ON wallet(pool_id, status);
CREATE INDEX IF NOT EXISTS wallet_switch_state_idx ON wallet(pool_id, switch_state);

CREATE OR REPLACE FUNCTION wallet_pool_binding_immutable() RETURNS trigger AS $$
BEGIN
  IF NEW.pool_id IS DISTINCT FROM OLD.pool_id
     OR NEW.chain_id IS DISTINCT FROM OLD.chain_id
     OR NEW.fund_class IS DISTINCT FROM OLD.fund_class THEN
    RAISE EXCEPTION 'wallet pool binding is immutable (pool_id / chain_id / fund_class cannot change)';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS wallet_pool_binding_immutable_trg ON wallet;
CREATE TRIGGER wallet_pool_binding_immutable_trg BEFORE UPDATE ON wallet
  FOR EACH ROW EXECUTE FUNCTION wallet_pool_binding_immutable();

-- ---------------------------------------------------------------- 预生成 / 激活批次
-- kind = WALLET_PROVISION（TreasuryIntent 第八取值，§19.5.2）；属追加枚举，不改既有七种语义。
CREATE SEQUENCE IF NOT EXISTS wallet_provision_nonce_seq;

CREATE TABLE IF NOT EXISTS wallet_provision_batch (
  batch_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pool_id                TEXT NOT NULL REFERENCES wallet_pool(pool_id),
  kind                   TEXT NOT NULL DEFAULT 'WALLET_PROVISION' CHECK (kind = 'WALLET_PROVISION'),
  wallet_count           INT  NOT NULL CHECK (wallet_count BETWEEN 1 AND 8),
  descriptor_merkle_root TEXT NOT NULL,
  cap_params             JSONB NOT NULL DEFAULT '{}'::jsonb,
  dedupe_key             TEXT NOT NULL,                  -- 幂等键：同一 pool 同一批次只生成一次
  status                 TEXT NOT NULL DEFAULT 'pending_sign'
                         CHECK (status IN ('pending_sign', 'signed', 'activated', 'expired', 'failed', 'cancelled')),
  nonce                  BIGINT NOT NULL DEFAULT nextval('wallet_provision_nonce_seq'),  -- 全局单调
  expires_at             TIMESTAMPTZ NOT NULL,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_signed_at        TIMESTAMPTZ,
  reviewer_attested_at   TIMESTAMPTZ,
  hsm_verified_at        TIMESTAMPTZ,
  activated_at           TIMESTAMPTZ,
  auth_object_type       TEXT,
  auth_hash              TEXT,
  contains_transfer      BOOLEAN NOT NULL DEFAULT FALSE,
  reason                 TEXT,
  -- 批次内不得携带任何转账指令（§19.4.10(3)）
  CONSTRAINT batch_no_transfer CHECK (contains_transfer = FALSE),
  -- 该动作不动钱、只开容量，expiresAt 放宽到 ≤24h（其余动作 ≤30 分钟）
  CONSTRAINT batch_ttl_24h CHECK (expires_at <= created_at + INTERVAL '24 hours'),
  CONSTRAINT batch_expires_after_created CHECK (expires_at > created_at),
  CONSTRAINT batch_pool_dedupe_uq UNIQUE (pool_id, dedupe_key)
);

CREATE INDEX IF NOT EXISTS batch_pool_status_idx ON wallet_provision_batch(pool_id, status);
CREATE INDEX IF NOT EXISTS batch_expires_idx ON wallet_provision_batch(status, expires_at);

-- 批次 × 钱包激活明细
CREATE TABLE IF NOT EXISTS wallet_activation (
  activation_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id          UUID NOT NULL REFERENCES wallet_provision_batch(batch_id),
  wallet_id         TEXT NOT NULL REFERENCES wallet(wallet_id),
  switch_state      TEXT CHECK (switch_state IN ('standby', 'in_service', 'switching_out', 'draining')),
  cap_applied_minor BIGINT,                              -- 单钱包 cap = min(10,000 USD, 5 天预测)，可小于 1,000 USD
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'activated', 'void')),
  activated_at      TIMESTAMPTZ,
  audit_hash        TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT activation_batch_wallet_uq UNIQUE (batch_id, wallet_id)
);

CREATE INDEX IF NOT EXISTS activation_batch_idx ON wallet_activation(batch_id);

-- 幂等重建 cap 约束（早期草稿曾写死 ≥1,000 USD；cap 下限只适用于被池上限压下来的情形）
ALTER TABLE wallet_activation DROP CONSTRAINT IF EXISTS wallet_activation_cap_applied_minor_check;
ALTER TABLE wallet_activation ADD CONSTRAINT wallet_activation_cap_applied_minor_check
  CHECK (cap_applied_minor IS NULL OR cap_applied_minor > 0);

-- ---------------------------------------------------------------- 事件（只追加留痕）
CREATE TABLE IF NOT EXISTS wallet_pool_event (
  seq      BIGSERIAL PRIMARY KEY,
  pool_id  TEXT NOT NULL,
  event    TEXT NOT NULL,
  batch_id UUID,
  actor    TEXT NOT NULL DEFAULT 'system:wallet_pool',
  payload  JSONB NOT NULL DEFAULT '{}'::jsonb,
  ts       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS wallet_pool_event_pool_idx ON wallet_pool_event(pool_id, seq);

CREATE OR REPLACE FUNCTION forbid_pool_event_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'wallet_pool_event is append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS wallet_pool_event_no_update ON wallet_pool_event;
CREATE TRIGGER wallet_pool_event_no_update BEFORE UPDATE OR DELETE ON wallet_pool_event
  FOR EACH ROW EXECUTE FUNCTION forbid_pool_event_mutation();

-- ---------------------------------------------------------------- 一期 3 池（平台热池不建）
-- Polygon × {客户热, 客户温, 平台温}；平台热池不建（运营资金直接进运营温钱包，决策 K5）。
INSERT INTO wallet_pool (pool_id, chain_id, role, fund_class, min_spare_count, max_active_count,
                         switch_threshold_pct, activate_batch_size, provision_lead_time_h,
                         pool_cap_minor, switch_policy, policy_version)
VALUES ('polygon:hot:customer',   'polygon', 'hot',  'customer', 3, 8, 70, 4, 12, 5000000, 'least_utilized', 'v4.0'),
       ('polygon:warm:customer',  'polygon', 'warm', 'customer', 3, 4, 70, 4, 12, 5000000, 'least_utilized', 'v4.0'),
       ('polygon:warm:platform',  'polygon', 'warm', 'platform', 3, 4, 70, 4, 12, 5000000, 'least_utilized', 'v4.0')
ON CONFLICT (pool_id) DO NOTHING;

COMMIT;
