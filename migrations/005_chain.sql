-- 005 · 链上收款（Polygon PoS）· E1/E2 入账基础（设计 v4 §19.6.1 / §20.1–20.4 / 附录 B.2，决策 K6）
--
-- 原则：
--   1) 只加表 / 只加列（§20.4.3 R1）：不删列、不改既有列语义。既有唯一改的是「加」。
--   2) 本迁移不写任何账本分录：只扩列 + 建表，不 INSERT ledger_entries / 不动 accounts 余额。
--      → 迁移前后 `ledger.recompute()` 的 entries / diff / 余额指纹必须完全一致（测试断言，见
--        tests/test_polygon_ingest.py::test_migration_is_idempotent_and_ledger_diff_zero）。
--   3) 幂等可重复执行：IF NOT EXISTS / ADD COLUMN IF NOT EXISTS / DROP ... IF EXISTS + ADD / CREATE OR REPLACE。
--   4) 表内不出现任何私钥、助记词、种子、xpub 原文：只存地址、hash、派生路径与 xpub 指纹。
--   5) 所有新增行为默认关闭：开关 polygon_ingest（三字段见 app/chain/__init__.py），本迁移只建结构。
BEGIN;

-- ────────────────────────────────────────────────────────────── 账本列扩展（只加列，R1）
-- spec/components/schemas/LedgerEntry 已声明 entry_type / unit_type / status / reverse_of 等字段；
-- 本仓 ledger_entries 尚无对应列，这里按 R1「只允许加列」补齐，既有列一字不动。
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS entry_type   TEXT;
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS unit_type    TEXT;          -- USD / COP / STABLE_USDT / FIAT_CNY
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS channel_id   TEXT;
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS asset_ref    TEXT;          -- 资产引用（如链上 USDT 合约）
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS ref_id       TEXT;          -- 业务对象（chain_tx_id 等）
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS status       TEXT;          -- 业务状态，默认由应用写明
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS policy_version TEXT;        -- R10：确认数/口径版本
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS qty_minor    BIGINT;        -- 资产辅助计量（USDT 6 位）
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS line_no      SMALLINT;      -- journal_line 行号（1 起）
-- 幂等键（R8 / I-8：source_type + source_id + event_seq 唯一；line_no 区分同一 journal 的多行）
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS source_type  TEXT;
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS source_id    TEXT;
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS event_seq    SMALLINT;
-- 冲正（R5 / B6）：冲正分录指向原分录 entry_id；原分录永不删改
ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS reverse_of   UUID;

ALTER TABLE ledger_entries DROP CONSTRAINT IF EXISTS ledger_entries_reverse_of_fkey;
ALTER TABLE ledger_entries ADD CONSTRAINT ledger_entries_reverse_of_fkey
  FOREIGN KEY (reverse_of) REFERENCES ledger_entries(entry_id);

-- 只对「带幂等键的新分录」生效（历史分录 source_type 为 NULL，不受影响）
CREATE UNIQUE INDEX IF NOT EXISTS ledger_entries_source_uq
  ON ledger_entries (source_type, source_id, event_seq, line_no)
  WHERE source_type IS NOT NULL;

CREATE INDEX IF NOT EXISTS ledger_entries_ref_idx
  ON ledger_entries (ref_id) WHERE ref_id IS NOT NULL;

-- ────────────────────────────────────────────────────────────── 收款地址（HD 派生，不含密钥）
CREATE TABLE IF NOT EXISTS deposit_address (
  address_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chain_id         TEXT NOT NULL,
  address          TEXT NOT NULL,                 -- 小写 0x 地址（存储层归一，见 CHECK）
  account_id       TEXT NOT NULL,                 -- 归属主体（一项活跃地址）
  purpose          TEXT NOT NULL DEFAULT 'user_deposit'
                   CHECK (purpose IN ('user_deposit', 'one_time', 'platform')),
  derivation_path  TEXT NOT NULL,                 -- m/44'/60'/0'/0/<index>；只是路径，不是密钥
  derivation_index INT  NOT NULL CHECK (derivation_index >= 0),
  xpub_fingerprint TEXT NOT NULL,                 -- sha256(xpub) 前 16 hex：对账锚，不含 xpub 原文
  wallet_id        TEXT,                          -- 软引用 wallet.wallet_id（不建 FK，见「只追加护栏」）
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'retired', 'reserved')),
  assign_expires_at TIMESTAMPTZ,                  -- 一次性地址 24h 有效期（默认关闭用途）
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 地址不复用（I-10）：同链同地址一条、全局地址唯一
  CONSTRAINT deposit_address_chain_addr_uq UNIQUE (chain_id, address),
  CONSTRAINT deposit_address_addr_uq       UNIQUE (address),
  CONSTRAINT deposit_address_path_uq       UNIQUE (chain_id, derivation_path),
  CONSTRAINT deposit_address_lower_ck      CHECK (address = lower(address))
);

-- 同一主体在同链只有一条 active 地址（§19.6.1「每用户一个活跃地址」）
CREATE UNIQUE INDEX IF NOT EXISTS deposit_address_one_active_uq
  ON deposit_address (chain_id, account_id) WHERE status = 'active';

-- wallet_id 只是软引用：不建 FK。原因——TRUNCATE 不触发行级 append-only 触发器，而
-- 「TRUNCATE wallet ... CASCADE」（钱包池维护/测试）会顺着 FK 级联清空 deposit_address → chain_tx
-- → chain_tx_event，把链上证据一夜清空。跨域 FK 让别的域的维护动作能删掉本域的只追加证据，
-- 因此在结构上断开。已建过 FK 的库用下面这条收敛（幂等）。
ALTER TABLE deposit_address DROP CONSTRAINT IF EXISTS deposit_address_wallet_id_fkey;

-- 地址行不可换主体 / 换地址 / 换派生路径；retired 后不得复活（I-10）
CREATE OR REPLACE FUNCTION deposit_address_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.address IS DISTINCT FROM OLD.address
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.chain_id IS DISTINCT FROM OLD.chain_id
     OR NEW.derivation_path IS DISTINCT FROM OLD.derivation_path
     OR NEW.derivation_index IS DISTINCT FROM OLD.derivation_index THEN
    RAISE EXCEPTION 'deposit_address is immutable (address / account / chain / derivation cannot change)';
  END IF;
  IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
    RAISE EXCEPTION 'deposit_address is retired and cannot be revived or reassigned';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS deposit_address_guard_trg ON deposit_address;
CREATE TRIGGER deposit_address_guard_trg BEFORE UPDATE ON deposit_address
  FOR EACH ROW EXECUTE FUNCTION deposit_address_guard();

-- ────────────────────────────────────────────────────────────── 链上交易（只追加）
-- 幂等键 (chain_id, tx_hash, log_index)：双扫描器/重复 webhook 只入账一次（§20.4.7 / I-9）
CREATE TABLE IF NOT EXISTS chain_tx (
  chain_tx_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chain_id         TEXT NOT NULL,
  tx_hash          TEXT NOT NULL,
  log_index        INT  NOT NULL CHECK (log_index >= 0),
  block_number     BIGINT NOT NULL CHECK (block_number >= 0),
  block_hash       TEXT NOT NULL,
  from_address     TEXT NOT NULL,
  to_address       TEXT NOT NULL,
  asset_contract   TEXT NOT NULL,                  -- 只认 USDT 合约（防假币）
  asset_decimals   SMALLINT NOT NULL DEFAULT 6 CHECK (asset_decimals BETWEEN 0 AND 36),
  qty_minor        BIGINT NOT NULL CHECK (qty_minor > 0),
  amount_minor     BIGINT NOT NULL CHECK (amount_minor > 0),   -- USD micro（1:1 折算，见 polygon.py）
  unit_type        TEXT NOT NULL DEFAULT 'USD',
  required_confirmations INT NOT NULL CHECK (required_confirmations >= 64),  -- 红线：确认数不得低于 64
  policy_version   TEXT NOT NULL,
  deposit_address_id UUID REFERENCES deposit_address(address_id),
  account_id       TEXT,
  scanner_id       TEXT NOT NULL,                  -- 首个发现者（留痕，不参与入账）
  detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 存储层归一，避免同一 tx 因大小写不同被当成两笔
  CONSTRAINT chain_tx_hash_lower_ck CHECK (tx_hash = lower(tx_hash)),
  CONSTRAINT chain_tx_block_lower_ck CHECK (block_hash = lower(block_hash)),
  CONSTRAINT chain_tx_from_lower_ck CHECK (from_address = lower(from_address)),
  CONSTRAINT chain_tx_to_lower_ck CHECK (to_address = lower(to_address)),
  CONSTRAINT chain_tx_asset_lower_ck CHECK (asset_contract = lower(asset_contract)),
  CONSTRAINT chain_tx_hash_uq UNIQUE (chain_id, tx_hash, log_index)
);

CREATE INDEX IF NOT EXISTS chain_tx_account_idx ON chain_tx (account_id, detected_at);
CREATE INDEX IF NOT EXISTS chain_tx_deposit_addr_idx ON chain_tx (deposit_address_id);

-- ────────────────────────────────────────────────────────────── 链上事件流（只追加）
-- 状态不写在 chain_tx 上，而是由事件推导（视图 chain_tx_state）：detected → (observed)* → confirmed → (void)
CREATE TABLE IF NOT EXISTS chain_tx_event (
  seq           BIGSERIAL PRIMARY KEY,
  chain_tx_id   UUID NOT NULL REFERENCES chain_tx(chain_tx_id),
  event         TEXT NOT NULL CHECK (event IN ('detected', 'observed', 'confirmed', 'rejected', 'held', 'reorged', 'void')),
  confirmations INT  NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
  block_hash    TEXT,
  reason_code   TEXT,                              -- wrong_chain / fake_token / unknown_address / reorg / ...
  actor         TEXT NOT NULL DEFAULT 'system:polygon_ingest',
  payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 「每个事件最多一次」由部分唯一索引兜底：并发下只有一个事务能写入成功
CREATE UNIQUE INDEX IF NOT EXISTS chain_tx_event_one_detected ON chain_tx_event (chain_tx_id) WHERE event = 'detected';
CREATE UNIQUE INDEX IF NOT EXISTS chain_tx_event_one_confirmed ON chain_tx_event (chain_tx_id) WHERE event = 'confirmed';
CREATE UNIQUE INDEX IF NOT EXISTS chain_tx_event_one_rejected ON chain_tx_event (chain_tx_id) WHERE event = 'rejected';
CREATE UNIQUE INDEX IF NOT EXISTS chain_tx_event_one_void ON chain_tx_event (chain_tx_id) WHERE event = 'void';
CREATE UNIQUE INDEX IF NOT EXISTS chain_tx_event_observed_uq ON chain_tx_event (chain_tx_id, confirmations) WHERE event = 'observed';

-- 只追加：链上事实与事件流都不许 UPDATE / DELETE（复用 001 的 forbid_mutation）
DROP TRIGGER IF EXISTS chain_tx_no_mutation ON chain_tx;
CREATE TRIGGER chain_tx_no_mutation BEFORE UPDATE OR DELETE ON chain_tx
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

DROP TRIGGER IF EXISTS chain_tx_event_no_mutation ON chain_tx_event;
CREATE TRIGGER chain_tx_event_no_mutation BEFORE UPDATE OR DELETE ON chain_tx_event
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- 只追加护栏（TRUNCATE 绕过行级触发器：必须用语句级触发器单独拦）
CREATE OR REPLACE FUNCTION forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS chain_tx_no_truncate ON chain_tx;
CREATE TRIGGER chain_tx_no_truncate BEFORE TRUNCATE ON chain_tx
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_truncate();

DROP TRIGGER IF EXISTS chain_tx_event_no_truncate ON chain_tx_event;
CREATE TRIGGER chain_tx_event_no_truncate BEFORE TRUNCATE ON chain_tx_event
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_truncate();

DROP TRIGGER IF EXISTS deposit_address_no_truncate ON deposit_address;
CREATE TRIGGER deposit_address_no_truncate BEFORE TRUNCATE ON deposit_address
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_truncate();

-- ────────────────────────────────────────────────────────────── 推导状态视图
-- 视图不是表：先 DROP 再建，保证列变更也能幂等重跑
DROP VIEW IF EXISTS chain_tx_state;
CREATE VIEW chain_tx_state AS
SELECT t.chain_tx_id,
       t.chain_id,
       t.tx_hash,
       t.log_index,
       t.block_number,
       t.to_address,
       t.block_hash,
       t.asset_contract,
       t.account_id,
       t.qty_minor,
       t.amount_minor,
       t.required_confirmations,
       t.policy_version,
       t.detected_at,
       COALESCE(max(e.confirmations), 0)                          AS confirmations,
       bool_or(e.event = 'confirmed')                             AS confirmed,
       bool_or(e.event = 'void')                                  AS voided,
       bool_or(e.event = 'rejected')                              AS rejected,
       CASE
         WHEN bool_or(e.event = 'void')     THEN 'void'
         WHEN bool_or(e.event = 'rejected') THEN 'rejected'
         WHEN bool_or(e.event = 'confirmed') THEN 'confirmed'
         WHEN bool_or(e.event = 'held')     THEN 'held'
         ELSE 'detected'
       END                                                        AS status,
       max(e.ts)                                                  AS last_event_at
  FROM chain_tx t
  LEFT JOIN chain_tx_event e ON e.chain_tx_id = t.chain_tx_id
 GROUP BY t.chain_tx_id;

-- 原分录 ↔ 冲正分录的对照（只读派生；原分录本身永不改）
DROP VIEW IF EXISTS ledger_entry_reversal;
CREATE VIEW ledger_entry_reversal AS
SELECT o.seq      AS orig_seq,
       o.entry_id AS orig_entry_id,
       o.memo     AS orig_memo,
       r.seq      AS reversal_seq,
       r.entry_id AS reversal_entry_id,
       r.source_id AS void_source_id,
       r.created_at AS reversed_at
  FROM ledger_entries r
  JOIN ledger_entries o ON r.reverse_of = o.entry_id
 WHERE r.reverse_of IS NOT NULL;

COMMIT;
