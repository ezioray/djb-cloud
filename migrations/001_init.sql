-- djb-cloud 001 · 计量账本最小 schema
-- 原则（设计文档 §4.2/§4.3）：收据双签、账本只追加、分录可复算
BEGIN;

CREATE TABLE IF NOT EXISTS accounts (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('user','node','platform','pool')),
  balance_micro BIGINT NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 账本：只追加。金额用「微单位」(1e-6) 整数，避免浮点误差。
CREATE TABLE IF NOT EXISTS ledger_entries (
  seq          BIGSERIAL PRIMARY KEY,
  entry_id     UUID NOT NULL DEFAULT gen_random_uuid(),
  receipt_id   UUID,
  debit        TEXT NOT NULL REFERENCES accounts(id),
  credit       TEXT NOT NULL REFERENCES accounts(id),
  amount_micro BIGINT NOT NULL CHECK (amount_micro > 0),
  currency     TEXT NOT NULL DEFAULT 'COIN',
  memo         TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  prev_hash    TEXT,
  hash         TEXT NOT NULL,
  UNIQUE (entry_id)
);

-- 双签收据：供方与用方各签一次，缺签不收
CREATE TABLE IF NOT EXISTS receipts (
  id            UUID PRIMARY KEY,
  node_id       TEXT NOT NULL,
  consumer_id   TEXT NOT NULL,
  request_id    TEXT NOT NULL UNIQUE,
  model         TEXT NOT NULL,
  tokens_in     BIGINT NOT NULL CHECK (tokens_in  >= 0),
  tokens_out    BIGINT NOT NULL CHECK (tokens_out >= 0),
  amount_micro  BIGINT NOT NULL CHECK (amount_micro > 0),
  sig_supplier  TEXT NOT NULL,
  sig_consumer  TEXT NOT NULL,
  ts_start      TIMESTAMPTZ NOT NULL,
  ts_end        TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (ts_end >= ts_start)
);

-- 只追加的硬保证：任何 UPDATE/DELETE 直接报错（不是靠自觉）
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'ledger_entries is append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_entries_no_update ON ledger_entries;
CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE OR DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

COMMIT;
