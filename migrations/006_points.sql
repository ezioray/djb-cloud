-- 006 · COP 积分台账与转让开关（K4 / v4 §4.5 §6.6 §9.1 §20.1 §20.4.4）
-- 原则：
--   1) COP 台账**独立**：不写 ledger_entries、不写 accounts，不产生 USD 分录；
--      本迁移不建/不改任何账本表（账本口径零改动）。
--   2) COP 只在 unit_type='COP' 维度内平衡（R9：USD 与 COP 永不互转）；
--      科目固定 2103（§20.1 COP 科目），永不记成 USD 科目。
--   3) 只追加：points_ledger / points_journal / points_transfer 均禁止 UPDATE/DELETE。
--   4) 幂等可重复执行：全部 IF NOT EXISTS / ON CONFLICT DO NOTHING / CREATE OR REPLACE VIEW。
BEGIN;

-- ---------------------------------------------------------------- 账户档案
CREATE TABLE IF NOT EXISTS points_account (
  account_id      TEXT PRIMARY KEY,                     -- 与平台账户体系统一（user:xxx / node:xxx）
  state           TEXT NOT NULL DEFAULT 'normal'
                  CHECK (state IN ('normal', 'frozen', 'closing', 'closed')),
  verified        BOOLEAN NOT NULL DEFAULT FALSE,        -- 实名 / 已验证（§9.1 仅 normal + 已验证可转让）
  device_cluster  TEXT,                                  -- 同设备簇（风控：不可互转）
  payment_cluster TEXT,                                  -- 同支付方式簇（风控：不可互转）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- 策略（单例）
-- points.transfer_enabled 是 P0 配置项；三字段（owner / expire_at / rollback_rule）随行落库，
-- 后续由配置中心（§21）发布版本，本表在 S1 作为生效值的落地处。
CREATE TABLE IF NOT EXISTS points_policy (
  policy_key             TEXT PRIMARY KEY DEFAULT 'default',
  transfer_enabled       BOOLEAN NOT NULL DEFAULT FALSE,        -- 默认不可转让（K4）
  per_transfer_max_units BIGINT  NOT NULL DEFAULT 1000 CHECK (per_transfer_max_units > 0),
  daily_out_max_units    BIGINT  NOT NULL DEFAULT 10000 CHECK (daily_out_max_units > 0),
  daily_in_max_units     BIGINT  NOT NULL DEFAULT 10000 CHECK (daily_in_max_units > 0),
  lock_days              INT     NOT NULL DEFAULT 7 CHECK (lock_days BETWEEN 1 AND 90),
  redeem_cop_per_usd     BIGINT  NOT NULL DEFAULT 100 CHECK (redeem_cop_per_usd > 0),  -- 1 USD = 100 COP
  redeem_max_share_bps   INT     NOT NULL DEFAULT 2000 CHECK (redeem_max_share_bps BETWEEN 0 AND 10000),
  policy_version         TEXT    NOT NULL DEFAULT 'v4.0',
  flag_owner             TEXT    NOT NULL DEFAULT 'cloud-dev',
  flag_expire_at         DATE    NOT NULL DEFAULT DATE '2026-12-31',
  flag_rollback_rule     TEXT    NOT NULL DEFAULT
                         '关闭 points.transfer_enabled 即禁止新转让；已转让积分保留、不回溯扣回（除非命中风控）',
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT points_policy_singleton CHECK (policy_key = 'default')
);

INSERT INTO points_policy (policy_key) VALUES ('default') ON CONFLICT (policy_key) DO NOTHING;

-- ---------------------------------------------------------------- 记账头（一次操作 = 一个 journal）
CREATE TABLE IF NOT EXISTS points_journal (
  journal_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action          TEXT NOT NULL,                          -- 六值 + transfer（§20.4.4）
  account_id      TEXT NOT NULL REFERENCES points_account(account_id),
  counterparty_id TEXT REFERENCES points_account(account_id),   -- transfer 的收款方
  units           BIGINT NOT NULL CHECK (units > 0),
  reason_code     TEXT,
  request_id      TEXT,
  ref_id          TEXT,
  policy_version  TEXT NOT NULL DEFAULT 'v4.0',
  actor           TEXT NOT NULL,
  approved_by     TEXT,                                   -- adjust 的二次复核人（SoD）
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT points_journal_action_ck CHECK (
    action IN ('earn', 'redeem', 'adjust', 'freeze', 'unfreeze', 'void', 'transfer')),
  CONSTRAINT points_journal_request_uq UNIQUE (request_id)   -- 幂等：同一 request_id 只记一次
);

-- ---------------------------------------------------------------- 分录（只追加，COP 维度）
CREATE TABLE IF NOT EXISTS points_ledger (
  seq            BIGSERIAL PRIMARY KEY,
  entry_id       UUID NOT NULL DEFAULT gen_random_uuid(),
  journal_id     UUID NOT NULL REFERENCES points_journal(journal_id),
  account_id     TEXT NOT NULL REFERENCES points_account(account_id),
  bucket         TEXT NOT NULL CHECK (bucket IN ('available', 'locked', 'system')),
  delta          BIGINT NOT NULL CHECK (delta <> 0),      -- COP 整数单位；系统对偶腿为负
  action         TEXT NOT NULL,                           -- 与 journal 一致，便于单表复算
  unit_type      TEXT NOT NULL DEFAULT 'COP' CHECK (unit_type = 'COP'),   -- 永不记 USD（R9）
  coa_code       TEXT NOT NULL DEFAULT '2103' CHECK (coa_code = '2103'),  -- §20.1 COP 科目
  reason_code    TEXT,
  ref_id         TEXT,                                    -- 释放腿指向被释放的 lot entry_id
  unlock_at      TIMESTAMPTZ,                             -- 收到转让的 7 天锁定到期时间
  reverse_of     UUID,                                    -- void 冲正指向原分录
  actor          TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT points_ledger_entry_uq UNIQUE (entry_id),
  CONSTRAINT points_ledger_action_ck CHECK (
    action IN ('earn', 'redeem', 'adjust', 'freeze', 'unfreeze', 'void', 'transfer')),
  CONSTRAINT points_ledger_reverse_of_fkey FOREIGN KEY (reverse_of) REFERENCES points_ledger(entry_id)
);

CREATE INDEX IF NOT EXISTS points_ledger_account_idx ON points_ledger(account_id, bucket);
CREATE INDEX IF NOT EXISTS points_ledger_journal_idx ON points_ledger(journal_id);
CREATE INDEX IF NOT EXISTS points_ledger_unlock_idx ON points_ledger(bucket, unlock_at)
  WHERE bucket = 'locked' AND unlock_at IS NOT NULL;

-- ---------------------------------------------------------------- 转让事件（审计，§9.1）
CREATE TABLE IF NOT EXISTS points_transfer (
  transfer_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  journal_id      UUID NOT NULL REFERENCES points_journal(journal_id),
  from_account_id TEXT NOT NULL REFERENCES points_account(account_id),
  to_account_id   TEXT NOT NULL REFERENCES points_account(account_id),
  amount_units    BIGINT NOT NULL CHECK (amount_units > 0),
  reason          TEXT,
  request_id      TEXT NOT NULL,
  policy_version  TEXT NOT NULL DEFAULT 'v4.0',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT points_transfer_request_uq UNIQUE (request_id),
  CONSTRAINT points_transfer_no_self CHECK (from_account_id <> to_account_id)
);

CREATE INDEX IF NOT EXISTS points_transfer_from_idx ON points_transfer(from_account_id, created_at);
CREATE INDEX IF NOT EXISTS points_transfer_to_idx ON points_transfer(to_account_id, created_at);

-- ---------------------------------------------------------------- 只追加硬保证
CREATE OR REPLACE FUNCTION forbid_points_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % not allowed', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS points_ledger_no_mutation ON points_ledger;
CREATE TRIGGER points_ledger_no_mutation BEFORE UPDATE OR DELETE ON points_ledger
  FOR EACH ROW EXECUTE FUNCTION forbid_points_mutation();

DROP TRIGGER IF EXISTS points_journal_no_mutation ON points_journal;
CREATE TRIGGER points_journal_no_mutation BEFORE UPDATE OR DELETE ON points_journal
  FOR EACH ROW EXECUTE FUNCTION forbid_points_mutation();

DROP TRIGGER IF EXISTS points_transfer_no_mutation ON points_transfer;
CREATE TRIGGER points_transfer_no_mutation BEFORE UPDATE OR DELETE ON points_transfer
  FOR EACH ROW EXECUTE FUNCTION forbid_points_mutation();

-- ---------------------------------------------------------------- 锁定 lot 视图（可释放量）
-- 收到转让的积分进 locked 桶并带 unlock_at；释放腿（bucket=locked, 负 delta）用 ref_id 指回原 lot，
-- 于是「未释放量 = lot.delta + 指向它的释放腿之和」，可重复执行且不会重复释放。
CREATE OR REPLACE VIEW points_locked_lot AS
SELECT l.entry_id AS lot_id,
       l.account_id,
       l.unlock_at,
       l.reason_code,
       l.delta AS lot_units,
       COALESCE(SUM(r.delta) FILTER (WHERE r.bucket = 'locked'), 0) AS released_units,
       l.delta + COALESCE(SUM(r.delta) FILTER (WHERE r.bucket = 'locked'), 0) AS outstanding_units
  FROM points_ledger l
  LEFT JOIN points_ledger r
         ON r.bucket = 'locked' AND r.ref_id = l.entry_id::text AND r.delta < 0
 WHERE l.bucket = 'locked' AND l.delta > 0
 GROUP BY l.entry_id, l.account_id, l.unlock_at, l.reason_code, l.delta;

-- ---------------------------------------------------------------- 持有量视图（可用 / 锁定）
CREATE OR REPLACE VIEW points_holding AS
SELECT a.account_id,
       COALESCE((SELECT SUM(p.delta) FROM points_ledger p
                  WHERE p.account_id = a.account_id AND p.bucket = 'available'), 0) AS usable_units,
       COALESCE((SELECT SUM(l.outstanding_units) FROM points_locked_lot l
                  WHERE l.account_id = a.account_id), 0) AS locked_units
  FROM points_account a;

-- ---------------------------------------------------------------- 系统对偶账户
INSERT INTO points_account (account_id, state, verified)
VALUES ('system:cop', 'normal', TRUE)
ON CONFLICT (account_id) DO NOTHING;

COMMIT;
