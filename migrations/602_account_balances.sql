-- 602 · M06 账本 · 派生余额（account_balances）
-- 规格：M06-ledger.md §3 INV-10（余额由分录派生：全量重建与增量值一致）/ §5（account_balances @ 602）
--       product/v4/src/20-payment-ledger.md §20.2.7（account_balance 作为派生缓存，真值永远在分录里）
--       _CR-REGISTER CR-L3：account_balances 是**唯一**余额源；M01 accounts.balance_micro 降为只读缓存
--
-- 设计：版本化的只追加快照 —— 每次变动插入 version+1 的新行，永不 UPDATE/DELETE。
--   · 让「余额」也满足 INV-08，任何历史版本可回溯，复算只需比对最新版本；
--   · 读最新余额用 account_balances_latest 视图（不要自己写 max(version) 子查询）；
--   · balance_minor 约定：借方为正的净额（Σ借 − Σ贷），贷方科目因此为负值；
--     展示「正常方向余额」由读方按科目方向取相反数（T3/T4），存储层不重复一份口径。
BEGIN;

CREATE TABLE IF NOT EXISTS account_balances (
  account_id    TEXT   NOT NULL,          -- 科目账户 / 主体账户（accounts 归 M01：软引用，不建 FK）
  unit_type     TEXT   NOT NULL,          -- 与凭证同口径：USD / COP / STABLE_USDT / FIAT_CNY
  sub_account   TEXT   NOT NULL DEFAULT 'AVAILABLE',   -- 用户子账户（§20.2.7）
  version       BIGINT NOT NULL,          -- 同一 (account, unit, sub) 单调 +1，从 1 开始
  balance_minor BIGINT NOT NULL,          -- 借方为正的净额（整数最小单位）
  journal_id    UUID REFERENCES journal_entry(journal_id),   -- 产生本版本的凭证（可回溯；期初行可为 NULL）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT account_balances_pk PRIMARY KEY (account_id, unit_type, sub_account, version),
  CONSTRAINT account_balances_account_ck CHECK (length(account_id) BETWEEN 1 AND 128),
  CONSTRAINT account_balances_unit_type_ck CHECK (
    unit_type IN ('USD', 'COP', 'STABLE_USDT', 'FIAT_CNY')
  ),
  CONSTRAINT account_balances_sub_account_ck CHECK (sub_account IN ('AVAILABLE', 'LOCKED')),
  CONSTRAINT account_balances_version_ck CHECK (version >= 1)
);

CREATE INDEX IF NOT EXISTS account_balances_journal_idx
  ON account_balances (journal_id) WHERE journal_id IS NOT NULL;

DROP TRIGGER IF EXISTS account_balances_no_mutation ON account_balances;
CREATE TRIGGER account_balances_no_mutation BEFORE UPDATE OR DELETE ON account_balances
  FOR EACH ROW EXECUTE FUNCTION m06_forbid_mutation();
DROP TRIGGER IF EXISTS account_balances_no_truncate ON account_balances;
CREATE TRIGGER account_balances_no_truncate BEFORE TRUNCATE ON account_balances
  FOR EACH STATEMENT EXECUTE FUNCTION m06_forbid_truncate();   -- 函数在 600 定义

-- 版本连续性（INV-10）：不得跳号、不得回退；并发插入同一版本由主键冲突兜底（失败重读再写）
CREATE OR REPLACE FUNCTION m06_balance_version_trg() RETURNS trigger AS $$
DECLARE
  v_max BIGINT;
BEGIN
  SELECT max(version) INTO v_max
    FROM account_balances
   WHERE account_id = NEW.account_id AND unit_type = NEW.unit_type AND sub_account = NEW.sub_account;
  IF NEW.version <> COALESCE(v_max, 0) + 1 THEN
    RAISE EXCEPTION 'account_balances: version must be % for (%, %, %), got % (INV-10)',
      COALESCE(v_max, 0) + 1, NEW.account_id, NEW.unit_type, NEW.sub_account, NEW.version
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS account_balances_version_guard ON account_balances;
CREATE TRIGGER account_balances_version_guard BEFORE INSERT ON account_balances
  FOR EACH ROW EXECUTE FUNCTION m06_balance_version_trg();

-- 最新余额读面（只读）：每 (account, unit, sub) 取最大 version
DROP VIEW IF EXISTS account_balances_latest;
CREATE VIEW account_balances_latest AS
SELECT DISTINCT ON (account_id, unit_type, sub_account)
       account_id, unit_type, sub_account, version, balance_minor, journal_id, created_at
  FROM account_balances
 ORDER BY account_id, unit_type, sub_account, version DESC;

COMMENT ON VIEW account_balances_latest IS
  'account_balances 最新版本视图（INV-10 读面）；余额真值在 journal_line，全量重建后必须与本视图一致。';

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['account_id','unit_type','sub_account','version','balance_minor','journal_id','created_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'account_balances' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'account_balances 结构与 602 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
