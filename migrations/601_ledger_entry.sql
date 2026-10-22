-- 601 · M06 账本 · 分录（ledger_entry）与 ledger_entries 兼容视图
-- 规格：M06-ledger.md §3 不变量 INV-02/05/07/08 · §5 数据所有权（ledger_entry @ 601）
--       product/v4/src/20-payment-ledger.md §20.4.1 三层模型 · §20.4.3 R1（只允许加列）/R5（冲正）/
--       R7（两套状态机不混用）· CR-L5（规范名 ledger_entry + 兼容视图，迁移期保留旧名）
--
-- 三层模型：ledger_entry（业务视角，1 条）← 1:1 — journal_line（会计视角 1 行）← N:1 — journal_entry（凭证）
--
-- 原则：
--   1) 只加不改：001 的 ledger_entries 表与 005 的加列一字不动；本文件只新建 ledger_entry + 一个只读视图。
--   2) 只追加（INV-08）：ledger_entry 拒绝 DELETE；只放行冲正所需的 status posted → voided。
--   3) 1:1 + 同凭证（INV-02）：journal_line 用复合外键 (ledger_entry_id, journal_id) 指向本表。
--   4) 冲正等额取反（INV-07 / R5）：reverse_of 非空时，金额与原分录相等、dc 取反、同单位同类；
--      每原分录至多一条冲正（唯一索引）。写入顺序：先插冲正分录 → 再把原分录置 voided。
--   5) 可重复执行：IF NOT EXISTS / DROP ... IF EXISTS + CREATE / DROP VIEW IF EXISTS + CREATE VIEW。
BEGIN;

-- ────────────────────────────────────────────────────────────── 分录（业务视角）
-- 列集合 = §20.4.1（account_id / entry_type / amount / status…）+ §20.4.3 R1 允许的新增列
-- （journal_id / line_no / dc / amount_minor / qty_minor / fund_class）。不入账科目码：科目只在本表
-- 的会计视角（journal_line.coa_code）出现，避免同义字段两处漂移。
CREATE TABLE IF NOT EXISTS ledger_entry (
  entry_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  journal_id   UUID NOT NULL,                                        -- 归属凭证（N:1，复合外键见下）
  line_no      SMALLINT NOT NULL,                                    -- 与 journal_line 同号（1:1）
  account_id   TEXT NOT NULL,                                        -- 主体 / 科目账户（accounts 归 M01：软引用）
  entry_type   TEXT NOT NULL,                                        -- 业务语义白名单（§20.4.4，16 值）
  unit_type    TEXT NOT NULL,                                        -- 与所属凭证同单位（复合外键，INV-04）
  dc           CHAR(1) NOT NULL,                                     -- D 借 / C 贷
  amount_minor BIGINT NOT NULL,                                      -- 与 journal_line.amount_minor 必须相等
  qty_minor    BIGINT,                                               -- 资产辅助计量（INV-11）
  fund_class   TEXT NOT NULL,                                        -- CLIENT / PLATFORM / FEE
  status       TEXT NOT NULL DEFAULT 'posted',                       -- 账本级两态（R7）
  reverse_of   UUID REFERENCES ledger_entry(entry_id),               -- 冲正分录指向原分录（R5）
  ref_id       TEXT,                                                 -- 业务对象（chain_tx_id / payment_order_id …）
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT ledger_entry_line_no_ck CHECK (line_no BETWEEN 1 AND 64),
  -- INV-05：未知 entry_type 一律拒绝（读路径同样不得静默跳过）
  CONSTRAINT ledger_entry_entry_type_ck CHECK (entry_type IN (
    'earn','redeem','adjust','freeze','unfreeze','void',
    'deposit','consume','payout','refund','chargeback','transfer','gas','conversion','fx_reval','writeoff'
  )),
  CONSTRAINT ledger_entry_unit_type_ck CHECK (
    unit_type IN ('USD', 'COP', 'STABLE_USDT', 'FIAT_CNY')
  ),
  CONSTRAINT ledger_entry_dc_ck CHECK (dc IN ('D', 'C')),
  CONSTRAINT ledger_entry_amount_ck CHECK (amount_minor > 0),
  CONSTRAINT ledger_entry_qty_ck CHECK (qty_minor IS NULL OR qty_minor > 0),
  CONSTRAINT ledger_entry_fund_class_ck CHECK (fund_class IN ('CLIENT', 'PLATFORM', 'FEE')),
  CONSTRAINT ledger_entry_status_ck CHECK (status IN ('posted', 'voided')),
  CONSTRAINT ledger_entry_ref_ck CHECK (ref_id IS NULL OR length(ref_id) BETWEEN 1 AND 128),
  -- 每个凭证行只有一条分录（与 journal_line (journal_id, line_no) 一一对应）
  CONSTRAINT ledger_entry_journal_line_uq UNIQUE (journal_id, line_no),
  -- 供 journal_line 的复合外键使用（同凭证校验，INV-02）
  CONSTRAINT ledger_entry_entry_journal_uq UNIQUE (entry_id, journal_id)
);

-- 同单位 + 属于同一凭证（INV-04）：复合外键，凭证 (journal_id, unit_type) 唯一在 600 已声明。
-- 单列外键由本复合外键替代（先删掉建表时自动生成的那条，保证重复执行幂等）。
ALTER TABLE ledger_entry DROP CONSTRAINT IF EXISTS ledger_entry_journal_id_fkey;
ALTER TABLE ledger_entry DROP CONSTRAINT IF EXISTS ledger_entry_journal_unit_fkey;
ALTER TABLE ledger_entry ADD CONSTRAINT ledger_entry_journal_unit_fkey
  FOREIGN KEY (journal_id, unit_type) REFERENCES journal_entry (journal_id, unit_type);

-- INV-07：每原分录至多一条冲正
CREATE UNIQUE INDEX IF NOT EXISTS ledger_entry_reverse_uq
  ON ledger_entry (reverse_of) WHERE reverse_of IS NOT NULL;
CREATE INDEX IF NOT EXISTS ledger_entry_ref_idx ON ledger_entry (ref_id) WHERE ref_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ledger_entry_journal_idx ON ledger_entry (journal_id);

DROP TRIGGER IF EXISTS ledger_entry_no_mutation ON ledger_entry;
CREATE TRIGGER ledger_entry_no_mutation BEFORE UPDATE OR DELETE ON ledger_entry
  FOR EACH ROW EXECUTE FUNCTION m06_allow_void_only();
DROP TRIGGER IF EXISTS ledger_entry_no_truncate ON ledger_entry;
CREATE TRIGGER ledger_entry_no_truncate BEFORE TRUNCATE ON ledger_entry
  FOR EACH STATEMENT EXECUTE FUNCTION m06_forbid_truncate();   -- 函数在 600 定义

-- 冲正等额取反（INV-07 / R5）：reverse_of 非空时逐项对照原分录
CREATE OR REPLACE FUNCTION m06_entry_reversal_trg() RETURNS trigger AS $$
DECLARE
  v_orig ledger_entry%ROWTYPE;
BEGIN
  IF NEW.reverse_of IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO v_orig FROM ledger_entry WHERE entry_id = NEW.reverse_of;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ledger_entry: reverse_of % not found (INV-07)', NEW.reverse_of
      USING ERRCODE = '23503';
  END IF;
  IF v_orig.status <> 'posted' THEN
    RAISE EXCEPTION 'ledger_entry: original % is already %, cannot reverse twice (INV-07)',
      v_orig.entry_id, v_orig.status
      USING ERRCODE = '42501';
  END IF;
  IF NEW.amount_minor <> v_orig.amount_minor THEN
    RAISE EXCEPTION 'ledger_entry: reversal amount % <> original % (INV-07)',
      NEW.amount_minor, v_orig.amount_minor
      USING ERRCODE = '23514';
  END IF;
  IF NEW.dc = v_orig.dc THEN
    RAISE EXCEPTION 'ledger_entry: reversal must flip dc (original %) (INV-07)', v_orig.dc
      USING ERRCODE = '23514';
  END IF;
  IF NEW.unit_type <> v_orig.unit_type OR NEW.fund_class <> v_orig.fund_class THEN
    RAISE EXCEPTION 'ledger_entry: reversal must keep unit_type/fund_class (INV-07)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_entry_reversal_guard ON ledger_entry;
CREATE TRIGGER ledger_entry_reversal_guard BEFORE INSERT ON ledger_entry
  FOR EACH ROW EXECUTE FUNCTION m06_entry_reversal_trg();

-- ────────────────────────────────────────────── 1:1 绑定：journal_line ⇄ ledger_entry（INV-02）
ALTER TABLE journal_line DROP CONSTRAINT IF EXISTS journal_line_ledger_entry_fkey;
ALTER TABLE journal_line ADD CONSTRAINT journal_line_ledger_entry_fkey
  FOREIGN KEY (ledger_entry_id, journal_id) REFERENCES ledger_entry (entry_id, journal_id);

-- 两表重复字段必须一致（dc / amount / qty / fund_class / line_no），防止一处被改出漂移
CREATE OR REPLACE FUNCTION m06_line_matches_entry_trg() RETURNS trigger AS $$
DECLARE
  v_entry ledger_entry%ROWTYPE;
BEGIN
  SELECT * INTO v_entry FROM ledger_entry WHERE entry_id = NEW.ledger_entry_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal_line: ledger_entry % not found (INV-02)', NEW.ledger_entry_id
      USING ERRCODE = '23503';
  END IF;
  IF v_entry.line_no <> NEW.line_no OR v_entry.dc <> NEW.dc
     OR v_entry.amount_minor <> NEW.amount_minor
     OR v_entry.qty_minor IS DISTINCT FROM NEW.qty_minor
     OR v_entry.fund_class <> NEW.fund_class
     OR v_entry.account_id <> NEW.account_id THEN
    RAISE EXCEPTION
      'journal_line does not match ledger_entry % (line_no/dc/amount/qty/fund_class/account_id) (INV-02)',
      NEW.ledger_entry_id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS journal_line_matches_entry ON journal_line;
CREATE TRIGGER journal_line_matches_entry BEFORE INSERT ON journal_line
  FOR EACH ROW EXECUTE FUNCTION m06_line_matches_entry_trg();

-- ────────────────────────────────────────────── ledger_entries 兼容视图（CR-L5）
-- 001 的 ledger_entries 是存量表（冻结、app/ledger.py 仍在写），因此**不能**直接建同名视图。
-- 本视图给出一个稳定的只读读面：历史行（存量表）+ 新分录（ledger_entry）并集，列名统一到规范名，
-- 并用 origin 标明来源，读方不必直接 join 旧基表（01-ownership §6）。
-- 迁移期保留旧名 → S1 末的退役动作（不在本任务内，见证据文件「回滚/退役」）：
--   DROP TABLE ledger_entries;  ALTER VIEW ledger_entries_compat RENAME TO ledger_entries;
-- UNION 视图不可写：任何 INSERT/UPDATE/DELETE 都报 "cannot ... view"，天然只读。
DROP VIEW IF EXISTS ledger_entries_compat;
CREATE VIEW ledger_entries_compat AS
SELECT l.entry_id,
       NULL::uuid        AS journal_id,
       l.line_no         AS line_no,
       l.entry_type      AS entry_type,
       l.unit_type       AS unit_type,
       NULL::text        AS dc,
       NULL::text        AS account_id,
       l.amount_micro    AS amount_minor,
       l.qty_minor       AS qty_minor,
       NULL::text        AS fund_class,
       l.status          AS status,
       l.reverse_of      AS reverse_of,
       l.ref_id          AS ref_id,
       l.source_type     AS source_type,
       l.source_id       AS source_id,
       l.event_seq       AS event_seq,
       l.created_at      AS created_at,
       'legacy'::text    AS origin
  FROM ledger_entries l
UNION ALL
SELECT e.entry_id,
       e.journal_id,
       e.line_no,
       e.entry_type,
       e.unit_type,
       e.dc::text,
       e.account_id,
       e.amount_minor,
       e.qty_minor,
       e.fund_class,
       e.status,
       e.reverse_of,
       e.ref_id,
       j.source_type,
       j.source_id,
       j.event_seq,
       e.created_at,
       'journal'::text   AS origin
  FROM ledger_entry e
  JOIN journal_entry j ON j.journal_id = e.journal_id;

COMMENT ON VIEW ledger_entries_compat IS
  'CR-L5 兼容读面：ledger_entries（存量）+ ledger_entry（规范）并集，只读；S1 末由该视图接管 ledger_entries 名。';

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['entry_id','journal_id','line_no','account_id','entry_type','unit_type','dc',
                      'amount_minor','qty_minor','fund_class','status','reverse_of','ref_id','created_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'ledger_entry' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'ledger_entry 结构与 601 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
