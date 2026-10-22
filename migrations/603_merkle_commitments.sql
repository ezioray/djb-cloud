-- 603 · M06 账本 · 期间根（merkle_commitments）
-- 规格：M06-ledger.md §3 INV-13（Merkle 根可由当期分录重算复现；发布后不可改）/ §5（merkle_commitments @ 603）
--       §8.2 MERKLE_KINDS_OWNED = journal, daily_close（audit 属 M16、por 属 M09，本表不得混入）
--       02-events.md §3 merkle.anchored（root / kind / period / anchored_at）
--
-- 设计：一条记录 = 一次「计算即发布」，因此没有「草稿 → 发布」的 UPDATE 路径（INV-08/INV-13）。
BEGIN;

CREATE TABLE IF NOT EXISTS merkle_commitments (
  period       TEXT NOT NULL,      -- 期间标识；粒度由 ledger.merkle_interval_h 决定（月 / 日 / 时）
  kind         TEXT NOT NULL,      -- 只允许 M06 拥有的两类根
  root         TEXT NOT NULL,      -- sha256 十六进制（64 位小写）
  entry_count  BIGINT NOT NULL,    -- 纳入本期根的凭证数
  algorithm    TEXT NOT NULL DEFAULT 'sha256',
  anchored_at  TIMESTAMPTZ NOT NULL DEFAULT now(),   -- 根的计算时刻（诚实时间）
  published_at TIMESTAMPTZ NOT NULL DEFAULT now(),   -- 发布时刻（写入即发布）
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT merkle_commitments_pk PRIMARY KEY (period, kind),   -- 同期同类只有一条根
  CONSTRAINT merkle_commitments_kind_ck CHECK (kind IN ('journal', 'daily_close')),
  CONSTRAINT merkle_commitments_period_ck CHECK (
    -- YYYY-MM / YYYY-MM-DD / YYYY-MM-DDTHH（月 01–12、日 01–31、时 00–23）
    period ~ '^[0-9]{4}-(0[1-9]|1[0-2])(-([0-2][0-9]|3[01])(T([01][0-9]|2[0-3]))?)?$'
  ),
  CONSTRAINT merkle_commitments_root_ck CHECK (root ~ '^[0-9a-f]{64}$'),
  CONSTRAINT merkle_commitments_count_ck CHECK (entry_count >= 0),
  CONSTRAINT merkle_commitments_algo_ck CHECK (algorithm = 'sha256'),
  CONSTRAINT merkle_commitments_time_ck CHECK (published_at >= anchored_at)
);

DROP TRIGGER IF EXISTS merkle_commitments_no_mutation ON merkle_commitments;
CREATE TRIGGER merkle_commitments_no_mutation BEFORE UPDATE OR DELETE ON merkle_commitments
  FOR EACH ROW EXECUTE FUNCTION m06_forbid_mutation();
DROP TRIGGER IF EXISTS merkle_commitments_no_truncate ON merkle_commitments;
CREATE TRIGGER merkle_commitments_no_truncate BEFORE TRUNCATE ON merkle_commitments
  FOR EACH STATEMENT EXECUTE FUNCTION m06_forbid_truncate();   -- 函数在 600 定义

-- ────────────────────────────────────────────── 结构断言
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(c, ', ') INTO v_missing
    FROM unnest(ARRAY['period','kind','root','entry_count','algorithm','anchored_at','published_at','created_at']) AS c
   WHERE NOT EXISTS (
     SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = 'merkle_commitments' AND column_name = c);
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'merkle_commitments 结构与 603 不符，缺列：%', v_missing;
  END IF;
END;
$$;

COMMIT;
