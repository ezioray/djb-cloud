-- 702 · M07 指标事实（reputation_events，只追加）
-- 规格：product/v4/modules/M07-reputation-cop.md §3（ReputationEvent：metric/value/weight/delta/ref_id，只追加）
--       §5（reputation_events，迁移 702，保留 ≥5 年）· §6.1（消费 usage.settled 写事实）
--       §7（事件重复 / 乱序 → 幂等丢弃，不改余额）
--       00-conventions §7.5（事件只追加，禁止 UPDATE / DELETE）
--
-- 原则：
--   1) **只追加**：UPDATE / DELETE / TRUNCATE 一律由触发器拒绝（INV-02 同源要求）。
--      更正只能追加一条反向事实（delta 取负、ref_id 指向被更正事实），不修改原行。
--   2) **可复算**（§3「指标事实（可复算）」）：score 必须能由本表 + 规则独立重算，
--      因此每行都带 weight 与 delta，且 delta 的符号语义固定（正=加分，负=惩罚）。
--   3) **消费幂等**：UNIQUE(account_id, metric, ref_id)——同一业务事实（如同一个 usage_id）
--      重放不会落第二条；ref_id 为空的事实不参与该唯一键（PG 部分唯一索引）。
--   4) 保留 ≥5 年：本表不提供清理入口；DELETE 被触发器拒绝，删除只能由 DBA 走保留策略。
BEGIN;

CREATE TABLE IF NOT EXISTS reputation_events (
  id           UUID PRIMARY KEY,                  -- UUIDv7（00-conventions §2）
  account_id   TEXT NOT NULL,                     -- 事实归属账户
  metric       TEXT NOT NULL,                     -- success_rate / latency_ok_rate / online_rate /
                                                  -- yield_response / penalty / usage_settled / …
  value        NUMERIC(14,4) NOT NULL,            -- 指标观测值（0–1000 或金额，按 metric 解释）
  weight       INTEGER NOT NULL DEFAULT 0,        -- 该项在评分中的权重（bps）
  delta        NUMERIC(14,4) NOT NULL,            -- 对总分的贡献（可为负：惩罚项）
  ref_id       TEXT,                              -- 业务事实 id（usage_id / case_id / grant_id）
  occurred_at  TIMESTAMPTZ NOT NULL,              -- 业务发生时间（UTC）
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now() -- 落库时刻（保留期 / 审计按它）
);

ALTER TABLE reputation_events DROP CONSTRAINT IF EXISTS reputation_events_metric_ck;
ALTER TABLE reputation_events ADD CONSTRAINT reputation_events_metric_ck
  CHECK (char_length(metric) BETWEEN 1 AND 64) NOT VALID;

ALTER TABLE reputation_events DROP CONSTRAINT IF EXISTS reputation_events_ref_ck;
ALTER TABLE reputation_events ADD CONSTRAINT reputation_events_ref_ck
  CHECK (ref_id IS NULL OR char_length(ref_id) BETWEEN 1 AND 128) NOT VALID;

ALTER TABLE reputation_events DROP CONSTRAINT IF EXISTS reputation_events_weight_ck;
ALTER TABLE reputation_events ADD CONSTRAINT reputation_events_weight_ck
  CHECK (weight BETWEEN -10000 AND 10000) NOT VALID;

-- 消费幂等：同一账户同一指标同一业务事实只落一次（重放 → 幂等丢弃，不改余额）
CREATE UNIQUE INDEX IF NOT EXISTS reputation_events_fact_uq
  ON reputation_events (account_id, metric, ref_id) WHERE ref_id IS NOT NULL;

-- 游标分页：按 occurred_at 倒序 + id 兜底（同一时刻多条也能稳定翻页）
CREATE INDEX IF NOT EXISTS reputation_events_page_idx
  ON reputation_events (account_id, occurred_at DESC, id DESC);

-- ────────────────────────────────────────────────────────── 只追加护栏
CREATE OR REPLACE FUNCTION m07_forbid_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only (M07 §3 INV-02): % not allowed', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION m07_forbid_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE not allowed (M07 §5)', TG_TABLE_NAME
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS reputation_events_no_mutation ON reputation_events;
CREATE TRIGGER reputation_events_no_mutation BEFORE UPDATE OR DELETE ON reputation_events
  FOR EACH ROW EXECUTE FUNCTION m07_forbid_mutation();

DROP TRIGGER IF EXISTS reputation_events_no_truncate ON reputation_events;
CREATE TRIGGER reputation_events_no_truncate BEFORE TRUNCATE ON reputation_events
  FOR EACH STATEMENT EXECUTE FUNCTION m07_forbid_truncate();

COMMENT ON TABLE reputation_events IS
  'M07 指标事实（M07 §5 / 迁移 702，保留 ≥5 年）：只追加；score 必须能由本表 + 规则复算';
COMMENT ON COLUMN reputation_events.delta IS
  '对总分的贡献；惩罚项为负。更正 = 追加反向事实（ref_id 指向原事实），不修改原行';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'reputation_events_fact_uq') THEN
    RAISE EXCEPTION '702: 缺消费幂等唯一索引 reputation_events_fact_uq';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'reputation_events_no_mutation') THEN
    RAISE EXCEPTION '702: 缺只追加触发器 reputation_events_no_mutation';
  END IF;
END
$$;

COMMIT;
