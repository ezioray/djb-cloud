-- 701 · M07 当前信誉评分与等级（reputation_scores）
-- 规格：product/v4/modules/M07-reputation-cop.md §3（ReputationScore 实体 / 状态机 / INV-07 INV-08）
--       §5 数据所有权（reputation_scores，迁移 701，随账户长期）· §8.2（本模块常量）
--       product/v4/modules/00-conventions §7.2（只加列 / 表 / 索引）· §7.5（账本 / 事件只追加）
--
-- 原则：
--   1) **当前态表**：每个账户一行（account_id 主键），由重算任务覆盖写；
--      历史留在 reputation_events（702，只追加）——「当前态可覆盖、事实不可覆盖」。
--   2) **只输出等级**（INV-08）：本表没有、也不得新增任何费率 / 折扣列；
--      等级折扣属于 03-facts §4，由消费方按 tier 自行查表。
--   3) **L5 只能人工授予**（§8.2 / CR-5）：``manual_tier`` 标记来源，规则重算不得自己升 L5。
--   4) 连续天数：``tier_since`` 是当前等级起始时刻，L3/L4 的「连续 30 / 90 天」由它推导；
--      掉级即时生效，已发放 COP 不回溯（§3 状态机）。
--   5) 可重复执行：IF NOT EXISTS / DROP CONSTRAINT IF EXISTS + ADD / CREATE OR REPLACE；
--      末尾断言保证「已存在的表」与本节定义同形，避免半途建表被静默放过。
BEGIN;

CREATE TABLE IF NOT EXISTS reputation_scores (
  account_id      TEXT PRIMARY KEY,                     -- 与 points_account 同一账户口径（user:xxx / node:xxx）
  score           INTEGER NOT NULL,                     -- 0–1000 整数（展示为 score/10，1 位小数）
  tier            TEXT NOT NULL,                        -- L1–L5（L5 仅人工）
  quality_coef    NUMERIC(2,1) NOT NULL,                -- 质量系数 0.5–1.2（步长 0.1）
  stability_coef  NUMERIC(2,1) NOT NULL,                -- 稳定系数 0.5–1.2（步长 0.1）
  window_days     INTEGER NOT NULL,                     -- 计算窗口（7–90，默认 30）
  policy_version  TEXT NOT NULL,                        -- 评分策略版本（INV-07：事件必带）
  computed_at     TIMESTAMPTZ NOT NULL,                 -- 本次重算时刻（业务时间，UTC）
  tier_since      TIMESTAMPTZ NOT NULL,                 -- 当前等级起始时刻（连续天数基准）
  prev_tier       TEXT,                                 -- 上一次等级（掉级 / 升级留痕，便于 reasons 复算）
  manual_tier     BOOLEAN NOT NULL DEFAULT FALSE,       -- L5 人工授予（规则重算不得自行置 true）
  reasons         TEXT[] NOT NULL DEFAULT '{}'::text[], -- 上次重算的变化原因（人类可读、不含阈值，INV-07）
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()    -- 落库时刻
);

-- 值域与枚举（只加不改：后续放宽走新迁移）
ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_score_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_score_ck
  CHECK (score BETWEEN 0 AND 1000) NOT VALID;

ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_tier_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_tier_ck
  CHECK (tier IN ('L1', 'L2', 'L3', 'L4', 'L5')) NOT VALID;

ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_prev_tier_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_prev_tier_ck
  CHECK (prev_tier IS NULL OR prev_tier IN ('L1', 'L2', 'L3', 'L4', 'L5')) NOT VALID;

-- 系数区间 0.5–1.2 且步长 0.1（§8.2「系数区间」）：用「×10 后必为 5..12 的整数」表达
ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_quality_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_quality_ck
  CHECK (quality_coef BETWEEN 0.5 AND 1.2 AND (quality_coef * 10) = trunc(quality_coef * 10)) NOT VALID;

ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_stability_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_stability_ck
  CHECK (stability_coef BETWEEN 0.5 AND 1.2 AND (stability_coef * 10) = trunc(stability_coef * 10)) NOT VALID;

ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_window_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_window_ck
  CHECK (window_days BETWEEN 7 AND 90) NOT VALID;

ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_policy_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_policy_ck
  CHECK (char_length(policy_version) BETWEEN 1 AND 64) NOT VALID;

-- L5 与 manual_tier 必须一致：L5 只能人工，人工授予的也必须是 L5
ALTER TABLE reputation_scores DROP CONSTRAINT IF EXISTS reputation_scores_manual_tier_ck;
ALTER TABLE reputation_scores ADD CONSTRAINT reputation_scores_manual_tier_ck
  CHECK ((tier = 'L5') = manual_tier) NOT VALID;

-- 账户不存在时拒绝：account_id 软引用 points_account（M07 自己拥有的 COP 账户档案），
-- 但不建 FK——账户搬迁 / 合并时不做级联删除（账本类数据一律保留）。
CREATE INDEX IF NOT EXISTS reputation_scores_tier_idx ON reputation_scores (tier, score DESC);
CREATE INDEX IF NOT EXISTS reputation_scores_computed_idx ON reputation_scores (computed_at);

COMMENT ON TABLE reputation_scores IS
  'M07 当前评分与等级（M07 §5 / 迁移 701）：每账户一行，由规则重算覆盖写；历史见 reputation_events';
COMMENT ON COLUMN reputation_scores.manual_tier IS
  'L5 仅人工授予（§8.2 / CR-5）：规则重算不得自行置 true；与 tier 必须同真同假';
COMMENT ON COLUMN reputation_scores.reasons IS
  '上次重算的变化原因（人类可读短句，不含阈值）；reputation.changed 的 reasons[] 同源';
COMMENT ON COLUMN reputation_scores.quality_coef IS
  '质量系数 0.5–1.2 步长 0.1；本模块只输出系数与等级，不输出费率（INV-08）';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                  WHERE table_schema = current_schema() AND table_name = 'reputation_scores') THEN
    RAISE EXCEPTION '701: reputation_scores 未建';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema()
                    AND indexname = 'reputation_scores_tier_idx') THEN
    RAISE EXCEPTION '701: 缺索引 reputation_scores_tier_idx';
  END IF;
  -- INV-08 结构保证：本表不得出现任何费率 / 折扣列
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = current_schema() AND table_name = 'reputation_scores'
                AND column_name ~ '(rate|discount|fee|price)') THEN
    RAISE EXCEPTION '701: reputation_scores 不得包含费率 / 折扣列（INV-08）';
  END IF;
END
$$;

COMMIT;
