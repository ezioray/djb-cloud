-- 404 · M04 scheduler-pricing · 决策日志（routing_decisions，只追加）
-- 规格：M04 §3 RoutingDecision / §5 数据所有权（**保留 12 个月**，CR-3 已裁决）
--       §6 流程 2（P1–P5）/ 流程 3（复算回放）· §7（决策日志写失败即熔断）
--       INV-03（四元锚点 ⇒ 同一决策）· INV-11（只追加、丢弃率 0）· INV-12（只存元数据与摘要）
--       02-events routing.decided
--
-- 设计要点
--   1) **四元锚点唯一**：(snapshot_ts, quote_version, policy_version, request_digest)
--      唯一索引把 INV-03 落到库层——同锚点并发 100 次只会有一行，读回同一条决策。
--   2) **幂等**：M04 §3「决策以 (trace_id, attempt_no) 唯一」——同一 trace 的第 2 次尝试
--      （最多 2 次，INV-12）用 attempt_no 区分；同锚点重放不再插入。
--   3) **只追加**：UPDATE 一律拒绝；DELETE 默认拒绝，只有归档作业显式
--      `SET LOCAL m04.archive = 'on'` 才能删（12 个月归档，T4/M16 作业用）。
--   4) **不进正文/凭据**：candidates / score_breakdown 只放输入快照（node_id、access、
--      model、报价、ρ、κ、λ）与分项，不含 prompt / response / 密钥（INV-12）。
BEGIN;

CREATE TABLE IF NOT EXISTS routing_decisions (
  decision_id       UUID PRIMARY KEY,                          -- 由四元锚点确定性派生（INV-03）
  trace_id          TEXT NOT NULL,
  attempt_no        SMALLINT NOT NULL DEFAULT 1,
  snapshot_ts       TIMESTAMPTZ NOT NULL,                      -- 锚点 1
  quote_version     BIGINT NOT NULL,                           -- 锚点 2
  policy_version    TEXT NOT NULL,                             -- 锚点 3
  request_digest    TEXT NOT NULL,                             -- 锚点 4（sha256 hex）
  candidates        JSONB NOT NULL,                            -- 候选集输入快照（复算用）
  eliminated        JSONB NOT NULL DEFAULT '[]'::jsonb,         -- [{node_id, reason_code}]
  score_breakdown   JSONB NOT NULL DEFAULT '[]'::jsonb,         -- [{node_id, ask, rho, kappa, lambda, cost}]
  chosen            JSONB,                                     -- RouteChosen；拒绝时为 NULL
  tie_break         TEXT,
  preempt_plan      JSONB NOT NULL DEFAULT '[]'::jsonb,
  fallbacks         JSONB NOT NULL DEFAULT '[]'::jsonb,
  reason_codes      JSONB NOT NULL DEFAULT '[]'::jsonb,        -- 粗粒度原因码（不含阈值）
  eta_seconds       INT,
  price_minor       BIGINT,
  outcome           TEXT NOT NULL,
  fallback_used     BOOLEAN NOT NULL DEFAULT FALSE,
  decided_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT routing_decisions_outcome_ck
    CHECK (outcome IN ('routed', 'fallback', 'queued', 'rejected')),
  CONSTRAINT routing_decisions_attempt_ck CHECK (attempt_no BETWEEN 1 AND 2),  -- INV-12 ≤2 次
  CONSTRAINT routing_decisions_quote_version_ck CHECK (quote_version >= 0),
  CONSTRAINT routing_decisions_policy_version_ck
    CHECK (char_length(policy_version) BETWEEN 1 AND 64),
  CONSTRAINT routing_decisions_digest_ck    CHECK (char_length(request_digest) = 64),
  CONSTRAINT routing_decisions_trace_ck     CHECK (char_length(trace_id) BETWEEN 1 AND 128),
  CONSTRAINT routing_decisions_eta_ck       CHECK (eta_seconds IS NULL OR eta_seconds >= 0),
  CONSTRAINT routing_decisions_price_ck     CHECK (price_minor IS NULL OR price_minor >= 0),
  -- 选了节点就必须有价格与 chosen；拒绝 / 排队时 chosen 必须为空（不制造假落点）
  CONSTRAINT routing_decisions_chosen_ck
    CHECK ((outcome IN ('routed', 'fallback')) = (chosen IS NOT NULL)),
  CONSTRAINT routing_decisions_candidates_ck CHECK (jsonb_typeof(candidates) = 'array'),
  CONSTRAINT routing_decisions_eliminated_ck CHECK (jsonb_typeof(eliminated) = 'array'),
  CONSTRAINT routing_decisions_scores_ck     CHECK (jsonb_typeof(score_breakdown) = 'array'),
  CONSTRAINT routing_decisions_preempt_ck    CHECK (jsonb_typeof(preempt_plan) = 'array'),
  CONSTRAINT routing_decisions_fallbacks_ck  CHECK (jsonb_typeof(fallbacks) = 'array'),
  CONSTRAINT routing_decisions_reasons_ck    CHECK (jsonb_typeof(reason_codes) = 'array'),

  -- INV-03：四元锚点唯一（同锚点必得同一决策）
  CONSTRAINT routing_decisions_anchor_uq
    UNIQUE (snapshot_ts, quote_version, policy_version, request_digest),
  -- M04 §3 幂等：决策以 (trace_id, attempt_no) 唯一
  CONSTRAINT routing_decisions_trace_uq UNIQUE (trace_id, attempt_no)
);

-- M04 §5 索引：routing_decisions(snapshot_ts)；复算回放与下钻用的补充索引
CREATE INDEX IF NOT EXISTS routing_decisions_snapshot_idx ON routing_decisions (snapshot_ts);
CREATE INDEX IF NOT EXISTS routing_decisions_decided_idx  ON routing_decisions (decided_at);
CREATE INDEX IF NOT EXISTS routing_decisions_outcome_idx   ON routing_decisions (outcome, decided_at);
CREATE INDEX IF NOT EXISTS routing_decisions_chosen_idx
  ON routing_decisions ((chosen->>'node_id')) WHERE chosen IS NOT NULL;

-- 只追加：UPDATE 永久拒绝；DELETE 仅归档作业（SET LOCAL m04.archive = 'on'）可执行
CREATE OR REPLACE FUNCTION m04_routing_decisions_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'routing_decisions 只追加：禁止 UPDATE（INV-11）';
  END IF;

  IF TG_OP = 'DELETE'
     AND COALESCE(current_setting('m04.archive', true), 'off') <> 'on' THEN
    RAISE EXCEPTION 'routing_decisions 只追加：禁止 DELETE（12 个月归档需 SET LOCAL m04.archive=on）';
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NULL;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS routing_decisions_guard_trg ON routing_decisions;
CREATE TRIGGER routing_decisions_guard_trg
  BEFORE UPDATE OR DELETE ON routing_decisions
  FOR EACH ROW EXECUTE FUNCTION m04_routing_decisions_guard();

COMMENT ON TABLE routing_decisions IS
  'M04 决策日志：只追加、丢弃率 0（INV-11）；四元锚点唯一（INV-03）；12 个月归档（CR-3）';
COMMENT ON COLUMN routing_decisions.decision_id IS '由 (snapshot_ts, quote_version, policy_version, request_digest) 确定性派生的 UUIDv5';
-- 12 个月归档（CR-3）：归档口径 = decided_at < now() - INTERVAL '12 months'，
-- 由 T4/M16 归档作业先导出再删除（DELETE 需 SET LOCAL m04.archive = 'on'）。
COMMENT ON COLUMN routing_decisions.candidates IS '候选集输入快照：只含 node_id/access/model/报价/ρ/κ 等输入，不含正文与凭据（INV-12）';

COMMIT;
