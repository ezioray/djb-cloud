-- 1740 · M17 canary / L4 行为指纹（C13）：内置 canary prompt / 运行 / 事件
-- 规格：M17-supply-integrity.md §5.2（行为指纹）· §5.4（canary）· §5.11（抽检类型）
--       · §6.1（作弊升级：canary 失败 → 复核）· §7 数据模型（1700–1799）
--
-- 原则：
--   1) **合成 prompt**：内置 canary 全部是合成题面（算术 / 首都 / 复述固定 token / 数列 / 色值），
--      **不含任何用户正文**；运行级 nonce 追加在题面末尾，用于防缓存（不回传正文）；
--   2) **响应正文绝不落库**：canary_runs 只存 ``response_hash = sha256(响应正文)`` 与 score；
--      detail 有 DB 黑名单（prompt / response / content / token / secret … 一律写不进）；
--   3) **一次一运行**：同一 ``(node_id, model)`` 同时只允许 1 条 ``issued``（部分唯一索引）；
--      运行状态单向 issued → passed / failed / missed，终态不可回写；
--   4) **L4 只是线索**：本表不写 M17 定级（model_attestations 由 C12/风控决定），
--      ``behavioral_evidence`` 只给出「连续 N 次 pass」的线索；
--   5) **不碰账本**：本迁移不创建 / 修改任何 ledger_* / account_balances / loss_pool 对象；
--   6) 事件只追加：canary_events 禁止 UPDATE / DELETE / TRUNCATE。
BEGIN;

-- ───────────────────────────────────────────────────────── canary_prompts
CREATE TABLE IF NOT EXISTS canary_prompts (
  id             UUID PRIMARY KEY,
  prompt_key     TEXT NOT NULL UNIQUE,                    -- 稳定键（审计 / 复算用）
  prompt         TEXT NOT NULL,                           -- **合成**题面（无用户正文）
  expected_kind  TEXT NOT NULL,                           -- exact / contains / regex
  expected_value TEXT NOT NULL,                           -- 期望答案（exact/contains）或模式（regex）
  max_tokens     INTEGER NOT NULL DEFAULT 16,             -- 期望输出上限（1..256）
  state          TEXT NOT NULL DEFAULT 'active',          -- active / retired
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT canary_prompts_key_ck CHECK (prompt_key ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'),
  CONSTRAINT canary_prompts_prompt_ck CHECK (char_length(prompt) BETWEEN 32 AND 2048),
  CONSTRAINT canary_prompts_kind_ck CHECK (expected_kind IN ('exact', 'contains', 'regex')),
  CONSTRAINT canary_prompts_expected_ck CHECK (char_length(expected_value) BETWEEN 1 AND 256),
  CONSTRAINT canary_prompts_max_tokens_ck CHECK (max_tokens BETWEEN 1 AND 256),
  CONSTRAINT canary_prompts_state_ck CHECK (state IN ('active', 'retired'))
);

CREATE INDEX IF NOT EXISTS idx_canary_prompts_state
  ON canary_prompts (state, prompt_key);

COMMENT ON TABLE canary_prompts IS
  'M17 §5.4 canary 题面（C13）：全部合成、无用户正文；expected 支持 exact/contains/regex；'
  '运行级 nonce 由 canary_runs 追加，不改题面';

-- ───────────────────────────────────────────────────────── canary_runs
CREATE TABLE IF NOT EXISTS canary_runs (
  id             UUID PRIMARY KEY,
  node_id        TEXT NOT NULL,
  upstream_id    TEXT,
  model          TEXT NOT NULL,
  prompt_id      UUID NOT NULL REFERENCES canary_prompts (id),
  nonce          TEXT NOT NULL,                           -- 运行级 nonce（追加进下发题面）
  status         TEXT NOT NULL DEFAULT 'issued',          -- issued / passed / failed / missed
  response_hash  TEXT,                                    -- sha256(响应正文)；**正文不落库**
  score          NUMERIC(4, 3),                           -- 0.000 – 1.000
  detail         JSONB NOT NULL DEFAULT '{}'::jsonb,      -- 匹配类型 / 长度 / 耗时 / 原因
  created_at     TIMESTAMPTZ NOT NULL,
  deadline_at    TIMESTAMPTZ NOT NULL,                    -- created_at + 120s
  resolved_at    TIMESTAMPTZ,
  CONSTRAINT canary_runs_status_ck CHECK
    (status IN ('issued', 'passed', 'failed', 'missed')),
  CONSTRAINT canary_runs_issued_ck CHECK (
    status <> 'issued' OR (response_hash IS NULL AND score IS NULL AND resolved_at IS NULL)),
  CONSTRAINT canary_runs_resolved_ck CHECK
    (status = 'issued' OR resolved_at IS NOT NULL),
  CONSTRAINT canary_runs_hash_ck CHECK (
    response_hash IS NULL OR response_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT canary_runs_score_ck CHECK (score IS NULL OR (score >= 0 AND score <= 1)),
  CONSTRAINT canary_runs_deadline_ck CHECK (deadline_at > created_at),
  CONSTRAINT canary_runs_nonce_ck CHECK (nonce ~ '^[0-9a-f]{16,64}$'),
  CONSTRAINT canary_runs_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT canary_runs_model_ck CHECK (char_length(model) BETWEEN 1 AND 128),
  -- detail 只放元数据：不得出现正文 / 凭据 / 阈值类键
  CONSTRAINT canary_runs_detail_ck CHECK (
    NOT (detail ?| ARRAY['prompt', 'response', 'messages', 'content', 'body', 'text',
                         'answer', 'token', 'secret', 'password', 'api_key', 'threshold']))
);

-- 同一 (node_id, model) 同时只 1 条 issued（客户端不能靠并发多领题）
CREATE UNIQUE INDEX IF NOT EXISTS uq_canary_runs_issued
  ON canary_runs (node_id, model) WHERE status = 'issued';
CREATE INDEX IF NOT EXISTS idx_canary_runs_node
  ON canary_runs (node_id, model, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_canary_runs_status
  ON canary_runs (status, deadline_at);
CREATE INDEX IF NOT EXISTS idx_canary_runs_prompt
  ON canary_runs (prompt_id);

COMMENT ON TABLE canary_runs IS
  'M17 §5.4 canary 运行（C13）：响应只存 sha256 + score（正文绝不落库）；'
  '同一 (node,model) 仅 1 条 issued；issued → passed/failed/missed 单向';

-- ───────────────────────────────────────────────────────── canary_events
CREATE TABLE IF NOT EXISTS canary_events (
  event_id   UUID PRIMARY KEY,
  run_id     UUID NOT NULL REFERENCES canary_runs (id),
  event      TEXT NOT NULL,                               -- issued / passed / failed / missed
  detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT canary_events_event_ck CHECK (event IN ('issued', 'passed', 'failed', 'missed')),
  CONSTRAINT canary_events_detail_ck CHECK (
    NOT (detail ?| ARRAY['prompt', 'response', 'messages', 'content', 'body', 'text',
                         'answer', 'token', 'secret', 'password', 'api_key', 'threshold']))
);

CREATE INDEX IF NOT EXISTS idx_canary_events_run
  ON canary_events (run_id, created_at DESC);

COMMENT ON TABLE canary_events IS
  'M17 §5.4 canary 事件流水（只追加）：issued / passed / failed / missed；detail 不含正文';

-- ───────────────────────────────────────────────────────── 护栏函数
CREATE OR REPLACE FUNCTION m17_canary_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% 只追加：禁止 TRUNCATE', TG_TABLE_NAME USING ERRCODE = '42501';
END $$;

-- 题面：内容不可变 / active → retired 单向 / 禁止 DELETE
CREATE OR REPLACE FUNCTION m17_canary_prompt_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'canary_prompts 禁止 DELETE（题面与历史运行保留可审计）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.prompt_key IS DISTINCT FROM OLD.prompt_key
     OR NEW.prompt IS DISTINCT FROM OLD.prompt
     OR NEW.expected_kind IS DISTINCT FROM OLD.expected_kind
     OR NEW.expected_value IS DISTINCT FROM OLD.expected_value
     OR NEW.max_tokens IS DISTINCT FROM OLD.max_tokens
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'canary_prompts 题面 / 期望值 / max_tokens 不可变' USING ERRCODE = '42501';
  END IF;
  IF OLD.state <> 'active' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'canary prompt 已 retired：不可回写' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS canary_prompts_guard ON canary_prompts;
CREATE TRIGGER canary_prompts_guard BEFORE UPDATE OR DELETE
  ON canary_prompts FOR EACH ROW EXECUTE FUNCTION m17_canary_prompt_guard();

DROP TRIGGER IF EXISTS canary_prompts_no_truncate ON canary_prompts;
CREATE TRIGGER canary_prompts_no_truncate BEFORE TRUNCATE
  ON canary_prompts FOR EACH STATEMENT EXECUTE FUNCTION m17_canary_forbid_truncate();

-- 运行：身份不可变 / 状态单向 / 结果字段只写一次 / 禁止 DELETE
CREATE OR REPLACE FUNCTION m17_canary_run_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'canary_runs 禁止 DELETE（运行记录保留可审计）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.upstream_id IS DISTINCT FROM OLD.upstream_id
     OR NEW.model IS DISTINCT FROM OLD.model
     OR NEW.prompt_id IS DISTINCT FROM OLD.prompt_id
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.deadline_at IS DISTINCT FROM OLD.deadline_at THEN
    RAISE EXCEPTION 'canary_runs 身份 / 题面 / 截止时间不可变' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'issued' AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'canary 运行已定结果（%）：不可再改', OLD.status USING ERRCODE = '42501';
  END IF;
  IF OLD.status = 'issued' AND NEW.status NOT IN ('issued', 'passed', 'failed', 'missed') THEN
    RAISE EXCEPTION 'canary 状态只能 issued → passed / failed / missed（当前 → %）', NEW.status
      USING ERRCODE = '42501';
  END IF;
  IF OLD.response_hash IS NOT NULL AND NEW.response_hash IS DISTINCT FROM OLD.response_hash THEN
    RAISE EXCEPTION 'canary 结果 hash 只写一次（不可翻案）' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS canary_runs_guard ON canary_runs;
CREATE TRIGGER canary_runs_guard BEFORE UPDATE OR DELETE
  ON canary_runs FOR EACH ROW EXECUTE FUNCTION m17_canary_run_guard();

DROP TRIGGER IF EXISTS canary_runs_no_truncate ON canary_runs;
CREATE TRIGGER canary_runs_no_truncate BEFORE TRUNCATE
  ON canary_runs FOR EACH STATEMENT EXECUTE FUNCTION m17_canary_forbid_truncate();

-- 事件：只追加
CREATE OR REPLACE FUNCTION m17_canary_event_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'canary_events 只追加：禁止 %', TG_OP USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS canary_events_guard ON canary_events;
CREATE TRIGGER canary_events_guard BEFORE UPDATE OR DELETE
  ON canary_events FOR EACH ROW EXECUTE FUNCTION m17_canary_event_guard();

DROP TRIGGER IF EXISTS canary_events_no_truncate ON canary_events;
CREATE TRIGGER canary_events_no_truncate BEFORE TRUNCATE
  ON canary_events FOR EACH STATEMENT EXECUTE FUNCTION m17_canary_forbid_truncate();

-- ───────────────────────────────────────────────────────── 内置 5 条合成 canary
-- 题面全部合成（无用户正文）；expected 写死；重跑迁移用 ON CONFLICT 幂等。
INSERT INTO canary_prompts (id, prompt_key, prompt, expected_kind, expected_value,
                            max_tokens, state)
VALUES
  ('00000000-0000-7400-8000-000000000001', 'arith.2plus2',
   'Answer with a single digit only, no words and no punctuation: what is 2 + 2?',
   'exact', '4', 8, 'active'),
  ('00000000-0000-7400-8000-000000000002', 'capital.france',
   'Answer with the city name only, lowercase, no country and no punctuation: what is the capital of France?',
   'exact', 'paris', 8, 'active'),
  ('00000000-0000-7400-8000-000000000003', 'echo.token',
   'Repeat the token CANARY-7F3A exactly once. You may add one short sentence, but the token must appear verbatim.',
   'contains', 'canary-7f3a', 32, 'active'),
  ('00000000-0000-7400-8000-000000000004', 'sequence.evens',
   'List the first four positive even numbers separated by single spaces. Do not add any other words.',
   'contains', '2 4 6 8', 16, 'active'),
  ('00000000-0000-7400-8000-000000000005', 'color.hex',
   'Reply with only the six-digit hexadecimal colour code for pure red, in the exact form #RRGGBB. No words.',
   'regex', '^#[0-9a-f]{6}$', 8, 'active')
ON CONFLICT (prompt_key) DO NOTHING;

-- ───────────────────────────────────────────────────────── 迁移自检（不碰账本）
-- 本迁移不创建、不修改任何账本对象（journal_entry / journal_line / ledger_entry /
-- account_balances / merkle_commitments / m06_outbox / loss_pool_entries 都属 M05/M06/M09）。
-- 「迁移前后账本结构指纹 + 真实行摘要 diff = 0」由
-- tests/integrity/test_canary_migration.py::test_ledger_unchanged_by_1740 证明。
COMMIT;
