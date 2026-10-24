-- 1730 · M17 可验证随机抽检（C14b）：epoch 承诺 / 抽签 / 事件
-- 规格：M17-supply-integrity.md §5.10（可验证随机抽检）/ §5.11（抽检类型）/ §6.1（作弊升级）· §7 数据模型
--
-- 原则：
--   1) **先承诺后揭晓**：open 只写 ``seed_commit = sha256(seed)``；**seed 本体不落库**
--      （没有 seed 列、也没有任何明文列），揭示时才写 ``seed_reveal`` 并置 state=revealed；
--   2) **可复算**：给定 (seed, contributions, draw_count) 任何人可重算抽签；
--      ``verify_epoch`` 用库里的承诺与快照重算并比对；
--   3) **不可挑拣**：抽签在 reveal 时按 HMAC 确定性排序 + 贡献权重无放回抽样，
--      平台不能在看到结果后改抽样框（contributions 快照不可变）；
--   4) **执行复用 C12**：每个 draw 关联一条 attestation_challenges（FK），
--      结果由 ``attest.submit_evidence`` 消费后回填；本表不复制 tokenizer 逻辑；
--   5) **不碰账本**：本迁移不创建/修改任何 ledger_* / account_balances / loss_pool 对象；
--   6) 事件只追加：sampling_events 禁止 UPDATE / DELETE / TRUNCATE。
BEGIN;

-- ───────────────────────────────────────────────────────── sampling_epochs
CREATE TABLE IF NOT EXISTS sampling_epochs (
  id             UUID PRIMARY KEY,                        -- UUIDv7（应用生成）
  epoch_no       BIGINT NOT NULL UNIQUE,                  -- 轮次号（唯一递增，业务侧保证连续）
  seed_commit    TEXT NOT NULL,                           -- sha256(seed) 十六进制（承诺）
  seed_reveal    TEXT,                                    -- 揭示后的 seed（十六进制）；揭晓前为空
  contributions  JSONB NOT NULL,                          -- 抽样框快照：[{node_id, model, weight}]
  state          TEXT NOT NULL DEFAULT 'committed',       -- committed / revealed / expired
  committed_at   TIMESTAMPTZ NOT NULL,
  revealed_at    TIMESTAMPTZ,
  draw_count     INTEGER NOT NULL,                        -- 本轮计划抽检数
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT sampling_epochs_no_ck CHECK (epoch_no >= 1),
  CONSTRAINT sampling_epochs_state_ck CHECK
    (state IN ('committed', 'revealed', 'expired')),
  CONSTRAINT sampling_epochs_commit_ck CHECK (seed_commit ~ '^[0-9a-f]{64}$'),
  CONSTRAINT sampling_epochs_reveal_ck CHECK
    (seed_reveal IS NULL OR seed_reveal ~ '^[0-9a-f]{64}$'),
  -- 承诺阶段不得带 seed / revealed_at；揭示阶段必须两者齐全
  CONSTRAINT sampling_epochs_committed_fields_ck CHECK (
    state <> 'committed' OR (seed_reveal IS NULL AND revealed_at IS NULL)),
  CONSTRAINT sampling_epochs_revealed_fields_ck CHECK (
    state <> 'revealed' OR (seed_reveal IS NOT NULL AND revealed_at IS NOT NULL)),
  CONSTRAINT sampling_epochs_draw_count_ck CHECK (draw_count BETWEEN 0 AND 1000),
  CONSTRAINT sampling_epochs_contributions_ck CHECK (
    jsonb_typeof(contributions) = 'array' AND jsonb_array_length(contributions) <= 10000)
);

CREATE INDEX IF NOT EXISTS idx_sampling_epochs_state
  ON sampling_epochs (state, committed_at DESC);

COMMENT ON TABLE sampling_epochs IS
  'M17 §5.10 抽检轮次（C14b）：commit-reveal；seed 只在 reveal 时落 seed_reveal，'
  '之前库中只有 sha256 承诺；contributions 为不可变抽样框快照';

-- ───────────────────────────────────────────────────────── sampling_draws
CREATE TABLE IF NOT EXISTS sampling_draws (
  id           UUID PRIMARY KEY,                          -- UUIDv7
  epoch_id     UUID NOT NULL REFERENCES sampling_epochs (id),
  node_id      TEXT NOT NULL,
  model        TEXT NOT NULL,
  weight       BIGINT NOT NULL,                           -- 贡献权重（来自 contributions 快照）
  rank         INTEGER NOT NULL,                          -- 本轮抽签中的确定性位次（1..k）
  challenge_id UUID REFERENCES attestation_challenges (id), -- 复用 C12 挑战（执行通道）
  status       TEXT NOT NULL DEFAULT 'pending',           -- pending / passed / failed / missed
  level        TEXT,                                      -- C12 定级结果（L0–L5）
  detail       JSONB NOT NULL DEFAULT '{}'::jsonb,        -- 计数 / 差异 / 粗粒度原因（不含正文）
  created_at   TIMESTAMPTZ NOT NULL,
  resolved_at  TIMESTAMPTZ,
  CONSTRAINT sampling_draws_status_ck CHECK
    (status IN ('pending', 'passed', 'failed', 'missed')),
  CONSTRAINT sampling_draws_level_ck CHECK
    (level IS NULL OR level IN ('L0', 'L1', 'L2', 'L3', 'L4', 'L5')),
  CONSTRAINT sampling_draws_weight_ck CHECK (weight >= 0),
  CONSTRAINT sampling_draws_rank_ck CHECK (rank >= 1),
  CONSTRAINT sampling_draws_pending_ck CHECK
    (status <> 'pending' OR resolved_at IS NULL),
  CONSTRAINT sampling_draws_resolved_ck CHECK
    (status = 'pending' OR resolved_at IS NOT NULL),
  CONSTRAINT sampling_draws_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT sampling_draws_model_ck CHECK (char_length(model) BETWEEN 1 AND 128),
  -- detail 只放元数据：不得出现正文 / 凭据 / 阈值类键
  CONSTRAINT sampling_draws_detail_ck CHECK (
    NOT (detail ?| ARRAY['prompt', 'response', 'messages', 'content', 'body', 'text',
                         'token', 'secret', 'password', 'api_key', 'threshold', 'weight_loss']))
);

-- 同一轮次里同一 (node, model) 只抽一次（无放回）
CREATE UNIQUE INDEX IF NOT EXISTS uq_sampling_draws_epoch_node_model
  ON sampling_draws (epoch_id, node_id, model);
CREATE INDEX IF NOT EXISTS idx_sampling_draws_epoch
  ON sampling_draws (epoch_id, status, rank);
CREATE INDEX IF NOT EXISTS idx_sampling_draws_node
  ON sampling_draws (node_id, model, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sampling_draws_challenge
  ON sampling_draws (challenge_id);

COMMENT ON TABLE sampling_draws IS
  'M17 §5.10 抽检命中（C14b）：同一 epoch 同一 (node,model) 唯一（无放回）；'
  'challenge_id 关联 C12 挑战；结果由 attest.submit_evidence 消费后回填';

-- ───────────────────────────────────────────────────────── sampling_events
CREATE TABLE IF NOT EXISTS sampling_events (
  event_id   UUID PRIMARY KEY,                           -- UUIDv7
  epoch_id   UUID REFERENCES sampling_epochs (id),
  draw_id    UUID REFERENCES sampling_draws (id),
  event      TEXT NOT NULL,                              -- committed/revealed/drawn/passed/failed/missed
  detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
  actor      TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT sampling_events_event_ck CHECK (event IN
    ('committed', 'revealed', 'drawn', 'passed', 'failed', 'missed')),
  CONSTRAINT sampling_events_actor_ck CHECK (char_length(actor) BETWEEN 1 AND 128),
  CONSTRAINT sampling_events_detail_ck CHECK (
    NOT (detail ?| ARRAY['prompt', 'response', 'messages', 'content', 'body', 'text',
                         'token', 'secret', 'password', 'api_key', 'seed', 'threshold']))
);

CREATE INDEX IF NOT EXISTS idx_sampling_events_epoch
  ON sampling_events (epoch_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sampling_events_draw
  ON sampling_events (draw_id, created_at DESC);

COMMENT ON TABLE sampling_events IS
  'M17 §5.10 抽检事件流水（只追加）：committed / revealed / drawn / passed / failed / missed；'
  'detail 不含 seed、正文、凭据（DB 黑名单兜底）';

-- ───────────────────────────────────────────────────────── 护栏函数
CREATE OR REPLACE FUNCTION m17_sampling_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% 只追加：禁止 TRUNCATE', TG_TABLE_NAME USING ERRCODE = '42501';
END $$;

-- epoch：承诺与抽样框不可变 / seed 只揭示一次 / 状态单向
CREATE OR REPLACE FUNCTION m17_sampling_epoch_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'sampling_epochs 禁止 DELETE（轮次与承诺保留可复算）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.epoch_no IS DISTINCT FROM OLD.epoch_no
     OR NEW.seed_commit IS DISTINCT FROM OLD.seed_commit
     OR NEW.contributions IS DISTINCT FROM OLD.contributions
     OR NEW.draw_count IS DISTINCT FROM OLD.draw_count
     OR NEW.committed_at IS DISTINCT FROM OLD.committed_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'sampling_epochs 承诺字段不可变（commit / contributions / draw_count）'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.seed_reveal IS NOT NULL AND NEW.seed_reveal IS DISTINCT FROM OLD.seed_reveal THEN
    RAISE EXCEPTION 'seed 已揭示：不可改写（承诺不可翻案）' USING ERRCODE = '42501';
  END IF;
  IF OLD.state <> 'committed' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION '轮次处于终态 %：不可再迁移', OLD.state USING ERRCODE = '42501';
  END IF;
  IF OLD.state = 'committed' AND NEW.state NOT IN ('committed', 'revealed', 'expired') THEN
    RAISE EXCEPTION '轮次状态只能 committed → revealed / expired（当前 → %）', NEW.state
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS sampling_epochs_guard ON sampling_epochs;
CREATE TRIGGER sampling_epochs_guard BEFORE UPDATE OR DELETE
  ON sampling_epochs FOR EACH ROW EXECUTE FUNCTION m17_sampling_epoch_guard();

DROP TRIGGER IF EXISTS sampling_epochs_no_truncate ON sampling_epochs;
CREATE TRIGGER sampling_epochs_no_truncate BEFORE TRUNCATE
  ON sampling_epochs FOR EACH STATEMENT EXECUTE FUNCTION m17_sampling_forbid_truncate();

-- draw：身份与抽签位次不可变 / 状态单向（pending → passed|failed|missed）/ 禁止删除
CREATE OR REPLACE FUNCTION m17_sampling_draw_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'sampling_draws 禁止 DELETE（抽检记录保留可复算）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.epoch_id IS DISTINCT FROM OLD.epoch_id
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.model IS DISTINCT FROM OLD.model
     OR NEW.weight IS DISTINCT FROM OLD.weight
     OR NEW.rank IS DISTINCT FROM OLD.rank
     OR NEW.challenge_id IS DISTINCT FROM OLD.challenge_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'sampling_draws 身份 / 抽签字段不可变（node/model/weight/rank/challenge）'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'pending' AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION '抽检结果已确定（%）：不可再改', OLD.status USING ERRCODE = '42501';
  END IF;
  IF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'passed', 'failed', 'missed') THEN
    RAISE EXCEPTION '抽检状态只能 pending → passed / failed / missed（当前 → %）', NEW.status
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS sampling_draws_guard ON sampling_draws;
CREATE TRIGGER sampling_draws_guard BEFORE UPDATE OR DELETE
  ON sampling_draws FOR EACH ROW EXECUTE FUNCTION m17_sampling_draw_guard();

DROP TRIGGER IF EXISTS sampling_draws_no_truncate ON sampling_draws;
CREATE TRIGGER sampling_draws_no_truncate BEFORE TRUNCATE
  ON sampling_draws FOR EACH STATEMENT EXECUTE FUNCTION m17_sampling_forbid_truncate();

-- 事件：只追加
CREATE OR REPLACE FUNCTION m17_sampling_event_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'sampling_events 只追加：禁止 %', TG_OP USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS sampling_events_guard ON sampling_events;
CREATE TRIGGER sampling_events_guard BEFORE UPDATE OR DELETE
  ON sampling_events FOR EACH ROW EXECUTE FUNCTION m17_sampling_event_guard();

DROP TRIGGER IF EXISTS sampling_events_no_truncate ON sampling_events;
CREATE TRIGGER sampling_events_no_truncate BEFORE TRUNCATE
  ON sampling_events FOR EACH STATEMENT EXECUTE FUNCTION m17_sampling_forbid_truncate();

-- ───────────────────────────────────────────────────────── 迁移自检（不碰账本）
-- 本迁移不创建、不修改任何账本对象（journal_entry / journal_line / ledger_entry /
-- account_balances / merkle_commitments / m06_outbox / loss_pool_entries 都属 M05/M06/M09）。
-- 「迁移前后账本结构指纹 + 真实行摘要 diff = 0」由
-- tests/integrity/test_sampling_migration.py::test_ledger_unchanged_by_1730 证明。
COMMIT;
