-- 1720 · M17 模型身份证明（C12）：三表 = 证明 / 挑战 / 事件
-- 规格：M17-supply-integrity.md §5.1（L0–L5 证据等级）· §5.3（tokenizer 校验）· §5.7（状态机与 TTL）
--       · §7 数据模型（迁移段 1700–1799）· §8.1（客户端上报字段）/ §8.2（挑战帧，本卡不接线）
--
-- 原则：
--   1) **服务端自己验证**：L3 只由服务端用自己注入的 tokenizer 计数与 usage 比对得出，
--      不采信客户端自报的 tokenizer_match；
--   2) **挑战一次性**：attestation_challenges 只允许 issued → consumed / expired，
--      consumed / expired 为终态（触发器守住，重放 100% 拒绝）；
--   3) **合成 prompt**：challenge.prompt 只放合成的探针文本（不含用户正文），长度受限；
--   4) **只升不降**：model_attestations.level 只允许升（触发器按 L0–L5 序比较），
--      过期 / 暂停走 state，不回头改等级；
--   5) **不碰账本**：本迁移不创建、不修改任何 ledger_* / account_balances / loss_pool 对象，
--      也不新增账本科目或分录；diff=0 由 tests/integrity/test_attest_migration.py 证明；
--   6) 事件只追加：attestation_events 禁止 UPDATE / DELETE / TRUNCATE（证据留痕）。
BEGIN;

-- ───────────────────────────────────────────────────────── model_attestations
CREATE TABLE IF NOT EXISTS model_attestations (
  id                UUID PRIMARY KEY,                      -- UUIDv7（应用生成）
  node_id           TEXT NOT NULL,                         -- 供应节点（M02）
  upstream_id       TEXT,                                  -- 可选：具体上游（relay / A1 / A2 / B）
  model             TEXT NOT NULL,                         -- canonical model slug
  level             TEXT NOT NULL DEFAULT 'L0',            -- §5.1 L0–L5
  state             TEXT NOT NULL DEFAULT 'active',        -- active / expired / suspended
  source            TEXT NOT NULL,                         -- server_challenge / client_report / provider
  tokenizer_version TEXT,                                  -- 服务端 tokenizer 版本（可空：L1/L2 未用到）
  evidence_ref      TEXT NOT NULL,                         -- 证据引用（challenge:<id> / case id / 收据 id）
  verified_at       TIMESTAMPTZ,                           -- 最近一次定级时间（L0 为空）
  expires_at        TIMESTAMPTZ,                           -- TTL 到期（L1/L2 24h、L3 7d；L0 为空）
  created_at        TIMESTAMPTZ NOT NULL,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT model_attestations_level_ck CHECK
    (level IN ('L0', 'L1', 'L2', 'L3', 'L4', 'L5')),
  CONSTRAINT model_attestations_state_ck CHECK
    (state IN ('active', 'expired', 'suspended')),
  CONSTRAINT model_attestations_source_ck CHECK
    (source IN ('server_challenge', 'client_report', 'provider')),
  -- L0 = 仅登记：没有 verified/expires；L1+ 必须有（TTL 由 service 写）
  CONSTRAINT model_attestations_level_fields_ck CHECK (
    (level = 'L0' AND verified_at IS NULL AND expires_at IS NULL)
    OR (level <> 'L0' AND verified_at IS NOT NULL AND expires_at IS NOT NULL)),
  -- 过期 / 暂停的行不应该再带"未来到期时间"造成误读：state<>active 时允许保留原值，
  -- 但 active 行必须有 expires_at（L0 除外）——由上面的 level_fields 覆盖。
  CONSTRAINT model_attestations_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT model_attestations_model_ck CHECK (char_length(model) BETWEEN 1 AND 128),
  CONSTRAINT model_attestations_evidence_ck CHECK (char_length(evidence_ref) BETWEEN 1 AND 128),
  CONSTRAINT model_attestations_tokenizer_ck CHECK
    (tokenizer_version IS NULL OR char_length(tokenizer_version) BETWEEN 1 AND 64)
);

-- 同一 (node_id, upstream_id, model) 只保留 1 条 active。
-- NULL upstream_id 在普通唯一索引里互不相等，因此用 COALESCE 表达式索引。
CREATE UNIQUE INDEX IF NOT EXISTS uq_attestations_active
  ON model_attestations (node_id, COALESCE(upstream_id, ''), model)
  WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_attestations_node
  ON model_attestations (node_id, model, state);
CREATE INDEX IF NOT EXISTS idx_attestations_level
  ON model_attestations (level, state, verified_at DESC);
CREATE INDEX IF NOT EXISTS idx_attestations_expiry
  ON model_attestations (expires_at) WHERE state = 'active' AND expires_at IS NOT NULL;

COMMENT ON TABLE model_attestations IS
  'M17 §5.1 模型身份证明（C12）：level 只升不降；TTL L1/L2 24h、L3 7d；'
  '同 (node_id, upstream_id, model) 仅 1 条 active；不写账本';

-- ───────────────────────────────────────────────────────── attestation_challenges
CREATE TABLE IF NOT EXISTS attestation_challenges (
  id            UUID PRIMARY KEY,                          -- UUIDv7（应用生成）
  node_id       TEXT NOT NULL,
  upstream_id   TEXT,
  model         TEXT NOT NULL,
  prompt        TEXT NOT NULL,                             -- **合成探针**（不含用户正文）
  prompt_tokens INTEGER NOT NULL,                          -- 服务端 tokenizer 计数
  nonce         TEXT NOT NULL UNIQUE,                      -- 随机 32 hex；一次性
  state         TEXT NOT NULL DEFAULT 'issued',            -- issued / consumed / expired
  expires_at    TIMESTAMPTZ NOT NULL,                      -- 签发 + 5 min
  created_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ,
  CONSTRAINT attestation_challenges_state_ck CHECK
    (state IN ('issued', 'consumed', 'expired')),
  CONSTRAINT attestation_challenges_prompt_ck CHECK
    (char_length(prompt) BETWEEN 32 AND 2048),
  CONSTRAINT attestation_challenges_tokens_ck CHECK (prompt_tokens BETWEEN 1 AND 100000),
  CONSTRAINT attestation_challenges_nonce_ck CHECK (nonce ~ '^[0-9a-f]{16,64}$'),
  CONSTRAINT attestation_challenges_ttl_ck CHECK (expires_at > created_at),
  CONSTRAINT attestation_challenges_consumed_ck CHECK
    (state <> 'consumed' OR consumed_at IS NOT NULL),
  CONSTRAINT attestation_challenges_not_consumed_ck CHECK
    (state = 'consumed' OR consumed_at IS NULL),
  CONSTRAINT attestation_challenges_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT attestation_challenges_model_ck CHECK (char_length(model) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_challenges_node
  ON attestation_challenges (node_id, model, state, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_challenges_expiry
  ON attestation_challenges (expires_at) WHERE state = 'issued';

COMMENT ON TABLE attestation_challenges IS
  'M17 §5.1 挑战池（C12）：合成 prompt + 一次性 nonce，TTL 5 min；'
  'issued → consumed / expired，终态不可回写（触发器守）；无用户正文';

-- ───────────────────────────────────────────────────────── attestation_events
CREATE TABLE IF NOT EXISTS attestation_events (
  event_id       UUID PRIMARY KEY,                         -- UUIDv7
  attestation_id UUID REFERENCES model_attestations (id),  -- 定级记录（challenge_issued 时为空）
  challenge_id   UUID REFERENCES attestation_challenges (id),
  node_id        TEXT NOT NULL,
  model          TEXT NOT NULL,
  event          TEXT NOT NULL,
  level          TEXT,                                     -- 事件发生后的等级（可空）
  detail         JSONB NOT NULL DEFAULT '{}'::jsonb,       -- 只放计数 / 差异 / 耗时 / 错误类
  actor          TEXT NOT NULL,                            -- node:<id> / system:ttl / admin:<id>
  created_at     TIMESTAMPTZ NOT NULL,
  CONSTRAINT attestation_events_event_ck CHECK (event IN
    ('challenge_issued', 'evidence_submitted', 'tokenizer_mismatch', 'failed',
     'level_up', 'expired', 'suspended')),
  CONSTRAINT attestation_events_level_ck CHECK
    (level IS NULL OR level IN ('L0', 'L1', 'L2', 'L3', 'L4', 'L5')),
  -- 证据只放元数据：不得出现正文 / 凭据 / 阈值类键（DB 兜底）
  CONSTRAINT attestation_events_detail_ck CHECK (
    NOT (detail ?| ARRAY['prompt', 'response', 'messages', 'content', 'body', 'text',
                         'token', 'secret', 'password', 'api_key', 'threshold', 'weight'])),
  CONSTRAINT attestation_events_actor_ck CHECK (char_length(actor) BETWEEN 1 AND 128),
  CONSTRAINT attestation_events_node_ck CHECK (char_length(node_id) BETWEEN 1 AND 128),
  CONSTRAINT attestation_events_model_ck CHECK (char_length(model) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_attestation_events_attestation
  ON attestation_events (attestation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attestation_events_challenge
  ON attestation_events (challenge_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attestation_events_node
  ON attestation_events (node_id, model, created_at DESC);

COMMENT ON TABLE attestation_events IS
  'M17 §5.2 证明事件流水（只追加）：challenge_issued / evidence_submitted / tokenizer_mismatch /'
  ' failed / level_up / expired / suspended；detail 只放计数与差异，不落正文';

-- ───────────────────────────────────────────────────────── 护栏函数
CREATE OR REPLACE FUNCTION m17_attest_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% 只追加：禁止 TRUNCATE', TG_TABLE_NAME USING ERRCODE = '42501';
END $$;

-- 证明记录：身份不可变 / 等级只升不降 / 终态不可回写 / 禁止 DELETE
CREATE OR REPLACE FUNCTION m17_attestation_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  old_rank INTEGER;
  new_rank INTEGER;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'model_attestations 禁止 DELETE（证明历史保留可查）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.upstream_id IS DISTINCT FROM OLD.upstream_id
     OR NEW.model IS DISTINCT FROM OLD.model
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'model_attestations 身份字段不可变（id/node/upstream/model/source/created_at）'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.state <> 'active' AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION '证明处于终态 %：不可再迁移', OLD.state USING ERRCODE = '42501';
  END IF;
  IF NEW.level IS DISTINCT FROM OLD.level THEN
    old_rank := CASE OLD.level WHEN 'L0' THEN 0 WHEN 'L1' THEN 1 WHEN 'L2' THEN 2
                               WHEN 'L3' THEN 3 WHEN 'L4' THEN 4 ELSE 5 END;
    new_rank := CASE NEW.level WHEN 'L0' THEN 0 WHEN 'L1' THEN 1 WHEN 'L2' THEN 2
                               WHEN 'L3' THEN 3 WHEN 'L4' THEN 4 ELSE 5 END;
    IF new_rank <= old_rank THEN
      RAISE EXCEPTION '证明等级只升不降（% → %）', OLD.level, NEW.level USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS model_attestations_guard ON model_attestations;
CREATE TRIGGER model_attestations_guard BEFORE UPDATE OR DELETE
  ON model_attestations FOR EACH ROW EXECUTE FUNCTION m17_attestation_guard();

DROP TRIGGER IF EXISTS model_attestations_no_truncate ON model_attestations;
CREATE TRIGGER model_attestations_no_truncate BEFORE TRUNCATE
  ON model_attestations FOR EACH STATEMENT EXECUTE FUNCTION m17_attest_forbid_truncate();

-- 挑战：内容不可变 / 一次性消费 / 终态不可回写 / 禁止 DELETE
CREATE OR REPLACE FUNCTION m17_challenge_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'attestation_challenges 禁止 DELETE（挑战历史保留可查）'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.upstream_id IS DISTINCT FROM OLD.upstream_id
     OR NEW.model IS DISTINCT FROM OLD.model
     OR NEW.prompt IS DISTINCT FROM OLD.prompt
     OR NEW.prompt_tokens IS DISTINCT FROM OLD.prompt_tokens
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'attestation_challenges 内容不可变（prompt / nonce / 计数 / TTL）'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.state <> 'issued' THEN
    RAISE EXCEPTION '挑战已处于终态 %：不可再消费（重放拒绝）', OLD.state
      USING ERRCODE = '42501';
  END IF;
  IF NEW.state NOT IN ('consumed', 'expired') THEN
    RAISE EXCEPTION '挑战状态只能 issued → consumed / expired（当前 → %）', NEW.state
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS attestation_challenges_guard ON attestation_challenges;
CREATE TRIGGER attestation_challenges_guard BEFORE UPDATE OR DELETE
  ON attestation_challenges FOR EACH ROW EXECUTE FUNCTION m17_challenge_guard();

DROP TRIGGER IF EXISTS attestation_challenges_no_truncate ON attestation_challenges;
CREATE TRIGGER attestation_challenges_no_truncate BEFORE TRUNCATE
  ON attestation_challenges FOR EACH STATEMENT EXECUTE FUNCTION m17_attest_forbid_truncate();

-- 事件：只追加
CREATE OR REPLACE FUNCTION m17_attest_event_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'attestation_events 只追加：禁止 %', TG_OP USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS attestation_events_guard ON attestation_events;
CREATE TRIGGER attestation_events_guard BEFORE UPDATE OR DELETE
  ON attestation_events FOR EACH ROW EXECUTE FUNCTION m17_attest_event_guard();

DROP TRIGGER IF EXISTS attestation_events_no_truncate ON attestation_events;
CREATE TRIGGER attestation_events_no_truncate BEFORE TRUNCATE
  ON attestation_events FOR EACH STATEMENT EXECUTE FUNCTION m17_attest_forbid_truncate();

-- ───────────────────────────────────────────────────────── 迁移自检（不碰账本）
-- 本迁移不创建、不修改任何账本对象（journal_entry / journal_line / ledger_entry /
-- account_balances / merkle_commitments / m06_outbox / loss_pool_entries 都属 M05/M06/M09）。
-- 「迁移前后账本结构指纹 + 真实行摘要 diff = 0」由
-- tests/integrity/test_attest_migration.py::test_ledger_unchanged_by_1720 证明。
COMMIT;
