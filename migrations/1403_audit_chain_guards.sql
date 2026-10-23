-- 1403 · M16 平台基础设施 · 链形状护栏 + 幂等去重护栏
-- 规格：M16-platform-infra.md §3（audit: GENESIS → entry(1..n) → daily_root）
--       §6.3（append：读上一条 hash → 计算 → 追加）· INV-M16-01（prev_hash / hash 可重算）
--
-- 为什么还要库层护栏（应用层已经算好了）：
--   审计链的唯一硬约束是"顺序 + 前向引用"。应用层用 advisory xact lock 串行化 append
--   （见 app/audit/store.py），但只要有别的写路径（psql 手工、误接的运维脚本）绕过应用，
--   链就可能出现"跳号 / prev_hash 指向不存在的行"。此处用触发器把这类写入挡在库层：
--     · 首条必须 seq = 1 且 prev_hash = 'GENESIS'；
--     · 后续必须 seq = 上一条 seq + 1，且 prev_hash = 上一条 hash。
--   这样即使有人手写 INSERT，也无法凭空插一条"看起来合法"的条目。
--   注意：这**不**替代 verify —— 有库权限的人仍可 DISABLE TRIGGER 篡改历史，
--   verify 的逐条重算就是为了发现这种篡改（发现即断链报警，绝不修链）。
BEGIN;

CREATE OR REPLACE FUNCTION m16_audit_chain_guard() RETURNS trigger AS $$
DECLARE
  tail_seq  BIGINT;
  tail_hash TEXT;
BEGIN
  SELECT seq, hash INTO tail_seq, tail_hash
    FROM audit_log ORDER BY seq DESC LIMIT 1;

  IF tail_seq IS NULL THEN
    IF NEW.seq <> 1 THEN
      RAISE EXCEPTION 'audit_log: first entry must be seq=1 (got %)', NEW.seq
        USING ERRCODE = '23514';
    END IF;
    IF NEW.prev_hash <> 'GENESIS' THEN
      RAISE EXCEPTION 'audit_log: first entry prev_hash must be GENESIS (got %)', NEW.prev_hash
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.seq <> tail_seq + 1 THEN
    RAISE EXCEPTION 'audit_log: seq must continue at % (got %)', tail_seq + 1, NEW.seq
      USING ERRCODE = '23514';
  END IF;
  IF NEW.prev_hash IS DISTINCT FROM tail_hash THEN
    RAISE EXCEPTION 'audit_log: prev_hash does not match the previous hash (chain break at seq %)',
      NEW.seq USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_chain_guard ON audit_log;
CREATE TRIGGER audit_log_chain_guard BEFORE INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION m16_audit_chain_guard();

-- 条目时间必须是"事实时间"（下界常量）；上界不写 now()：CHECK 里不用易变函数，
-- 时钟漂移由应用层 trace 与 verify 的 pending 超时判定处理。
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_ts_ck;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_ts_ck
  CHECK (ts > '2020-01-01T00:00:00Z'::timestamptz) NOT VALID;

-- audit.appended 必须指向真实存在的审计条目（同事务先写 audit_log 再写 outbox）
CREATE OR REPLACE FUNCTION m16_outbox_audit_ref_guard() RETURNS trigger AS $$
BEGIN
  IF NEW.type = 'audit.appended'
     AND NOT EXISTS (SELECT 1 FROM audit_log WHERE entry_id::text = NEW.aggregate_id) THEN
    RAISE EXCEPTION 'm16_outbox: audit.appended must reference an existing audit entry (%)',
      NEW.aggregate_id USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS m16_outbox_audit_ref_guard ON m16_outbox;
CREATE TRIGGER m16_outbox_audit_ref_guard BEFORE INSERT ON m16_outbox
  FOR EACH ROW EXECUTE FUNCTION m16_outbox_audit_ref_guard();

COMMENT ON FUNCTION m16_audit_chain_guard() IS
  'M16 审计链库层护栏：首条 seq=1/GENESIS，后续 seq 连续且 prev_hash = 上一条 hash';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_log_chain_guard') THEN
    RAISE EXCEPTION '1403: 缺链护栏触发器 audit_log_chain_guard';
  END IF;
END
$$;

COMMIT;
