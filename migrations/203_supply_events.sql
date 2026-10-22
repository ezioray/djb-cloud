-- 203 · M02 node-supply · 状态与审核留痕（node_events，只追加）
-- 规格：M02 §3 生命周期 / §5 数据所有权（node_events：id/node_id/kind/from_state/to_state/
--       reason_code/actor/ts，保留 90 天，只追加）/ §6 关键流程 / §9 验收
--
-- 用途：状态机、审核、绑定、密钥轮换、凭据扫描拒绝的**唯一历史来源**；绑定不建独立表
-- （CR-4：绑定存 nodes 列 + node_events 历史）。
BEGIN;

CREATE TABLE IF NOT EXISTS node_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- 插入序（单调）：同一微秒内的多条留痕也要有稳定顺序（UUIDv7 同毫秒会撞随机位）
  seq           BIGSERIAL NOT NULL UNIQUE,
  node_id       TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  kind          TEXT NOT NULL,
  from_state    TEXT,
  to_state      TEXT,
  reason_code   TEXT,
  reason        TEXT,
  actor         TEXT,                                   -- 管理面 actor / 'self' / 'system'
  payload       JSONB NOT NULL DEFAULT '{}'::jsonb,     -- 只放事实（不落凭据 / 指纹明文 / PII）
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- kind 不锁白名单（T3/T4 会新增 kind），只约束形态；新增 kind 必须同步到 app/supply/events.py
  CONSTRAINT node_events_kind_chk CHECK (kind ~ '^[a-z][a-z0-9_]*$'),
  CONSTRAINT node_events_from_chk
    CHECK (from_state IS NULL OR from_state IN ('pending', 'active', 'frozen', 'retired')),
  CONSTRAINT node_events_to_chk
    CHECK (to_state IS NULL OR to_state IN ('pending', 'active', 'frozen', 'retired')),
  CONSTRAINT node_events_reason_chk CHECK (reason IS NULL OR char_length(reason) <= 500),
  CONSTRAINT node_events_payload_ck CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS node_events_node_ts_idx
  ON node_events (node_id, ts DESC, seq DESC);
CREATE INDEX IF NOT EXISTS node_events_kind_idx
  ON node_events (kind, ts DESC);

-- 只追加（00-conventions §7.5 / §8.5：审计与事件表只追加，不删不改）
CREATE OR REPLACE FUNCTION m02_node_events_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'node_events 只追加：禁止 %（M02 §5）', TG_OP;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS node_events_append_only_trg ON node_events;
CREATE TRIGGER node_events_append_only_trg
  BEFORE UPDATE OR DELETE ON node_events
  FOR EACH ROW EXECUTE FUNCTION m02_node_events_append_only();

COMMIT;
