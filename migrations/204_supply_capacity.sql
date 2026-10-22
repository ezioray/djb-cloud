-- 204 · M02 node-supply · 容量公告快照（capacity_announcements）
-- 规格：M02 §3 CapacityAnnouncement / §5 数据所有权（原文 30 天 / 聚合 90 天）/
--       §6.2 心跳与公告 / INV-07（同一 (node_id, model, kind) 以 seq 最大一条为准；
--       now > expires_at 不得进入 M04 候选集）
--
-- 时序数据：只追加；seq 由服务端按节点单调分配（INV-07），客户端不能回退覆盖历史。
BEGIN;

CREATE TABLE IF NOT EXISTS capacity_announcements (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- announcement_id（全局唯一）
  node_id        TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  seq            BIGINT NOT NULL,
  announced_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at     TIMESTAMPTZ NOT NULL,
  capabilities   JSONB NOT NULL DEFAULT '[]'::jsonb,

  CONSTRAINT capacity_announcements_seq_chk CHECK (seq > 0),
  CONSTRAINT capacity_announcements_expiry_chk CHECK (expires_at > announced_at),
  CONSTRAINT capacity_announcements_caps_ck
    CHECK (jsonb_typeof(capabilities) = 'array'
           AND jsonb_array_length(capabilities) <= 200),        -- §8.2 公告单批上限 200
  CONSTRAINT capacity_announcements_seq_uq UNIQUE (node_id, seq)
);

CREATE INDEX IF NOT EXISTS capacity_announcements_node_seq_idx
  ON capacity_announcements (node_id, seq DESC);
CREATE INDEX IF NOT EXISTS capacity_announcements_expiry_idx
  ON capacity_announcements (expires_at);

-- 快照只追加：历史进快照后不得改（M02 §3「历史进快照」）
CREATE OR REPLACE FUNCTION m02_capacity_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'capacity_announcements 只追加：禁止 %（M02 §5）', TG_OP;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS capacity_announcements_append_only_trg ON capacity_announcements;
CREATE TRIGGER capacity_announcements_append_only_trg
  BEFORE UPDATE OR DELETE ON capacity_announcements
  FOR EACH ROW EXECUTE FUNCTION m02_capacity_append_only();

COMMIT;
