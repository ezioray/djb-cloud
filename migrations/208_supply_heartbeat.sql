-- 208 · M02 node-supply · 心跳与公告（nodes 心跳列 + 跨模块快照视图）
-- 规格：M02 §3「一层权威 + 一层派生」/ §4.3 内部 job / §5 数据所有权（nodes / capacity_announcements）
--       §6.2 心跳与公告 / §8.1 配置键（heartbeat_interval_s / stale_after_s / announcement_ttl_s）
--       INV-07（公告时序与过期过滤）· 00-conventions §7.4（跨模块只读视图 v_<module>_<object>）
--
-- 本迁移只加列与视图，不改既有定义：
--   1) nodes.heartbeat_seq：公告 seq 的**唯一分配点**（同一节点内单调，INV-07）；
--   2) nodes.offline_announced_at：离线事件去重标记（派生 offline 只能「每段离线发一次」event）；
--   3) 两个**只读视图**给 M04（01-ownership：M02 拥有 nodes / capacity_announcements）：
--      v_supply_node_snapshot   节点身份与版本（不含任何凭据 / 指纹明细）
--      v_supply_capacity_latest 每个 (node_id, kind, model) 的最新一条公告，且**已过滤过期与 0 容量**
BEGIN;

-- ---------------------------------------------------------------- 心跳与离线判定
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS heartbeat_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS offline_announced_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_heartbeat_seq_chk') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_heartbeat_seq_chk
      CHECK (heartbeat_seq >= 0) NOT VALID;
  END IF;
END
$$;

-- 心跳超时扫描（§4.3 内部 job）：active + 已上报过 + 尚未宣告离线
CREATE INDEX IF NOT EXISTS nodes_offline_scan_idx
  ON nodes (last_seen_at)
  WHERE state = 'active' AND offline_announced_at IS NULL;

-- ---------------------------------------------------------------- 只读视图（M04 用；M02 唯一写者）
CREATE OR REPLACE VIEW v_supply_node_snapshot AS
  SELECT id            AS node_id,
         account_id,
         tenant_id,
         platform,
         state         AS lifecycle_state,
         region,
         protocol_version,
         policy_version,
         last_seen_at,
         bound_account_id,
         revoked_at,
         heartbeat_seq
    FROM nodes;

-- 最新一条公告：同一 (node_id, kind, model) 以 seq 最大为准（INV-07）；
-- now > expires_at 与 max_qps = 0 的行**不进视图**（M04 候选集不得包含它们）。
CREATE OR REPLACE VIEW v_supply_capacity_latest AS
  SELECT DISTINCT ON (a.node_id, item->>'kind', item->>'model')
         a.node_id,
         a.id            AS announcement_id,
         a.seq,
         a.announced_at,
         a.expires_at,
         item->>'kind'          AS kind,
         item->>'access'        AS access,
         item->>'model'         AS model,
         (item->>'max_qps')::numeric      AS max_qps,
         item->>'ask_price'     AS ask_price,
         item->>'unit'          AS unit,
         item->>'resource_level' AS resource_level,
         item->>'gpu'           AS gpu,
         (item->>'ram_gb')::numeric       AS ram_gb
    FROM capacity_announcements a
    JOIN nodes n ON n.id = a.node_id AND n.state = 'active'   -- 冻结 / 清退 / 未准入不进候选集
    CROSS JOIN LATERAL jsonb_array_elements(a.capabilities) AS item
   WHERE a.expires_at > now()
     -- 形态守卫：脏数据（非数字）不应让视图整表报错；域层已在写入前校验
     AND COALESCE(item->>'max_qps', '') ~ '^[0-9]+(\.[0-9]+)?$'
     AND (item->>'max_qps')::numeric > 0
   ORDER BY a.node_id, item->>'kind', item->>'model', a.seq DESC;

COMMENT ON VIEW v_supply_capacity_latest IS
  'M02 → M04 只读快照：每 (node_id, kind, model) 取 seq 最大一条，已过滤过期与 0 容量（INV-07）';
COMMENT ON VIEW v_supply_node_snapshot IS
  'M02 → M04 只读快照：节点身份 / 版本 / 在线判定输入（last_seen_at），不含凭据与指纹';

COMMIT;
