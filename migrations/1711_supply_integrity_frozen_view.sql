-- 1711 · M17 冻结只读视图（C14 下游接线）
-- 规格：M17 §6.1 / §7；01-ownership：其他模块只读视图，不 join 基表。
-- 只暴露「当前生效」的冻结（active 且未到期）；不写任何表、不碰账本。
BEGIN;

CREATE OR REPLACE VIEW v_supply_integrity_frozen AS
SELECT h.node_id,
       h.model,
       max(h.level)      AS level,
       max(h.ratio_bp)   AS ratio_bp,
       max(h.frozen_amount_micro) AS frozen_amount_micro
  FROM supplier_integrity_holds h
 WHERE h.state = 'active'
   AND (h.expires_at IS NULL OR h.expires_at > now())
 GROUP BY h.node_id, h.model;

COMMENT ON VIEW v_supply_integrity_frozen IS
  'M17 当前生效冻结（C14，只读）：调度/公告门控用；不含账本金额写入。';

COMMIT;
