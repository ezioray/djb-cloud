-- 209 · M02 node-supply · 已验证上游只读视图（v_supply_upstream_verified）
-- 规格：M02 §3 NodeUpstream（state / verified_at）/ §6.3 上游申报与本地体检回执
--       01-ownership §2（跨模块只读依赖）/ 00-conventions §7.4（跨模块只读视图 v_<module>_<object>）
--
-- 用途（C9b「容量与调度只认已验证上游」）：M04 的候选集必须先证明
-- 「该 (node_id, access, model) 来自一条 state=verified 的上游」，而不是相信客户端在心跳里
-- 公告的容量数字。视图把 node_upstreams.models 数组展开成「一行一个模型」，只暴露
-- (node_id, access_type, model, verified_at) 四列——不含 base_url / credential_handle。
--
-- 边界（INV-04 / H1）：
--   * 本迁移**只加只读视图**：不新增表、不新增列、不改既有对象、不碰 ledger；
--   * 视图是派生层（M02 §3「一层权威 + 一层派生」），唯一写者仍是 node_upstreams；
--   * 「多少秒算新鲜」是运营参数，不固化进 DDL：视图只暴露 verified_at 真值，
--     由读取方按 probe_freshness（默认 900 s，见 M02/M04 facts）过滤。
-- 回滚（app/supply/migrate.py 的 DOWN_SQL 持有，逆序执行且可重复）：
--   DROP VIEW IF EXISTS v_supply_upstream_verified
-- 回滚不放在 migrations/ 下：CI 会把 *.sql 全部当正向迁移执行。
BEGIN;

CREATE OR REPLACE VIEW v_supply_upstream_verified AS
  SELECT u.node_id,
         u.access_type,
         model,
         u.verified_at
    FROM node_upstreams u
    CROSS JOIN LATERAL jsonb_array_elements_text(u.models) AS model
   WHERE u.state = 'verified';

COMMENT ON VIEW v_supply_upstream_verified IS
  'M02 → M04 只读视图：state=verified 的上游 × 其 models（一行一个模型）；新鲜度由读取方按 verified_at 过滤';

COMMIT;
