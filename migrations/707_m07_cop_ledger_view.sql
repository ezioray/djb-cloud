-- 707 · M07 只读视图 v_m07_cop_ledger（COP 台账的 spec 映射，**不新建台账表**）
-- 规格：product/v4/modules/M07-reputation-cop.md §5（cop_ledger 的字段与唯一键）
--       §3 **INV-02**（只追加）· **INV-05**（每条分录带 source 与 ref_id，
--       source ∈ {usage, invite, reward, transfer_in, transfer_out, redeem, revoke}）
--       CR-3（v_m07_cop_ledger 与 M06 2103 日终入账；M07 不写 journal）
--
-- Lead 裁决（task-5）：**COP 账本不重建**。COP 唯一账本是既有 ``points_*``
-- （migrations/006_points.sql + app/points.py，DEV-0003）；本模块不建 cop_ledger（703），
-- 只提供只读映射视图，把 points_ledger / points_journal 映射成 spec 的 CopLedgerEntry 字段：
--
--   id / account_id / direction / amount / source / ref_id / status / lock_until / created_at
--
-- 映射规则（只读、不改任何 points_* 结构与数据）：
--   · 只暴露用户可见分录：排除 ``bucket='system'`` 的系统对偶腿（那是 COP 维度内的平衡腿）；
--   · 排除 ``freeze`` / ``unfreeze``：它们是风控冻结 / 到解锁的内部搬桶动作，
--     spec 的 source 枚举（INV-05）是封闭的七值、没有 hold 类来源；
--     锁定余额仍然在 GET /user/cop 的 ``locked`` 里可见，且 ``v_m07_cop_status`` 可核对差额；
--   · direction 由 delta 符号决定（credit = delta>0 / debit = delta<0），amount = |delta|；
--   · source：earn 按 reason_code 细分 usage / invite / reward；redeem → redeem；
--     transfer 按方向 → transfer_out / transfer_in；adjust 正负 → reward / revoke；void → revoke；
--   · status：兑换与转出 → spent；扣回与冲正（负向 adjust/void）→ revoked；
--     仍在锁定期内（unlock_at > now()）→ locked；其余 → available；
--   · ref_id：优先分录自带，其次 journal 的，最后退到 entry_id（保证 INV-05「必带 ref_id」）。
BEGIN;

-- 状态视图：把「当前持有量 + 风险冻结差额」放在一处，供对账与 GET /user/cop 使用。
-- 可重复执行（CREATE OR REPLACE：列集合不变）。
CREATE OR REPLACE VIEW v_m07_cop_status AS
SELECT h.account_id,
       h.usable_units                                   AS available,
       h.locked_units                                   AS locked,
       h.usable_units + h.locked_units                  AS total,
       COALESCE(earned.total_earned, 0)                 AS total_earned,
       h.usable_units + h.locked_units
         - COALESCE(ledger.net_units, 0)                AS risk_hold_delta
  FROM points_holding h
  LEFT JOIN (
        SELECT account_id, SUM(delta) AS net_units
          FROM points_ledger
         WHERE bucket <> 'system' AND action IN ('earn', 'redeem', 'adjust', 'transfer', 'void')
         GROUP BY account_id
       ) ledger ON ledger.account_id = h.account_id
  LEFT JOIN (
        SELECT account_id, SUM(delta) AS total_earned
          FROM points_ledger
         WHERE bucket <> 'system' AND delta > 0
           AND action IN ('earn', 'adjust', 'transfer', 'void')
         GROUP BY account_id
       ) earned ON earned.account_id = h.account_id;

COMMENT ON VIEW v_m07_cop_status IS
  'M07 只读：可用 / 锁定 / 累计 COP + 风险冻结差额（risk_hold_delta = freeze/unfreeze 净额）';

CREATE OR REPLACE VIEW v_m07_cop_ledger AS
SELECT l.entry_id                                            AS id,
       l.account_id                                          AS account_id,
       CASE WHEN l.delta > 0 THEN 'credit' ELSE 'debit' END   AS direction,
       abs(l.delta)                                           AS amount,
       CASE
         WHEN l.action = 'earn' THEN
              CASE WHEN l.reason_code LIKE 'usage%'  THEN 'usage'
                   WHEN l.reason_code LIKE 'invite%' THEN 'invite'
                   ELSE 'reward' END
         WHEN l.action = 'redeem'   THEN 'redeem'
         WHEN l.action = 'transfer' THEN
              CASE WHEN l.delta < 0 THEN 'transfer_out' ELSE 'transfer_in' END
         WHEN l.action = 'adjust'   THEN
              CASE WHEN l.delta > 0 THEN 'reward' ELSE 'revoke' END
         ELSE 'revoke'                                        -- void：正向冲正
       END                                                    AS source,
       COALESCE(NULLIF(l.ref_id, ''), NULLIF(j.ref_id, ''),
                l.entry_id::text)                             AS ref_id,
       CASE
         WHEN l.action = 'redeem' THEN 'spent'
         WHEN l.action = 'transfer' AND l.delta < 0 THEN 'spent'
         WHEN l.action IN ('adjust', 'void') AND l.delta < 0 THEN 'revoked'
         WHEN l.unlock_at IS NOT NULL AND l.unlock_at > now() THEN 'locked'
         ELSE 'available'
       END                                                    AS status,
       l.unlock_at                                            AS lock_until,
       l.created_at                                           AS created_at,
       -- 以下为排障用的附加列（spec additionalProperties: true 允许扩展）
       l.journal_id                                           AS journal_id,
       l.action                                               AS action,
       l.reason_code                                          AS reason_code,
       j.policy_version                                       AS policy_version
  FROM points_ledger l
  JOIN points_journal j ON j.journal_id = l.journal_id
 WHERE l.bucket <> 'system'
   AND l.action IN ('earn', 'redeem', 'adjust', 'transfer', 'void');

COMMENT ON VIEW v_m07_cop_ledger IS
  'M07 只读：points_ledger/points_journal → spec CopLedgerEntry（COP 唯一账本仍是 points_*，本视图不改数据）';
COMMENT ON COLUMN v_m07_cop_ledger.source IS
  'INV-05 七值枚举；freeze/unfreeze（风控搬桶）不在用户可见台账内，见 v_m07_cop_status.risk_hold_delta';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.views
                  WHERE table_schema = current_schema() AND table_name = 'v_m07_cop_ledger') THEN
    RAISE EXCEPTION '707: 缺视图 v_m07_cop_ledger';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.views
                  WHERE table_schema = current_schema() AND table_name = 'v_m07_cop_status') THEN
    RAISE EXCEPTION '707: 缺视图 v_m07_cop_status';
  END IF;
END
$$;

COMMIT;
