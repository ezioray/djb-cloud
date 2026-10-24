-- 1721 · M17 证明只读视图（C12 下游门控）
-- 只暴露「当前生效、等级 ≥ L3」的证明；调度/公告按此门控。不写表、不碰账本。
BEGIN;

CREATE OR REPLACE VIEW v_supply_model_attested AS
SELECT DISTINCT ON (a.node_id, a.model)
       a.node_id,
       a.model,
       a.level,
       a.tokenizer_version,
       a.verified_at,
       a.expires_at
  FROM model_attestations a
 WHERE a.state = 'active'
   AND a.level IN ('L3', 'L4', 'L5')
   AND (a.expires_at IS NULL OR a.expires_at > now())
 ORDER BY a.node_id, a.model,
          CASE a.level WHEN 'L5' THEN 5 WHEN 'L4' THEN 4 ELSE 3 END DESC,
          a.verified_at DESC NULLS LAST;

COMMENT ON VIEW v_supply_model_attested IS
  'M17 当前生效 L3+ 证明（C12，只读）：调度/公告门控用；不含账本写入。';

COMMIT;
