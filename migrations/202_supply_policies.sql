-- 202 · M02 node-supply · 策略版本（node_policies）
-- 规格：M02 §3 NodePolicy / §5 数据所有权（保留 12 个月）/ §6.4 策略下发 / INV-06
--       （policy_version 单调递增、digest = sha256(canonical_json) 与内容一致）
--
-- 不可变性：每版本签发后**内容不可变**（M02 §3「每版本不可变；历史只读」）。库层用触发器兜底：
--   * INSERT / DELETE：DELETE 永远拒绝（只追加）；
--   * UPDATE：只允许 ``status: active → superseded``，且其余列必须逐字节不变。
-- 版本单调与 digest 复算属于领域层（T5），但库层先把**不可篡改**这一层钉死。
BEGIN;

CREATE TABLE IF NOT EXISTS node_policies (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_version   TEXT NOT NULL,                       -- 单调递增（TEXT：允许 'v12' 这类可读形态）
  node_id          TEXT REFERENCES nodes(id) ON DELETE RESTRICT,  -- NULL = 全局策略
  protocol_version TEXT NOT NULL,
  issued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_at     TIMESTAMPTZ NOT NULL,
  digest           TEXT NOT NULL,                       -- sha256(canonical_json(doc))
  doc              JSONB NOT NULL,                       -- quotas[{name,window_seconds,value}] + directives[]
  status           TEXT NOT NULL DEFAULT 'active',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT node_policies_version_chk CHECK (char_length(policy_version) BETWEEN 1 AND 64),
  CONSTRAINT node_policies_digest_chk CHECK (digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT node_policies_status_ck CHECK (status IN ('active', 'superseded')),
  CONSTRAINT node_policies_doc_ck CHECK (jsonb_typeof(doc) = 'object'),
  CONSTRAINT node_policies_effective_chk CHECK (effective_at >= issued_at),
  -- 不得内置任何配额默认值（M02 §1）：策略内容必须显式带 quotas 与 directives 两个键
  CONSTRAINT node_policies_doc_keys_ck CHECK (doc ?& ARRAY['quotas', 'directives'])
);

-- 全局策略：同一 policy_version 只有一条；节点策略：同一节点同一版本只有一条
CREATE UNIQUE INDEX IF NOT EXISTS node_policies_global_uq
  ON node_policies (policy_version) WHERE node_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS node_policies_node_uq
  ON node_policies (node_id, policy_version) WHERE node_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS node_policies_node_idx
  ON node_policies (node_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS node_policies_digest_idx
  ON node_policies (digest);

-- 不可变：DELETE 拒绝；UPDATE 只允许 status active → superseded（其余列必须不变）
CREATE OR REPLACE FUNCTION m02_node_policies_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'node_policies 只追加：禁止 DELETE（M02 §3 每版本不可变）';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.status = 'active' AND NEW.status = 'superseded'
       AND NEW.id = OLD.id
       AND NEW.policy_version = OLD.policy_version
       AND NEW.node_id IS NOT DISTINCT FROM OLD.node_id
       AND NEW.protocol_version = OLD.protocol_version
       AND NEW.issued_at = OLD.issued_at
       AND NEW.effective_at = OLD.effective_at
       AND NEW.digest = OLD.digest
       AND NEW.doc = OLD.doc
       AND NEW.created_at = OLD.created_at
    THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'node_policies 只追加：只允许 status active→superseded，其余列不可改';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS node_policies_guard_trg ON node_policies;
CREATE TRIGGER node_policies_guard_trg
  BEFORE UPDATE OR DELETE ON node_policies
  FOR EACH ROW EXECUTE FUNCTION m02_node_policies_guard();

COMMIT;
