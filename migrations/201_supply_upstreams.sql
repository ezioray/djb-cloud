-- 201 · M02 node-supply · 上游申报（node_upstreams）
-- 规格：M02 §3 NodeUpstream / §5 数据所有权 / §6.3 上游申报 / §8.2 上限
--       INV-04（服务端不接收凭据本体：只登记 credential_handle，不解析、不回显）
--
-- 状态机（M02 §3）：declared → probing → verified | rejected（库层用 CHECK 兜底枚举）
-- 幂等（M02 §3 幂等段）：(node_id, access_type, base_url) 唯一 → 重复申报返回同一条
BEGIN;

CREATE TABLE IF NOT EXISTS node_upstreams (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id              TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  access_type          TEXT NOT NULL,                       -- A1 直填 Key / A2 本机代理 / B 企业网关
  base_url             TEXT NOT NULL,
  models               JSONB NOT NULL DEFAULT '[]'::jsonb,  -- 模型清单（slug 归一由 M04 只读校验）
  protocol             TEXT,
  credential_handle    TEXT,                                -- **本地**凭据句柄：只登记，不解析
  state                TEXT NOT NULL DEFAULT 'declared',
  verified_at          TIMESTAMPTZ,
  rejected_reason_code TEXT,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT node_upstreams_access_type_ck CHECK (access_type IN ('A1', 'A2', 'B')),
  CONSTRAINT node_upstreams_state_ck
    CHECK (state IN ('declared', 'probing', 'verified', 'rejected')),
  -- 端点不得带 userinfo（M02 §6.3「禁 userinfo」）；凭据本体永不上行
  CONSTRAINT node_upstreams_base_url_chk
    CHECK (base_url ~ '^[A-Za-z][A-Za-z0-9+.-]*://'
           AND base_url !~ '^[A-Za-z][A-Za-z0-9+.-]*://[^/?#@]*@'),
  CONSTRAINT node_upstreams_models_ck
    CHECK (jsonb_typeof(models) = 'array' AND jsonb_array_length(models) BETWEEN 1 AND 200),
  CONSTRAINT node_upstreams_handle_len_ck
    CHECK (credential_handle IS NULL OR char_length(credential_handle) BETWEEN 1 AND 200),
  CONSTRAINT node_upstreams_verified_chk
    CHECK (state <> 'verified' OR verified_at IS NOT NULL),
  CONSTRAINT node_upstreams_rejected_chk
    CHECK (state <> 'rejected' OR rejected_reason_code IS NOT NULL),
  -- 幂等：同一节点的同一接入类型 + 同一端点只有一条
  CONSTRAINT node_upstreams_decl_uq UNIQUE (node_id, access_type, base_url)
);

CREATE INDEX IF NOT EXISTS node_upstreams_node_state_idx
  ON node_upstreams (node_id, state);
CREATE INDEX IF NOT EXISTS node_upstreams_node_idx
  ON node_upstreams (node_id, created_at DESC);

COMMIT;
