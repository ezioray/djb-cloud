-- 207 · M02 node-supply · 一次性绑定码（node_binding_codes）
-- 规格：spec 1.2.0 `NodeBindingRequest.code`（一次性绑定码：网页端签发、一次性、短时效）·
--       M02 §6.5 绑定 / 解绑 / 轮换 · INV-08（一个节点同时只有一条有效绑定）
--
-- 为什么需要这张表：绑定关系本身存 nodes 列 + node_events（CR-4 已裁决，**不建绑定表**）；
-- 但「网页端签发的一次性短时效凭据」必须服务端可验，且必须能证明「未被用过」——
-- 这与 M01 的 identity_scan_tickets（120 s 一次性中间态）同型，故单列一张**码表**。
-- 码只存 sha256；明文只在签发响应里出现一次（不落库、不落日志）。
BEGIN;

CREATE TABLE IF NOT EXISTS node_binding_codes (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id       TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  account_id    UUID NOT NULL,                     -- 签发时的登录账户（网页端已鉴权）
  code_hash     TEXT NOT NULL,                     -- sha256(code)
  status        TEXT NOT NULL DEFAULT 'issued',
  issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ,
  attempts      INT NOT NULL DEFAULT 0,

  CONSTRAINT node_binding_codes_hash_uq UNIQUE (code_hash),
  CONSTRAINT node_binding_codes_status_ck
    CHECK (status IN ('issued', 'consumed', 'expired', 'revoked')),
  CONSTRAINT node_binding_codes_hash_chk CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT node_binding_codes_ttl_chk
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '1 hour'),
  CONSTRAINT node_binding_codes_consumed_chk
    CHECK (status <> 'consumed' OR consumed_at IS NOT NULL),
  CONSTRAINT node_binding_codes_attempts_chk CHECK (attempts >= 0)
);

CREATE INDEX IF NOT EXISTS node_binding_codes_node_idx
  ON node_binding_codes (node_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS node_binding_codes_expiry_idx
  ON node_binding_codes (expires_at);

COMMIT;
