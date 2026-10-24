![ci](https://github.com/ezioray/djb-cloud/actions/workflows/ci.yml/badge.svg)

# djb-cloud（最小骨架 v0.1）

对应设计文档 §4.2 计量与双签收据、§4.3 可信账本（只追加、可复算）。

## 这一版只做三件事
1. **双签收据**入库（供方签名 + 用方签名，缺一不可）
2. **只追加账本**：每条分录带 `prev_hash`/`hash`，禁止 UPDATE/DELETE（触发器强制）
3. **可复算**：`scripts/recompute.py` 重算 hash 链与余额，任何篡改都会让 `diff != 0`

## 本地/云端跑法
```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
export DJB_DSN="postgresql://djb_dev_app:***@127.0.0.1:5432/djb_dev"
psql "$DJB_DSN" -f migrations/001_init.sql
PYTHONPATH=. python scripts/seed_demo.py          # 写入 1 条双签收据 + 2 条分录
PYTHONPATH=. python scripts/recompute.py --expect-zero
pytest -q
uvicorn app.api:app --host 127.0.0.1 --port 1717
```

## CI 门禁（每次 push 自动跑）

| Job | 作用 |
|---|---|
| `secret-scan` | gitleaks 扫全历史，任何密钥入库即红 |
| `redline-scan` | 代码扫「代币化/绕限制/托管凭据」实现；文档只扫「肯定动词+能力」组合 |
| `test` | 起 Postgres 16 service → 迁移 → 写入双签收据 → **全量复算 diff 必须 0** → pytest |
| `dco` | 提交必须带 `Signed-off-by`（`git commit -s`） |
| `license-headers` | 每个 `.py` 必须有 SPDX 头 |
| `risk-config-guard` | 反作弊规则/阈值/名单**不得**入库（放私有仓 `djb/risk-config`） |

> 设计取舍：红线扫描第一版把 `SECURITY.md` 里的**禁令原文**（「禁止代币化」）判成违规 —— 已收敛为「肯定动词 + 能力」才报，避免自我误伤。

## 完整链路（用方 → 收据 → 账本 → 复算）

```bash
KEY=$(python scripts/mint_key.py user:demo-001)          # 明文只打印一次
curl -s -X POST localhost:1717/v1/chat/completions \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"djb/chat-lite","messages":[{"role":"user","content":"hi"}]}'
# → chat.completion + djb_receipt_id；同事务写入 receipts + 2 条 ledger 分录
python scripts/recompute.py --expect-zero                 # 必须 diff=0
```

实测（devbox）：27 条分录 hash 链连续、`diff=0`；收据两侧签名均为 `hmac-sha256:`；
`X-DJB-Idempotency-Key` 重复调用回放同一收据、**不重复扣费**；`stream:true` 走 SSE。

## 契约（spec 是唯一真源）

- CI 从 `ezioray/djb-node` **固定 SHA** 拉 `openapi.yaml` 到 `spec/`（不入库）
- `tests/test_spec_contract.py`：**实现了 spec 未声明的端点即失败**；响应必填字段需与 spec 一致；spec 不得含反作弊内部字段
- 实战胜例：本仓一度把 `/api/v1/user/usage/summary` 写成 `/api/v1/usage/summary`，被契约测试当场拦下并修正

## 许可证

`djb-cloud` 自 2026-10-24 起以 **AGPL-3.0-or-later** 分发；历史 tag 仍为 Apache-2.0（`LICENSE-APACHE-2.0.txt`）。
闭源/SaaS 商用需另行取得商业授权，见 [`COMMERCIAL.md`](COMMERCIAL.md)。`djb-node` 保持 Apache-2.0。
