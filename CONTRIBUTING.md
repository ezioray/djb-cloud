# 贡献指南（DJB）

> 放置路径：复制到每个**公开仓**的仓库根 → `CONTRIBUTING.md`
> 本文件同时是「什么可以进公开仓」的权威说明。规则变更有争议时以本文件 + `SECURITY.md` 为准。

## 0 四个仓，先弄清你该往哪提

| 仓库 | 可见性 | 放什么 | 你能直接提 PR 吗 |
| --- | --- | --- | --- |
| `djb/node` | 公开 | 客户端、协议 spec、SDK | ✅ 可以 |
| `djb/cloud` | 公开 | 网关、计量、账本、调度、门户、后台 | ✅ 可以（账本/凭据边界改动需维护者 review） |
| `djb/handbook` | 公开 | 设计、运维手册（已脱敏） | ✅ 可以 |
| `djb/risk-config` | **私有** | 反作弊规则集、阈值、名单、评分权重 | ❌ 不接受外部 PR |

## 1 反作弊配置**不进公开仓**（最重要的一条）

**不要**在公开仓里提交以下任何东西，哪怕只是"示例值"：

- 反作弊/风控的**具体规则**（`risk-rules.*`、`anti-cheat.*`）
- **阈值**（`threshold*`、`risk_threshold`）与**评分权重**（`score_weight`）
- **名单**（`blocklist`、`denylist`、`allowlist` 的**真实内容**）
- 真实的生产配置、上游凭据、审计 HMAC 密钥

**正确做法**：代码只写「读取配置 → 校验格式 → 应用」的逻辑，阈值与规则由**运行时配置**注入；
配置本体放私有仓 `djb/risk-config`，通过部署流程下发。

> 只要阈值被硬编码进公开仓，它就等于公开了——攻击者只需要读源码就知道边界在哪。
> CI 有 `risk-config-guard` job 会拦截这类文件/字段；测试固件必须放 `tests/fixtures/` 并在文件里标注 `non-production`。

## 2 贡献者需要签 DCO（不需要 CLA）

本项目**不要求签 CLA**。你只需要在每个提交里加一行签名：

```bash
git commit -s -m "fix: 修正计量取整边界"
# 自动追加：
# Signed-off-by: Your Name <you@example.com>
```

`Signed-off-by` 表示你**有权**按本仓许可证提交这段代码（对齐 [Developer Certificate of Origin 1.1](https://developercertificate.org/)）。
CI 的 `dco` job 会逐个提交检查；漏签会被拒。

**为什么不要 CLA**：本项目已全开源，代码在公开许可证下分发，贡献者保留版权即可，无需把版权转让或额外授权给我们；
少一道法律流程 = 少一道外部贡献门槛。**唯一保留的例外**见 §4。

## 3 许可证

- **`djb-cloud` 自 2026-10-24 起为 AGPL-3.0-or-later**（见仓库根 `LICENSE`）；历史 tag 仍为 Apache-2.0（`LICENSE-APACHE-2.0.txt`）。
- **`djb-node` 保持 Apache-2.0**（客户端要能被广泛集成）。
- 每个源文件头部要有 SPDX 标识：

```
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 DJB contributors
```

  Shell/Python 用 `#`，JS/TS/Go/Rust/Java 用各自行注释。CI 的 `license-headers` job 会检查。
- 商业闭源使用需另取商业授权，见 `COMMERCIAL.md`；AGPL 义务不因商业授权之外的分支而消失。

## 4 这些改动必须维护者 review（DCO 之外唯一的额外门）

以下区域的 PR **必须**由维护者（`@maintainers`）明确批准后才合并——因为它们一旦出错是全量风险，而不是局部 bug：

1. **凭据边界**：任何读取/传递/落盘密钥、令牌、证书私钥的代码路径。
2. **护栏（guardrail）**：限流、配额、风控调用点、反作弊接口的**签名与调用时机**（不含阈值本身）。
3. **审计链**：`audit/` 下的哈希链、HMAC 校验、封盘逻辑。
4. **账本/计量**：任何影响金额、配额、结算的算法或取整规则。

## 5 代码与提交要求

- 分支：从 `main` 切 `feat/*`、`fix/*`、`docs/*`；发布用 `release/*` + 语义化 tag。
- 提交信息：`type(scope): 摘要`（Conventional Commits），一个提交一件事。
- PR 必须：CI 全绿（含 `secret-scan`、`redline-scan`、`risk-config-guard`、`license-headers`、`dco`）。
- 不要提交：`.env`、`*.key`、`*.pem`、`credentials*`、任何真实令牌。提交前请自行确认未包含任何真实令牌。

## 6 发现安全问题怎么办

**不要**开公开 issue。请按仓库根 `SECURITY.md`（或 `/.well-known/security.txt`）给出的私密渠道报告，
我们会确认、修复并在修复后致谢（如你愿意署名）。**请勿**在公开 issue/PR 里贴可利用细节。
