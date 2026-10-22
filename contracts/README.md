# contracts/ · 机器可读契约与 fixtures

> 性质：由设计包生成/同步的只读投影，模块代码与测试的唯一来源。
> 规则：本目录下的 `03-facts.md`、`02-events.md` 是**同步副本**，不要在本仓手改；改动先改工作区 `product/v4/modules/` 对应文件，再由 Lead 同步。

## 文件

| 文件 | 来源 | 生成/校验 |
| --- | --- | --- |
| `03-facts.md` | `product/v4/modules/03-facts.md`（逐字节同步） | 人工源 |
| `02-events.md` | `product/v4/modules/02-events.md`（逐字节同步） | 人工源 |
| `facts.yaml` | `contracts/03-facts.md` | `python3 tools/gen_facts.py`；CI `--check` |
| `fixtures/<Mxx>/*.json` | 各模块 Owner | `tools/ci/fixtures_check.py` |

## 同步命令（Lead）

```bash
cp product/v4/modules/03-facts.md repos/djb-cloud/contracts/03-facts.md
cp product/v4/modules/02-events.md repos/djb-cloud/contracts/02-events.md
cd repos/djb-cloud && python3 tools/gen_facts.py
```

## 门禁

- `tools/gen_facts.py --check`：facts.yaml 与人工源一致。
- `tools/ci/fixtures_check.py`：每个 Mxx 至少 success / error / boundary 各 1 组。
- `tools/ci/migration_check.py`：迁移文件号唯一且在模块号段。
- `tools/ci/architecture_check.py`：模块包之间无跨模块 import。
- `tools/ci/event_schema.py`：代码里的事件字面量都已在 `02-events.md` 登记。

以上由 `.github/workflows/design-gates.yml` 在 push / PR 时执行。
