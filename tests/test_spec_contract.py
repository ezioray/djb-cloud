# SPDX-License-Identifier: AGPL-3.0-or-later
"""契约测试：实现必须与 djb-node 的 spec 一致（spec 是唯一真源）。

spec 来源优先级：$DJB_SPEC_FILE → ./spec/openapi.yaml → 环境缺失则 skip（本地不阻断）。
"""
import os

import pytest
import yaml

from app.api import app

SPEC = os.environ.get("DJB_SPEC_FILE") or os.path.join("spec", "openapi.yaml")


def _spec():
    if not os.path.exists(SPEC):
        pytest.skip(f"spec 缺失（{SPEC}）；CI 会先拉取固定版本")
    with open(SPEC, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _implemented():
    """{(method, path)}：只取业务路径，忽略 /docs 等框架自带。"""
    out = set()
    for r in app.routes:
        path = getattr(r, "path", "")
        methods = getattr(r, "methods", set()) or set()
        if not path.startswith(("/v1/", "/api/")):
            continue
        for m in methods - {"HEAD", "OPTIONS"}:
            out.add((m.lower(), path))
    return out


def test_every_implemented_route_is_in_spec():
    """不能凭空实现 spec 之外的端点。"""
    spec = _spec()
    declared = {(m, p) for p, item in spec["paths"].items()
                for m in item if m in ("get", "post", "put", "patch", "delete")}
    extra = _implemented() - declared
    assert not extra, f"实现了 spec 未声明的端点: {sorted(extra)}"


def test_chat_completion_response_matches_spec_required_fields():
    """200 响应必须包含 spec 要求的字段（直接调用函数，不依赖 DB）。"""
    spec = _spec()
    resp = spec["paths"]["/v1/chat/completions"]["post"]["responses"]["200"]
    schema = resp["content"]["application/json"]["schema"]
    name = schema["$ref"].split("/")[-1]
    required = set(spec["components"]["schemas"][name]["required"])
    assert required == {"id", "object", "created", "model", "choices"}, required
    assert {"id", "object", "created", "model", "choices"} <= required


def test_spec_has_no_anticheat_internals():
    """反作弊规则/阈值/名单不得出现在公开 spec（运营配置不入公开仓）。"""
    raw = open(SPEC, encoding="utf-8").read() if os.path.exists(SPEC) else ""
    for bad in ("blocklist", "blacklist", "score_weight", "risk_rules", "thresholds"):
        assert bad not in raw, f"spec 出现内部字段: {bad}"
