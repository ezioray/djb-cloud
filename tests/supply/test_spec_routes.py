# SPDX-License-Identifier: Apache-2.0
"""route-vs-spec：M02 拥有的路径与 spec 1.2.x 差集必须为 0（04-api-contracts §4 门禁）。

spec 来源优先级：``$DJB_SPEC_FILE`` → ``<workspace>/spec/openapi.yaml`` → 缺则 skip。

M02 拥有：``/api/v1/node/*``（排除 ``/node/receipts``，按 01-ownership carve-out 归 M05）、
``/api/v1/protocol/*``、``/api/v1/admin/supply/*``。
"""
from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from app.supply import router as router_module

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OWNED_PREFIXES = ("/api/v1/node/", "/api/v1/protocol/", "/api/v1/admin/supply/")
#: 01-ownership carve-out（CR-1）：收据归 M05，M02 不实现
CARVE_OUTS = ("/api/v1/node/receipts",)
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _spec_path() -> pathlib.Path:
    env = os.environ.get("DJB_SPEC_FILE")
    candidates = [pathlib.Path(env)] if env else []
    candidates += [REPO_ROOT / "spec" / "openapi.yaml",
                   REPO_ROOT.parent / "spec" / "openapi.yaml"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    pytest.skip("spec/openapi.yaml 缺失（设置 DJB_SPEC_FILE 或先同步 spec）")


def _spec_paths() -> dict[tuple[str, str], str]:
    data = yaml.safe_load(_spec_path().read_text(encoding="utf-8"))
    out: dict[tuple[str, str], str] = {}
    for path, item in data["paths"].items():
        if not path.startswith(OWNED_PREFIXES) or path.startswith(CARVE_OUTS):
            continue
        for method in _HTTP_METHODS:
            if method in item:
                out[(method.upper(), path)] = item[method].get("operationId", "")
    return out


def _implemented() -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for route in router_module.router.routes:
        path = getattr(route, "path", "")
        if not path.startswith(OWNED_PREFIXES):
            continue
        for method in (getattr(route, "methods", set()) or set()) - {"HEAD", "OPTIONS"}:
            out[(method.upper(), path)] = str(getattr(route, "operation_id", "")
                                              or getattr(route, "name", ""))
    return out


def test_route_vs_spec_difference_is_empty():
    declared = _spec_paths()
    implemented = _implemented()
    assert declared, "spec 里应当有 M02 拥有的路径（检查 spec 版本）"
    missing = sorted(set(declared) - set(implemented))
    extra = sorted(set(implemented) - set(declared))
    assert missing == [], f"spec 有、实现缺：{missing}"
    assert extra == [], f"实现有、spec 无：{extra}"


def test_operation_ids_match_spec():
    declared = _spec_paths()
    implemented = _implemented()
    mismatched = {key: (declared[key], implemented.get(key))
                  for key in sorted(set(declared) & set(implemented))
                  if declared[key] and declared[key] != implemented[key]}
    assert mismatched == {}, f"operationId 与 spec 不一致：{mismatched}"


def test_carve_out_is_not_implemented():
    paths = {path for _method, path in _implemented()}
    assert not any(path.startswith(CARVE_OUTS) for path in paths)
