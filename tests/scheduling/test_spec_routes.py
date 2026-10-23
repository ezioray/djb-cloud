# SPDX-License-Identifier: Apache-2.0
"""route-vs-spec：M04 拥有的路径与 spec 1.2.x 差集必须为 0（04-api-contracts §4 门禁）。

spec 来源优先级：``$DJB_SPEC_FILE`` → ``<workspace>/spec/openapi.yaml`` → 缺则 skip。

M04 拥有：``/api/v1/schedule/*``（01-ownership §1）+ ``/api/v1/user/quote-settings`` /
``/api/v1/provider/quote-settings``（CR-1 裁决归 M04，**T3 起实现**，本任务登记为未做项）。
"""
from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from app.scheduling import router as router_module

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OWNED_PREFIXES = ("/api/v1/schedule/",)
#: 本任务（T1+T2）不实现的已登记端点（T3 起）：quote-settings 读写
DEFERRED_PREFIXES = ("/api/v1/user/quote-settings", "/api/v1/provider/quote-settings")
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
        if not path.startswith(OWNED_PREFIXES):
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


def test_every_spec_path_is_implemented():
    """route-vs-spec 差集 0：spec 有、实现没有 → 红。"""
    spec = _spec_paths()
    implemented = _implemented()
    missing = sorted(set(spec) - set(implemented))
    assert missing == [], f"spec 已登记但未实现：{missing}"


def test_every_implemented_path_is_in_spec():
    """反向差集：实现有、spec 没有 → 红（禁止「事实上的契约」）。"""
    spec = _spec_paths()
    implemented = _implemented()
    extra = sorted(set(implemented) - set(spec))
    assert extra == [], f"实现多了 spec 没登记的路径：{extra}"


def test_route_prefix_is_owned_by_m04():
    for _method, path in _implemented():
        assert path.startswith(OWNED_PREFIXES), path
        assert not path.startswith(DEFERRED_PREFIXES), path


def test_deferred_quote_settings_are_registered_in_ownership():
    """CR-1：quote-settings 归 M04，但 T1/T2 不实现（在证据文件里登记为未做项）。"""
    candidates = [REPO_ROOT.parents[offset] / "product" / "v4" / "modules" / "01-ownership.md"
                  for offset in (2, 1, 3)]
    ownership = next((path for path in candidates if path.exists()), None)
    if ownership is None:
        pytest.skip("01-ownership 不在工作树可及范围（workspace/product/v4/modules）")
    text = ownership.read_text(encoding="utf-8")
    assert "/api/v1/user/quote-settings" in text
    assert "/api/v1/provider/quote-settings" in text
