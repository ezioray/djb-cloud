# SPDX-License-Identifier: Apache-2.0
"""route-vs-spec：M03 拥有的路径与 spec 1.2.x 差集必须可解释（04-api-contracts §4 门禁）。

spec 来源优先级：``$DJB_SPEC_FILE`` → ``<workspace>/spec/openapi.yaml`` → 缺则 skip。

M03 拥有（01-ownership §1）：``/v1/chat/completions``、``/v1/models``、``/v1/batches*``。
本任务（T1+T2）只实现前两个；``/v1/batches*`` 归 T4，登记为**显式未做项**（差集 = 3 条）。
"""
from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from app.gateway import router as router_module

ROOT = pathlib.Path(__file__).resolve().parents[2]
OWNED_PREFIXES = ("/v1/",)
#: T4 已全部实现（提交 / 轮询 / 取消），差集必须为 0
DEFERRED: set[tuple[str, str]] = set()
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _spec_path() -> pathlib.Path:
    env = os.environ.get("DJB_SPEC_FILE")
    candidates = [pathlib.Path(env)] if env else []
    candidates += [ROOT / "spec" / "openapi.yaml",
                   ROOT.parent / "spec" / "openapi.yaml",
                   ROOT.parent.parent / "spec" / "openapi.yaml"]
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


def test_every_owned_path_is_either_implemented_or_explicitly_deferred():
    spec = _spec_paths()
    implemented = _implemented()
    missing = set(spec) - set(implemented)
    assert missing == DEFERRED, f"差集与登记不一致：{sorted(missing)}"
    assert set(implemented) <= set(spec), "实现了 spec 里没有的路径（先改契约）"


def test_implemented_operation_ids_match_the_spec():
    spec = _spec_paths()
    implemented = _implemented()
    assert set(implemented) == {("POST", "/v1/chat/completions"), ("GET", "/v1/models"),
                                ("POST", "/v1/batches"), ("GET", "/v1/batches/{id}"),
                                ("POST", "/v1/batches/{id}/cancel")}
    # 路径必须与 spec 完全一致（含大小写与方法）
    for key in implemented:
        assert key in spec, key


def test_spec_responses_for_chat_include_the_cr3_status_codes():
    """CR-3 裁决：402 / 413 / 409 必须出现在 spec（本模块的对外承诺）。"""
    data = yaml.safe_load(_spec_path().read_text(encoding="utf-8"))
    responses = data["paths"]["/v1/chat/completions"]["post"]["responses"]
    assert {"200", "400", "401", "402", "403", "409", "413", "429", "503"} <= set(responses)


def test_spec_error_envelope_requires_the_four_fields():
    data = yaml.safe_load(_spec_path().read_text(encoding="utf-8"))
    error = data["components"]["schemas"]["Error"]["properties"]["error"]
    assert set(error["required"]) == {"type", "code", "message", "request_id"}


def test_protocol_version_header_is_declared():
    data = yaml.safe_load(_spec_path().read_text(encoding="utf-8"))
    params = data["components"]["parameters"]
    assert params["ProtocolVersion"]["name"] == "DJB-Protocol-Version"
    assert params["RequestId"]["name"] == "X-Request-Id"
    assert params["IdempotencyKey"]["name"] == "X-DJB-Idempotency-Key"
