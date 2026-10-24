# SPDX-License-Identifier: AGPL-3.0-or-later
"""spec 1.2.6 /v1/models 的可选 ``price_version``（M03 §4.1，只加不改）。

覆盖：有快照版本 → 回显；无 → 缺省（公开侧允许）；嵌套 ``price.price_version`` 宽容读取；
非字符串忽略；对象型 catalog 行同样投影；鉴权保持 userBearer（1.2.6 **不收紧**）。
"""
from __future__ import annotations

import pytest

from app.gateway import facts, providers
from gatewaykit import FakeCatalog


def _auth() -> dict[str, str]:
    return {facts.AUTH_HEADER: "Bearer djb_live_w3gap"}


@pytest.fixture
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.gateway import router as router_module

    app = FastAPI()
    app.include_router(router_module.router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def api(wired):
    """接上假 provider（鉴权 / 路由 / 上游 / 计量），catalog 由用例自己设。"""
    return wired


class _CatalogRow:
    """对象型 catalog 行（M04 ORM / dataclass 形态）。"""

    def __init__(self, **values) -> None:
        for name, value in values.items():
            setattr(self, name, value)


def _models(client):
    response = client.get("/v1/models", headers=_auth())
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- 成功
def test_models_include_price_version_when_catalog_has_it(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog(items=[
        {"id": "m1", "owned_by": "djb", "context_window": 8192, "unit": "token",
         "price": {"amount": "0.02", "unit": "token"}, "price_version": "pv-2026-10"},
    ]))
    payload = _models(client)
    assert payload["object"] == "list"
    item = payload["data"][0]
    assert item["id"] == "m1" and item["object"] == "model"
    assert item["price_version"] == "pv-2026-10"
    assert item["price"] == {"amount": "0.02", "unit": "token"}   # 原字段不变


def test_models_omit_price_version_when_absent(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog())
    payload = _models(client)
    assert len(payload["data"]) == 2
    assert all("price_version" not in item for item in payload["data"])


def test_models_tolerate_null_price_version(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog(items=[
        {"id": "m1", "owned_by": "djb", "price_version": None},
    ]))
    item = _models(client)["data"][0]
    assert "price_version" not in item                            # 允许缺省为 null


def test_models_read_price_version_from_nested_price(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog(items=[
        {"id": "m2", "owned_by": "djb",
         "price": {"amount": "0.01", "unit": "token", "price_version": "pv-nested"}},
    ]))
    assert _models(client)["data"][0]["price_version"] == "pv-nested"


def test_models_ignore_non_string_price_version(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog(items=[
        {"id": "m3", "owned_by": "djb", "price_version": 42},
    ]))
    assert "price_version" not in _models(client)["data"][0]


def test_object_catalog_rows_expose_price_version(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog(items=[
        _CatalogRow(id="m4", owned_by="djb", unit="token", price_version="pv-obj"),
    ]))
    assert _models(client)["data"][0]["price_version"] == "pv-obj"


# --------------------------------------------------------------------------- 未认证（保持现有口径）
def test_models_still_require_user_bearer(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog())
    response = client.get("/v1/models")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == 40101
    assert response.headers["X-Request-Id"]


def test_models_unknown_fields_are_ignored(client, api):   # noqa: ARG001
    providers.set_model_catalog_provider(FakeCatalog(items=[
        {"id": "m5", "owned_by": "djb", "future_field": "ignored"},
    ]))
    response = client.get("/v1/models", headers=_auth())
    assert response.status_code == 200
    assert response.json()["data"][0]["id"] == "m5"

# --------------------------------------------------------------------------- 契约（spec 1.2.6）

def _spec() -> dict:
    """spec 来源：$DJB_SPEC_FILE → 仓库 spec/ → 向上最多 4 级祖先的 spec/（CI 与工作区同一实现）。"""
    import os
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[2]
    candidates = [pathlib.Path(os.environ["DJB_SPEC_FILE"])] if os.environ.get("DJB_SPEC_FILE") \
        else []
    candidates.append(root / "spec" / "openapi.yaml")
    candidates += [parent / "spec" / "openapi.yaml" for parent in list(root.parents)[:4]]
    for candidate in candidates:
        if candidate.exists():
            return yaml.safe_load(candidate.read_text(encoding="utf-8"))
    pytest.skip("spec/openapi.yaml 缺失（设置 DJB_SPEC_FILE 或先同步 spec）")


def test_price_version_is_optional_in_spec_1_2_6():
    spec = _spec()
    operation = spec["paths"]["/v1/models"]["get"]
    assert operation["security"] == [{"userBearer": []}]         # 1.2.6 不收紧鉴权
    declared = spec["components"]["schemas"]["Model"]["properties"]["price_version"]
    assert declared["type"] == ["string", "null"]                # 可选可缺省
    assert "id" in spec["components"]["schemas"]["Model"]["properties"]

