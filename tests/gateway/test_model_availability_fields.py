# SPDX-License-Identifier: Apache-2.0
"""spec 1.2.8：Model.available / Model.probe 的透传（C9 收尾）。

只测 M03 的字段规整与响应组装；不依赖数据库、不联网。
"""
from __future__ import annotations

from app.gateway import providers
from app.gateway import router


def _row(**extra):
    row = {"id": "gpt-x", "object": "model", "owned_by": "djb"}
    row.update(extra)
    return row


def test_model_dict_keeps_optional_availability():
    payload = providers._model_dict(_row(available=False,
                                         probe={"level": None, "verified_at": None,
                                                "fresh": False, "reason": "unverified"}))
    assert payload["available"] is False
    assert payload["probe"]["reason"] == "unverified"


def test_model_dict_does_not_invent_missing_fields():
    payload = providers._model_dict(_row())
    assert "available" not in payload
    assert "probe" not in payload


def test_model_payload_includes_false_not_dropped():
    payload = router._model_payload(_row(available=False,
                                         probe={"level": None, "verified_at": None,
                                                "fresh": False, "reason": "no_capacity"}))
    assert payload["id"] == "gpt-x"
    assert payload["available"] is False
    assert payload["probe"]["reason"] == "no_capacity"


def test_model_payload_omits_missing_availability():
    payload = router._model_payload(_row(price_version="pv-1"))
    assert "available" not in payload
    assert "probe" not in payload
    assert payload["price_version"] == "pv-1"


def test_spec_model_declares_both_optional_fields():
    import os
    from pathlib import Path

    import yaml

    path = Path(os.environ.get("DJB_SPEC_FILE", "../../spec/openapi.yaml"))
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    model = spec["components"]["schemas"]["Model"]
    assert spec["info"]["version"] == "1.2.8"
    assert model["properties"]["available"]["type"] == "boolean"
    probe = model["properties"]["probe"]
    assert probe["additionalProperties"] is False
    assert set(probe["properties"]) == {"level", "verified_at", "fresh", "reason"}
    assert set(model["required"]) == {"id", "object", "owned_by"}
