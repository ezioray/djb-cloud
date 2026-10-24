# SPDX-License-Identifier: AGPL-3.0-or-later
"""SupplyAvailability（C9 收尾）：M03 `/v1/models` 的真实可用性四态。

只读 M02 两个视图；数据用 schedulingkit 夹具扮演上游，不写 ledger。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.wiring.availability import SupplyAvailability
from app.wiring.db import Database
from app.wiring.nodes import DemoCatalog
from gatewaykit import NOW, dsn
from tests.scheduling.schedulingkit import seed_capacity, seed_node


def test_no_capacity(migrated: str):
    db = Database(schema=migrated, dsn=dsn())
    seed_node(db.schema, "avail-none")
    status = SupplyAvailability(db).status("avail-none-model", now=NOW)
    assert status["available"] is False
    assert status["probe"]["reason"] == "no_capacity"


def test_capacity_but_unverified(migrated: str):
    db = Database(schema=migrated, dsn=dsn())
    seed_node(db.schema, "avail-unverified")
    seed_capacity(db.schema, "avail-unverified", models=("avail-unverified-model",),
                  verified=False)
    status = SupplyAvailability(db).status("avail-unverified-model", now=NOW)
    assert status["available"] is False
    assert status["probe"]["reason"] == "unverified"
    assert status["probe"]["fresh"] is False


def test_verified_but_stale(migrated: str):
    db = Database(schema=migrated, dsn=dsn())
    seed_node(db.schema, "avail-stale")
    seed_capacity(db.schema, "avail-stale", models=("avail-stale-model",),
                  verified=True, verified_at=NOW - timedelta(seconds=901))
    status = SupplyAvailability(db).status("avail-stale-model", now=NOW)
    assert status["available"] is False
    assert status["probe"]["reason"] == "stale"
    assert status["probe"]["verified_at"] is not None


def test_verified_and_fresh(migrated: str):
    db = Database(schema=migrated, dsn=dsn())
    seed_node(db.schema, "avail-fresh")
    seed_capacity(db.schema, "avail-fresh", models=("avail-fresh-model",),
                  verified=True, verified_at=NOW)
    status = SupplyAvailability(db).status("avail-fresh-model", now=NOW)
    assert status["available"] is True
    assert status["probe"]["fresh"] is True
    assert status["probe"]["reason"] is None
    assert status["probe"]["verified_at"] is not None


def test_demo_catalog_injects_real_status():
    class FakeAvailability:
        def status(self, model: str):
            return {"available": False,
                    "probe": {"level": None, "verified_at": None,
                              "fresh": False, "reason": "no_capacity"}}

    rows = DemoCatalog(availability=FakeAvailability()).list_models()
    assert rows[0]["available"] is False
    assert rows[0]["probe"]["reason"] == "no_capacity"


def test_demo_catalog_without_provider_does_not_claim_available():
    rows = DemoCatalog().list_models()
    assert "available" not in rows[0]
    assert "probe" not in rows[0]
