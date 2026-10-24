# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/integrity 夹具（M17 C14 待分润冻结）。

隔离：

* ``migrated``（session 级共享）：全量迁移一次，读写用例共用；每个用例在自己的事务里跑，
  结束回滚（``conn`` 夹具）——不改别人 schema、不污染 public；
* ``base_schema``（session 级）：只跑到 1403（1700 段之前），供 1710 的「升级 / 回滚 /
  重跑 / 账本 diff」演练——DDL 在 PG 里是事务性的，用例里应用 1710 后回滚即可复原；
* 缺 ``DJB_DSN`` 时整体 skip（纯函数用例仍跑）。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for _path in (str(_HERE), str(_REPO_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from kit import (                                     # noqa: E402
    FIXED_NOW,
    apply_migrations,
    base_migration_files,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M17_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:                    # noqa: ARG001
    return os.environ.get(SCHEMA_ENV) or f"m17_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


@pytest.fixture(scope="session")
def migrated(db: str, schema_prefix: str) -> str:     # noqa: ARG001
    """全量迁移（001…1710）一次，session 内共享。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="session")
def base_schema(db: str, schema_prefix: str) -> str:  # noqa: ARG001
    """只到 1700 段之前（升级 / 回滚 / 账本 diff 的前置基线）。"""
    name = f"{schema_prefix}_base_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name, base_migration_files())
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：用例结束回滚（不改共享 schema 的数据）。"""
    connection = connect(migrated, autocommit=False)
    connection.execute("SELECT 1")          # 显式开启外层事务：之后只允许 SAVEPOINT
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def now():
    return FIXED_NOW


@pytest.fixture
def feature_on(monkeypatch):
    """打开 ``supply.freeze.enabled``（默认关闭；写路径用例显式请求）。"""
    from app.integrity import features

    monkeypatch.setattr(features, "enabled", lambda name: True)
    return True


@pytest.fixture(autouse=True)
def _reset_integrity_hooks(monkeypatch):
    """每个用例后复位鉴权钩子 / tokenizer provider / DJB_ATTEST 环境（不污染他人）。"""
    monkeypatch.delenv("DJB_ATTEST", raising=False)
    monkeypatch.delenv("DJB_FREEZE", raising=False)
    monkeypatch.delenv("DJB_SAMPLING", raising=False)
    from app.integrity import attest_router, providers, sampling_router
    from app.integrity import router as hold_router

    providers.reset_token_counter()
    try:
        yield
    finally:
        attest_router.set_node_authenticator(None)
        attest_router.set_admin_authenticator(None)
        sampling_router.set_admin_authenticator(None)
        hold_router.set_admin_authenticator(None)
        providers.reset_token_counter()


@pytest.fixture
def fake_tokenizer():
    """注入确定性 tokenizer（按空白切分），并把版本钉成 fake-1。"""
    from app.integrity import providers

    counter = lambda prompt, model: len(prompt.split())          # noqa: E731
    providers.set_token_counter(counter, version="fake-1")
    return counter


@pytest.fixture
def fixed_tokenizer():
    """注入「固定计数」tokenizer（用例自己控制 expected 值，便于测容差边界）。"""

    from app.integrity import providers

    class _Fixed:
        value = 100

        def __call__(self, prompt: str, model: str) -> int:
            return self.value

    counter = _Fixed()
    providers.set_token_counter(counter, version="fixed-1")
    return counter
