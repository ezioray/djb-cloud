# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-M06-T1 账本地基测试夹具。

约定：
  · 每个测试用独立 schema（``m06_t1_<hex>``），结束 ``DROP SCHEMA ... CASCADE``；
    不读写 public，也不碰别人的 schema；
  · 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一条路径），DSN 由 ``DJB_DSN`` 注入，
    测试文件不存凭据；
  · 写库断言一律在事务里做：借贷平衡是 DEFERRABLE 约束触发器，**提交时刻**才报错。
"""
from __future__ import annotations

import pathlib
import sys
import uuid

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for _path in (str(_HERE), str(_REPO_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from ledgerkit import apply_migrations, create_schema, drop_schema   # noqa: E402


@pytest.fixture(scope="session")
def schema_prefix() -> str:
    return f"m06_t1_{uuid.uuid4().hex[:6]}"


@pytest.fixture
def schema(schema_prefix: str) -> str:
    """空 schema（未跑任何迁移）。"""
    name = f"{schema_prefix}_{uuid.uuid4().hex[:6]}"
    create_schema(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def migrated(schema: str) -> str:
    """已执行 001–604 的 schema。"""
    apply_migrations(schema)
    return schema


@pytest.fixture(scope="module")
def shared(schema_prefix: str) -> str:
    """模块级共享 schema：迁移只跑一次。

    用于「用例之间互不干扰」的约束/护栏测试（每个用例用自己的随机幂等键与 id），
    避免 130+ 次建库-迁移-删库把 NAS 拖慢；需要空库语义的用例仍用函数级 ``migrated``。
    """
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)
