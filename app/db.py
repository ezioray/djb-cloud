# SPDX-License-Identifier: AGPL-3.0-or-later
"""最小 DB 访问层（psycopg3，无 ORM）。"""
from contextlib import contextmanager

import psycopg

from .config import dsn


@contextmanager
def conn():
    with psycopg.connect(dsn(), autocommit=False) as c:
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
