# SPDX-License-Identifier: AGPL-3.0-or-later
"""兼容 shim：``app.ledger`` 的旧符号仍然可用（DEV-M06-T2 起实现搬进 ``app/ledger/`` 包）。

为什么保留本文件（虽然 Python 导入时同名包优先，实际命中的是 ``app/ledger/__init__.py``）：
  1) 按文件路径加载（importlib.spec_from_file_location）或代码审查时，旧入口还在；
  2) 明确记录「实现已迁到 app/ledger/legacy.py」，避免有人以为账本实现还在这一个文件里；
  3) 旧符号的清单在这里可见，改动时必须同步 app/ledger/__init__.py 的 __all__。

行为契约：本文件与 app/ledger/__init__.py 导出的旧符号**必须同一份实现**（都来自
app/ledger/legacy.py），不复制代码。
"""
from __future__ import annotations

from app.ledger.legacy import (
    GENESIS,
    LEDGER_APPEND_LOCK_ID,
    PostResult,
    entry_hash,
    post_entry,
    recompute,
)

__all__ = ["GENESIS", "LEDGER_APPEND_LOCK_ID", "PostResult", "entry_hash", "post_entry", "recompute"]
