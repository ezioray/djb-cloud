# SPDX-License-Identifier: AGPL-3.0-or-later
"""审计 HMAC 密钥的读法（**只读引用，绝不落库 / 落日志 / 落证据**）。

M16 §1「密钥」：KMS / Secret 引用、路径注入；审计链 HMAC 密钥由决策人保管并以**文件路径**注入。
因此本模块只认两种来源：

1. :class:`FileKeyProvider` —— 从 ``DJB_AUDIT_HMAC_KEY_FILE`` 指向的文件读（权限必须 0600）；
2. :class:`StaticKeyProvider` —— 测试 / 演练用注入式 provider（进程内存里的字节）。

任何"读不到 / 权限不对 / 空文件 / 太短"都返回 ``None`` 或抛 :class:`app.audit.errors.ChainLocked`，
调用方据此 **fail-closed**：写入 423 + 42301，verify 返回 ``ok=false``（不静默通过）。
"""
from __future__ import annotations

import os
import pathlib
import stat
from typing import Any, Mapping, Protocol, runtime_checkable

from . import errors, facts


@runtime_checkable
class KeyProvider(Protocol):
    """密钥提供者：返回 key bytes，或 ``None`` 表示"当前不可用"。"""

    def get(self) -> bytes | None:  # pragma: no cover - 协议声明
        ...


class FileKeyProvider:
    """从 0600 文件读密钥（每次调用都读，支持轮换后立即生效；不做内存缓存）。"""

    def __init__(self, path: str | os.PathLike[str] | None) -> None:
        self._path = str(path) if path else None

    @property
    def path(self) -> str | None:
        return self._path

    def get(self) -> bytes | None:
        if not self._path:
            return None
        target = pathlib.Path(self._path)
        if not target.exists():
            return None
        if not target.is_file():
            raise errors.ChainLocked("审计链密钥引用不是普通文件：拒绝写入（fail-closed）",
                                     reason="audit_key_invalid")
        mode = stat.S_IMODE(target.stat().st_mode)
        if mode & 0o077:
            raise errors.ChainLocked(
                f"审计链密钥文件权限必须是 0600（当前 {mode:04o}）：拒绝写入（fail-closed）",
                reason="audit_key_permissions")
        raw = target.read_bytes().strip()
        if not raw:
            raise errors.ChainLocked("审计链密钥文件为空：拒绝写入（fail-closed）",
                                     reason="audit_key_empty")
        if len(raw) < facts.MIN_KEY_BYTES:
            raise errors.ChainLocked(
                f"审计链密钥强度不足（<{facts.MIN_KEY_BYTES} 字节）：拒绝写入（fail-closed）",
                reason="audit_key_weak")
        return raw

    def __repr__(self) -> str:                       # pragma: no cover - 脱敏
        return "FileKeyProvider(path=<redacted>)"


class StaticKeyProvider:
    """注入式 provider（测试 / 演练 / KMS 适配器）：只持有内存字节，不读环境。"""

    def __init__(self, key: bytes | str | None) -> None:
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._key = key

    def get(self) -> bytes | None:
        return self._key

    def __repr__(self) -> str:                       # pragma: no cover - 脱敏
        return "StaticKeyProvider(key=<redacted>)"


def from_env(env: Mapping[str, str] | None = None) -> KeyProvider:
    """按 ``DJB_AUDIT_HMAC_KEY_FILE`` 构造 provider（未配置 → 每次 get() 返回 None）。"""
    source = os.environ if env is None else env
    return FileKeyProvider(source.get(facts.KEY_FILE_ENV))


def read_key(provider: Any) -> bytes | None:
    """统一读取入口：兼容 ``KeyProvider`` 对象、可调用对象与 ``None``。"""
    if provider is None:
        return None
    if isinstance(provider, (bytes, bytearray)):
        return bytes(provider)
    if isinstance(provider, str):
        return provider.encode("utf-8")
    getter = getattr(provider, "get", None)
    if callable(getter):
        value = getter()
    elif callable(provider):
        value = provider()
    else:                                            # pragma: no cover - 接线错误
        raise errors.ChainLocked("密钥 provider 形态非法：拒绝写入（fail-closed）",
                                 reason="audit_key_provider_invalid")
    if value is None:
        return None
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


__all__ = ["KeyProvider", "FileKeyProvider", "StaticKeyProvider", "from_env", "read_key"]
