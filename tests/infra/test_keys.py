# SPDX-License-Identifier: Apache-2.0
"""密钥读取（fail-closed）：只认 0600 文件或注入式 provider；缺失 / 弱 / 权限错都拒绝。"""
from __future__ import annotations

import os

import pytest

from app.audit import errors, facts, keys


def write_key(path, content: bytes, mode: int = 0o600):
    path.write_bytes(content)
    os.chmod(path, mode)
    return path


def test_missing_path_env_returns_none(tmp_path):
    provider = keys.FileKeyProvider(None)
    assert provider.get() is None
    assert provider.path is None


def test_nonexistent_file_returns_none(tmp_path):
    assert keys.FileKeyProvider(tmp_path / "nope.key").get() is None


def test_0600_file_is_read_and_stripped(tmp_path):
    path = write_key(tmp_path / "audit.key", b"0123456789abcdef0123456789abcdef\n")
    assert keys.FileKeyProvider(path).get() == b"0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
def test_loose_permissions_are_rejected(tmp_path, mode):
    path = write_key(tmp_path / "audit.key", b"0123456789abcdef", mode=mode)
    with pytest.raises(errors.ChainLocked) as excinfo:
        keys.FileKeyProvider(path).get()
    assert excinfo.value.reason == "audit_key_permissions"
    assert excinfo.value.status_code == 423


def test_empty_file_is_rejected(tmp_path):
    path = write_key(tmp_path / "audit.key", b"   \n")
    with pytest.raises(errors.ChainLocked) as excinfo:
        keys.FileKeyProvider(path).get()
    assert excinfo.value.reason == "audit_key_empty"


def test_weak_key_is_rejected(tmp_path):
    path = write_key(tmp_path / "audit.key", b"short")
    with pytest.raises(errors.ChainLocked) as excinfo:
        keys.FileKeyProvider(path).get()
    assert excinfo.value.reason == "audit_key_weak"


def test_directory_reference_is_rejected(tmp_path):
    with pytest.raises(errors.ChainLocked) as excinfo:
        keys.FileKeyProvider(tmp_path).get()
    assert excinfo.value.reason == "audit_key_invalid"


def test_from_env_reads_the_path_only(tmp_path):
    path = write_key(tmp_path / "audit.key", b"0123456789abcdef0123456789abcdef")
    provider = keys.from_env({facts.KEY_FILE_ENV: str(path)})
    assert provider.get() == b"0123456789abcdef0123456789abcdef"
    assert keys.from_env({}).get() is None


def test_static_provider_accepts_bytes_and_str():
    assert keys.StaticKeyProvider(b"abc").get() == b"abc"
    assert keys.StaticKeyProvider("abc").get() == b"abc"
    assert keys.StaticKeyProvider(None).get() is None


def test_read_key_accepts_every_supported_shape():
    assert keys.read_key(None) is None
    assert keys.read_key(b"abc") == b"abc"
    assert keys.read_key("abc") == b"abc"
    assert keys.read_key(keys.StaticKeyProvider(b"abc")) == b"abc"
    assert keys.read_key(lambda: b"abc") == b"abc"
    assert keys.read_key(keys.StaticKeyProvider(None)) is None


def test_read_key_rejects_invalid_provider_shape():
    class Broken:
        pass

    with pytest.raises(errors.ChainLocked) as excinfo:
        keys.read_key(Broken())
    assert excinfo.value.reason == "audit_key_provider_invalid"


def test_repr_never_leaks_key_material(tmp_path):
    path = write_key(tmp_path / "audit.key", b"0123456789abcdef0123456789abcdef")
    assert "0123456789abcdef" not in repr(keys.FileKeyProvider(path))
    assert "0123456789abcdef" not in repr(keys.StaticKeyProvider(b"0123456789abcdef"))
