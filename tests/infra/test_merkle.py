# SPDX-License-Identifier: Apache-2.0
"""每日 Merkle 根（纯函数；与 ops/audit/verify.mjs 的算式逐字一致）。"""
from __future__ import annotations

import hashlib

from app.audit import merkle


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def test_empty_day_root_is_empty_marker():
    assert merkle.merkle_root([]) == merkle.EMPTY_ROOT == "EMPTY"


def test_single_leaf_root_is_the_leaf():
    assert merkle.merkle_root(["a" * 64]) == "a" * 64


def test_two_leaves_root_is_sha256_of_concatenated_hex():
    left, right = "a" * 64, "b" * 64
    assert merkle.merkle_root([left, right]) == sha(left + right)


def test_three_leaves_duplicates_the_odd_leaf():
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    expected = sha(sha(a + b) + sha(c + c))
    assert merkle.merkle_root([a, b, c]) == expected


def test_four_leaves_root():
    a, b, c, d = "1" * 64, "2" * 64, "3" * 64, "4" * 64
    assert merkle.merkle_root([a, b, c, d]) == sha(sha(a + b) + sha(c + d))


def test_root_is_order_sensitive():
    a, b = "a" * 64, "b" * 64
    assert merkle.merkle_root([a, b]) != merkle.merkle_root([b, a])


def test_root_changes_when_any_leaf_changes():
    leaves = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
    baseline = merkle.merkle_root(leaves)
    leaves[2] = "e" * 64
    assert merkle.merkle_root(leaves) != baseline


def test_levels_expose_each_layer():
    leaves = ["a" * 64, "b" * 64, "c" * 64]
    layers = merkle.levels(leaves)
    assert layers[0] == leaves
    assert len(layers) == 3                       # 3 → 2 → 1
    assert layers[-1] == [merkle.merkle_root(leaves)]


def test_levels_of_empty_is_empty():
    assert merkle.levels([]) == [[]]
