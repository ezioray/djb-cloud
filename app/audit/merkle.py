# SPDX-License-Identifier: Apache-2.0
"""每日 Merkle 根（M16 §3 ``daily_root`` / §6.3 ``--seal``；等价于 ops/audit/verify.mjs 的算法）。

算式（与 ``verify.mjs`` 第 133–140 行逐字一致，改实现必须同步改运维链）::

    leaves = 当日条目按 seq 升序的 hash（hex 字符串）
    root(leaves) =
        "EMPTY"                                    若 leaves 为空
        leaves[0]                                  若只有 1 片叶子
        fold(leaves)                               否则，逐层归并：

    fold(level):
        下一层 = [ SHA256( 左hex ‖ 右hex )  for 每对相邻叶子 ]
                 奇数个时最后一个**复制自身**参与（right = left）
        重复直到只剩 1 个根

即 ``node = SHA256(ascii(hex(left) + hex(right)))``，输出仍是 hex。叶子哈希本身已经是
HMAC-SHA256 的值，Merkle 层只负责"把一天的条目压成一个可对外承诺的根"。

为什么不用 HMAC：日根要能被第三方（审计 / PoR 读者）用公开算法独立复算，
密钥只保护条目层的不可伪造性；日根的作用是「当天条目集合没被增删改」。
"""
from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

EMPTY_ROOT = "EMPTY"


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("ascii")).hexdigest()


def merkle_root(leaves: Iterable[str]) -> str:
    """按上述算式计算 Merkle 根（确定性：只依赖叶子顺序与内容）。"""
    level: list[str] = [str(leaf) for leaf in leaves]
    if not level:
        return EMPTY_ROOT
    while len(level) > 1:
        nxt: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            nxt.append(_hash_pair(left, right))
        level = nxt
    return level[0]


def levels(leaves: Sequence[str]) -> list[list[str]]:
    """返回逐层节点（排障 / 证据用：可核对第 k 层）。"""
    layer: list[str] = [str(leaf) for leaf in leaves]
    out: list[list[str]] = [list(layer)]
    while len(layer) > 1:
        nxt: list[str] = []
        for index in range(0, len(layer), 2):
            left = layer[index]
            right = layer[index + 1] if index + 1 < len(layer) else left
            nxt.append(_hash_pair(left, right))
        layer = nxt
        out.append(list(layer))
    return out


__all__ = ["EMPTY_ROOT", "merkle_root", "levels"]
