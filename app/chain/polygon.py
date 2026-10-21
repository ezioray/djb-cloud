# SPDX-License-Identifier: Apache-2.0
"""Polygon PoS 收款：地址派生 · 扫描入账（E1/E2）· 确认数策略 · 错链/假充值冲正。

对应设计 v4：§19.4.2（一期单链 Polygon PoS）、§19.6.1（确认数 64 / 大额 200、幂等键
``chain_id+tx_hash+log_index``、错链不入账）、§20.1–20.4（E1/E2/E16、只追加、R5/R8/B6/R10）、
附录 B.2（``deposit_address`` / ``chain_tx`` / ``chain_tx_event``）、I-9 / I-10。

红线（本模块的「不做」）
------------------------------------------------------------------
1. **不持私钥、不碰签名**：地址只从 ``xpub``（公开扩展公钥）按 BIP32 非硬化路径派生；
   本模块不接受任何私钥/助记词/种子参数，表里也不存这些列（``deposit_address`` 只存派生路径与 xpub 指纹）。
2. **不接真实 RPC**：入口是扫描器交来的已解析事件（``Transfer``），测试用假扫描器。
3. **不改既有账本函数签名**：``app.ledger.post_entry`` 一字未动；本模块的账本网关
   ``_append_entry`` 复用 ``app.ledger.entry_hash`` 的哈希口径，并额外写 entry_type / source_* /
   reverse_of 这些**只加列**的元数据（§20.4.3 R1 允许加列）。
4. **只追加**：错链/假充值只能 ``void`` + ``reverse_of`` 生成反向分录，绝不 UPDATE/DELETE 原分录
   （DB 触发器 ``forbid_mutation`` 硬拦）。
5. **默认关闭**：开关 ``polygon_ingest``（见 ``app.chain.FEATURE_FLAGS``），关闭时 ``observe`` /
   ``assign_deposit_address`` 直接返回 ``skipped``，不写任何表。

记账口径（与 §20.3.1 的对应）
------------------------------------------------
本仓账本 ``ledger_entries`` 是「一对账户的转账」：``post_entry(debit=D, credit=C, amt)`` 让
D 余额 ``-amt``、C 余额 ``+amt``，``recompute()`` 要求 ``余额 == Σcredit − Σdebit``。
因此全表恒有 **Σ余额 = 0**：资产类科目为正、负债/权益类科目为负（符号即借贷方向）。
于是设计文档的四行分录落成本仓的两条转账对：

=====  ============================  =======================================  ==========================
事件    设计 §20.3.1 分录              本仓 ledger_entries（debit → credit）      落地后余额
=====  ============================  =======================================  ==========================
E1     借 1111 100 / 贷 2990 100      coa:2990 → coa:1111                      1111 +100，2990 −100
E2     借 1101 100 / 贷 1111 100      coa:1111 → coa:1101                      1111 0，1101 +100
       借 2990 100 / 贷 2101 100      coa:2101 → coa:2990                      2990 0，2101 −100
E16    借 2101 100 / 贷 1101 100      （由上面两条 E2 分录各生成一条取反分录）      全部归零
=====  ============================  =======================================  ==========================

E16 在本仓实现为「对该 chain_tx 已入账的**每一条**分录整单取反」（B6：冲正必须整单取反），
净额与设计一致（1101 −100 / 2101 +100），且把 E1/E2 的中转科目 1111/2990 一并清零。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Iterable

from psycopg.types.json import Jsonb

from ..ledger import entry_hash
from . import flag_enabled

__all__ = [
    "CHAIN_ID", "ASSET_CONTRACT", "ASSET_SYMBOL", "ASSET_DECIMALS",
    "CONFIRMATIONS_NORMAL", "CONFIRMATIONS_LARGE", "CONFIRMATIONS_FLOOR",
    "DEFAULT_LARGE_AMOUNT_MINOR", "POLICY_VERSION", "COA",
    "ConfirmationPolicy", "Transfer", "ChainIngestError",
    "ensure_chain_accounts", "observe", "ingest", "void_deposit",
    "assign_deposit_address", "state", "derive_address", "derivation_path",
    "xpub_fingerprint", "parse_xpub", "encode_xpub",
]

# ─────────────────────────────────────────────── 常量（与 v4 §19.6.1 / 附录 B.8 对齐）
CHAIN_ID = "polygon"                                   # 一期只上 Polygon PoS（决策 K6）
CHAIN_DISPLAY = "Polygon PoS"
ASSET_CONTRACT = "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"   # USDT (PoS)
ASSET_SYMBOL = "USDT"
ASSET_DECIMALS = 6
UNIT_SCALE_USD = 6                                     # USD micro（1e-6）

CONFIRMATIONS_NORMAL = 64                              # 常规确认数（硬下限）
CONFIRMATIONS_LARGE = 200                              # 大额确认数
CONFIRMATIONS_FLOOR = 64                               # 红线：任何配置都不得低于 64
DEFAULT_LARGE_AMOUNT_MINOR = 1_000 * 1_000_000         # 大额阈值 1,000 USD（可配，见 ConfirmationPolicy）
POLICY_VERSION = "v4.0"

# 科目编码（§20.2）：只用作 accounts.id 的命名空间，不改变既有列语义
COA = {
    "in_transit": "coa:1111",        # 1111 链上在途
    "hot_wallet": "coa:1101",        # 1101 客户资金-热钱包（Polygon）
    "pending_deposit": "coa:2990",   # 2990 确认中充值（负债，符号为负）
    "service_prepaid": "coa:2101",   # 2101 服务预付款（负债，符号为负）
}
_CHAIN_ACCOUNTS = tuple(COA.values())

ACTOR_DEFAULT = "system:polygon_ingest"
_LEDGER_APPEND_LOCK = 4_442_002   # pg_advisory_xact_lock：串行化账本追加，防 hash 链分叉

_EVENT_CONFLICT = {
    "detected": "(chain_tx_id) WHERE event = 'detected'",
    "confirmed": "(chain_tx_id) WHERE event = 'confirmed'",
    "rejected": "(chain_tx_id) WHERE event = 'rejected'",
    "void": "(chain_tx_id) WHERE event = 'void'",
    "observed": "(chain_tx_id, confirmations) WHERE event = 'observed'",
}

_HEX40 = re.compile(r"^0x[0-9a-f]{40}$")
_HEX64 = re.compile(r"^0x[0-9a-f]{64}$")


class ChainIngestError(Exception):
    """链上收款域的输入/状态错误（拒绝写入，不外抛到 HTTP 层）。"""


# ─────────────────────────────────────────────── 确认数策略（可配，红线兜底）
@dataclass(frozen=True)
class ConfirmationPolicy:
    """确认数策略：常规 64 / 大额 200，大额阈值可配；全部进 ``policy_version``（R10）。

    ``normal`` 低于 64、``large`` 低于 ``normal``、阈值非正数 → 直接报错（fail-closed），
    不允许「配错了就悄悄降到 12 确认」。
    """

    normal: int = CONFIRMATIONS_NORMAL
    large: int = CONFIRMATIONS_LARGE
    large_amount_minor: int = DEFAULT_LARGE_AMOUNT_MINOR
    version: str = ""

    def __post_init__(self) -> None:
        if self.normal < CONFIRMATIONS_FLOOR:
            raise ChainIngestError(
                f"常规确认数 {self.normal} < {CONFIRMATIONS_FLOOR}：违反 §19.6.1 红线，拒绝启动")
        if self.large < self.normal:
            raise ChainIngestError(f"大额确认数 {self.large} < 常规 {self.normal}")
        if self.large_amount_minor <= 0:
            raise ChainIngestError("大额阈值必须为正整数（USD micro）")
        if not self.version:
            object.__setattr__(
                self, "version",
                f"{POLICY_VERSION}:{CHAIN_ID}:{self.normal}/{self.large}:large>={self.large_amount_minor}")

    def required_for(self, amount_minor: int) -> int:
        """按金额给出所需确认数：≥ 大额阈值走 200，否则 64。"""
        if amount_minor <= 0:
            raise ChainIngestError(f"金额必须为正整数 micro：{amount_minor}")
        return self.large if amount_minor >= self.large_amount_minor else self.normal

    def is_large(self, amount_minor: int) -> bool:
        return amount_minor >= self.large_amount_minor

    @classmethod
    def from_env(cls, env: dict | None = None) -> "ConfirmationPolicy":
        """从环境读：DJB_CHAIN_CONFIRMATIONS_{NORMAL,LARGE} / DJB_CHAIN_LARGE_AMOUNT_MINOR。"""
        e = os.environ if env is None else env

        def _int(key: str, default: int) -> int:
            raw = e.get(key)
            if raw is None or str(raw).strip() == "":
                return default
            try:
                return int(str(raw).strip())
            except ValueError:
                raise ChainIngestError(f"{key} 不是整数：{raw!r}") from None

        return cls(
            normal=_int("DJB_CHAIN_CONFIRMATIONS_NORMAL", CONFIRMATIONS_NORMAL),
            large=_int("DJB_CHAIN_CONFIRMATIONS_LARGE", CONFIRMATIONS_LARGE),
            large_amount_minor=_int("DJB_CHAIN_LARGE_AMOUNT_MINOR", DEFAULT_LARGE_AMOUNT_MINOR),
            version=e.get("DJB_CHAIN_POLICY_VERSION", "") or "",
        )


# ─────────────────────────────────────────────── 扫描器事件（无密钥）
@dataclass(frozen=True)
class Transfer:
    """扫描器交来的一条 ``Transfer`` 事件（已解析，不含任何签名材料）。"""

    chain_id: str
    tx_hash: str
    log_index: int
    block_number: int
    block_hash: str
    from_address: str
    to_address: str
    asset_contract: str
    qty_minor: int                      # 资产最小单位（USDT 6 位小数）
    confirmations: int = 0              # 扫描时看到的确认数
    tx_status: str = "success"          # success / reverted
    asset_decimals: int = ASSET_DECIMALS
    scanner_id: str = "scanner:unknown"

    @property
    def amount_minor(self) -> int:
        """折算成 USD micro：USDT 与 USD 1:1，按最小单位换算（§19.6.3「链上达确认数」）。"""
        return _to_usd_minor(self.qty_minor, self.asset_decimals)


def _to_usd_minor(qty_minor: int, decimals: int) -> int:
    if qty_minor <= 0:
        raise ChainIngestError(f"qty_minor 必须为正整数：{qty_minor}")
    if not 0 <= decimals <= 36:
        raise ChainIngestError(f"asset_decimals 越界：{decimals}")
    if decimals == UNIT_SCALE_USD:
        return qty_minor
    if decimals < UNIT_SCALE_USD:
        return qty_minor * 10 ** (UNIT_SCALE_USD - decimals)
    # 小数位多于 6：按 P3 在单笔层面截断（禁止先汇总后舍入）；截断为 0 说明低于记账精度，拒绝
    value = qty_minor // 10 ** (decimals - UNIT_SCALE_USD)
    if value <= 0:
        raise ChainIngestError(f"金额 {qty_minor}@{decimals} 位低于 USD micro 精度，拒绝入账")
    return value


def _hex(value: str, n: int, *, what: str) -> str:
    """归一化十六进制值：去空白、转小写、补 0x，长度必须匹配。"""
    if not isinstance(value, str) or not value.strip():
        raise ChainIngestError(f"{what} 不能为空")
    v = value.strip().lower()
    if not v.startswith("0x"):
        v = "0x" + v
    pat = _HEX40 if n == 40 else _HEX64
    if not pat.match(v):
        raise ChainIngestError(f"{what} 不是合法的 {n} 位十六进制：{value!r}")
    return v


def _normalize(tr: Transfer) -> Transfer:
    """大小写/格式归一：同一 tx 不因 scanner 写法不同被当成两笔（配合 DB 唯一键）。"""
    if not isinstance(tr, Transfer):
        raise ChainIngestError("observe 只接受 Transfer")
    if not str(tr.chain_id).strip():
        raise ChainIngestError("chain_id 不能为空")
    if tr.log_index < 0 or tr.block_number < 0:
        raise ChainIngestError("log_index / block_number 不能为负")
    if tr.confirmations < 0:
        raise ChainIngestError("confirmations 不能为负")
    tx_status = str(tr.tx_status).strip().lower()
    if tx_status in ("ok", "0x1", "1"):
        tx_status = "success"
    if tx_status in ("0x0", "0", "fail", "failed"):
        tx_status = "reverted"
    return replace(
        tr,
        chain_id=str(tr.chain_id).strip().lower(),
        tx_hash=_hex(tr.tx_hash, 64, what="tx_hash"),
        block_hash=_hex(tr.block_hash, 64, what="block_hash"),
        from_address=_hex(tr.from_address, 40, what="from_address"),
        to_address=_hex(tr.to_address, 40, what="to_address"),
        asset_contract=_hex(tr.asset_contract, 40, what="asset_contract"),
        tx_status=tx_status,
        scanner_id=str(tr.scanner_id or "scanner:unknown"),
    )


# ─────────────────────────────────────────────── secp256k1 / keccak256 / BIP32（纯公开数学生成，无密钥）
_MASK64 = (1 << 64) - 1
_P = 2**256 - 2**32 - 977                        # secp256k1 域素数（公开常量）
_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)   # 群阶
_G = (int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
      int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16))  # 生成元 G
_RC = (0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
_ROT = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _rol(value: int, n: int) -> int:
    value &= _MASK64
    return ((value << n) | (value >> (64 - n))) & _MASK64 if n else value


def _keccak_f(state: list[int]) -> None:
    for rnd in range(24):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x + 5 * y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Keccak-256（以太坊口径，padding 0x01…0x80；与 hashlib.sha3_256 不同）。"""
    rate = 136
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % rate:
        buf.append(0)
    buf[-1] ^= 0x80
    state = [0] * 25
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(buf[off + 8 * i: off + 8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def _padd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _P == 0:
            return None
        lam = 3 * p[0] * p[0] * pow(2 * p[1], _P - 2, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _P - 2, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return (x, (lam * (p[0] - x) - p[1]) % _P)


def _pmul(k: int, point=_G):
    result, addend = None, point
    k %= _N
    while k:
        if k & 1:
            result = _padd(result, addend)
        addend = _padd(addend, addend)
        k >>= 1
    return result


def _ser_pub(point) -> bytes:
    return (b"\x03" if point[1] & 1 else b"\x02") + point[0].to_bytes(32, "big")


def _de_pub(raw: bytes):
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ChainIngestError("压缩公钥格式非法（需要 33 字节 0x02/0x03 前缀）")
    x = int.from_bytes(raw[1:], "big")
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        raise ChainIngestError("公钥不在曲线上")
    if (y & 1) != (raw[0] & 1):
        y = _P - y
    return (x, y)


def _address_from_pub(raw_pub: bytes) -> str:
    x, y = _de_pub(raw_pub)
    digest = keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))
    return "0x" + digest[-20:].hex()


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = 0
    for byte in raw:
        if byte:
            break
        pad += 1
    return "1" * pad + out


def _b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        if ch not in _B58:
            raise ChainIngestError(f"xpub 含非法 base58 字符：{ch!r}")
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in text:
        if ch != "1":
            break
        pad += 1
    return b"\x00" * pad + raw


def _sha256d(raw: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


_XPUB_VERSION = b"\x04\x88\xb2\x1e"     # xpub（mainnet public）


def encode_xpub(pubkey: bytes, chain_code: bytes, *, depth: int = 3,
                parent_fingerprint: bytes = b"\x00\x00\x00\x00", child_number: int = 0) -> str:
    """把（公钥, 链码）编码成 xpub。**只接收公钥**，没有私钥入口。"""
    if len(pubkey) != 33 or len(chain_code) != 32 or len(parent_fingerprint) != 4:
        raise ChainIngestError("xpub 编码参数长度不对（pubkey 33 / chain_code 32 / parent_fp 4）")
    payload = (_XPUB_VERSION + bytes([depth]) + parent_fingerprint
               + int(child_number).to_bytes(4, "big") + chain_code + pubkey)
    return _b58encode(payload + _sha256d(payload)[:4])


@dataclass(frozen=True)
class _XpubNode:
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    pubkey: bytes


def parse_xpub(xpub: str) -> _XpubNode:
    """解析 xpub（校验 base58check + 版本字）。私钥版本（xprv）直接拒绝。"""
    if not isinstance(xpub, str) or not xpub.strip():
        raise ChainIngestError("xpub 为空")
    raw = _b58decode(xpub.strip())
    if len(raw) != 82:      # 78 字节负载 + 4 字节 base58check 校验和
        raise ChainIngestError(f"xpub 长度非法：{len(raw)}（应为 82 字节 = 78 负载 + 4 校验和）")
    if _sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ChainIngestError("xpub 校验和不对")
    if raw[:4] != _XPUB_VERSION:
        raise ChainIngestError("只接受 xpub（公开扩展公钥）；xprv / 私钥版本一律拒绝")
    return _XpubNode(depth=raw[4], parent_fingerprint=raw[5:9],
                     child_number=int.from_bytes(raw[9:13], "big"),
                     chain_code=raw[13:45], pubkey=raw[45:78])


def ckd_pub(node: _XpubNode, index: int) -> _XpubNode:
    """BIP32 非硬化子公钥派生（CKDpub）；硬化/私钥路径无法也不允许在此进行。"""
    if not 0 <= index < 2**31:
        raise ChainIngestError(f"派生索引必须在 [0, 2^31)：{index}（硬化派生需要私钥，本模块不支持）")
    digest = hmac.new(node.chain_code, node.pubkey + index.to_bytes(4, "big"), hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= _N:
        raise ChainIngestError("派生结果越界（可忽略概率事件），换下一个索引")
    child = _padd(_pmul(tweak), _de_pub(node.pubkey))
    if child is None:
        raise ChainIngestError("派生得到无穷远点（可忽略概率事件），换下一个索引")
    return _XpubNode(depth=node.depth + 1, parent_fingerprint=b"\x00\x00\x00\x00",
                     child_number=index, chain_code=digest[32:], pubkey=_ser_pub(child))


def derivation_path(index: int, *, change: int = 0) -> str:
    """标准以太坊外部链路径：m/44'/60'/0'/change/index（只有最后两段可从 xpub 派生）。"""
    if not 0 <= index < 2**31 or not 0 <= change < 2**31:
        raise ChainIngestError("派生索引越界")
    return f"m/44'/60'/0'/{change}/{index}"


def derive_address(xpub: str, index: int, *, change: int = 0) -> str:
    """由 xpub 派生收款地址（小写 0x）。输入只有公开材料，函数内无任何私钥。"""
    node = parse_xpub(xpub)
    node = ckd_pub(ckd_pub(node, change), index)
    return _address_from_pub(node.pubkey)


def xpub_fingerprint(xpub: str) -> str:
    """xpub 指纹（sha256 前 16 hex）：表里只存它，用于对账锚，不存 xpub 原文。"""
    parse_xpub(xpub)          # 先校验，避免把乱七八糟的字符串算成指纹
    return hashlib.sha256(xpub.strip().encode()).hexdigest()[:16]


# ─────────────────────────────────────────────── 账本网关（R2 的最小实现；哈希口径复用 app.ledger）
def ensure_chain_accounts(c) -> list[str]:
    """幂等建科目录（accounts.kind 既有取值里 platform 最贴近；不改 kind 的 CHECK）。"""
    with c.cursor() as cur:
        cur.executemany(
            "INSERT INTO accounts (id, kind) VALUES (%s, 'platform') ON CONFLICT (id) DO NOTHING",
            [(a,) for a in _CHAIN_ACCOUNTS])
    return list(_CHAIN_ACCOUNTS)


def _append_entry(c, *, debit: str, credit: str, amount_micro: int, memo: str, entry_type: str,
                  source_type: str, source_id: str, event_seq: int, line_no: int,
                  ref_id: str | None = None, policy_version: str | None = None,
                  qty_minor: int | None = None, reverse_of: str | None = None) -> dict:
    """写一条只追加分录（含元数据列）。

    与 ``app.ledger.post_entry`` 的分工：哈希链算法完全复用 ``ledger.entry_hash``，余额更新口径一致；
    额外写 entry_type / source_* / reverse_of（§20.4.3 R1 允许加列），并用事务级 advisory lock
    串行化追加，避免并发下 prev_hash 分叉（``recompute`` 会因此报 chain_bad）。
    """
    if amount_micro <= 0:
        raise ChainIngestError("amount_micro 必须 > 0")
    with c.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (_LEDGER_APPEND_LOCK,))
        cur.execute("SELECT hash FROM ledger_entries ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else None
        digest = entry_hash(prev, debit, credit, amount_micro, memo)
        cur.execute(
            """INSERT INTO ledger_entries
                 (debit, credit, amount_micro, memo, prev_hash, hash, entry_type, unit_type, ref_id,
                  status, policy_version, qty_minor, source_type, source_id, event_seq, line_no, reverse_of)
               VALUES (%s,%s,%s,%s,%s,%s,%s,'USD',%s,'settled',%s,%s,%s,%s,%s,%s,%s)
               RETURNING seq, entry_id""",
            (debit, credit, amount_micro, memo, prev, digest, entry_type, ref_id,
             policy_version, qty_minor, source_type, source_id, event_seq, line_no, reverse_of))
        seq, entry_id = cur.fetchone()
        cur.execute("UPDATE accounts SET balance_micro = balance_micro - %s WHERE id = %s",
                    (amount_micro, debit))
        if cur.rowcount != 1:
            raise ChainIngestError(f"账本科目不存在：{debit}")
        cur.execute("UPDATE accounts SET balance_micro = balance_micro + %s WHERE id = %s",
                    (amount_micro, credit))
        if cur.rowcount != 1:
            raise ChainIngestError(f"账本科目不存在：{credit}")
    return {"seq": seq, "entry_id": str(entry_id), "hash": digest, "event_seq": event_seq, "line_no": line_no}


# ─────────────────────────────────────────────── 表操作
def _find_deposit_address(c, tr: Transfer):
    with c.cursor() as cur:
        cur.execute("""SELECT address_id, account_id, purpose, status, assign_expires_at
                         FROM deposit_address WHERE chain_id = %s AND address = %s""",
                    (tr.chain_id, tr.to_address))
        return cur.fetchone()


def _verdict(tr: Transfer, deposit, now: datetime) -> tuple[str, str | None]:
    """入账前判定：ok / hold（可挂账）/ reject（完全不入账）。"""
    if tr.chain_id != CHAIN_ID:
        return "reject", "wrong_chain"          # §19.6.1：错链不自动入账
    if tr.asset_contract != ASSET_CONTRACT:
        return "reject", "fake_token"           # 只认 USDT 合约地址（防假币）
    if tr.tx_status != "success":
        return "reject", "tx_failed"            # 失败/回滚的 tx 不入账
    if deposit is None:
        return "reject", "unknown_address"      # 不是我们的地址 → 人工工单
    purpose, _status, expires_at = deposit[2], deposit[3], deposit[4]
    if purpose == "one_time" and expires_at is not None and expires_at < now:
        return "hold", "one_time_expired"        # 一次性地址过期 → 挂账人工复核
    return "ok", None


def _insert_chain_tx(c, tr: Transfer, deposit, required: int, policy_version: str,
                     amount_minor: int, now: datetime) -> tuple[str, bool]:
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO chain_tx
                 (chain_id, tx_hash, log_index, block_number, block_hash, from_address, to_address,
                  asset_contract, asset_decimals, qty_minor, amount_minor, unit_type,
                  required_confirmations, policy_version, deposit_address_id, account_id, scanner_id, detected_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'USD',%s,%s,%s,%s,%s,%s)
               ON CONFLICT (chain_id, tx_hash, log_index) DO NOTHING
               RETURNING chain_tx_id""",
            (tr.chain_id, tr.tx_hash, tr.log_index, tr.block_number, tr.block_hash,
             tr.from_address, tr.to_address, tr.asset_contract, tr.asset_decimals, tr.qty_minor,
             amount_minor, required, policy_version,
             deposit[0] if deposit else None, deposit[1] if deposit else None,
             tr.scanner_id, now))
        row = cur.fetchone()
    if row:
        return str(row[0]), True
    with c.cursor() as cur:
        cur.execute("SELECT chain_tx_id FROM chain_tx WHERE chain_id=%s AND tx_hash=%s AND log_index=%s",
                    (tr.chain_id, tr.tx_hash, tr.log_index))
        return str(cur.fetchone()[0]), False


def _record_event(c, chain_tx_id: str, event: str, *, confirmations: int = 0, block_hash: str | None = None,
                  reason_code: str | None = None, payload: dict | None = None,
                  actor: str = ACTOR_DEFAULT) -> bool:
    """写事件；有唯一索引的事件（detected/observed/confirmed/rejected/void）天然幂等。"""
    sql = ("INSERT INTO chain_tx_event (chain_tx_id, event, confirmations, block_hash, reason_code, actor, payload) "
           "VALUES (%s,%s,%s,%s,%s,%s,%s)")
    target = _EVENT_CONFLICT.get(event)
    if target:
        sql += f" ON CONFLICT {target} DO NOTHING"
    sql += " RETURNING seq"
    with c.cursor() as cur:
        cur.execute(sql, (chain_tx_id, event, confirmations, block_hash, reason_code, actor, Jsonb(payload or {})))
        return cur.fetchone() is not None


def state(c, chain_tx_id: str) -> dict | None:
    """链上 tx 的推导状态（confirmations / status / confirmed / voided）。"""
    with c.cursor() as cur:
        cur.execute("""SELECT chain_tx_id, chain_id, tx_hash, log_index, block_number, block_hash, to_address,
                              account_id, qty_minor, amount_minor, required_confirmations, policy_version,
                              confirmations, confirmed, voided, rejected, status, last_event_at
                         FROM chain_tx_state WHERE chain_tx_id = %s""", (chain_tx_id,))
        row = cur.fetchone()
        if not row:
            return None
        cols = [d.name for d in cur.description]
    out = dict(zip(cols, row))
    out["chain_tx_id"] = str(out["chain_tx_id"])
    return out


def _source_id(tr: Transfer) -> str:
    """账本幂等键的 source_id。

    §20.3.1 的 E1/E2 幂等键写作 ``chain_tx / tx_hash / 1|2``；但同一笔 tx 可以有**多条** Transfer
    日志（log_index 不同）——那是多笔入金，必须各自入账。只用 tx_hash 会被幂等键吞掉第二笔（漏账），
    因此这里用 ``tx_hash#log_index``：可读、且与 chain_tx 的唯一键 (chain_id, tx_hash, log_index) 对齐。
    """
    return f"{tr.tx_hash}#{tr.log_index}"


def _post_e1(c, tr: Transfer, chain_tx_id: str, amount_minor: int, policy_version: str) -> dict:
    """E1：检测到（0 确认）→ 借 1111 在途 / 贷 2990 确认中充值。"""
    ensure_chain_accounts(c)
    return _append_entry(
        c, debit=COA["pending_deposit"], credit=COA["in_transit"], amount_micro=amount_minor,
        memo=f"E1 链上在途 {tr.tx_hash}#{tr.log_index}",
        entry_type="deposit", source_type="chain_tx", source_id=_source_id(tr), event_seq=1, line_no=1,
        ref_id=chain_tx_id, policy_version=policy_version, qty_minor=tr.qty_minor)


def _post_e2(c, tr: Transfer, chain_tx_id: str, amount_minor: int, policy_version: str) -> list[dict]:
    """E2：达确认数 → 在途转客户资金热钱包 + 确认中充值转服务预付款。"""
    ensure_chain_accounts(c)
    memo = f"E2 确认入账 {tr.tx_hash}#{tr.log_index} ({tr.confirmations} 确认)"
    first = _append_entry(
        c, debit=COA["in_transit"], credit=COA["hot_wallet"], amount_micro=amount_minor,
        memo=memo + " · 在途→客户资金热钱包",
        entry_type="deposit", source_type="chain_tx", source_id=_source_id(tr), event_seq=2, line_no=1,
        ref_id=chain_tx_id, policy_version=policy_version, qty_minor=tr.qty_minor)
    second = _append_entry(
        c, debit=COA["service_prepaid"], credit=COA["pending_deposit"], amount_micro=amount_minor,
        memo=memo + " · 确认中充值→服务预付款",
        entry_type="deposit", source_type="chain_tx", source_id=_source_id(tr), event_seq=2, line_no=2,
        ref_id=chain_tx_id, policy_version=policy_version, qty_minor=tr.qty_minor)
    return [first, second]


# ─────────────────────────────────────────────── 对外：扫描入账
def observe(c, transfer: Transfer, *, scanner_id: str | None = None,
            policy: ConfirmationPolicy | None = None, enabled: bool | None = None,
            now: datetime | None = None) -> dict:
    """处理扫描器的一次观察（幂等）。

    流程：开关 → 归一化 → 判定（错链/假币/未知地址/失败 tx）→ 去重插入 chain_tx →
    （首见）E1 → 达确认数则 E2。重复观察不会重复入账；两个扫描器并发只有一个能写成功。
    """
    if not flag_enabled("polygon_ingest", override=enabled):
        return {"action": "skipped", "reason": "flag_disabled", "chain_tx_id": None,
                "posted": [], "dedupe_hit": False}

    policy = policy or ConfirmationPolicy.from_env()
    if scanner_id:
        transfer = replace(transfer, scanner_id=scanner_id)
    tr = _normalize(transfer)
    now = now or datetime.now(timezone.utc)
    amount_minor = tr.amount_minor
    required = policy.required_for(amount_minor)
    deposit = _find_deposit_address(c, tr)
    verdict, reason = _verdict(tr, deposit, now)

    chain_tx_id, created = _insert_chain_tx(c, tr, deposit, required, policy.version, amount_minor, now)
    posted: list[dict] = []

    if created:
        _record_event(c, chain_tx_id, "detected", confirmations=tr.confirmations, block_hash=tr.block_hash)
        if verdict == "reject":
            _record_event(c, chain_tx_id, "rejected", confirmations=tr.confirmations,
                          block_hash=tr.block_hash, reason_code=reason,
                          payload={"scanner_id": tr.scanner_id, "chain_id": tr.chain_id,
                                   "asset_contract": tr.asset_contract, "tx_status": tr.tx_status})
            st = state(c, chain_tx_id)
            return {"action": "rejected", "reason": reason, "chain_tx_id": chain_tx_id,
                    "status": st["status"], "posted": posted, "dedupe_hit": False,
                    "confirmations": tr.confirmations, "required_confirmations": required}
        if verdict == "hold":
            _record_event(c, chain_tx_id, "held", confirmations=tr.confirmations,
                          block_hash=tr.block_hash, reason_code=reason,
                          payload={"scanner_id": tr.scanner_id})
            st = state(c, chain_tx_id)
            return {"action": "held", "reason": reason, "chain_tx_id": chain_tx_id,
                    "status": st["status"], "posted": posted, "dedupe_hit": False,
                    "confirmations": tr.confirmations, "required_confirmations": required}
        posted.append(_post_e1(c, tr, chain_tx_id, amount_minor, policy.version))

    st = state(c, chain_tx_id)
    if st is None:  # pragma: no cover - 事务内刚插入，不可能读不到
        raise ChainIngestError("chain_tx 状态读取失败")

    if st["voided"] or st["rejected"]:
        return {"action": "duplicate", "reason": st["status"], "chain_tx_id": chain_tx_id,
                "status": st["status"], "posted": posted, "dedupe_hit": not created,
                "confirmations": st["confirmations"], "required_confirmations": st["required_confirmations"]}

    # reorg 保护：块哈希变了但确认数已够 → 不确认，记 reorged，等人工/下一轮重扫
    if tr.confirmations >= st["required_confirmations"] and tr.block_hash != st["block_hash"]:
        _record_event(c, chain_tx_id, "reorged", confirmations=tr.confirmations, block_hash=tr.block_hash,
                      reason_code="block_hash_mismatch",
                      payload={"expected": st["block_hash"], "got": tr.block_hash, "scanner_id": tr.scanner_id})
        return {"action": "reorged", "reason": "block_hash_mismatch", "chain_tx_id": chain_tx_id,
                "status": st["status"], "posted": posted, "dedupe_hit": not created,
                "confirmations": tr.confirmations, "required_confirmations": st["required_confirmations"]}

    action = "e1" if posted else "duplicate"
    if tr.confirmations >= st["required_confirmations"]:
        # 谁能抢到 confirmed 事件，谁负责写 E2（并发下只有一个成功）
        if _record_event(c, chain_tx_id, "confirmed", confirmations=tr.confirmations,
                         block_hash=tr.block_hash,
                         payload={"scanner_id": tr.scanner_id, "amount_minor": amount_minor,
                                  "required_confirmations": st["required_confirmations"]}):
            posted.extend(_post_e2(c, tr, chain_tx_id, amount_minor, policy.version))
            action = "e2"
    elif tr.confirmations > 0:
        if _record_event(c, chain_tx_id, "observed", confirmations=tr.confirmations, block_hash=tr.block_hash,
                         payload={"scanner_id": tr.scanner_id}):
            action = "observed" if action == "duplicate" else action

    st = state(c, chain_tx_id)
    return {"action": action, "reason": None, "chain_tx_id": chain_tx_id, "status": st["status"],
            "posted": posted, "dedupe_hit": not created,
            "confirmations": st["confirmations"], "required_confirmations": st["required_confirmations"]}


def ingest(c, transfers: Iterable[Transfer], *, scanner_id: str | None = None,
           policy: ConfirmationPolicy | None = None, enabled: bool | None = None,
           now: datetime | None = None) -> list[dict]:
    """批量扫描入口：同一事务内逐条 ``observe``（任一条失败整批回滚）。"""
    policy = policy or ConfirmationPolicy.from_env()
    return [observe(c, tr, scanner_id=scanner_id, policy=policy, enabled=enabled, now=now)
            for tr in transfers]


# ─────────────────────────────────────────────── 对外：错链 / 假充值冲正
def _posted_entries(c, chain_tx_id: str) -> list[dict]:
    with c.cursor() as cur:
        cur.execute(
            """SELECT seq, entry_id, debit, credit, amount_micro, qty_minor, event_seq, line_no
                 FROM ledger_entries
                WHERE source_type = 'chain_tx' AND ref_id = %s
                ORDER BY seq""", (chain_tx_id,))
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def void_deposit(c, *, chain_tx_id: str, reason_code: str, actor: str = "ops:manual",
                 note: str | None = None) -> dict:
    """错链 / 假充值 / 误报 → 冲正（§20.4.6 / E16 / R5 / B6）。

    - 只新增反向分录，**不 UPDATE/DELETE 原分录**；每条反向分录 ``reverse_of`` 指向原 entry_id；
    - 每条原 journal 至多冲正一次（``chain_tx_event`` 的 void 唯一索引 + ledger 幂等键双保险）；
    - 冲正不受 ``polygon_ingest`` 开关影响：开关关闭只停「扫描/入账」，纠错路径必须一直在。
    """
    if not reason_code or not str(reason_code).strip():
        raise ChainIngestError("void 必须给 reason_code（wrong_chain / fake_token / reorg / ...）")
    with c.cursor() as cur:
        cur.execute("""SELECT chain_tx_id, chain_id, tx_hash, log_index, amount_minor, policy_version
                         FROM chain_tx WHERE chain_tx_id = %s""", (chain_tx_id,))
        tx = cur.fetchone()
    if not tx:
        raise ChainIngestError(f"chain_tx 不存在：{chain_tx_id}")
    tx_hash, policy_version = tx[2], tx[5]

    originals = _posted_entries(c, chain_tx_id)
    payload = {
        "reason_code": reason_code,
        "note": note,
        "reversed": [{"seq": r["seq"], "entry_id": str(r["entry_id"]), "event_seq": r["event_seq"],
                      "line_no": r["line_no"]} for r in originals],
        "tx_hash": tx_hash,
    }
    if not _record_event(c, chain_tx_id, "void", reason_code=reason_code, actor=actor, payload=payload):
        return {"action": "already_voided", "chain_tx_id": chain_tx_id, "reversed": []}

    reversed_entries = []
    for i, original in enumerate(reversed(originals), start=1):   # 逆序取反，便于人读
        reversed_entries.append(_append_entry(
            c, debit=original["credit"], credit=original["debit"],
            amount_micro=original["amount_micro"],
            memo=f"E16 冲正({reason_code}) {tx_hash}#{tx[3]} → seq={original['seq']}",
            entry_type="void", source_type="void", source_id=chain_tx_id, event_seq=1, line_no=i,
            ref_id=chain_tx_id, policy_version=policy_version,
            qty_minor=original["qty_minor"], reverse_of=str(original["entry_id"])))
    st = state(c, chain_tx_id)
    return {"action": "void", "reason": reason_code, "chain_tx_id": chain_tx_id,
            "status": st["status"], "reversed": reversed_entries,
            "reversed_count": len(reversed_entries)}


# ─────────────────────────────────────────────── 对外：地址分配（HD，仅 xpub）
def assign_deposit_address(c, *, account_id: str, xpub: str, index: int | None = None,
                           purpose: str = "user_deposit", chain_id: str = CHAIN_ID,
                           expires_at: datetime | None = None, wallet_id: str | None = None,
                           enabled: bool | None = None) -> dict:
    """给主体分配一个 HD 派生收款地址（不再复用；retired 不复活）。

    只接受 ``xpub``（公开扩展公钥）；私钥/助记词没有入口，表里也只存派生路径与 xpub 指纹。
    """
    if not flag_enabled("polygon_ingest", override=enabled):
        return {"action": "skipped", "reason": "flag_disabled", "address": None}
    if not account_id or not str(account_id).strip():
        raise ChainIngestError("account_id 必填")
    fingerprint = xpub_fingerprint(xpub)
    with c.cursor() as cur:
        # 同链串行发号，避免并发分配撞同一个 derivation_index
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"djb:deposit_address:{chain_id}",))
        if index is None:
            cur.execute("""SELECT COALESCE(max(derivation_index), -1) + 1
                             FROM deposit_address WHERE chain_id = %s""", (chain_id,))
            index = int(cur.fetchone()[0])
        address = derive_address(xpub, int(index))
        # ON CONFLICT DO NOTHING 不指定仲裁者：地址唯一 / 派生路径唯一 / 每主体一条活跃 三种冲突
        # 都收敛成同一个结果（不写入），由下面统一解释成人话错误，不把 DB 异常抛给调用方。
        cur.execute(
            """INSERT INTO deposit_address
                 (chain_id, address, account_id, purpose, derivation_path, derivation_index,
                  xpub_fingerprint, wallet_id, status, assign_expires_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'active',%s)
               ON CONFLICT DO NOTHING
               RETURNING address_id""",
            (chain_id, address, account_id, purpose, derivation_path(int(index)), int(index),
             fingerprint, wallet_id, expires_at))
        row = cur.fetchone()
        if not row:
            cur.execute(
                """SELECT address_id, account_id, status, derivation_path FROM deposit_address
                    WHERE address = %s
                       OR (chain_id = %s AND derivation_index = %s)
                       OR (chain_id = %s AND account_id = %s AND status = 'active')
                    LIMIT 1""",
                (address, chain_id, int(index), chain_id, account_id))
            clash = cur.fetchone()
    if not row:
        if clash and clash[1] != account_id:
            raise ChainIngestError(f"地址不复用：{address} 已属于 {clash[1]}（§19.6.1 / I-10）")
        if clash and clash[2] == "active":
            raise ChainIngestError(f"主体 {account_id} 已有活跃收款地址 {clash[3]}（每用户一个活跃地址）")
        raise ChainIngestError(f"HD 派生索引 {index} 已被占用（{address}），请换索引")
    return {"action": "assigned", "address_id": str(row[0]), "address": address,
            "account_id": account_id, "derivation_path": derivation_path(int(index)),
            "derivation_index": int(index), "xpub_fingerprint": fingerprint,
            "chain_id": chain_id, "purpose": purpose}
