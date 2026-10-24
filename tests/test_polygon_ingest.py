# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-0002 · Polygon 收款与确认（E1/E2 · 64/200 确认）。

覆盖验收：
  ① 0 确认只记 E1（在途），达 64 确认转 E2；
  ② 大额 200 确认、阈值可配、确认数不得低于 64（红线 fail-closed）；
  ③ 同一 (chain_id, tx_hash, log_index) 被两个扫描器并发发现只入账一次；
  ④ deposit_address 唯一、地址派生不落私钥；
  ⑤ 错链 / 假充值走 ``void`` + ``reverse_of``，原分录不删不改；
  ⑥ 每处写账本都断言 ``recompute diff=0``（含迁移前后指纹不变）；
  ⑦ 新行为默认关闭，开关 ``polygon_ingest`` 三字段齐全。

数据库：用 ``DJB_DSN`` 指向的开发库；库不可达时整文件 skip。
注意：``chain_tx`` / ``chain_tx_event`` / ``ledger_entries`` 都是只追加表，
用例不删除历史行——每个用例用随机 tx_hash / 账户，断言只做**增量**比较。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

import psycopg
import pytest

from app import db
from app.chain import FEATURE_FLAGS, flag_enabled, flag_spec
from app.chain import polygon as P
from app.config import dsn
from app.ledger import recompute

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "005_chain.sql"
# 测试用 xpub：由公开材料（secp256k1 生成元 G + 固定链码）编码而成，不含任何私钥
XPUB = P.encode_xpub(P._ser_pub(P._G), b"\x01" * 32)
USDT = P.ASSET_CONTRACT
NOW = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
USD = 1_000_000                      # 1 USD = 1e6 micro
LARGE = 5_000 * USD                  # 5,000 USD ≥ 默认大额阈值 1,000 USD


# ───────────────────────────────────────────────────────────── 基础设施
@pytest.fixture(scope="module", autouse=True)
def _schema():
    if not os.environ.get("DJB_DSN"):
        pytest.skip("缺 DJB_DSN：开发库未注入")
    try:
        conn = psycopg.connect(dsn(), autocommit=True)
    except psycopg.OperationalError as exc:          # pragma: no cover - 环境缺库
        pytest.skip(f"开发库不可达：{exc}")
    with conn:
        conn.execute(MIGRATION.read_text(encoding="utf-8"))     # 幂等：重复应用无副作用


def _hex(n: int = 32) -> str:
    return "0x" + (uuid.uuid4().hex * 2)[: n * 2]


def _account(tag: str = "u") -> str:
    """每个用例一个独立主体 + 独立地址，互不干扰（地址唯一约束按主体判活跃）。"""
    return f"user:dev0002-{tag}-{uuid.uuid4().hex[:10]}"


def _assign(account: str | None = None, *, index: int | None = None, purpose: str = "user_deposit",
            expires_at: datetime | None = None) -> dict:
    account = account or _account()
    with db.conn() as c:
        return P.assign_deposit_address(c, account_id=account, xpub=XPUB, index=index,
                                        purpose=purpose, expires_at=expires_at, enabled=True)


def _transfer(to_address: str, *, qty: int = 100 * USD, confirmations: int = 0,
              tx_hash: str | None = None, log_index: int = 0, chain_id: str = P.CHAIN_ID,
              asset: str = USDT, block_hash: str | None = None, block_number: int = 60_000_000,
              status: str = "success", scanner: str = "scanner:a") -> P.Transfer:
    tx_hash = tx_hash or _hex()
    return P.Transfer(
        chain_id=chain_id, tx_hash=tx_hash, log_index=log_index, block_number=block_number,
        block_hash=block_hash or "0x" + hashlib.sha256(tx_hash.encode()).hexdigest(),
        from_address=_hex(20), to_address=to_address, asset_contract=asset, qty_minor=qty,
        confirmations=confirmations, tx_status=status, scanner_id=scanner)


def _balances(c, accounts=P._CHAIN_ACCOUNTS) -> dict[str, int]:
    with c.cursor() as cur:
        cur.execute("SELECT id, balance_micro FROM accounts WHERE id = ANY(%s)", (list(accounts),))
        rows = dict(cur.fetchall())
    return {a: rows.get(a, 0) for a in accounts}


def _entries_of(c, chain_tx_id: str) -> list[dict]:
    with c.cursor() as cur:
        cur.execute(
            """SELECT seq, entry_id, entry_type, debit, credit, amount_micro, memo, hash,
                      source_type, source_id, event_seq, line_no, reverse_of, policy_version
                 FROM ledger_entries WHERE ref_id = %s ORDER BY seq""", (chain_tx_id,))
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _chain_tx_rows(c, tx_hash: str) -> list[tuple]:
    with c.cursor() as cur:
        cur.execute("""SELECT chain_tx_id, chain_id, tx_hash, log_index, required_confirmations,
                              amount_minor, policy_version FROM chain_tx WHERE tx_hash = %s""", (tx_hash,))
        return cur.fetchall()


def _events(c, chain_tx_id: str) -> list[tuple]:
    with c.cursor() as cur:
        cur.execute("SELECT event, confirmations, reason_code FROM chain_tx_event "
                    "WHERE chain_tx_id = %s ORDER BY seq", (chain_tx_id,))
        return cur.fetchall()


def _ledger_fingerprint(c) -> dict:
    with c.cursor() as cur:
        cur.execute("SELECT seq, debit, credit, amount_micro, memo, prev_hash, hash "
                    "FROM ledger_entries ORDER BY seq")
        entries = cur.fetchall()
        cur.execute("SELECT id, kind, balance_micro FROM accounts ORDER BY id")
        accounts = cur.fetchall()
    blob = repr((entries, accounts)).encode()
    return {"entries": len(entries), "accounts": len(accounts),
            "sha256": hashlib.sha256(blob).hexdigest()}


def _assert_ledger_sound() -> dict:
    """账本必须自洽：hash 链连续、余额=Σ贷−Σ借、全表 Σ余额=0、diff=0。"""
    with db.conn() as c:
        rep = recompute(c)
        with c.cursor() as cur:
            cur.execute("SELECT COALESCE(sum(balance_micro), 0) FROM accounts")
            total = cur.fetchone()[0]
    assert rep["diff"] == 0, rep
    assert rep["chain_bad"] == [] and rep["balance_bad"] == {}, rep
    assert total == 0, f"Σ余额 = {total}（转账账本必须恒为 0）"
    return rep


# ───────────────────────────────────────────────────────────── ⑦ 开关（默认关闭 + 三字段）
def test_flag_is_off_by_default_with_three_fields(monkeypatch):
    spec = flag_spec("polygon_ingest")
    assert spec["default"] is False
    assert spec["owner"] == "chain-dev"
    assert spec["expire_at"] == "2026-12-31"
    assert "停止扫描" in spec["rollback_rule"] and "冲正" in spec["rollback_rule"]
    assert set(("owner", "expire_at", "rollback_rule")) <= set(spec)

    monkeypatch.delenv("DJB_FF_POLYGON_INGEST", raising=False)
    assert flag_enabled("polygon_ingest") is False
    monkeypatch.setenv("DJB_FF_POLYGON_INGEST", "1")
    assert flag_enabled("polygon_ingest") is True
    monkeypatch.setenv("DJB_FF_POLYGON_INGEST", "off")
    assert flag_enabled("polygon_ingest") is False
    # expire_at 到期即强制为关（fail-closed），不允许静默续期
    assert flag_enabled("polygon_ingest", override=True, today=date(2027, 1, 1)) is False
    assert FEATURE_FLAGS["polygon_ingest"]["default"] is False


def test_flag_off_writes_no_chain_or_ledger_rows():
    addr = _assign()["address"]
    before = _ledger_fingerprint_of_module()
    tr = _transfer(addr, confirmations=64)
    with db.conn() as c:
        out = P.observe(c, tr, enabled=False)
    assert out["action"] == "skipped" and out["reason"] == "flag_disabled"
    with db.conn() as c:
        assert _chain_tx_rows(c, tr.tx_hash) == []
        with c.cursor() as cur:
            cur.execute("SELECT count(*) FROM ledger_entries WHERE source_id LIKE %s", (tr.tx_hash + "#%",))
            assert cur.fetchone()[0] == 0
    assert _ledger_fingerprint_of_module() == before      # 一个字节都没动
    _assert_ledger_sound()


def _ledger_fingerprint_of_module() -> dict:
    with db.conn() as c:
        return _ledger_fingerprint(c)


# ───────────────────────────────────────────────────────────── ① E1 → E2（0 确认 / 64 确认）
def test_zero_confirmations_records_only_e1_in_transit():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=100 * USD, confirmations=0)
    with db.conn() as c:
        before = _balances(c)
        out = P.observe(c, tr, enabled=True)
    assert out["action"] == "e1" and len(out["posted"]) == 1
    cid = out["chain_tx_id"]
    with db.conn() as c:
        entries = _entries_of(c, cid)
        after = _balances(c)
    assert len(entries) == 1
    e1 = entries[0]
    assert (e1["entry_type"], e1["source_type"], e1["event_seq"], e1["line_no"]) == ("deposit", "chain_tx", 1, 1)
    assert (e1["debit"], e1["credit"], e1["amount_micro"]) == (P.COA["pending_deposit"], P.COA["in_transit"], 100 * USD)
    # 在途：1111 +100，2990 −100；热钱包 / 服务预付款未动
    assert after[P.COA["in_transit"]] - before[P.COA["in_transit"]] == 100 * USD
    assert after[P.COA["pending_deposit"]] - before[P.COA["pending_deposit"]] == -100 * USD
    assert after[P.COA["hot_wallet"]] == before[P.COA["hot_wallet"]]
    assert after[P.COA["service_prepaid"]] == before[P.COA["service_prepaid"]]
    _assert_ledger_sound()


def test_64_confirmations_promotes_e1_to_e2_exactly_once():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=100 * USD)
    with db.conn() as c:
        before = _balances(c)
        out = P.observe(c, tr, enabled=True)
        cid = out["chain_tx_id"]
        # 63 确认：仍然只有 E1（在途）
        for conf in (1, 32, 63):
            mid = P.observe(c, _transfer(addr, qty=100 * USD, tx_hash=tr.tx_hash, confirmations=conf),
                            enabled=True)
            assert mid["action"] == "observed", mid
        assert len(_entries_of(c, cid)) == 1
        # 64 确认：转 E2（两条转账对 = 设计 E2 的四行分录）
        done = P.observe(c, _transfer(addr, qty=100 * USD, tx_hash=tr.tx_hash, confirmations=64), enabled=True)
        assert done["action"] == "e2" and len(done["posted"]) == 2
        # 重复观察 / 更多确认：绝不重复入账
        again = P.observe(c, _transfer(addr, qty=100 * USD, tx_hash=tr.tx_hash, confirmations=64), enabled=True)
        assert again["action"] == "duplicate" and again["posted"] == []
        more = P.observe(c, _transfer(addr, qty=100 * USD, tx_hash=tr.tx_hash, confirmations=512), enabled=True)
        assert more["posted"] == []
        entries = _entries_of(c, cid)
        after = _balances(c)
    assert len(entries) == 3, entries
    e2 = [e for e in entries if e["event_seq"] == 2]
    assert [(e["line_no"], e["debit"], e["credit"]) for e in e2] == [
        (1, P.COA["in_transit"], P.COA["hot_wallet"]),
        (2, P.COA["service_prepaid"], P.COA["pending_deposit"]),
    ]
    # E2 之后：在途与确认中充值清零，客户资金 +100，服务预付款 −100（负债）
    assert after[P.COA["in_transit"]] == before[P.COA["in_transit"]]
    assert after[P.COA["pending_deposit"]] == before[P.COA["pending_deposit"]]
    assert after[P.COA["hot_wallet"]] - before[P.COA["hot_wallet"]] == 100 * USD
    assert after[P.COA["service_prepaid"]] - before[P.COA["service_prepaid"]] == -100 * USD
    # 状态与事件流
    with db.conn() as c:
        st = P.state(c, cid)
        evs = _events(c, cid)
    assert st["status"] == "confirmed" and st["confirmed"] and st["confirmations"] == 64
    assert [e[0] for e in evs].count("confirmed") == 1
    assert [e[0] for e in evs].count("detected") == 1
    _assert_ledger_sound()


# ───────────────────────────────────────────────────────────── ② 大额 200 确认 + 可配 + 红线
def test_large_amount_needs_200_confirmations_and_threshold_is_configurable():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=LARGE)
    with db.conn() as c:
        out = P.observe(c, tr, enabled=True)
        cid = out["chain_tx_id"]
    with db.conn() as c:
        rows = _chain_tx_rows(c, tr.tx_hash)
    assert rows[0][4] == 200, rows          # required_confirmations 落库 = 200
    with db.conn() as c:
        for conf in (64, 199):
            mid = P.observe(c, _transfer(addr, qty=LARGE, tx_hash=tr.tx_hash, confirmations=conf), enabled=True)
            assert mid["action"] == "observed", mid
        assert len(_entries_of(c, cid)) == 1        # 只有 E1
        done = P.observe(c, _transfer(addr, qty=LARGE, tx_hash=tr.tx_hash, confirmations=200), enabled=True)
        assert done["action"] == "e2"
        assert len(_entries_of(c, cid)) == 3
        st = P.state(c, cid)
    assert st["required_confirmations"] == 200 and st["status"] == "confirmed"
    _assert_ledger_sound()

    # 阈值可配：把大额阈值降到 50 USD → 100 USD 的单子就要 200 确认
    tight = P.ConfirmationPolicy(large_amount_minor=50 * USD)
    assert tight.required_for(100 * USD) == 200
    assert tight.required_for(49 * USD) == 64
    # 环境变量可配
    env_policy = P.ConfirmationPolicy.from_env({
        "DJB_CHAIN_CONFIRMATIONS_NORMAL": "96", "DJB_CHAIN_CONFIRMATIONS_LARGE": "240",
        "DJB_CHAIN_LARGE_AMOUNT_MINOR": str(2_000 * USD)})
    assert (env_policy.normal, env_policy.large, env_policy.required_for(2_000 * USD)) == (96, 240, 240)
    assert "96/240" in env_policy.version

    # 红线：确认数不得低于 64 / 大额不得低于常规 / 阈值必须为正 → fail-closed
    for bad in ({"normal": 32}, {"normal": 64, "large": 63}, {"large_amount_minor": 0}):
        with pytest.raises(P.ChainIngestError):
            P.ConfirmationPolicy(**bad)


# ───────────────────────────────────────────────────────────── ③ 双扫描器并发只入账一次
def test_two_scanners_find_same_tx_but_only_one_posting():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=200 * USD)

    def scan(conf, scanner):
        with db.conn() as c:
            return P.observe(c, _transfer(addr, qty=200 * USD, tx_hash=tr.tx_hash,
                                          confirmations=conf, scanner=scanner), enabled=True)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = list(pool.map(lambda s: scan(0, s), ("scanner:rpc-a", "scanner:rpc-b")))
    cids = {r["chain_tx_id"] for r in first}
    assert len(cids) == 1, first
    cid = cids.pop()
    assert sum(1 for r in first if r["posted"]) == 1, first     # 只有一个扫描器写了 E1

    with ThreadPoolExecutor(max_workers=2) as pool:
        second = list(pool.map(lambda s: scan(64, s), ("scanner:rpc-a", "scanner:rpc-b")))
    assert sum(len(r["posted"]) for r in second) == 2, second    # E2 只写一次（两条）

    with db.conn() as c:
        assert len(_chain_tx_rows(c, tr.tx_hash)) == 1           # 唯一键 (chain_id, tx_hash, log_index)
        entries = _entries_of(c, cid)
        evs = _events(c, cid)
    assert len(entries) == 3, entries
    assert [e[0] for e in evs].count("detected") == 1
    assert [e[0] for e in evs].count("confirmed") == 1
    _assert_ledger_sound()

    # 另一扫描器用不同大小写/不同 log_index 报告：前者归一为同一 tx，后者是另一条日志
    with db.conn() as c:
        dup = P.observe(c, _transfer(addr, qty=200 * USD, tx_hash=tr.tx_hash.upper().replace("0X", "0x"),
                                     confirmations=64, scanner="scanner:rpc-c"), enabled=True)
    assert dup["dedupe_hit"] is True and dup["posted"] == []
    with db.conn() as c:
        other_log = P.observe(c, _transfer(addr, qty=200 * USD, tx_hash=tr.tx_hash, log_index=7,
                                           confirmations=0, scanner="scanner:rpc-c"), enabled=True)
    assert other_log["chain_tx_id"] != cid and len(other_log["posted"]) == 1
    _assert_ledger_sound()


# ───────────────────────────────────────────────────────────── ④ 地址唯一 + 派生不落私钥
def test_deposit_address_is_unique_and_derivation_never_touches_keys():
    account = _account("addr")
    first = _assign(account)
    address = first["address"]
    assert address == address.lower() and len(address) == 42 and address.startswith("0x")
    assert first["derivation_path"].startswith("m/44'/60'/0'/0/")
    assert first["xpub_fingerprint"] == P.xpub_fingerprint(XPUB)

    # 同主体第二条活跃地址 → 被「每主体一条 active」唯一索引拒绝（应用层转成人话错误）
    with pytest.raises(P.ChainIngestError):
        _assign(account)

    # 同地址再分配给别的主体 → 地址不复用（应用层拒绝 + DB 唯一约束兜底）
    with pytest.raises(P.ChainIngestError):
        with db.conn() as c:
            P.assign_deposit_address(c, account_id=_account("addr2"), xpub=XPUB,
                                     index=first["derivation_index"], enabled=True)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with db.conn() as c, c.cursor() as cur:            # 绕过应用层直插：地址唯一
            cur.execute("""INSERT INTO deposit_address
                             (chain_id, address, account_id, derivation_path, derivation_index, xpub_fingerprint)
                           VALUES (%s,%s,%s,%s,%s,%s)""",
                        (P.CHAIN_ID, address, _account("raw"), "m/44'/60'/0'/0/999997",
                         999997, "0000000000000000"))
    with pytest.raises(psycopg.errors.UniqueViolation):
        with db.conn() as c, c.cursor() as cur:            # 同链派生路径唯一
            cur.execute("""INSERT INTO deposit_address
                             (chain_id, address, account_id, derivation_path, derivation_index, xpub_fingerprint)
                           VALUES (%s,%s,%s,%s,%s,%s)""",
                        (P.CHAIN_ID, _hex(20), _account("raw2"), first["derivation_path"],
                         first["derivation_index"], "0000000000000000"))

    # 表里没有任何密钥列（只允许指纹）
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT column_name FROM information_schema.columns
                        WHERE table_schema='public' AND table_name IN ('deposit_address','chain_tx')""")
        cols = {r[0] for r in cur.fetchall()}
    forbidden = {"private_key", "privkey", "secret", "mnemonic", "seed", "key_material",
                 "signing_key", "xpub", "xprv"}
    assert not (cols & forbidden), cols & forbidden
    assert "xpub_fingerprint" in cols and "derivation_path" in cols

    # 派生只吃 xpub：改索引得到新地址、可复现、切片长度稳定
    assert P.derive_address(XPUB, 0) == P.derive_address(XPUB, 0)
    assert P.derive_address(XPUB, 0) != P.derive_address(XPUB, 1)
    assert P.derive_address(XPUB, 0) == address or P.derive_address(XPUB, first["derivation_index"]) == address
    # 私钥版本 / 垃圾串一律拒绝（本模块没有私钥入口）
    # 这里用「xprv 版本字 + 全零负载」拼一个版本字合法的串，不含任何真实私钥材料
    payload = b"\x04\x88\xad\xe4" + b"\x00" * 74
    xprv_like = P._b58encode(payload + P._sha256d(payload)[:4])
    with pytest.raises(P.ChainIngestError):
        P.parse_xpub(xprv_like)
    with pytest.raises(P.ChainIngestError):
        P.derive_address("not-an-xpub", 0)


def test_derivation_matches_published_keccak_and_address_vectors():
    # keccak-256 KAT（以太坊口径，非 SHA3）
    assert P.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert P.keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    # 地址 KAT：1·G / 2·G / 3·G 的以太坊地址（公开测试向量）
    assert P._address_from_pub(P._ser_pub(P._pmul(1))) == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    assert P._address_from_pub(P._ser_pub(P._pmul(2))) == "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
    assert P._address_from_pub(P._ser_pub(P._pmul(3))) == "0x6813eb9362372eef6200f3b1dbc3f819671cba69"
    # CKDpub 公式校验：父公钥 = G（离散对数 = 1）时，子公钥必须等于 (IL+1)·G
    import hmac as _hmac
    cc = b"\x02" * 32
    digest = _hmac.new(cc, P._ser_pub(P._G) + (0).to_bytes(4, "big"), hashlib.sha512).digest()
    expected = P._pmul((int.from_bytes(digest[:32], "big") + 1) % P._N)
    child = P.ckd_pub(P._XpubNode(0, b"\x00" * 4, 0, cc, P._ser_pub(P._G)), 0)
    assert child.pubkey == P._ser_pub(expected) and child.chain_code == digest[32:]
    # xpub 编码/解析往返（只有公钥，没有私钥材料）
    node = P.parse_xpub(XPUB)
    assert node.pubkey == P._ser_pub(P._G) and node.depth == 3


# ───────────────────────────────────────────────────────────── ⑤ 错链 / 假充值：void + reverse_of
def test_wrong_chain_void_reverses_every_entry_and_keeps_originals():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=300 * USD)
    with db.conn() as c:
        before = _balances(c)
        cid = P.observe(c, tr, enabled=True)["chain_tx_id"]
        P.observe(c, _transfer(addr, qty=300 * USD, tx_hash=tr.tx_hash, confirmations=64), enabled=True)
    with db.conn() as c:
        originals = _entries_of(c, cid)
    assert len(originals) == 3

    with db.conn() as c:
        out = P.void_deposit(c, chain_tx_id=cid, reason_code="wrong_chain", actor="test:ops",
                             note="扫描器把 TRON 的 tx 误报成 Polygon")
    assert out["action"] == "void" and out["reversed_count"] == 3

    with db.conn() as c:
        after_entries = _entries_of(c, cid)
        after = _balances(c)
        st = P.state(c, cid)
        with c.cursor() as cur:
            cur.execute("SELECT orig_seq, reversal_seq FROM ledger_entry_reversal WHERE void_source_id = %s "
                        "ORDER BY orig_seq", (cid,))
            links = cur.fetchall()
    reversals = [e for e in after_entries if e["entry_type"] == "void"]
    assert len(reversals) == 3
    assert all(e["source_type"] == "void" and e["event_seq"] == 1 for e in reversals)
    # reverse_of 逐条指向原分录（UUID 完全一致）
    orig_by_id = {str(e["entry_id"]): e for e in originals}
    assert {str(e["reverse_of"]) for e in reversals} == set(orig_by_id)
    for rev in reversals:
        orig = orig_by_id[str(rev["reverse_of"])]
        assert (rev["debit"], rev["credit"], rev["amount_micro"]) == (
            orig["credit"], orig["debit"], orig["amount_micro"])      # 整单等额取反
    # 原分录一个字节都没改（只追加）
    assert [{k: e[k] for k in ("seq", "entry_id", "entry_type", "debit", "credit",
                               "amount_micro", "memo", "hash")} for e in after_entries[:3]] == \
           [{k: e[k] for k in ("seq", "entry_id", "entry_type", "debit", "credit",
                               "amount_micro", "memo", "hash")} for e in originals]
    assert len(links) == 3
    # 全部回到冲正前水位（在途 / 热钱包 / 服务预付款 / 确认中充值 都清零）
    assert all(after[a] == before[a] for a in P._CHAIN_ACCOUNTS), (after, before)
    assert st["status"] == "void" and st["voided"] is True
    _assert_ledger_sound()

    # 二次冲正：幂等拒绝，不再写分录
    with db.conn() as c:
        twice = P.void_deposit(c, chain_tx_id=cid, reason_code="wrong_chain")
        assert twice["action"] == "already_voided" and twice["reversed"] == []
        assert len(_entries_of(c, cid)) == 6
        assert [e[0] for e in _events(c, cid)].count("void") == 1
    # 原分录不可 UPDATE（DB 触发器硬拦）
    with pytest.raises(Exception) as ei:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("UPDATE ledger_entries SET amount_micro = amount_micro + 1 WHERE seq = %s",
                        (originals[0]["seq"],))
    assert "append-only" in str(ei.value).lower()
    _assert_ledger_sound()


def test_fake_token_void_before_confirmation_only_reverses_e1():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=40 * USD)
    with db.conn() as c:
        before = _balances(c)
        cid = P.observe(c, tr, enabled=True)["chain_tx_id"]
        assert len(_entries_of(c, cid)) == 1
        out = P.void_deposit(c, chain_tx_id=cid, reason_code="fake_token",
                             note="事后复核发现合约地址被伪造")
        after = _balances(c)
        entries = _entries_of(c, cid)
    assert out["reversed_count"] == 1
    assert len(entries) == 2 and entries[1]["entry_type"] == "void"
    assert str(entries[1]["reverse_of"]) == str(entries[0]["entry_id"])
    assert all(after[a] == before[a] for a in P._CHAIN_ACCOUNTS)
    _assert_ledger_sound()


def test_wrong_chain_fake_token_and_unknown_address_are_not_credited():
    addr = _assign()["address"]
    cases = [
        (_transfer(addr, chain_id="tron"), "wrong_chain"),
        (_transfer(addr, asset="0x" + "ab" * 20), "fake_token"),
        (_transfer(addr, status="reverted"), "tx_failed"),
        (_transfer("0x" + "cd" * 20), "unknown_address"),
    ]
    for tr, reason in cases:
        with db.conn() as c:
            out = P.observe(c, tr, enabled=True)
            cid = out["chain_tx_id"]
            assert out["action"] == "rejected" and out["reason"] == reason
            assert out["posted"] == []
            assert _entries_of(c, cid) == []                  # 不入账
            assert P.state(c, cid)["status"] == "rejected"
            assert ("rejected", 0, reason) in _events(c, cid)
    _assert_ledger_sound()


def test_one_time_address_expired_is_held_not_credited():
    addr = _assign(purpose="one_time", expires_at=NOW - timedelta(hours=1))["address"]
    tr = _transfer(addr, qty=10 * USD, confirmations=64)
    with db.conn() as c:
        out = P.observe(c, tr, enabled=True, now=NOW)
        cid = out["chain_tx_id"]
        assert out["action"] == "held" and out["reason"] == "one_time_expired"
        assert _entries_of(c, cid) == []
        assert P.state(c, cid)["status"] == "held"
    _assert_ledger_sound()


def test_reorg_block_hash_mismatch_blocks_confirmation():
    addr = _assign()["address"]
    tr = _transfer(addr, qty=20 * USD)
    with db.conn() as c:
        cid = P.observe(c, tr, enabled=True)["chain_tx_id"]
        out = P.observe(c, _transfer(addr, qty=20 * USD, tx_hash=tr.tx_hash, confirmations=64,
                                     block_hash=_hex()), enabled=True)
        assert out["action"] == "reorged" and out["posted"] == []
        assert len(_entries_of(c, cid)) == 1        # 仍是 E1，不确认
        ok = P.observe(c, _transfer(addr, qty=20 * USD, tx_hash=tr.tx_hash, confirmations=64), enabled=True)
        assert ok["action"] == "e2" and len(ok["posted"]) == 2
        assert [e[0] for e in _events(c, cid)].count("reorged") == 1
    _assert_ledger_sound()


# ───────────────────────────────────────────────────────────── ⑥ 迁移前后账本零差异
def test_migration_is_idempotent_and_ledger_diff_zero():
    sql = MIGRATION.read_text(encoding="utf-8")
    with db.conn() as c:
        before = _ledger_fingerprint(c)
        rep_before = recompute(c)
    with db.conn() as c, c.cursor() as cur:
        cur.execute(sql)                      # 重复应用 #1
    with db.conn() as c, c.cursor() as cur:
        cur.execute(sql)                      # 重复应用 #2
    with db.conn() as c:
        after = _ledger_fingerprint(c)
        rep_after = recompute(c)
    assert before == after, (before, after)
    assert rep_before["diff"] == rep_after["diff"] == 0
    assert rep_after["entries"] == before["entries"]
    # schema 也齐了（列只加不改）
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT column_name FROM information_schema.columns
                        WHERE table_schema='public' AND table_name='ledger_entries'""")
        cols = {r[0] for r in cur.fetchall()}
        cur.execute("""SELECT table_name FROM information_schema.tables
                        WHERE table_schema='public'""")
        tables = {r[0] for r in cur.fetchall()}
    assert {"entry_type", "reverse_of", "source_type", "source_id", "event_seq", "line_no",
            "policy_version", "unit_type"} <= cols
    assert {"deposit_address", "chain_tx", "chain_tx_event"} <= tables


def test_chain_evidence_is_append_only_even_against_truncate():
    """链上证据表不能被 TRUNCATE 带走（行级触发器管不到 TRUNCATE）。"""
    with pytest.raises(Exception) as ei:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("TRUNCATE chain_tx CASCADE")
    assert "append-only" in str(ei.value).lower()
    with pytest.raises(Exception) as ei2:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("TRUNCATE chain_tx_event")
    assert "append-only" in str(ei2.value).lower()
    # deposit_address 不挂 wallet 的 FK：wallet 侧 TRUNCATE ... CASCADE 不会级联清空链上证据
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT count(*) FROM pg_constraint co JOIN pg_class t ON t.oid = co.conrelid
                        WHERE co.contype = 'f' AND t.relname = 'deposit_address'""")
        assert cur.fetchone()[0] == 0
        cur.execute("""SELECT tgname FROM pg_trigger WHERE NOT tgisinternal
                        AND tgname IN ('chain_tx_no_truncate', 'chain_tx_event_no_truncate',
                                       'deposit_address_no_truncate')""")
        assert len(cur.fetchall()) == 3


def test_final_ledger_recompute_is_zero():
    rep = _assert_ledger_sound()
    print(f"\n[evidence] ledger recompute: entries={rep['entries']} diff={rep['diff']} "
          f"chain_bad={rep['chain_bad']} balance_bad={rep['balance_bad']}")
