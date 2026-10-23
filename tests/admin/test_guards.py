# SPDX-License-Identifier: Apache-2.0
"""架构 / 安全 / 不变量静态扫描（INV-01 / INV-04 / INV-06 / INV-08 / S6）。

这些断言不依赖数据库：读 ``app/data_gov/*.py`` 的 AST 与字符串常量，证明
M14 **只写自有表**、只读视图 / audit_log、无跨模块 import、无密钥 / PII。
"""
from __future__ import annotations

import ast
import pathlib
import re

from app.data_gov import errors as m14_errors
from app.data_gov import facts

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MODULE_DIR = REPO_ROOT / "app" / "data_gov"
FACADE = REPO_ROOT / "app" / "admin" / "data_gov.py"

M14_TABLES = {"data_export_requests", "retention_jobs", "admin_saved_views", "data_gov_outbox"}
READ_ONLY_SOURCES = {"audit_log", "account_balances_latest", "chain_tx_state", "v_m09_run_diff"}

WRITE_RE = re.compile(
    r"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
FROM_RE = re.compile(r"\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"postgresql://[^\s'\"]*:[^\s'\"]*@"),
    re.compile(r"(?i)\b(password|passwd|secret)\s*=\s*['\"][^'\"]{6,}['\"]"),
)

PII_KEYS = ("email", "phone", "card", "pan", "id_card", "ip", "address", "prompt",
            "response", "signature", "private_key")


def _module_files() -> list[pathlib.Path]:
    return sorted(MODULE_DIR.glob("*.py"))


def _string_literals(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and id(node) not in docstrings]


# ─────────────────────────────────────────────────────── INV-01：只写自有表
def test_sql_writes_target_only_m14_tables() -> None:
    targets: list[tuple[str, str]] = []
    for path in _module_files() + [FACADE]:
        for literal in _string_literals(path):
            for match in WRITE_RE.finditer(literal):
                targets.append((path.name, match.group(1)))
    assert targets, "应至少扫描到 M14 自有表写入"
    illegal = [(name, table) for name, table in targets if table not in M14_TABLES]
    assert illegal == [], f"检测到对非自有表的写操作：{illegal}"


def test_sql_reads_only_views_or_audit_log() -> None:
    allowed = M14_TABLES | READ_ONLY_SOURCES
    illegal: list[tuple[str, str]] = []
    for path in _module_files():
        for literal in _string_literals(path):
            for match in FROM_RE.finditer(literal):
                table = match.group(1)
                if table in allowed or table.startswith("pg_"):
                    continue
                illegal.append((path.name, table))
    assert illegal == [], f"检测到直读非白名单对象：{illegal}"


def test_no_audit_or_business_table_writes_in_migrations() -> None:
    migrations = sorted((REPO_ROOT / "migrations").glob("13*.sql"))
    assert [path.name for path in migrations] == [
        "1301_data_export_requests.sql", "1302_retention_jobs.sql",
        "1303_admin_saved_views.sql", "1304_data_gov_outbox.sql"]
    for path in migrations:
        text = path.read_text(encoding="utf-8").lower()
        for forbidden in ("update audit_log", "delete from audit_log",
                          "delete from data_export_requests", "delete from retention_jobs"):
            assert forbidden not in text, (path.name, forbidden)


# ─────────────────────────────────────────────────────── 模块边界：无跨模块 import
def test_no_cross_module_imports() -> None:
    illegal: list[tuple[str, str]] = []
    for path in _module_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.startswith("app.") and not module.startswith("app.data_gov"):
                    illegal.append((path.name, module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("app.") and not alias.name.startswith(
                            "app.data_gov"):
                        illegal.append((path.name, alias.name))
    assert illegal == [], f"跨模块 import：{illegal}"


def test_facade_is_thin() -> None:
    tree = ast.parse(FACADE.read_text(encoding="utf-8"))
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    assert functions == [], "app/admin/data_gov.py 只应是薄门面（不写业务逻辑）"


# ─────────────────────────────────────────────────────── 安全：无密钥 / PII 字面量
def test_no_secret_literals() -> None:
    hits: list[tuple[str, str]] = []
    for path in _module_files() + [FACADE] + sorted(HERE.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                hits.append((path.name, match.group(0)[:60]))
    assert hits == [], f"疑似密钥 / 连接串：{hits}"


def test_no_pii_columns_or_payload_fields() -> None:
    for fields in facts.EVENT_PAYLOAD_FIELDS.values():
        assert not {field for field in fields if any(
            token in field.lower() for token in PII_KEYS)}, fields
    for fields in facts.CONSUMED_PAYLOAD_FIELDS.values():
        assert not {field for field in fields if any(
            token in field.lower() for token in PII_KEYS)}, fields


# ─────────────────────────────────────────────────────── 不变量 / 常量（M14 §3/§5/§8.2）
def test_export_state_machine_matches_spec() -> None:
    assert facts.EXPORT_STATES == ("pending", "approved", "running", "done", "failed",
                                   "expired")
    assert set(facts.EXPORT_TRANSITIONS) == set(facts.EXPORT_STATES)
    assert facts.EXPORT_TRANSITIONS["pending"] == frozenset({"approved", "failed", "expired"})
    assert facts.EXPORT_TRANSITIONS["approved"] == frozenset({"running", "failed", "expired"})
    assert facts.EXPORT_TRANSITIONS["running"] == frozenset({"done", "failed"})
    assert facts.EXPORT_TRANSITIONS["failed"] == frozenset()
    assert facts.EXPORT_CANCELLABLE_STATES == frozenset({"pending", "approved"})
    assert "cancelled" not in facts.EXPORT_STATES          # CR-M14-CR3：不新造枚举


def test_retention_state_machine_and_matrix() -> None:
    assert facts.RETENTION_STATES == ("queued", "running", "done", "failed")
    assert facts.RETENTION_TRANSITIONS["failed"] == frozenset({"queued"})
    assert facts.RETENTION_TRANSITIONS["done"] == frozenset()
    assert facts.RETENTION_POLICY_DAYS["backups"] == 35
    assert facts.RETENTION_POLICY_DAYS["logs"] == 30
    assert facts.RETENTION_POLICY_DAYS["analytics"] <= 14 * 31
    assert facts.RETENTION_POLICY_DAYS["tickets"] == 720
    assert facts.RETENTION_SLA_DAYS == 30 and facts.RETENTION_SAMPLE_DAYS == 40
    assert len(facts.RETENTION_OBJECTS) == 6


def test_export_and_batch_limits() -> None:
    assert facts.EXPORT_MAX_ROWS_DEFAULT == 200_000
    assert facts.EXPORT_LINK_TTL_MAX_S <= 15 * 60
    assert facts.EXPORT_FILE_TTL_D == 7
    assert facts.EXPORT_LARGE_ROWS == 1_000
    assert facts.EXPORT_DAILY_LARGE_LIMIT == 1
    assert facts.BATCH_MAX_ITEMS == 200
    assert facts.BATCH_DUAL_REVIEW_ITEMS == 50
    assert facts.BATCH_UNDO_WINDOW_S == 600
    assert facts.BATCH_SAMPLE_SIZE == 10
    assert facts.SANDBOX_MAX_S == 4 * 3600
    assert facts.DUAL_REVIEW_ACTIONS == frozenset(
        {"freeze", "payout_proposal", "refund_proposal"})


def test_domains_and_health_blocks() -> None:
    assert len(facts.DOMAINS) == 11
    assert len(facts.HEALTH_BLOCKS) == 7
    assert facts.HEALTH_BLOCKS == ("gateway", "scheduling", "ledger", "recon", "wallet",
                                   "config", "notification")
    assert set(facts.HEALTH_STATUSES) == {"green", "yellow", "red"}
    assert set(facts.HEALTH_CHANGE_PATTERNS) == set(facts.HEALTH_BLOCKS)


def test_events_registered_and_whitelisted() -> None:
    assert facts.PRODUCED_EVENTS == ("data.export.completed", "retention.executed")
    assert facts.EVENT_PAYLOAD_FIELDS[facts.EVENT_EXPORT_COMPLETED] == frozenset(
        {"export_id", "requester", "rows"})
    assert facts.EVENT_PAYLOAD_FIELDS[facts.EVENT_RETENTION_EXECUTED] == frozenset(
        {"job_id", "object", "deleted_count"})
    assert len(facts.CONSUMED_EVENTS) == 7
    assert set(facts.CONSUMED_PAYLOAD_FIELDS) == set(facts.CONSUMED_EVENTS)


def test_error_codes_use_registered_segments_only() -> None:
    classes = [value for value in vars(m14_errors).values()
               if isinstance(value, type) and issubclass(value, m14_errors.M14Error)
               and value is not m14_errors.M14Error]
    codes = {cls.code for cls in classes}
    assert codes == set(m14_errors.REGISTERED_CODES)
    assert m14_errors.StepUpRequired().code == 42401
    assert m14_errors.StepUpRequired().status_code == 424
    assert m14_errors.ExportTooLarge("x").code == 49001
