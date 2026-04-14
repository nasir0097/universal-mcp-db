"""
Tests for universal-mcp-db server.
Uses the local SQLite demo connection — no cloud credentials needed.
"""
import json, pytest
from fastapi.testclient import TestClient

# patch config before importing server
import os
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

from server import load_config, build_tools, handle_tool_call


@pytest.fixture
def config():
    return load_config()


# ── Role enforcement ──────────────────────────────────────────────────────────
def test_roles_block_delete_on_read_only():
    from roles import check
    with pytest.raises(ValueError, match="does not allow"):
        check("DELETE FROM users", "read-only")

def test_roles_block_drop_on_read_write():
    from roles import check
    with pytest.raises(ValueError, match="does not allow DDL"):
        check("DROP TABLE users", "read-write")

def test_roles_allow_select_on_read_only():
    from roles import check
    check("SELECT * FROM users", "read-only")  # should not raise

def test_roles_allow_insert_on_read_write():
    from roles import check
    check("INSERT INTO users VALUES (1)", "read-write")  # should not raise


# ── SQL injection filter ──────────────────────────────────────────────────────
def test_safe_filter_blocks_drop():
    from server import _safe_filter
    with pytest.raises(ValueError, match="Disallowed keyword"):
        _safe_filter("1=1; DROP TABLE users")

def test_safe_filter_blocks_exec():
    from server import _safe_filter
    with pytest.raises(ValueError, match="Disallowed keyword"):
        _safe_filter("1=1; EXEC xp_cmdshell('whoami')")

def test_safe_filter_allows_normal():
    from server import _safe_filter
    assert _safe_filter("id = 1") == "id = 1"
    assert _safe_filter("status = 'active'") == "status = 'active'"
    assert _safe_filter(None) is None

def test_safe_filter_blocks_too_long():
    from server import _safe_filter
    with pytest.raises(ValueError, match="too long"):
        _safe_filter("a" * 501)


# ── Tool building ─────────────────────────────────────────────────────────────
def test_build_tools_creates_schema_and_query(config):
    tools = build_tools(config)
    names = [t["name"] for t in tools]
    assert "local-sqlite__schema" in names
    assert "local-sqlite__query" in names

def test_build_tools_query_requires_sql(config):
    tools = build_tools(config)
    query_tool = next(t for t in tools if t["name"] == "local-sqlite__query")
    assert "sql" in query_tool["inputSchema"]["required"]


# ── SQLite driver end-to-end ──────────────────────────────────────────────────
def test_schema_tool_returns_tables(config):
    result = handle_tool_call("local-sqlite__schema", {}, config)
    assert "customers" in result
    assert "orders" in result

def test_query_tool_returns_rows(config):
    result = handle_tool_call("local-sqlite__query", {"sql": "SELECT * FROM customers LIMIT 2"}, config)
    rows = json.loads(result)
    assert isinstance(rows, list)
    assert len(rows) <= 2

def test_query_tool_blocks_delete(config):
    with pytest.raises(ValueError, match="does not allow"):
        handle_tool_call("local-sqlite__query", {"sql": "DELETE FROM customers"}, config)

def test_query_tool_unknown_connection(config):
    with pytest.raises(ValueError, match="No connection"):
        handle_tool_call("nonexistent__query", {"sql": "SELECT 1"}, config)
