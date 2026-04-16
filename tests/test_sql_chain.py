"""
SQL chain tests — MCP tool call → SQL → result, end-to-end through
the JSON-RPC layer. Tests the full call chain that Claude Code uses.
"""
import json, os, pytest
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from server import create_app, load_config

@pytest.fixture(scope="module")
def client():
    config = load_config()
    app = create_app(config)
    return TestClient(app)


def mcp_call(client, tool_name, arguments=None):
    """Helper: send a tools/call JSON-RPC request, return the text content."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {}
        }
    }
    r = client.post("/mcp", json=payload)
    assert r.status_code == 200
    body = r.json()
    content = body["result"]["content"][0]["text"]
    return content, body["result"].get("isError", False)


# ── Schema chain ──────────────────────────────────────────────────────────────
def test_schema_chain_returns_table_names(client):
    text, is_error = mcp_call(client, "local-sqlite__schema")
    assert not is_error
    assert "customers" in text
    assert "orders" in text

def test_schema_chain_includes_column_info(client):
    text, is_error = mcp_call(client, "local-sqlite__schema")
    assert not is_error
    # schema should mention column types or column names
    assert "id" in text.lower() or "INTEGER" in text or "TEXT" in text


# ── Query chain ───────────────────────────────────────────────────────────────
def test_query_chain_select_all(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT * FROM customers"})
    assert not is_error
    rows = json.loads(text)
    assert isinstance(rows, list)

def test_query_chain_select_with_limit(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT * FROM customers LIMIT 2"})
    assert not is_error
    rows = json.loads(text)
    assert len(rows) <= 2

def test_query_chain_select_specific_columns(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT id, name FROM customers LIMIT 3"})
    assert not is_error
    rows = json.loads(text)
    if rows:
        assert "id" in rows[0]
        assert "name" in rows[0]

def test_query_chain_count(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT COUNT(*) as total FROM customers"})
    assert not is_error
    rows = json.loads(text)
    assert rows[0]["total"] >= 0

def test_query_chain_where_clause(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT * FROM customers WHERE id = 1"})
    assert not is_error
    rows = json.loads(text)
    assert isinstance(rows, list)

def test_query_chain_join(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT c.name, o.id FROM customers c "
                                       "LEFT JOIN orders o ON o.customer_id = c.id LIMIT 5"})
    assert not is_error

def test_query_chain_aggregate(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "SELECT customer_id, COUNT(*) as order_count "
                                       "FROM orders GROUP BY customer_id LIMIT 5"})
    assert not is_error
    rows = json.loads(text)
    if rows:
        assert "order_count" in rows[0]


# ── Security blocks through MCP layer ────────────────────────────────────────
def test_mcp_blocks_delete(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "DELETE FROM customers"})
    assert is_error
    assert "allow" in text.lower() or "error" in text.lower()

def test_mcp_blocks_drop(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "DROP TABLE customers"})
    assert is_error

def test_mcp_blocks_insert_on_read_only(client):
    text, is_error = mcp_call(client, "local-sqlite__query",
                               {"sql": "INSERT INTO customers (name) VALUES ('hacker')"})
    assert is_error

def test_mcp_unknown_tool_returns_error(client):
    text, is_error = mcp_call(client, "nonexistent__query", {"sql": "SELECT 1"})
    assert is_error


# ── Full MCP handshake chain ──────────────────────────────────────────────────
def test_full_mcp_handshake_then_query(client):
    """Simulate exactly what Claude Code does: initialize → tools/list → tools/call."""
    # 1. Initialize
    r1 = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r1.json()["result"]["protocolVersion"] == "2024-11-05"

    # 2. List tools
    r2 = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = {t["name"] for t in r2.json()["result"]["tools"]}
    assert "local-sqlite__query" in tools

    # 3. Call a tool
    r3 = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 3,
        "method": "tools/call",
        "params": {"name": "local-sqlite__query", "arguments": {"sql": "SELECT COUNT(*) as n FROM customers"}}
    })
    result = r3.json()["result"]
    assert not result.get("isError")
    rows = json.loads(result["content"][0]["text"])
    assert rows[0]["n"] >= 0
