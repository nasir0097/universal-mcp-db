"""
Smoke tests — server starts, all key endpoints respond correctly.
Uses FastAPI TestClient (no live server needed).
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


# ── Health ────────────────────────────────────────────────────────────────────
def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_health_lists_connections(client):
    r = client.get("/health")
    ids = [c["id"] for c in r.json()["connections"]]
    assert "local-sqlite" in ids

def test_health_includes_version(client):
    r = client.get("/health")
    assert "version" in r.json()


# ── UI ────────────────────────────────────────────────────────────────────────
def test_ui_returns_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "<title>" in r.text

def test_docs_reachable(client):
    r = client.get("/docs")
    assert r.status_code == 200


# ── REST list tables ──────────────────────────────────────────────────────────
def test_list_tables_sqlite(client):
    r = client.get("/api/local-sqlite")
    assert r.status_code == 200
    body = r.json()
    assert "tables" in body
    assert "customers" in body["tables"]

def test_list_tables_unknown_conn(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404


# ── REST query ────────────────────────────────────────────────────────────────
def test_rest_get_customers(client):
    r = client.get("/api/local-sqlite/customers")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 0
    assert body["table"] == "customers"

def test_rest_get_respects_limit(client):
    r = client.get("/api/local-sqlite/customers?limit=1")
    assert r.status_code == 200
    assert r.json()["count"] <= 1


# ── MCP endpoint ─────────────────────────────────────────────────────────────
def test_mcp_initialize(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert result["serverInfo"]["name"] == "universal-mcp-db"

def test_mcp_tools_list(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert r.status_code == 200
    tools = r.json()["result"]["tools"]
    names = [t["name"] for t in tools]
    assert "local-sqlite__query" in names
    assert "local-sqlite__schema" in names

def test_mcp_unknown_method_returns_error(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "bad/method"})
    assert r.status_code == 200
    assert "error" in r.json()
