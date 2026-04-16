"""
Security tests — SQL injection in URL params, header injection, path traversal,
role enforcement, and bandit static analysis gate.
"""
import json, os, subprocess, sys, pytest
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from server import create_app, load_config, _safe_filter, _safe_column, _safe_row_id

@pytest.fixture(scope="module")
def client():
    config = load_config()
    app = create_app(config)
    return TestClient(app)


# ── _safe_filter — URL query-param injection ──────────────────────────────────
@pytest.mark.parametrize("payload", [
    "1=1; DROP TABLE customers",
    "1=1; EXEC xp_cmdshell('whoami')",
    "1=1 UNION SELECT password FROM users--",
    "'; EXEC sp_configure 'xp_cmdshell',1--",
    "1=1; INSERT INTO users VALUES('hacker','hacked')",
    "1=1; UPDATE users SET password='pwned'",
    "1 OR 1=1; DELETE FROM orders",
    "a" * 501,                                   # length bomb
])
def test_safe_filter_blocks_injection(payload):
    with pytest.raises(ValueError):
        _safe_filter(payload)


@pytest.mark.parametrize("safe_value", [
    "id = 1",
    "status = 'active'",
    "category = 'Security'",
    "created_at > '2024-01-01'",
    None,
])
def test_safe_filter_allows_legitimate(safe_value):
    result = _safe_filter(safe_value)
    assert result == safe_value


# ── _safe_column — column-name injection ──────────────────────────────────────
@pytest.mark.parametrize("bad_col", [
    "id; DROP TABLE users",
    "col--comment",
    "col/*injection*/",
    "col UNION SELECT",
    "a" * 65,
])
def test_safe_column_blocks_bad_names(bad_col):
    with pytest.raises(ValueError):
        _safe_column(bad_col)


@pytest.mark.parametrize("good_col", ["id", "user_name", "created_at", "col123"])
def test_safe_column_allows_valid(good_col):
    assert _safe_column(good_col) == good_col


# ── _safe_row_id — path param injection ──────────────────────────────────────
@pytest.mark.parametrize("bad_id", ["1; DROP TABLE", "abc", "1.5", "", "1 OR 1=1"])
def test_safe_row_id_blocks_non_integers(bad_id):
    with pytest.raises(ValueError):
        _safe_row_id(bad_id)

def test_safe_row_id_allows_integer():
    assert _safe_row_id("42") == 42


# ── URL injection via HTTP layer ──────────────────────────────────────────────
@pytest.mark.parametrize("injection", [
    "1=1; DROP TABLE customers",
    "UNION SELECT * FROM sqlite_master",
    "1=1; EXEC xp_cmdshell('id')",
])
def test_rest_filter_injection_blocked(client, injection):
    r = client.get(f"/api/local-sqlite/customers?filter={injection}")
    # must never return 200 with data on an injection attempt
    assert r.status_code != 200, f"Injection was not blocked: {injection}"


def test_rest_limit_above_max_is_capped(client):
    r = client.get("/api/local-sqlite/customers?limit=9999")
    # FastAPI Query(le=1000) rejects it
    assert r.status_code == 422


# ── Role enforcement via REST ─────────────────────────────────────────────────
def test_rest_post_blocked_on_read_only_conn(client):
    r = client.post("/api/local-sqlite/customers", json={"name": "hacker"})
    assert r.status_code in (403, 400), f"Expected 400/403, got {r.status_code}: {r.text}"


def test_rest_delete_blocked_on_read_only_conn(client):
    r = client.delete("/api/local-sqlite/customers/1")
    assert r.status_code in (403, 400), f"Expected 400/403, got {r.status_code}: {r.text}"


# ── Path traversal ────────────────────────────────────────────────────────────
def test_path_traversal_in_conn_id(client):
    r = client.get("/api/../../../etc/passwd")
    assert r.status_code in (404, 422)

def test_path_traversal_in_table(client):
    r = client.get("/api/local-sqlite/../../../etc/passwd")
    assert r.status_code in (404, 400, 500)


# ── Bandit static analysis ────────────────────────────────────────────────────
def test_bandit_no_high_severity():
    """
    Run bandit and fail if any HIGH severity issues are found.
    Medium issues are allowed (some are nosec-annotated intentionally).
    """
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", ".",
         "--exclude", "./tests,./demo.db,./.git",
         "-l",          # report only HIGH level
         "-f", "json"],
        capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), "..")
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.skip("bandit not installed or produced no JSON output")
        return

    high_issues = [
        i for i in report.get("results", [])
        if i["issue_severity"] == "HIGH"
    ]
    if high_issues:
        details = "\n".join(
            f"  {i['filename']}:{i['line_number']} — {i['issue_text']}"
            for i in high_issues
        )
        pytest.fail(f"Bandit found {len(high_issues)} HIGH severity issue(s):\n{details}")
