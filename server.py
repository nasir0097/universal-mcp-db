"""
server.py — Universal MCP DB Server
Exposes every configured database connection as:
  - MCP tools   → /mcp          (Claude Desktop, AI Foundry, Copilot)
  - REST API     → /api/{conn}/{table}  (GET/POST/PUT/DELETE)
  - GraphQL      → /graphql/{conn}      (query / mutation)
  - Web UI       → /                    (browser dashboard)

Usage:
    python server.py              # HTTP mode
    python server.py --stdio      # stdio mode (Claude Desktop local)
"""
import json, sys, os, argparse, re
from db import get_driver
from roles import check

# ── Auth middleware ────────────────────────────────────────────────────────────
# Supports three modes set via config.json "auth" block:
#
#  API key (simplest — good for internal tools, Claude Desktop):
#    "auth": { "type": "api-key", "keys": ["key1", "key2"] }
#    Client sends:  Authorization: Bearer key1
#
#  Entra ID / Azure AD (enterprise Azure):
#    "auth": { "type": "entra", "tenant_id": "...", "client_id": "..." }
#    Client sends:  Authorization: Bearer <Azure AD JWT>
#    Server validates signature + audience against Microsoft JWKS
#
#  AWS IAM (enterprise AWS):
#    "auth": { "type": "aws-iam", "region": "us-east-1", "role_arn": "..." }
#    Client sends:  Authorization: Bearer <STS token>
#    Server calls STS GetCallerIdentity to verify
#
#  None (default — no auth, local use only):
#    omit "auth" block entirely

def _validate_token(token: str | None, config: dict) -> dict:
    """
    Validate the incoming Bearer token.
    Returns a dict with caller info: {"user": "...", "role": "..."}
    Raises ValueError on auth failure.
    """
    auth_cfg = config.get("auth", {})
    if not auth_cfg or auth_cfg.get("type", "none") == "none":
        return {"user": "anonymous", "role": "admin"}   # no auth = local mode

    if not token:
        raise ValueError("Authorization required — provide a Bearer token")

    auth_type = auth_cfg.get("type")

    # ── API key ────────────────────────────────────────────────────────────────
    if auth_type == "api-key":
        allowed = auth_cfg.get("keys", [])
        if token not in allowed:
            raise ValueError("Invalid API key")
        return {"user": "api-key-client", "role": auth_cfg.get("role", "read-only")}

    # ── Entra ID / Azure AD ────────────────────────────────────────────────────
    if auth_type == "entra":
        return _validate_entra_token(token, auth_cfg)

    # ── AWS IAM / STS ──────────────────────────────────────────────────────────
    if auth_type == "aws-iam":
        return _validate_aws_token(token, auth_cfg)

    raise ValueError(f"Unknown auth type: {auth_type}")


def _validate_entra_token(token: str, cfg: dict) -> dict:
    """
    Validate an Azure AD / Entra ID JWT.
    Uses python-jose + Microsoft's public JWKS endpoint.
    No MSAL dependency needed — works for any OAuth2 client that gets a token
    from Azure AD (service principals, managed identities, user logins).
    """
    try:
        from jose import jwt, jwk
        from jose.exceptions import JWTError
        import urllib.request
    except ImportError:
        raise ImportError("python-jose required: pip install python-jose[cryptography]")

    tenant_id = cfg.get("tenant_id", "common")
    client_id = cfg.get("client_id", "")

    # Fetch Microsoft's public signing keys
    jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    try:
        with urllib.request.urlopen(jwks_url, timeout=5) as r:  # nosec B310 - URL is hardcoded Microsoft JWKS endpoint, not user input
            jwks = json.loads(r.read())
    except Exception as e:
        raise ValueError(f"Could not fetch Entra ID signing keys: {e}")

    try:
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=client_id or None,
            options={"verify_aud": bool(client_id)}
        )
    except JWTError as e:
        raise ValueError(f"Entra ID token invalid: {e}")

    # Map Azure AD groups → roles
    group_role_map = cfg.get("group_roles", {})
    user_groups    = claims.get("groups", [])
    role = "read-only"   # default
    for group_id, mapped_role in group_role_map.items():
        if group_id in user_groups:
            role = mapped_role
            break

    return {
        "user":  claims.get("preferred_username") or claims.get("upn") or claims.get("sub"),
        "role":  role,
        "email": claims.get("email", ""),
        "name":  claims.get("name", ""),
    }


def _validate_aws_token(token: str, cfg: dict) -> dict:
    """
    Validate an AWS STS token by calling GetCallerIdentity.
    The client generates a pre-signed GetCallerIdentity URL and sends it as the token.
    Server calls STS to verify — no secret sharing needed.
    """
    try:
        import boto3, botocore
    except ImportError:
        raise ImportError("boto3 required: pip install boto3")

    region     = cfg.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    role_arn   = cfg.get("role_arn", "")   # optional: restrict to specific role

    try:
        import urllib.request, urllib.parse
        # token is a pre-signed STS GetCallerIdentity URL
        with urllib.request.urlopen(token, timeout=5) as r:  # nosec B310 - token is AWS pre-signed STS URL validated by format check above
            import xml.etree.ElementTree as ET
            root    = ET.fromstring(r.read())  # nosec B314 - XML is from AWS STS HTTPS endpoint, not user-supplied
            ns      = {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"}
            user_id = root.find(".//sts:UserId",  ns)
            arn     = root.find(".//sts:Arn",     ns)
            account = root.find(".//sts:Account", ns)
    except Exception as e:
        raise ValueError(f"AWS STS validation failed: {e}")

    arn_str = arn.text if arn is not None else ""
    if role_arn and role_arn not in arn_str:
        raise ValueError(f"AWS identity '{arn_str}' is not allowed (expected role: {role_arn})")

    # Map ARN patterns → roles
    arn_role_map = cfg.get("arn_roles", {})   # {"arn:aws:iam::123:role/admin": "admin"}
    role = "read-only"
    for pattern, mapped_role in arn_role_map.items():
        if pattern in arn_str:
            role = mapped_role
            break

    return {
        "user":    arn_str,
        "role":    role,
        "account": account.text if account is not None else "",
    }

# ── Input sanitisation ─────────────────────────────────────────────────────────
_DANGEROUS = re.compile(
    r"\b(drop|truncate|alter|create|exec|execute|xp_|sp_|insert|update|delete|merge|grant|revoke|union|select|into|load_file|outfile)\b",
    re.IGNORECASE
)
_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_\.\s,\-]+$")

def _safe_filter(value: str | None) -> str | None:
    """Block obvious injection in WHERE / ORDER BY user input."""
    if not value:
        return value
    if _DANGEROUS.search(value):
        raise ValueError(f"Disallowed keyword in filter/order: '{value}'")
    if len(value) > 500:
        raise ValueError("filter/order value too long")
    return value

def _safe_column(name: str) -> str:
    """Ensure a column name is alphanumeric + underscores only, max 64 chars."""
    if len(name) > 64:
        raise ValueError(f"Column name too long: '{name[:20]}...'")
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise ValueError(f"Invalid column name: '{name}'")
    return name

def _safe_row_id(row_id: str) -> int:
    """Ensure row_id is a plain integer — no injection possible."""
    try:
        return int(row_id)
    except ValueError:
        raise ValueError(f"row_id must be an integer, got: '{row_id}'")

CONFIG_PATH  = os.path.join(os.path.dirname(__file__), "config.json")
AUTH_DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")


# ── auth.db — users · connection ACL · audit log ──────────────────────────────
def _auth_db():
    """Return a connection to auth.db (thread-safe with check_same_thread=False)."""
    import sqlite3
    return sqlite3.connect(AUTH_DB_PATH, check_same_thread=False)

def _init_auth_db(admin_username: str = "admin"):
    """Create tables on first run and bootstrap the admin user."""
    import sqlite3
    con = _auth_db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username    TEXT PRIMARY KEY,
            global_role TEXT NOT NULL DEFAULT 'viewer',
            created_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS connection_permissions (
            username    TEXT NOT NULL,
            conn_id     TEXT NOT NULL,
            role        TEXT NOT NULL,
            granted_by  TEXT,
            granted_at  TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (username, conn_id)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL,
            conn_id      TEXT NOT NULL,
            sql_query    TEXT,
            rows_returned INTEGER,
            duration_ms  INTEGER,
            status       TEXT,
            error_msg    TEXT,
            ts           TEXT DEFAULT (datetime('now'))
        );
    """)
    # Bootstrap: ensure admin user exists with global admin role
    con.execute(
        "INSERT OR IGNORE INTO users (username, global_role) VALUES (?, 'admin')",
        (admin_username,)
    )
    con.commit()
    con.close()

def _bootstrap_admin_permissions(admin_username: str, conn_ids: list[str]):
    """Grant admin the ability to use every connection (run after config loads)."""
    con = _auth_db()
    for cid in conn_ids:
        con.execute(
            "INSERT OR IGNORE INTO connection_permissions (username, conn_id, role, granted_by) "
            "VALUES (?, ?, 'admin', 'system')",
            (admin_username, cid)
        )
    con.commit()
    con.close()

def _acl_role(username: str, conn_id: str) -> str | None:
    """Return the role for username on conn_id, or None if no access."""
    con = _auth_db()
    # Global admins bypass per-connection ACL
    row = con.execute(
        "SELECT global_role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and row[0] == "admin":
        con.close()
        return "admin"
    row = con.execute(
        "SELECT role FROM connection_permissions WHERE username = ? AND conn_id = ?",
        (username, conn_id)
    ).fetchone()
    con.close()
    return row[0] if row else None

def _user_conn_ids(username: str) -> list[str] | None:
    """Return list of conn_ids the user can access, or None = all (admin)."""
    con = _auth_db()
    row = con.execute(
        "SELECT global_role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and row[0] == "admin":
        con.close()
        return None  # None = all connections
    rows = con.execute(
        "SELECT conn_id FROM connection_permissions WHERE username = ?", (username,)
    ).fetchall()
    con.close()
    return [r[0] for r in rows]

def _write_audit(username: str, conn_id: str, sql: str,
                 rows: int, duration_ms: int, status: str, error: str = ""):
    try:
        con = _auth_db()
        con.execute(
            "INSERT INTO audit_log (username, conn_id, sql_query, rows_returned, "
            "duration_ms, status, error_msg) VALUES (?,?,?,?,?,?,?)",
            (username, conn_id, sql[:2000], rows, duration_ms, status, error[:500])
        )
        con.commit()
        con.close()
    except Exception:
        pass  # never let audit failure break a query

def load_config():
    # If MCP_CONNECTION_ID env var is set, build config from environment
    # This allows container deployments without mounting a config.json
    if os.environ.get("MCP_CONNECTION_ID"):
        tables_raw = os.environ.get("MCP_TABLES", "*")
        tables = [t.strip() for t in tables_raw.split(",")] if tables_raw != "*" else ["*"]
        conn = {
            "id":       os.environ["MCP_CONNECTION_ID"],
            "name":     os.environ.get("MCP_CONNECTION_NAME", os.environ["MCP_CONNECTION_ID"]),
            "type":     os.environ.get("MCP_CONNECTION_TYPE", "mssql"),
            "server":   os.environ.get("MCP_SERVER", ""),
            "database": os.environ.get("MCP_DATABASE", ""),
            "username": os.environ.get("MCP_USERNAME", ""),
            "password": os.environ.get("MCP_PASSWORD", ""),
            "port":     int(os.environ["MCP_PORT"]) if os.environ.get("MCP_PORT") else None,
            "role":     os.environ.get("MCP_ROLE", "read-only"),
            "tables":   tables,
        }
        config = {
            "connections": [conn],
            "server": {
                "host": os.environ.get("HOST", "0.0.0.0"),  # nosec B104 - intentional for container deployments
                "port": int(os.environ.get("PORT", 7654))
            }
        }
        return _resolve_vault_secrets(config)
    with open(CONFIG_PATH, encoding="utf-8") as f:
        config = json.load(f)
    return _resolve_vault_secrets(config)

def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


# ── HashiCorp Vault secret resolution ─────────────────────────────────────────
# Any connection field value starting with "vault://" is resolved at startup.
# Format: "vault://secret/data/myapp#field_name"
# Example config.json:
#   "password": "vault://secret/data/prod-sql#password"
#
# Vault config in config.json (optional):
#   "vault": {
#     "url": "https://vault.mycompany.com",
#     "method": "token",          # token | approle | aws | azure
#     "token": "hvs.xxx",         # for method=token (or set VAULT_TOKEN env var)
#     "role_id": "...",            # for method=approle
#     "secret_id": "...",          # for method=approle
#   }

def _resolve_vault_secrets(config: dict) -> dict:
    vault_cfg = config.get("vault")
    if not vault_cfg:
        # Still check env var — vault might be configured via environment
        vault_url = os.environ.get("VAULT_ADDR")
        if not vault_url:
            return config
        vault_cfg = {"url": vault_url, "method": "token"}

    # Check if any connection has a vault:// reference
    has_vault_refs = any(
        isinstance(v, str) and v.startswith("vault://")
        for conn in config.get("connections", [])
        for v in conn.values()
    )
    if not has_vault_refs:
        return config

    try:
        import hvac
    except ImportError:
        raise ImportError("hvac is required for Vault integration: pip install hvac")

    url    = vault_cfg.get("url", os.environ.get("VAULT_ADDR", "http://localhost:8200"))
    method = vault_cfg.get("method", "token")
    client = hvac.Client(url=url)

    if method == "token":
        token = vault_cfg.get("token", os.environ.get("VAULT_TOKEN", ""))
        client.token = token

    elif method == "approle":
        role_id   = vault_cfg.get("role_id",   os.environ.get("VAULT_ROLE_ID", ""))
        secret_id = vault_cfg.get("secret_id", os.environ.get("VAULT_SECRET_ID", ""))
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)

    elif method == "aws":
        client.auth.aws.iam_login(
            access_key=os.environ.get("AWS_ACCESS_KEY_ID"),
            secret_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            role=vault_cfg.get("role", "")
        )

    elif method == "azure":
        client.auth.azure.login(
            role=vault_cfg.get("role", ""),
            jwt=vault_cfg.get("jwt", os.environ.get("VAULT_AZURE_JWT", ""))
        )

    if not client.is_authenticated():
        raise ValueError("Vault authentication failed — check your vault config")

    # Resolve all vault:// references in connection configs
    for conn in config.get("connections", []):
        for key, value in list(conn.items()):
            if not isinstance(value, str) or not value.startswith("vault://"):
                continue
            # vault://secret/data/myapp#fieldname  (KV v2 full path format)
            ref   = value[len("vault://"):]
            ref, field = ref.rsplit("#", 1) if "#" in ref else (ref, key)
            # hvac read_secret_version expects mount_point + relative path
            # e.g. "secret/data/azure-sql" → mount_point="secret", path="azure-sql"
            if "/data/" in ref:
                mount_point, secret_path = ref.split("/data/", 1)
            else:
                mount_point, secret_path = "secret", ref
            secret = client.secrets.kv.v2.read_secret_version(
                path=secret_path, mount_point=mount_point, raise_on_deleted_version=True
            )
            conn[key] = secret["data"]["data"][field]
            print(f"  [vault] resolved {key} from {mount_point}/data/{secret_path}#{field}")

    return config

def build_tools(config):
    tools = []
    for conn in config["connections"]:
        cid  = conn["id"]
        name = conn["name"]
        role = conn.get("role", "read-only")
        tools.append({
            "name": f"{cid}__schema",
            "description": f"Get full schema for: {name}",
            "inputSchema": {"type": "object", "properties": {}}
        })
        tools.append({
            "name": f"{cid}__query",
            "description": f"Run SQL on: {name}. Role: {role}.",
            "inputSchema": {
                "type": "object",
                "properties": {"sql": {"type": "string"}},
                "required": ["sql"]
            }
        })
    return tools

def handle_tool_call(name: str, args: dict, config: dict):
    parts = name.split("__", 1)
    if len(parts) != 2:
        raise ValueError(f"Unknown tool: {name}")
    cid, action = parts
    conn_cfg = next((c for c in config["connections"] if c["id"] == cid), None)
    if not conn_cfg:
        raise ValueError(f"No connection: {cid}")
    driver = get_driver(conn_cfg)
    role   = conn_cfg.get("role", "read-only")

    if action == "schema":
        return driver.schema()
    if action == "query":
        sql = args.get("sql", "").strip()
        if not sql:
            raise ValueError("sql is required")
        check(sql, role)
        first = sql.split()[0].lower()
        if first == "select":
            return json.dumps(driver.query(sql), indent=2, default=str)
        else:
            return f"{driver.execute(sql)} row(s) affected."
    raise ValueError(f"Unknown action: {action}")


# ── STDIO MODE ─────────────────────────────────────────────────────────────────
def run_stdio(config):
    tools = build_tools(config)

    def send(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def handle(req):
        method = req.get("method")
        rid    = req.get("id")
        if method == "initialize":
            return {"jsonrpc":"2.0","id":rid,"result":{
                "protocolVersion":"2024-11-05",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"universal-mcp-db","version":"2.0.0"}
            }}
        if method == "tools/list":
            return {"jsonrpc":"2.0","id":rid,"result":{"tools": tools}}
        if method == "tools/call":
            n = req["params"]["name"]
            a = req["params"].get("arguments", {})
            try:
                result = handle_tool_call(n, a, config)
                return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":result}]}}
            except Exception as e:
                return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":f"Error: {e}"}],"isError":True}}
        if method == "notifications/initialized":
            return None
        return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Method not found: {method}"}}

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req  = json.loads(line)
            resp = handle(req)
            if resp:
                send(resp)
        except Exception as e:
            send({"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":str(e)}})


# ── HTTP MODE ──────────────────────────────────────────────────────────────────
def create_app(config):
    """Build and return the FastAPI app (used by tests and run_http)."""
    from fastapi import FastAPI, Request, Path as FPath, Query
    from fastapi.responses import JSONResponse, HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
    import strawberry
    from strawberry.fastapi import GraphQLRouter
    from strawberry.scalars import JSON as GQL_JSON
    from typing import List, Optional
    import typing

    from fastapi import HTTPException
    from fastapi.exceptions import RequestValidationError

    app   = FastAPI(title="Universal MCP DB Server", version="2.0.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    tools = build_tools(config)

    @app.exception_handler(ValueError)
    async def value_error_handler(request, exc):
        return JSONResponse({"error": str(exc)}, status_code=400)

    def _auth(request: Request):
        """Extract and validate Bearer token from request. Returns caller info dict."""
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip() or None
        try:
            return _validate_token(token, config)
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail=str(e))

    # ── MCP endpoint ──────────────────────────────────────────────────────────
    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        caller = _auth(request)
        req    = await request.json()
        method = req.get("method")
        rid    = req.get("id")
        # resolve UI session username (MCP calls from the UI send the Bearer token)
        sess_token = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
        ui_sess    = _sessions.get(sess_token)
        username   = ui_sess["username"] if ui_sess else (caller.get("user","mcp-client") if isinstance(caller, dict) else "mcp-client")
        if method == "initialize":
            return {"jsonrpc":"2.0","id":rid,"result":{
                "protocolVersion":"2024-11-05",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"universal-mcp-db","version":"2.0.0"}
            }}
        if method == "tools/list":
            # filter tools list to connections the user can access
            allowed = _user_conn_ids(username)
            visible = tools if allowed is None else [
                t for t in tools if t["name"].split("__")[0] in allowed
            ]
            return {"jsonrpc":"2.0","id":rid,"result":{"tools": visible}}
        if method == "tools/call":
            n       = req["params"]["name"]
            a       = req["params"].get("arguments", {})
            conn_id = n.rsplit("__", 1)[0] if "__" in n else ""
            # ACL check
            if conn_id and _acl_role(username, conn_id) is None:
                return {"jsonrpc":"2.0","id":rid,"result":{
                    "content":[{"type":"text","text":f"Access denied to connection '{conn_id}'"}],
                    "isError":True}}
            t0 = _time.monotonic()
            try:
                result  = handle_tool_call(n, a, config)
                ms      = int((_time.monotonic() - t0) * 1000)
                rows    = len(__import__("json").loads(result)) if result.startswith("[") else 0
                _write_audit(username, conn_id, a.get("sql", n), rows, ms, "ok")
                return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":result}]}}
            except Exception as e:
                ms = int((_time.monotonic() - t0) * 1000)
                _write_audit(username, conn_id, a.get("sql", n), 0, ms, "error", str(e))
                return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":f"Error: {e}"}],"isError":True}}
        if method == "notifications/initialized":
            return JSONResponse({})
        return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Method not found: {method}"}}

    # ── REST API ──────────────────────────────────────────────────────────────
    @app.get("/api/{conn_id}/{table}")
    async def rest_get(
        request: Request,
        conn_id: str,
        table:   str,
        limit:   int   = Query(100, le=1000),
        offset:  int   = Query(0),
        order:   str   = Query(None),
        filter:  str   = Query(None, description="SQL WHERE clause e.g. id=1")
    ):
        _auth(request)
        conn_cfg = _get_conn(conn_id, config)
        driver   = get_driver(conn_cfg)
        _assert_table_allowed(table, driver)
        safe_filter = _safe_filter(filter)
        safe_order  = _safe_filter(order)
        sql = f"SELECT * FROM {table}"  # nosec B608 - table validated by _assert_table_allowed
        if safe_filter: sql += f" WHERE {safe_filter}"
        if safe_order:  sql += f" ORDER BY {safe_order}"
        sql += f" LIMIT {limit} OFFSET {offset}"
        # MSSQL doesn't support LIMIT/OFFSET — translate
        if conn_cfg["type"] in ("mssql", "azuresql"):
            sql = f"SELECT * FROM {table}"  # nosec B608
            if safe_filter: sql += f" WHERE {safe_filter}"
            if safe_order:  sql += f" ORDER BY {safe_order}"
            else:           sql += " ORDER BY (SELECT NULL)"
            sql += f" OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
        rows = driver.query(sql)
        return {"data": rows, "count": len(rows), "table": table, "connection": conn_id}

    @app.post("/api/{conn_id}/{table}")
    async def rest_post(conn_id: str, table: str, request: Request):
        conn_cfg = _get_conn(conn_id, config)
        check("INSERT placeholder", conn_cfg.get("role", "read-only"))
        driver = get_driver(conn_cfg)
        _assert_table_allowed(table, driver)
        body = await request.json()
        safe_cols = [_safe_column(k) for k in body.keys()]
        cols = ", ".join(safe_cols)
        vals = ", ".join([f"'{str(v).replace(chr(39), chr(39)+chr(39))}'" for v in body.values()])
        n = driver.execute(f"INSERT INTO {table} ({cols}) VALUES ({vals})")  # nosec B608 - table validated, cols via _safe_column, vals single-quote escaped
        return {"affected": n, "table": table}

    @app.put("/api/{conn_id}/{table}/{row_id}")
    async def rest_put(conn_id: str, table: str, row_id: str, request: Request):
        conn_cfg = _get_conn(conn_id, config)
        check("UPDATE placeholder", conn_cfg.get("role", "read-only"))
        driver = get_driver(conn_cfg)
        _assert_table_allowed(table, driver)
        body = await request.json()
        safe_id = _safe_row_id(row_id)
        sets = ", ".join([f"{_safe_column(k)}='{str(v).replace(chr(39), chr(39)+chr(39))}'" for k, v in body.items()])
        n = driver.execute(f"UPDATE {table} SET {sets} WHERE id={safe_id}")  # nosec B608 - table validated, cols via _safe_column, vals escaped, id is int
        return {"affected": n, "table": table, "id": row_id}

    @app.delete("/api/{conn_id}/{table}/{row_id}")
    async def rest_delete(conn_id: str, table: str, row_id: str):
        conn_cfg = _get_conn(conn_id, config)
        check("DELETE placeholder", conn_cfg.get("role", "read-only"))
        driver = get_driver(conn_cfg)
        _assert_table_allowed(table, driver)
        safe_id = _safe_row_id(row_id)
        n = driver.execute(f"DELETE FROM {table} WHERE id={safe_id}")  # nosec B608 - table validated, id is int
        return {"affected": n, "table": table, "id": row_id}

    @app.get("/api/{conn_id}")
    async def rest_list_tables(conn_id: str):
        conn_cfg = _get_conn(conn_id, config)
        driver   = get_driver(conn_cfg)
        tables   = driver.list_tables()
        return {"connection": conn_id, "tables": tables}

    # ── GraphQL ───────────────────────────────────────────────────────────────
    # One dynamic GraphQL schema per connection, mounted at /graphql/{conn_id}
    for conn_cfg in config["connections"]:
        _mount_graphql(app, conn_cfg)

    # ── UI + management ───────────────────────────────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    def ui():
        return open(os.path.join(os.path.dirname(__file__), "ui.html"), encoding="utf-8").read()

    @app.get("/health")
    def health(request: Request):
        auth  = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        sess  = _sessions.get(token)
        if sess:
            allowed = _user_conn_ids(sess["username"])  # None = all
            conns = [
                {"id":c["id"],"name":c["name"],"role":c.get("role","read-only"),"type":c.get("type","")}
                for c in config["connections"]
                if allowed is None or c["id"] in allowed
            ]
        else:
            conns = []
        return {"status":"ok","connections":conns,"version":"2.0.0"}

    # ── UI Auth (Vault-backed) ────────────────────────────────────────────────
    import secrets as _secrets
    import time as _time
    _sessions: dict[str, dict] = {}  # token → {username, global_role}

    def _ui_session(request: Request) -> dict:
        """Extract session from Bearer token. Raises 401 if missing/invalid."""
        auth  = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        sess  = _sessions.get(token)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return sess

    def _vault_ui_creds() -> tuple[str, str]:
        """Fetch UI admin credentials from Vault at request time (so rotation works live)."""
        vault_cfg = config.get("vault")
        if not vault_cfg:
            raise ValueError("No vault config — cannot validate UI login")
        try:
            import hvac as _hvac
            client = _hvac.Client(url=vault_cfg["url"])
            client.token = vault_cfg.get("token", os.environ.get("VAULT_TOKEN", ""))
            secret = client.secrets.kv.v2.read_secret_version(
                path="ui-admin", mount_point="secret", raise_on_deleted_version=True
            )
            data = secret["data"]["data"]
            return data["username"], data["password"]
        except Exception as e:
            raise ValueError(f"Vault lookup failed: {e}")

    @app.post("/auth/login")
    async def ui_login(request: Request):
        body = await request.json()
        username = body.get("username", "")
        password = body.get("password", "")
        try:
            vault_user, vault_pass = _vault_ui_creds()
        except ValueError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=503)
        if username == vault_user and password == vault_pass:
            token = _secrets.token_hex(32)
            _sessions[token] = {"username": vault_user, "global_role": "admin"}
            # Bootstrap auth.db on first login
            _init_auth_db(vault_user)
            _bootstrap_admin_permissions(vault_user,
                [c["id"] for c in config["connections"]])
            return {"ok": True, "token": token, "role": "admin", "username": vault_user}
        return JSONResponse({"ok": False, "error": "Invalid username or password"}, status_code=401)

    @app.post("/auth/logout")
    async def ui_logout(request: Request):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        _sessions.pop(token, None)
        return {"ok": True}

    @app.get("/auth/me")
    async def ui_me(request: Request):
        auth  = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        sess  = _sessions.get(token)
        if not sess:
            return JSONResponse({"authenticated": False}, status_code=401)
        return {"authenticated": True, "role": sess["global_role"], "username": sess["username"]}

    @app.post("/connections/test")
    async def test_connection(request: Request):
        conn = await request.json()
        try:
            driver = get_driver(conn)
            driver.schema()
            return {"ok": True, "message": "Connection successful"}
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    @app.post("/connections")
    async def add_connection(request: Request):
        conn = await request.json()
        for f in ["id", "name", "type", "role"]:
            if not conn.get(f):
                return JSONResponse({"error": f"Missing: {f}"}, status_code=400)
        if any(c["id"] == conn["id"] for c in config["connections"]):
            return JSONResponse({"error": f"ID '{conn['id']}' already exists"}, status_code=409)
        config["connections"].append(conn)
        save_config(config)
        nonlocal tools
        tools = build_tools(config)
        _mount_graphql(app, conn)
        return {"ok": True, "id": conn["id"]}

    @app.delete("/connections/{conn_id}")
    def delete_connection(conn_id: str):
        before = len(config["connections"])
        config["connections"] = [c for c in config["connections"] if c["id"] != conn_id]
        if len(config["connections"]) == before:
            return JSONResponse({"error": "Not found"}, status_code=404)
        save_config(config)
        nonlocal tools
        tools = build_tools(config)
        return {"ok": True}

    # ── Admin endpoints ───────────────────────────────────────────────────────
    def _require_admin(request: Request) -> dict:
        sess = _ui_session(request)
        if sess["global_role"] != "admin":
            raise HTTPException(status_code=403, detail="Admin role required")
        return sess

    @app.get("/admin/users")
    def admin_list_users(request: Request):
        _require_admin(request)
        import sqlite3
        con = _auth_db()
        users = con.execute(
            "SELECT u.username, u.global_role, u.created_at, "
            "GROUP_CONCAT(p.conn_id || ':' || p.role) as perms "
            "FROM users u LEFT JOIN connection_permissions p ON u.username=p.username "
            "GROUP BY u.username ORDER BY u.username"
        ).fetchall()
        con.close()
        result = []
        for u in users:
            perms = {}
            if u[3]:
                for p in u[3].split(","):
                    cid, role = p.split(":", 1)
                    perms[cid] = role
            result.append({"username": u[0], "global_role": u[1],
                            "created_at": u[2], "permissions": perms})
        return {"users": result}

    @app.post("/admin/users")
    async def admin_add_user(request: Request):
        _require_admin(request)
        body = await request.json()
        username = body.get("username", "").strip()
        role     = body.get("global_role", "viewer")
        if not username:
            return JSONResponse({"error": "username required"}, status_code=400)
        if role not in ("admin", "viewer"):
            return JSONResponse({"error": "global_role must be admin or viewer"}, status_code=400)
        con = _auth_db()
        try:
            con.execute("INSERT INTO users (username, global_role) VALUES (?, ?)", (username, role))
            con.commit()
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        finally:
            con.close()
        return {"ok": True, "username": username, "global_role": role}

    @app.delete("/admin/users/{username}")
    def admin_delete_user(username: str, request: Request):
        sess = _require_admin(request)
        if username == sess["username"]:
            return JSONResponse({"error": "Cannot delete yourself"}, status_code=400)
        con = _auth_db()
        con.execute("DELETE FROM connection_permissions WHERE username = ?", (username,))
        con.execute("DELETE FROM users WHERE username = ?", (username,))
        con.commit()
        con.close()
        return {"ok": True}

    @app.post("/admin/permissions")
    async def admin_grant(request: Request):
        sess = _require_admin(request)
        body = await request.json()
        username = body.get("username", "").strip()
        conn_id  = body.get("conn_id", "").strip()
        role     = body.get("role", "read-only")
        if not username or not conn_id:
            return JSONResponse({"error": "username and conn_id required"}, status_code=400)
        if role not in ("read-only", "read-write", "admin"):
            return JSONResponse({"error": "role must be read-only, read-write, or admin"}, status_code=400)
        con = _auth_db()
        con.execute(
            "INSERT INTO connection_permissions (username, conn_id, role, granted_by) "
            "VALUES (?,?,?,?) ON CONFLICT(username, conn_id) DO UPDATE SET role=excluded.role",
            (username, conn_id, role, sess["username"])
        )
        con.commit()
        con.close()
        return {"ok": True}

    @app.delete("/admin/permissions/{username}/{conn_id}")
    def admin_revoke(username: str, conn_id: str, request: Request):
        _require_admin(request)
        con = _auth_db()
        con.execute(
            "DELETE FROM connection_permissions WHERE username=? AND conn_id=?",
            (username, conn_id)
        )
        con.commit()
        con.close()
        return {"ok": True}

    @app.get("/admin/audit")
    def admin_audit(request: Request,
                    limit: int = 100, offset: int = 0,
                    username: str = None, conn_id: str = None, status: str = None):
        _require_admin(request)
        where, params = [], []
        if username: where.append("username=?");  params.append(username)
        if conn_id:  where.append("conn_id=?");   params.append(conn_id)
        if status:   where.append("status=?");    params.append(status)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        con  = _auth_db()
        rows = con.execute(
            f"SELECT id,username,conn_id,sql_query,rows_returned,duration_ms,status,error_msg,ts "  # nosec B608
            f"FROM audit_log {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        total = con.execute(f"SELECT COUNT(*) FROM audit_log {clause}", params).fetchone()[0]  # nosec B608
        con.close()
        keys = ["id","username","conn_id","sql","rows","duration_ms","status","error","ts"]
        return {"total": total, "rows": [dict(zip(keys, r)) for r in rows]}

    return app


def run_http(config):
    from fastapi import FastAPI
    import uvicorn
    app  = create_app(config)
    host = config["server"]["host"]
    port = config["server"]["port"]
    print(f"\nUniversal MCP DB Server v2.0")
    print(f"  UI       ->  http://{host}:{port}/")
    print(f"  MCP      ->  http://{host}:{port}/mcp")
    print(f"  REST     ->  http://{host}:{port}/api/{{conn}}/{{table}}")
    print(f"  GraphQL  ->  http://{host}:{port}/graphql/{{conn}}")
    print(f"  Docs     ->  http://{host}:{port}/docs")
    print(f"\n  Connections ({len(config['connections'])}):")
    for c in config["connections"]:
        print(f"    [{c.get('role','read-only'):12}] {c['id']}  ({c.get('type','')})")
    print()

    # Auto-enable TLS if cert.pem + key.pem exist next to server.py
    base = os.path.dirname(__file__)
    cert = os.path.join(base, "cert.pem")
    key  = os.path.join(base, "key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        scheme = "https"
        print(f"  TLS      ->  cert.pem + key.pem found, HTTPS enabled")
        uvicorn.run(app, host=host, port=port, ssl_certfile=cert, ssl_keyfile=key)
    else:
        scheme = "http"
        uvicorn.run(app, host=host, port=port)


# ── Helpers ────────────────────────────────────────────────────────────────────
def _get_conn(conn_id: str, config: dict) -> dict:
    from fastapi import HTTPException
    conn = next((c for c in config["connections"] if c["id"] == conn_id), None)
    if not conn:
        raise HTTPException(status_code=404, detail=f"Connection '{conn_id}' not found")
    return conn

def _assert_table_allowed(table: str, driver):
    from fastapi import HTTPException
    allowed = driver.list_tables()
    if table not in allowed:
        raise HTTPException(status_code=403, detail=f"Table '{table}' not exposed for this connection")

def _mount_graphql(app, conn_cfg: dict):
    """
    Mount a GraphQL endpoint at /graphql/{conn_id}.
    Schema:
      query  { rows(table: "x", limit: 100, filter: "id=1") : [JSON]
               tables : [String]
               schema : String }
      mutation { execute(sql: "...") : String }   (write roles only)
    """
    import strawberry
    from strawberry.fastapi import GraphQLRouter
    from typing import List, Optional
    import json as _json

    cid       = conn_cfg["id"]
    role      = conn_cfg.get("role", "read-only")
    can_write = role in ("read-write", "admin")

    @strawberry.type
    class Query:
        @strawberry.field
        def rows(self, table: str, limit: int = 100, filter: Optional[str] = None) -> List[str]:
            d   = get_driver(conn_cfg)
            _assert_table_allowed_gql(table, d)
            safe_filter = _safe_filter(filter)
            sql = f"SELECT * FROM {table}"  # nosec B608 - table validated by _assert_table_allowed_gql
            if safe_filter: sql += f" WHERE {safe_filter}"
            if conn_cfg["type"] not in ("mssql", "azuresql"):
                sql += f" LIMIT {limit}"
            else:
                base = f"SELECT * FROM {table}"  # nosec B608
                if safe_filter: base += f" WHERE {safe_filter}"
                sql = base + f" ORDER BY (SELECT NULL) OFFSET 0 ROWS FETCH NEXT {limit} ROWS ONLY"
            return [_json.dumps(r, default=str) for r in d.query(sql)]

        @strawberry.field
        def tables(self) -> List[str]:
            return get_driver(conn_cfg).list_tables()

        @strawberry.field
        def schema(self) -> str:
            return get_driver(conn_cfg).schema()

    if can_write:
        @strawberry.type
        class Mutation:
            @strawberry.mutation
            def execute(self, sql: str) -> str:
                check(sql, role)
                n = get_driver(conn_cfg).execute(sql)
                return f"{n} row(s) affected."
        schema_obj = strawberry.Schema(query=Query, mutation=Mutation)
    else:
        schema_obj = strawberry.Schema(query=Query)

    router = GraphQLRouter(schema_obj, path=f"/graphql/{cid}")
    app.include_router(router)


def _assert_table_allowed_gql(table: str, driver):
    allowed = driver.list_tables()
    if table not in allowed:
        raise ValueError(f"Table '{table}' not exposed for this connection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdio", action="store_true")
    args   = parser.parse_args()
    config = load_config()
    if args.stdio:
        run_stdio(config)
    else:
        run_http(config)
