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

# ── Input sanitisation ─────────────────────────────────────────────────────────
_DANGEROUS = re.compile(
    r"\b(drop|truncate|alter|create|exec|execute|xp_|sp_|insert|update|delete|merge|grant|revoke)\b",
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
    """Ensure a column name is alphanumeric + underscores only."""
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise ValueError(f"Invalid column name: '{name}'")
    return name

def _safe_row_id(row_id: str) -> int:
    """Ensure row_id is a plain integer — no injection possible."""
    try:
        return int(row_id)
    except ValueError:
        raise ValueError(f"row_id must be an integer, got: '{row_id}'")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

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
def run_http(config):
    from fastapi import FastAPI, Request, Path as FPath, Query
    from fastapi.responses import JSONResponse, HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn, strawberry
    from strawberry.fastapi import GraphQLRouter
    from strawberry.scalars import JSON as GQL_JSON
    from typing import List, Optional
    import typing

    app   = FastAPI(title="Universal MCP DB Server", version="2.0.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    tools = build_tools(config)

    # ── MCP endpoint ──────────────────────────────────────────────────────────
    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        req    = await request.json()
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
            return JSONResponse({})
        return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Method not found: {method}"}}

    # ── REST API ──────────────────────────────────────────────────────────────
    @app.get("/api/{conn_id}/{table}")
    async def rest_get(
        conn_id: str,
        table:   str,
        limit:   int   = Query(100, le=1000),
        offset:  int   = Query(0),
        order:   str   = Query(None),
        filter:  str   = Query(None, description="SQL WHERE clause e.g. id=1")
    ):
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
    def health():
        conns = [{"id":c["id"],"name":c["name"],"role":c.get("role","read-only"),"type":c.get("type","")}
                 for c in config["connections"]]
        return {"status":"ok","connections":conns,"version":"2.0.0"}

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
