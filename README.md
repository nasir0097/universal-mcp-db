# Universal MCP DB Manager

A GUI-first, open-source MCP server that connects **any database** to AI tools — Claude, GitHub Copilot, Azure AI Foundry — without writing code.

![CI](https://github.com/nasir0097/universal-mcp-db/actions/workflows/ci.yml/badge.svg)

---

## Why this exists

Every existing solution has a catch:

| Tool | Problem |
|---|---|
| Microsoft DAB | CLI-only, Azure-only, no GUI |
| Azure AI Foundry connections | Cloud-only, requires Entra ID setup |
| Custom MCP scripts | You write one per database |

**Universal MCP DB Manager** runs locally in 30 seconds, works with any database, and exposes three protocols at once — no cloud account required.

---

## What it does

One server. Three protocols. Any database.

```
Your Database  →  universal-mcp-db  →  MCP   (Claude, Copilot, AI Foundry)
                                    →  REST  (/api/{conn}/{table})
                                    →  GraphQL (/graphql/{conn})
```

**Web UI** to add and manage connections — no config files to edit by hand.

---

## Supported databases

| Database | Type string |
|---|---|
| SQLite | `sqlite` |
| SQL Server / Azure SQL | `mssql` / `azuresql` |
| PostgreSQL | `postgres` |
| MySQL | `mysql` |
| AWS RDS (PostgreSQL) | `awsrds-postgres` |
| AWS RDS (MySQL) | `awsrds-mysql` |
| AWS Aurora (MySQL) | `aurora-mysql` |
| Azure CosmosDB | `cosmosdb` |
| AWS Bedrock Knowledge Base | `bedrock-kb` |

---

## Quickstart

```bash
git clone https://github.com/nasir0097/universal-mcp-db.git
cd universal-mcp-db

pip install -r requirements.txt

cp config.example.json config.json   # edit with your connections

python server.py
# Open http://localhost:7654
```

Or with Docker:

```bash
docker compose up
```

---

## Add a connection

Open **http://localhost:7654**, click **+ Add Connection**, fill in the form, hit **Test Connection**, then **Add**.

No YAML. No CLI flags. No restart required.

---

## Connect to Claude Code

Add this to `~/.claude.json`:

```json
{
  "mcpServers": {
    "universal-mcp-db": {
      "command": "python",
      "args": ["/path/to/universal-mcp-db/server.py", "--stdio"],
      "cwd": "/path/to/universal-mcp-db"
    }
  }
}
```

Restart Claude Code. Type `/mcp` to confirm tools are loaded. Then ask Claude:

> *"How many rows are in my orders table?"*

Claude will call `{conn_id}__query` automatically.

---

## Connect to Claude Desktop

Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "universal-mcp-db": {
      "command": "python",
      "args": ["/path/to/universal-mcp-db/server.py", "--stdio"],
      "cwd": "/path/to/universal-mcp-db"
    }
  }
}
```

---

## Connect to Azure AI Foundry

Your server must be reachable over HTTPS. Deploy via Docker to any cloud VM or container service, then add the `/mcp` endpoint as an MCP connection in AI Foundry.

---

## REST API

```
GET    /api/{conn}/{table}?limit=100&offset=0&filter=id=1&order=name
POST   /api/{conn}/{table}          body: { "col": "val", ... }
PUT    /api/{conn}/{table}/{id}      body: { "col": "val", ... }
DELETE /api/{conn}/{table}/{id}
GET    /api/{conn}                   list tables
```

## GraphQL

```
GET/POST /graphql/{conn}

query {
  rows(table: "orders", limit: 10, filter: "status='active'")
  tables
  schema
}

mutation {
  execute(sql: "UPDATE orders SET status='shipped' WHERE id=1")
}
```

---

## Role enforcement

Set per connection in `config.json` or the UI:

| Role | SELECT | INSERT/UPDATE/DELETE | DDL |
|---|---|---|---|
| `read-only` | ✅ | ❌ | ❌ |
| `read-write` | ✅ | ✅ | ❌ |
| `admin` | ✅ | ✅ | ✅ |

---

## config.json reference

```json
{
  "connections": [
    {
      "id": "my-sql",
      "name": "Production SQL",
      "type": "mssql",
      "server": "myserver.database.windows.net",
      "database": "mydb",
      "username": "sqladmin",
      "password": "YOUR_PASSWORD",
      "port": 1433,
      "role": "read-only",
      "tables": ["customers", "orders"]
    }
  ],
  "server": {
    "host": "0.0.0.0",
    "port": 7654
  }
}
```

`tables: ["*"]` exposes all tables. Listing specific tables restricts what AI tools can see.

> **Never commit `config.json`** — it is in `.gitignore`. Use `config.example.json` as a template.

---

## Security

- `config.json` is gitignored — credentials stay local
- `filter` and `order` params are scanned for dangerous keywords (`DROP`, `EXEC`, `xp_`, etc.)
- Column names validated as `[a-zA-Z_][a-zA-Z0-9_]*` before INSERT/UPDATE
- `row_id` enforced as integer before DELETE/UPDATE
- Role enforcement blocks writes on read-only connections at the SQL keyword level

---

## Development

```bash
# Run tests
pytest tests/ -v

# Security scan
pip install bandit
bandit -r server.py db.py roles.py -ll

# Docker build
docker build -t universal-mcp-db .
```

CI runs all three on every push via GitHub Actions.

---

## License

MIT
