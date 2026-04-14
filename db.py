"""
db.py — universal database connector
Supports: SQLite, SQL Server (Azure/local), PostgreSQL, MySQL, AWS RDS, CosmosDB, AWS Bedrock KB
"""
import sqlite3, json, os
from typing import Any


def get_driver(conn_cfg: dict):
    t = conn_cfg["type"]
    if t == "sqlite":
        return SQLiteDriver(conn_cfg)
    elif t in ("mssql", "azuresql"):
        return MSSQLDriver(conn_cfg)
    elif t in ("postgres", "postgresql", "awsrds-postgres"):
        return PostgresDriver(conn_cfg)
    elif t in ("mysql", "awsrds-mysql", "aurora-mysql"):
        return MySQLDriver(conn_cfg)
    elif t in ("cosmosdb", "cosmos"):
        return CosmosDriver(conn_cfg)
    elif t in ("bedrock-kb", "aws-bedrock"):
        return BedrockKBDriver(conn_cfg)
    else:
        raise ValueError(f"Unsupported db type: {t}")


def filter_tables(all_tables: list[str], allowed: list[str] | None) -> list[str]:
    """Return only tables that are in the allowed list. '*' means all."""
    if not allowed or allowed == ["*"]:
        return all_tables
    return [t for t in all_tables if t in allowed]


# ── SQLite ─────────────────────────────────────────────────────────────────────
class SQLiteDriver:
    def __init__(self, cfg):
        self.path   = cfg["database"]
        self.tables = cfg.get("tables", ["*"])

    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def query(self, sql: str) -> list[dict]:
        conn = self._conn()
        cur  = conn.cursor()
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def execute(self, sql: str) -> int:
        conn = self._conn()
        cur  = conn.cursor()
        cur.execute(sql)
        conn.commit()
        n = cur.rowcount
        conn.close()
        return n

    def list_tables(self) -> list[str]:
        rows = self.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        all_t = [r["name"] for r in rows]
        return filter_tables(all_t, self.tables)

    def table_columns(self, table: str) -> list[dict]:
        rows = self.query(f"PRAGMA table_info({table})")
        return [{"name": r["name"], "type": r["type"]} for r in rows]

    def schema(self) -> str:
        lines = []
        for t in self.list_tables():
            cols = self.table_columns(t)
            lines.append(f"Table: {t}")
            for c in cols:
                lines.append(f"  - {c['name']} ({c['type']})")
        return "\n".join(lines)


# ── SQL Server / Azure SQL ─────────────────────────────────────────────────────
class MSSQLDriver:
    def __init__(self, cfg):
        import pyodbc
        self.pyodbc  = pyodbc
        self.tables  = cfg.get("tables", ["*"])
        pwd = cfg.get("password", os.environ.get("SQL_PASSWORD", ""))
        self.conn_str = (
            f"DRIVER={{SQL Server}};SERVER={cfg.get('server','')},1433;"
            f"DATABASE={cfg.get('database','')};UID={cfg.get('username','')};"
            f"PWD={pwd};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
        )

    def _conn(self):
        return self.pyodbc.connect(self.conn_str)

    def query(self, sql: str) -> list[dict]:
        conn = self._conn()
        cur  = conn.cursor()
        cur.execute(sql)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        conn.close()
        return rows

    def execute(self, sql: str) -> int:
        conn = self._conn()
        cur  = conn.cursor()
        cur.execute(sql)
        conn.commit()
        n = cur.rowcount
        conn.close()
        return n

    def list_tables(self) -> list[str]:
        rows = self.query("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
        all_t = [r["TABLE_NAME"] for r in rows]
        return filter_tables(all_t, self.tables)

    def table_columns(self, table: str) -> list[dict]:
        rows = self.query(f"SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{table}' ORDER BY ORDINAL_POSITION")  # nosec B608 - table comes from list_tables() which is config-controlled
        return [{"name": r["COLUMN_NAME"], "type": r["DATA_TYPE"]} for r in rows]

    def schema(self) -> str:
        lines = []
        for t in self.list_tables():
            cols = self.table_columns(t)
            lines.append(f"Table: {t}")
            for c in cols:
                lines.append(f"  - {c['name']} ({c['type']})")
        return "\n".join(lines)


# ── PostgreSQL / AWS RDS PG ────────────────────────────────────────────────────
class PostgresDriver:
    def __init__(self, cfg):
        import psycopg2, psycopg2.extras
        self.psycopg2 = psycopg2
        self.extras   = psycopg2.extras
        self.tables   = cfg.get("tables", ["*"])
        self.dsn = (
            f"host={cfg.get('server','')} dbname={cfg.get('database','')} "
            f"user={cfg.get('username','')} password={cfg.get('password', os.environ.get('PG_PASSWORD',''))} "
            f"port={cfg.get('port', 5432)}"
        )

    def _conn(self):
        return self.psycopg2.connect(self.dsn)

    def query(self, sql: str) -> list[dict]:
        conn = self._conn()
        cur  = conn.cursor(cursor_factory=self.extras.RealDictCursor)
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def execute(self, sql: str) -> int:
        conn = self._conn()
        cur  = conn.cursor()
        cur.execute(sql)
        conn.commit()
        n = cur.rowcount
        conn.close()
        return n

    def list_tables(self) -> list[str]:
        rows = self.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name")
        all_t = [r["table_name"] for r in rows]
        return filter_tables(all_t, self.tables)

    def table_columns(self, table: str) -> list[dict]:
        rows = self.query(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='{table}' ORDER BY ordinal_position")  # nosec B608 - table comes from list_tables() which is config-controlled
        return [{"name": r["column_name"], "type": r["data_type"]} for r in rows]

    def schema(self) -> str:
        lines = []
        for t in self.list_tables():
            cols = self.table_columns(t)
            lines.append(f"Table: {t}")
            for c in cols:
                lines.append(f"  - {c['name']} ({c['type']})")
        return "\n".join(lines)


# ── MySQL / AWS RDS MySQL / Aurora ─────────────────────────────────────────────
class MySQLDriver:
    def __init__(self, cfg):
        import pymysql, pymysql.cursors
        self.pymysql = pymysql
        self.tables  = cfg.get("tables", ["*"])
        self.db_name = cfg.get("database", "")
        self.connect_args = dict(
            host=cfg.get("server", ""),
            port=int(cfg.get("port", 3306)),
            user=cfg.get("username", ""),
            password=cfg.get("password", os.environ.get("MYSQL_PASSWORD", "")),
            database=self.db_name,
            cursorclass=pymysql.cursors.DictCursor,
        )

    def _conn(self):
        return self.pymysql.connect(**self.connect_args)

    def query(self, sql: str) -> list[dict]:
        conn = self._conn()
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = list(cur.fetchall())
        conn.close()
        return rows

    def execute(self, sql: str) -> int:
        conn = self._conn()
        with conn.cursor() as cur:
            cur.execute(sql)
            conn.commit()
            n = cur.rowcount
        conn.close()
        return n

    def list_tables(self) -> list[str]:
        rows = self.query(f"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='{self.db_name}' ORDER BY TABLE_NAME")  # nosec B608 - db_name comes from config, not user input
        all_t = [r["TABLE_NAME"] for r in rows]
        return filter_tables(all_t, self.tables)

    def table_columns(self, table: str) -> list[dict]:
        rows = self.query(f"SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='{self.db_name}' AND TABLE_NAME='{table}' ORDER BY ORDINAL_POSITION")  # nosec B608 - both come from config/list_tables()
        return [{"name": r["COLUMN_NAME"], "type": r["DATA_TYPE"]} for r in rows]

    def schema(self) -> str:
        lines = []
        for t in self.list_tables():
            cols = self.table_columns(t)
            lines.append(f"Table: {t}")
            for c in cols:
                lines.append(f"  - {c['name']} ({c['type']})")
        return "\n".join(lines)


# ── Azure CosmosDB (NoSQL) ─────────────────────────────────────────────────────
class CosmosDriver:
    def __init__(self, cfg):
        from azure.cosmos import CosmosClient
        self.tables     = cfg.get("tables", ["*"])   # "tables" = containers
        self.db_name    = cfg.get("database", "")
        endpoint = cfg.get("server", "")
        key      = cfg.get("password", os.environ.get("COSMOS_KEY", ""))
        self.client  = CosmosClient(endpoint, credential=key)
        self.database = self.client.get_database_client(self.db_name)

    def list_tables(self) -> list[str]:
        all_c = [c["id"] for c in self.database.list_containers()]
        return filter_tables(all_c, self.tables)

    def table_columns(self, container: str) -> list[dict]:
        # Cosmos is schemaless — sample first doc for field names
        try:
            cont  = self.database.get_container_client(container)
            items = list(cont.query_items("SELECT TOP 1 * FROM c", enable_cross_partition_query=True))
            if items:
                return [{"name": k, "type": type(v).__name__} for k, v in items[0].items()]
        except Exception:
            pass
        return [{"name": "id", "type": "string"}]

    def query(self, sql: str) -> list[dict]:
        # sql format: "container_name: SELECT * FROM c WHERE ..."
        if ":" in sql:
            container, query = sql.split(":", 1)
            container = container.strip()
            query     = query.strip()
        else:
            raise ValueError("CosmosDB query format: 'container_name: SELECT * FROM c WHERE ...'")
        cont  = self.database.get_container_client(container)
        items = list(cont.query_items(query, enable_cross_partition_query=True))
        return items

    def execute(self, sql: str) -> int:
        raise ValueError("Use CosmosDB SDK for write operations — raw SQL writes not supported.")

    def schema(self) -> str:
        lines = []
        for c in self.list_tables():
            cols = self.table_columns(c)
            lines.append(f"Container: {c}")
            for col in cols:
                lines.append(f"  - {col['name']} ({col['type']})")
        return "\n".join(lines)


# ── AWS Bedrock Knowledge Base ─────────────────────────────────────────────────
class BedrockKBDriver:
    def __init__(self, cfg):
        import boto3
        self.tables       = cfg.get("tables", ["*"])   # "tables" = knowledge base IDs
        self.kb_ids       = cfg.get("knowledge_bases", [])
        region = cfg.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        self.client = boto3.client(
            "bedrock-agent-runtime",
            region_name=region,
            aws_access_key_id=cfg.get("aws_access_key_id", os.environ.get("AWS_ACCESS_KEY_ID")),
            aws_secret_access_key=cfg.get("aws_secret_access_key", os.environ.get("AWS_SECRET_ACCESS_KEY")),
        )
        self.bedrock = boto3.client(
            "bedrock-agent",
            region_name=region,
            aws_access_key_id=cfg.get("aws_access_key_id", os.environ.get("AWS_ACCESS_KEY_ID")),
            aws_secret_access_key=cfg.get("aws_secret_access_key", os.environ.get("AWS_SECRET_ACCESS_KEY")),
        )

    def list_tables(self) -> list[str]:
        resp  = self.bedrock.list_knowledge_bases(maxResults=50)
        all_k = [kb["knowledgeBaseId"] for kb in resp.get("knowledgeBaseSummaries", [])]
        return filter_tables(all_k, self.tables)

    def table_columns(self, kb_id: str) -> list[dict]:
        try:
            kb = self.bedrock.get_knowledge_base(knowledgeBaseId=kb_id)
            name = kb["knowledgeBase"].get("name", kb_id)
            return [{"name": "query", "type": "string"}, {"name": "kb_name", "type": f"{name}"}]
        except Exception:
            return [{"name": "query", "type": "string"}]

    def query(self, sql: str) -> list[dict]:
        # sql = "kb_id: natural language question"
        if ":" in sql:
            kb_id, question = sql.split(":", 1)
            kb_id    = kb_id.strip()
            question = question.strip()
        else:
            raise ValueError("Bedrock KB query format: 'knowledge_base_id: your question here'")
        resp    = self.client.retrieve(
            knowledgeBaseId=kb_id,
            retrievalQuery={"text": question},
            retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 5}}
        )
        results = []
        for r in resp.get("retrievalResults", []):
            results.append({
                "content": r["content"]["text"],
                "score":   round(r.get("score", 0), 4),
                "source":  r.get("location", {}).get("s3Location", {}).get("uri", "")
            })
        return results

    def execute(self, sql: str) -> int:
        raise ValueError("Bedrock Knowledge Bases are read-only via retrieval API.")

    def schema(self) -> str:
        lines = []
        for kb_id in self.list_tables():
            cols = self.table_columns(kb_id)
            lines.append(f"Knowledge Base: {kb_id}")
            for c in cols:
                lines.append(f"  - {c['name']}: {c['type']}")
        return "\n".join(lines)
