"""
roles.py — permission enforcement
Roles: read-only, read-write, admin
"""


ROLES = {
    "read-only":  {"select": True,  "insert": False, "update": False, "delete": False, "ddl": False},
    "read-write": {"select": True,  "insert": True,  "update": True,  "delete": True,  "ddl": False},
    "admin":      {"select": True,  "insert": True,  "update": True,  "delete": True,  "ddl": True},
}

DDL_KEYWORDS    = {"create", "drop", "alter", "truncate"}
WRITE_KEYWORDS  = {"insert", "update", "delete", "merge"}


def check(sql: str, role: str) -> None:
    """Raise ValueError if the SQL is not allowed under the given role."""
    perms = ROLES.get(role)
    if not perms:
        raise ValueError(f"Unknown role: {role}")

    first = sql.strip().split()[0].lower()

    if first in DDL_KEYWORDS and not perms["ddl"]:
        raise ValueError(f"Role '{role}' does not allow DDL statements ({first.upper()}).")

    if first in WRITE_KEYWORDS and not perms["insert"]:
        raise ValueError(f"Role '{role}' does not allow write statements ({first.upper()}).")

    if first == "select" and not perms["select"]:
        raise ValueError(f"Role '{role}' does not allow SELECT.")
