"""
query/sql_guard.py

Critical security boundary: the LLM query planner (query/llm.py) generates
SQL from natural language. That SQL must NEVER be executed directly — an
LLM can be prompt-injected, can hallucinate a destructive statement, or can
simply make a mistake. This module is the single choke point everything
must pass through before touching the real database.

Rules enforced:
  1. Must be a single statement.
  2. Must start with SELECT (case-insensitive).
  3. Must not contain any write/DDL/pragma/attach keywords, anywhere.
  4. Every table referenced must be in db.schema.ALLOWED_TABLES.
  5. Must not contain a semicolon other than an optional single trailing one
     (blocks statement stacking like "SELECT 1; DROP TABLE alerts").
"""

import re

from db.schema import ALLOWED_TABLES

_FORBIDDEN_KEYWORDS = [
    "insert", "update", "delete", "drop", "alter", "create", "attach",
    "detach", "pragma", "vacuum", "replace", "truncate", "grant", "revoke",
    "exec", "execute",
]

_TABLE_NAME_PATTERN = re.compile(r"\bfrom\s+([a-zA-Z_][a-zA-Z0-9_]*)|\bjoin\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)


class SQLValidationError(Exception):
    pass


def validate(sql: str) -> str:
    if not sql or not sql.strip():
        raise SQLValidationError("Empty SQL")

    cleaned = sql.strip()

    # Allow exactly one optional trailing semicolon, reject any stacking.
    body = cleaned[:-1] if cleaned.endswith(";") else cleaned
    if ";" in body:
        raise SQLValidationError("Multiple statements are not allowed")

    if not re.match(r"^\s*select\b", body, re.IGNORECASE):
        raise SQLValidationError("Only SELECT statements are allowed")

    lowered = body.lower()
    for kw in _FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{kw}\b", lowered):
            raise SQLValidationError(f"Forbidden keyword detected: {kw}")

    tables_found = set()
    for match in _TABLE_NAME_PATTERN.finditer(body):
        name = match.group(1) or match.group(2)
        if name:
            tables_found.add(name.lower())

    if not tables_found:
        raise SQLValidationError("Could not identify any table in the query")

    unknown = tables_found - {t.lower() for t in ALLOWED_TABLES}
    if unknown:
        raise SQLValidationError(f"Query references unknown/disallowed table(s): {unknown}")

    return body
