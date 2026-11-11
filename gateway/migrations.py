"""Minimal, idempotent schema migration for the request_logs table.

TODO: this hand-rolled ALTER TABLE is only meant for the SQLite phase of the
project. Once the gateway moves to Postgres, use Alembic for real, versioned
migrations instead.
"""
from sqlalchemy import inspect, text

TABLE = "request_logs"

# column name -> DDL fragment. Defaults make the column valid for old rows too.
NEW_COLUMNS = {
    "action": "VARCHAR DEFAULT 'allow'",
    "direction": "VARCHAR DEFAULT 'input'",
    "data_types": "VARCHAR DEFAULT ''",
}


def migrate_schema(engine) -> list:
    """Add any missing columns to an existing request_logs table.

    Returns the names of the columns that were added (empty when up to date).
    Safe to run on every startup.
    """
    if TABLE not in inspect(engine).get_table_names():
        return []
    existing = {column["name"] for column in inspect(engine).get_columns(TABLE)}
    added = []
    with engine.begin() as connection:
        for name, ddl in NEW_COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE {TABLE} ADD COLUMN {name} {ddl}"))
                added.append(name)
        if "action" in added:
            # rows written before DLP existed: a blocked row was a block
            connection.execute(
                text(f"UPDATE {TABLE} SET action = 'block' WHERE is_blocked = 1")
            )
    return added
