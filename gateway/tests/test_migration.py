from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import main
from migrations import NEW_COLUMNS, TABLE, migrate_schema

# the request_logs table exactly as it was created before the DLP columns existed
OLD_SCHEMA = """
CREATE TABLE request_logs (
    id INTEGER NOT NULL,
    prompt VARCHAR NOT NULL,
    is_blocked BOOLEAN,
    risk_score INTEGER,
    threat_type VARCHAR,
    timestamp DATETIME,
    PRIMARY KEY (id)
)
"""
OLD_COLUMNS = ["id", "prompt", "is_blocked", "risk_score", "threat_type", "timestamp"]


@pytest.fixture
def old_engine(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'old.db'}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    now = datetime.utcnow().isoformat(sep=" ")
    with engine.begin() as connection:
        connection.execute(text(OLD_SCHEMA))
        connection.execute(
            text("INSERT INTO request_logs VALUES (1, 'old blocked', 1, 80, 'DLP Violation', :ts)"),
            {"ts": now},
        )
        connection.execute(
            text("INSERT INTO request_logs VALUES (2, 'old fine', 0, 10, 'Safe', :ts)"),
            {"ts": now},
        )
    yield engine
    engine.dispose()


def column_names(engine):
    return [column["name"] for column in inspect(engine).get_columns(TABLE)]


def test_migration_adds_missing_columns_and_keeps_old_rows(old_engine):
    assert column_names(old_engine) == OLD_COLUMNS

    added = migrate_schema(old_engine)

    assert added == list(NEW_COLUMNS)
    assert column_names(old_engine) == OLD_COLUMNS + list(NEW_COLUMNS)
    with old_engine.connect() as connection:
        rows = connection.execute(
            text("SELECT id, prompt, is_blocked, risk_score, threat_type, action, direction, data_types "
                 "FROM request_logs ORDER BY id")
        ).all()
    assert [tuple(r) for r in rows] == [
        (1, "old blocked", 1, 80, "DLP Violation", "block", "input", ""),
        (2, "old fine", 0, 10, "Safe", "allow", "input", ""),
    ]


def test_migration_is_idempotent(old_engine):
    migrate_schema(old_engine)
    assert migrate_schema(old_engine) == []
    assert column_names(old_engine) == OLD_COLUMNS + list(NEW_COLUMNS)


def test_migration_only_adds_what_is_missing(old_engine):
    with old_engine.begin() as connection:
        connection.execute(text("ALTER TABLE request_logs ADD COLUMN direction VARCHAR DEFAULT 'input'"))

    assert migrate_schema(old_engine) == ["action", "data_types"]


def test_migration_ignores_a_database_without_the_table(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    assert migrate_schema(engine) == []
    assert TABLE not in inspect(engine).get_table_names()


def test_app_startup_migrates_an_existing_database(old_engine, monkeypatch):
    """Existing Docker volumes hold the old table: startup must upgrade it."""
    monkeypatch.setattr(main, "engine", old_engine)
    factory = sessionmaker(bind=old_engine, autoflush=False)

    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_get_db
    try:
        with TestClient(main.app) as client:
            assert column_names(old_engine) == OLD_COLUMNS + list(NEW_COLUMNS)

            # the old rows are served, and new requests work on the migrated table
            old = client.get("/history").json()["records"]
            assert [(r["prompt"], r["action"], r["direction"], r["data_types"]) for r in old] == [
                ("old blocked", "block", "input", []),
                ("old fine", "allow", "input", []),
            ]
            assert client.post("/inspect", json={"prompt": "hello"}).status_code == 200
            assert client.get("/stats").json()["total_requests"] == 3
            assert client.get("/stats").json()["data_leaks_prevented"] == 1

        # a second startup is a no-op
        with TestClient(main.app):
            assert column_names(old_engine) == OLD_COLUMNS + list(NEW_COLUMNS)
    finally:
        main.app.dependency_overrides.clear()
