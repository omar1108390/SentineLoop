"""Small SQLite/PostgreSQL store for firewall decisions and fuzzer attempts."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_SQLITE = Path(__file__).resolve().parents[2] / "artifacts" / "sentinelloop.db"
EVENT_FIELDS = (
    "request_id",
    "layer",
    "verdict",
    "score",
    "latency_ms",
    "reason",
    "stage",
    "source",
    "excerpt",
)


class EventStore:
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or os.getenv("SENTINELLOOP_DATABASE_URL", f"sqlite:///{DEFAULT_SQLITE.as_posix()}")
        if self.dsn.startswith("sqlite:///"):
            self.backend = "sqlite"
            self.sqlite_path = Path(self.dsn[len("sqlite:///") :])
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        elif self.dsn.startswith(("postgresql://", "postgres://")):
            self.backend = "postgres"
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as error:
                raise RuntimeError("PostgreSQL storage needs the optional .[storage] dependency") from error
            self._psycopg = psycopg
            self._dict_row = dict_row
        else:
            raise ValueError("SENTINELLOOP_DATABASE_URL must use sqlite:/// or postgresql://")
        self._initialize()

    def _connect(self):
        if self.backend == "sqlite":
            connection = sqlite3.connect(self.sqlite_path, timeout=10)
            connection.row_factory = sqlite3.Row
            return connection
        return self._psycopg.connect(self.dsn, row_factory=self._dict_row)

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        if self.backend == "sqlite":
            key, real = "INTEGER PRIMARY KEY AUTOINCREMENT", "REAL"
        else:
            key, real = "BIGSERIAL PRIMARY KEY", "DOUBLE PRECISION"
        statements = [
            f"""CREATE TABLE IF NOT EXISTS firewall_events (
                id {key}, request_id TEXT, layer TEXT NOT NULL, verdict TEXT NOT NULL,
                score {real} NOT NULL, latency_ms {real} NOT NULL, reason TEXT NOT NULL,
                created_at {real} NOT NULL)""",
            f"""CREATE TABLE IF NOT EXISTS fuzzer_attempts (
                id {key}, run_id TEXT NOT NULL, attempt_index INTEGER NOT NULL,
                family TEXT NOT NULL, outcome TEXT NOT NULL, payload_json TEXT NOT NULL,
                created_at {real} NOT NULL)""",
        ]
        with self._connection() as connection:
            for statement in statements:
                connection.execute(statement)
        # Columns added in v0.2; older databases are migrated in place.
        for column in ("stage", "source", "excerpt"):
            try:
                with self._connection() as connection:
                    connection.execute(f"ALTER TABLE firewall_events ADD COLUMN {column} TEXT")
            except Exception:
                pass

    def append_event(self, event: dict[str, Any]) -> None:
        placeholder = "?" if self.backend == "sqlite" else "%s"
        columns = (*EVENT_FIELDS, "created_at")
        sql = (
            f"INSERT INTO firewall_events ({', '.join(columns)}) "
            f"VALUES ({', '.join([placeholder] * len(columns))})"
        )
        values = tuple(event.get(name) for name in EVENT_FIELDS) + (event.get("timestamp"),)
        with self._connection() as connection:
            connection.execute(sql, values)

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        placeholder = "?" if self.backend == "sqlite" else "%s"
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT {', '.join(EVENT_FIELDS)}, created_at FROM firewall_events "
                f"ORDER BY id DESC LIMIT {placeholder}",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [
            {**{name: row[name] for name in EVENT_FIELDS}, "timestamp": row["created_at"]} for row in rows
        ]

    def store_attempts(self, records: list[dict[str, Any]], run_id: str | None = None) -> str:
        run_id = run_id or uuid.uuid4().hex
        placeholder = "?" if self.backend == "sqlite" else "%s"
        sql = (
            "INSERT INTO fuzzer_attempts (run_id, attempt_index, family, outcome, payload_json, created_at) "
            f"VALUES ({', '.join([placeholder] * 6)})"
        )
        now = time.time()
        values = [
            (run_id, int(record["index"]), record["family"], record["outcome"],
             json.dumps(record, ensure_ascii=False), now)  # fmt: skip
            for record in records
        ]
        with self._connection() as connection:
            cursor = connection.cursor()
            try:
                cursor.executemany(sql, values)
            finally:
                cursor.close()
        return run_id


@lru_cache(maxsize=1)
def default_store() -> EventStore:
    return EventStore()
