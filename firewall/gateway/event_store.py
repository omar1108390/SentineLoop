"""Small SQLite/PostgreSQL event and fuzzer-attempt store."""

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any


class EventStore:
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or os.getenv(
            "SENTINELLOOP_DATABASE_URL", "sqlite:///artifacts/sentinelloop.db"
        )
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
                raise RuntimeError(
                    "PostgreSQL storage needs the optional .[storage] dependency"
                ) from error
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
            schema = """
                CREATE TABLE IF NOT EXISTS firewall_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, layer TEXT NOT NULL,
                    verdict TEXT NOT NULL, score REAL NOT NULL, latency_ms REAL NOT NULL,
                    reason TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fuzzer_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, attempt_index INTEGER NOT NULL,
                    family TEXT NOT NULL, outcome TEXT NOT NULL, payload_json TEXT NOT NULL, created_at REAL NOT NULL
                );
            """
        else:
            schema = """
                CREATE TABLE IF NOT EXISTS firewall_events (
                    id BIGSERIAL PRIMARY KEY, request_id TEXT, layer TEXT NOT NULL,
                    verdict TEXT NOT NULL, score DOUBLE PRECISION NOT NULL, latency_ms DOUBLE PRECISION NOT NULL,
                    reason TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fuzzer_attempts (
                    id BIGSERIAL PRIMARY KEY, run_id TEXT NOT NULL, attempt_index INTEGER NOT NULL,
                    family TEXT NOT NULL, outcome TEXT NOT NULL, payload_json TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL
                );
            """
        with self._connection() as connection:
            if self.backend == "sqlite":
                connection.executescript(schema)
            else:
                for statement in schema.strip().split(";"):
                    if statement.strip():
                        connection.execute(statement)

    def append_event(self, event: dict[str, Any]) -> None:
        placeholder = "?" if self.backend == "sqlite" else "%s"
        sql = (
            "INSERT INTO firewall_events (request_id, layer, verdict, score, latency_ms, reason, created_at) "
            f"VALUES ({', '.join([placeholder] * 7)})"
        )
        values = tuple(
            event.get(key)
            for key in (
                "request_id",
                "layer",
                "verdict",
                "score",
                "latency_ms",
                "reason",
                "timestamp",
            )
        )
        with self._connection() as connection:
            connection.execute(sql, values)

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        placeholder = "?" if self.backend == "sqlite" else "%s"
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT request_id, layer, verdict, score, latency_ms, reason, created_at "
                f"FROM firewall_events ORDER BY id DESC LIMIT {placeholder}",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [
            {
                "request_id": row["request_id"],
                "layer": row["layer"],
                "verdict": row["verdict"],
                "score": row["score"],
                "latency_ms": row["latency_ms"],
                "reason": row["reason"],
                "timestamp": row["created_at"],
            }
            for row in rows
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
            (
                run_id,
                int(record["index"]),
                record["family"],
                record["outcome"],
                json.dumps(record, ensure_ascii=False),
                now,
            )
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
