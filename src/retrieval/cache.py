"""SQLite cache for API responses (design spec section 8.1-8.2).

Values are stored as JSON with the time they were fetched. Entries older than the
TTL are "stale": get() ignores them, but get_stale() still returns them so the
service can fall back to old data when an API is down (offline demo).
"""

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    fetched_at REAL NOT NULL
)
"""


class SqliteCache:
    """A tiny key -> JSON store in one SQLite file."""

    def __init__(self, path, ttl_seconds: float = 24 * 60 * 60, clock=time.time):
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._run(_CREATE_TABLE)

    def get(self, key: str):
        """The value if it is younger than the TTL, else None."""
        row = self._fetch_row(key)
        if row is None:
            return None
        value, fetched_at = row
        if self.clock() - fetched_at >= self.ttl_seconds:
            return None
        return json.loads(value)

    def get_stale(self, key: str):
        """The value however old it is, else None."""
        row = self._fetch_row(key)
        return None if row is None else json.loads(row[0])

    def set(self, key: str, value) -> None:
        """Store `value` (anything JSON can hold), replacing any old entry."""
        self._run(
            "INSERT OR REPLACE INTO cache (key, value, fetched_at) VALUES (?, ?, ?)",
            (key, json.dumps(value), self.clock()),
        )

    def _fetch_row(self, key: str):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute(
                "SELECT value, fetched_at FROM cache WHERE key = ?", (key,)
            ).fetchone()

    def _run(self, sql: str, parameters: tuple = ()) -> None:
        # A short-lived connection per call keeps things simple and thread-safe.
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(sql, parameters)
