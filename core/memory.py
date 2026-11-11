from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "backups" / "campaign_memory.db"


class CampaignMemory:
    """Persistent storage for attack campaign history and successful payloads."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS attacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        target_goal TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        model_response TEXT NOT NULL
                    )
                """)

    def log_attempt(self, goal: str, payload: str, success: bool, response: str) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO attacks (timestamp, target_goal, payload, success, model_response)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (now_utc, goal, payload, bool(success), response),
                )

    def get_successful_payloads(self, goal_keyword: Optional[str] = None) -> list[str]:
        query = "SELECT payload FROM attacks WHERE success = 1"
        params: list[str] = []

        if goal_keyword:
            # Escape literal wildcard characters for SQL LIKE
            escaped_kw = goal_keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            query += " AND target_goal LIKE ? ESCAPE '\\'"
            params.append(f"%{escaped_kw}%")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [row[0] for row in cursor.fetchall()]
