"""
Shared report store — SQLite-backed, 30-day TTL.

Reports are keyed by a random URL-safe ID and expire automatically.
No user accounts or authentication required.
"""
import json
import os
import secrets
import sqlite3
import time
from typing import Optional

TTL_SECONDS = 30 * 24 * 3600  # 30 days

# Store the DB next to the project root in a data/ directory
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.getenv("SLOPSICURITY_DB", os.path.join(_HERE, "data", "reports.db"))


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS shared_reports (
            id         TEXT    PRIMARY KEY,
            data       TEXT    NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    con.commit()
    return con


def save_report(report_data: dict) -> str:
    """Persist a report and return its share ID."""
    share_id  = secrets.token_urlsafe(8)   # ~11 chars, URL-safe
    now       = int(time.time())
    expires   = now + TTL_SECONDS

    with _conn() as con:
        # Prune expired rows on every write to avoid unbounded growth
        con.execute("DELETE FROM shared_reports WHERE expires_at < ?", (now,))
        con.execute(
            "INSERT INTO shared_reports (id, data, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (share_id, json.dumps(report_data), now, expires),
        )

    return share_id


def get_report(share_id: str) -> Optional[dict]:
    """Retrieve a report by ID, or None if expired / not found."""
    now = int(time.time())
    with _conn() as con:
        row = con.execute(
            "SELECT data FROM shared_reports WHERE id = ? AND expires_at > ?",
            (share_id, now),
        ).fetchone()

    return json.loads(row[0]) if row else None


def days_remaining(share_id: str) -> Optional[int]:
    """Return how many days until this share link expires, or None if gone."""
    now = int(time.time())
    with _conn() as con:
        row = con.execute(
            "SELECT expires_at FROM shared_reports WHERE id = ? AND expires_at > ?",
            (share_id, now),
        ).fetchone()

    if not row:
        return None
    return max(0, int((row[0] - now) / 86400))
