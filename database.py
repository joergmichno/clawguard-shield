"""
ClawGuard Shield — Database Layer (SQLite)
Manages API keys, usage tracking, and rate limit data.
"""

import sqlite3
import os
import threading
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = os.environ.get("SHIELD_DB_PATH", "/app/data/shield.db")

_local = threading.local()


def get_connection() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "connection") or _local.connection is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _local.connection = sqlite3.connect(DB_PATH)
        _local.connection.row_factory = sqlite3.Row
        _local.connection.execute("PRAGMA journal_mode=WAL")
        _local.connection.execute("PRAGMA foreign_keys=ON")
    return _local.connection


@contextmanager
def get_db():
    """Context manager for database operations with auto-commit."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Create all tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                email TEXT NOT NULL,
                tier TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                subscription_status TEXT
            );

            CREATE TABLE IF NOT EXISTS usage_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                text_length INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                risk_score INTEGER NOT NULL DEFAULT 0,
                response_time_ms INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (key_hash) REFERENCES api_keys(key_hash)
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL,
                window_start TEXT NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                UNIQUE(key_hash, window_start)
            );

            CREATE INDEX IF NOT EXISTS idx_usage_key_ts
                ON usage_log(key_hash, timestamp);

            CREATE INDEX IF NOT EXISTS idx_rate_key_window
                ON rate_limits(key_hash, window_start);

            CREATE INDEX IF NOT EXISTS idx_keys_prefix
                ON api_keys(key_prefix);

            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                score TEXT,
                lead_type TEXT,
                source TEXT DEFAULT 'risk-score-widget',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_leads_email
                ON leads(email);
        """)

        # Migration: add newsletter_consent column if missing
        cols = [r[1] for r in conn.execute("PRAGMA table_info(api_keys)").fetchall()]
        if "newsletter_consent" not in cols:
            conn.execute("ALTER TABLE api_keys ADD COLUMN newsletter_consent INTEGER NOT NULL DEFAULT 0")


# ─── API Key Operations ──────────────────────────────────────────────────────

def insert_api_key(key_hash: str, key_prefix: str, email: str, tier: str = "free",
                   newsletter_consent: bool = False):
    """Store a new API key (hashed)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, email, tier, created_at, newsletter_consent) VALUES (?, ?, ?, ?, ?, ?)",
            (key_hash, key_prefix, email, tier, now, int(newsletter_consent)),
        )


def get_api_key(key_hash: str) -> dict | None:
    """Look up an API key by its hash. Returns dict or None."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1", (key_hash,)
        ).fetchone()
        if row:
            return dict(row)
    return None


def update_last_used(key_hash: str):
    """Update the last_used_at timestamp for an API key."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", (now, key_hash)
        )


def deactivate_key(key_hash: str):
    """Soft-delete an API key."""
    with get_db() as conn:
        conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE key_hash = ?", (key_hash,)
        )


def email_exists(email: str) -> bool:
    """Check if an email already has a registered key."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM api_keys WHERE email = ? AND is_active = 1", (email,)
        ).fetchone()
        return row is not None


def get_all_emails(newsletter_only: bool = False) -> list[dict]:
    """Get all registered emails. Optionally filter by newsletter consent."""
    with get_db() as conn:
        if newsletter_only:
            rows = conn.execute(
                "SELECT email, tier, created_at, newsletter_consent FROM api_keys WHERE is_active = 1 AND newsletter_consent = 1 ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT email, tier, created_at, newsletter_consent FROM api_keys WHERE is_active = 1 ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]


# ─── Usage Logging ────────────────────────────────────────────────────────────

def log_usage(key_hash: str, endpoint: str, text_length: int = 0,
              findings_count: int = 0, risk_score: int = 0, response_time_ms: int = 0):
    """Log an API request for analytics."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO usage_log
               (key_hash, endpoint, timestamp, text_length, findings_count, risk_score, response_time_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (key_hash, endpoint, now, text_length, findings_count, risk_score, response_time_ms),
        )


def get_usage_stats(key_hash: str, since: str | None = None) -> dict:
    """Get usage statistics for an API key."""
    with get_db() as conn:
        if since:
            rows = conn.execute(
                "SELECT * FROM usage_log WHERE key_hash = ? AND timestamp >= ? ORDER BY timestamp DESC",
                (key_hash, since),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM usage_log WHERE key_hash = ? ORDER BY timestamp DESC LIMIT 100",
                (key_hash,),
            ).fetchall()

        total = len(rows)
        total_findings = sum(r["findings_count"] for r in rows)
        avg_response = (
            sum(r["response_time_ms"] for r in rows) / total if total > 0 else 0
        )

        return {
            "total_requests": total,
            "total_findings": total_findings,
            "avg_response_time_ms": round(avg_response, 1),
        }


# ─── Rate Limit Helpers ──────────────────────────────────────────────────────

def get_request_count_today(key_hash: str) -> int:
    """Get the number of requests made today (UTC)."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_db() as conn:
        row = conn.execute(
            "SELECT request_count FROM rate_limits WHERE key_hash = ? AND window_start = ?",
            (key_hash, today),
        ).fetchone()
        return row["request_count"] if row else 0


def increment_request_count(key_hash: str):
    """Increment today's request counter."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.execute(
            """INSERT INTO rate_limits (key_hash, window_start, request_count)
               VALUES (?, ?, 1)
               ON CONFLICT(key_hash, window_start)
               DO UPDATE SET request_count = request_count + 1""",
            (key_hash, today),
        )


def atomic_check_and_increment(key_hash: str, limit: int, period: str = "day") -> tuple:
    """Atomically check rate limit and increment counter.
    Prevents race condition with BEGIN IMMEDIATE transaction.
    Returns (allowed: bool, current_count: int)."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if period == "month":
                month = datetime.now(timezone.utc).strftime("%Y-%m")
                row = conn.execute(
                    "SELECT SUM(request_count) as total FROM rate_limits "
                    "WHERE key_hash = ? AND window_start LIKE ?",
                    (key_hash, f"{month}%"),
                ).fetchone()
                current = row["total"] if row and row["total"] else 0
            else:
                row = conn.execute(
                    "SELECT request_count FROM rate_limits "
                    "WHERE key_hash = ? AND window_start = ?",
                    (key_hash, today),
                ).fetchone()
                current = row["request_count"] if row else 0

            if current >= limit:
                conn.execute("COMMIT")
                return False, current

            conn.execute(
                """INSERT INTO rate_limits (key_hash, window_start, request_count)
                   VALUES (?, ?, 1)
                   ON CONFLICT(key_hash, window_start)
                   DO UPDATE SET request_count = request_count + 1""",
                (key_hash, today),
            )
            conn.execute("COMMIT")
            return True, current + 1
        except Exception:
            conn.execute("ROLLBACK")
            raise


def get_request_count_month(key_hash: str) -> int:
    """Get the number of requests made this month (UTC)."""
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    with get_db() as conn:
        row = conn.execute(
            "SELECT SUM(request_count) as total FROM rate_limits WHERE key_hash = ? AND window_start LIKE ?",
            (key_hash, f"{month}%"),
        ).fetchone()
        return row["total"] if row and row["total"] else 0


def cleanup_old_rate_limits(days: int = 7):
    """Remove rate limit entries older than N days."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (cutoff,))
