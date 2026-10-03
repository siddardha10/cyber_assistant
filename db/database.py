"""
db/database.py

Thread-safety note: multiple monitor threads write concurrently. SQLite allows
only one writer at a time, so rather than fight WAL-mode lock contention with
N separate connections, we use a single shared connection guarded by a
threading.Lock. WAL mode still lets readers (the query engine) read without
blocking writers. This trades a little write throughput for correctness —
fine here since our write volume is "a few rows every few seconds," not
high-frequency trading.
"""

import sqlite3
import threading
from datetime import datetime, timezone

import config
from db.schema import SCHEMA_STATEMENTS, INDEX_STATEMENTS, MIGRATIONS
from utils.logger import get_logger

log = get_logger("database")

_lock = threading.Lock()
_conn = None

# How long a repeated alert with the same dedup_key is folded into the
# existing row (as an occurrence-count bump) instead of creating a new one.
_ALERT_DEDUP_WINDOW_MIN = getattr(config, "ALERT_DEDUP_WINDOW_MIN", 15)


def now_iso() -> str:
    # microsecond precision — with second-level precision, every row written
    # in the same monitor cycle (e.g. a first-scan backlog of 200 downloads)
    # ties on timestamp, and "ORDER BY timestamp DESC" then falls back to
    # storage order for ties, which silently buries whichever source was
    # inserted first (this was the root cause of "downloads only show one
    # browser"). Microsecond precision makes real chronological order stick.
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")


def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.execute("PRAGMA foreign_keys=ON;")
        _conn.row_factory = sqlite3.Row
    return _conn


def init_db():
    """Create all tables/indexes if they don't already exist. Safe to call every startup."""
    conn = get_connection()
    with _lock:
        for stmt in SCHEMA_STATEMENTS:
            conn.execute(stmt)
        conn.commit()
    log.info("Database initialized at %s", config.DB_PATH)
    # Migrations must run BEFORE index creation: an existing database (from
    # before this schema version) has the `alerts` table already, so
    # CREATE TABLE IF NOT EXISTS is a no-op — the new columns only appear
    # after migrate_db() runs, and any index referencing them must wait.
    migrate_db()
    with _lock:
        for stmt in INDEX_STATEMENTS:
            conn.execute(stmt)
        conn.commit()


def migrate_db():
    """
    Adds columns introduced after the original schema shipped, so an existing
    database (like one that's already been collecting data for weeks) picks
    up new fields without needing to be deleted and recreated. Safe to call
    every startup — already-applied migrations fail silently (duplicate
    column) and are ignored.
    """
    conn = get_connection()
    applied = 0
    with _lock:
        for table, column, decl in MIGRATIONS:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
                applied += 1
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    log.warning("Migration failed for %s.%s: %s", table, column, e)
        conn.commit()
    if applied:
        log.info("Applied %d schema migration(s)", applied)


def insert(table: str, row: dict) -> int:
    """
    Generic parameterized insert. `table` is only ever passed by our own
    monitor code (never user input), but we still validate it's a real
    identifier to avoid accidental typos silently building bad SQL.
    """
    if not table.replace("_", "").isalnum():
        raise ValueError(f"Unsafe table name: {table}")
    columns = ", ".join(row.keys())
    placeholders = ", ".join("?" for _ in row)
    sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
    conn = get_connection()
    with _lock:
        cur = conn.execute(sql, tuple(row.values()))
        conn.commit()
        return cur.lastrowid


def insert_alert(category: str, severity: str, message: str, source_table: str = None,
                  source_id: int = None, reason: str = None, dedup_key: str = None):
    """
    Insert an alert — or, if an alert with the same `dedup_key` fired within
    the last `_ALERT_DEDUP_WINDOW_MIN` minutes, fold this occurrence into that
    existing row instead of creating a new one.

    Without this, a single sustained condition (e.g. one CPU spike that's
    still ongoing at the next 30s check) creates a brand new alert row every
    cycle, which both floods the table and makes the threat level look far
    worse than reality. `dedup_key` should identify the *condition*, not the
    individual event — e.g. f"cpu_anomaly:{process_name}" so repeats of the
    same process spiking collapse together, but a different process spiking
    is still its own alert.

    `reason` is the general "why this category of event matters" explanation
    (independent of this specific instance) — this is what the UI's threat
    tooltip and the /api/alerts consumers show as the human-readable "why".
    """
    conn = get_connection()
    ts = now_iso()

    if dedup_key:
        with _lock:
            cutoff = (datetime.now(timezone.utc).astimezone()).isoformat(timespec="microseconds")
            existing = conn.execute(
                "SELECT id, occurrence_count FROM alerts WHERE dedup_key = ? "
                "AND datetime(last_seen) >= datetime(?, ?) ORDER BY id DESC LIMIT 1",
                (dedup_key, cutoff, f"-{_ALERT_DEDUP_WINDOW_MIN} minutes"),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE alerts SET occurrence_count = ?, last_seen = ?, message = ?, timestamp = ? WHERE id = ?",
                    (existing["occurrence_count"] + 1, ts, message, ts, existing["id"]),
                )
                conn.commit()
                return existing["id"]

    log.warning("ALERT [%s] %s: %s", severity, category, message)
    return insert("alerts", {
        "timestamp": ts,
        "category": category,
        "severity": severity,
        "message": message,
        "reason": reason,
        "source_table": source_table,
        "source_id": source_id,
        "acknowledged": 0,
        "dedup_key": dedup_key,
        "occurrence_count": 1,
        "last_seen": ts,
    })


def acknowledge_alert(alert_id: int) -> bool:
    """
    Mark an alert as handled so it no longer counts toward threat level.
    Returns False if the id does not exist.
    """
    conn = get_connection()
    with _lock:
        row = conn.execute("SELECT id FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
        if row is None:
            return False
        conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (int(alert_id),))
        conn.commit()
    return True


def run_readonly_query(sql: str, params: tuple = ()) -> list:
    """
    Executes a pre-validated read-only SQL string (validation happens in
    query/sql_guard.py BEFORE this is ever called — this function trusts
    its caller and does not re-validate, by design, to keep concerns separate).
    """
    conn = get_connection()
    with _lock:
        cur = conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    return rows


def get_recent(table: str, limit: int = 20) -> list:
    if not table.replace("_", "").isalnum():
        raise ValueError(f"Unsafe table name: {table}")
    # id DESC as a tiebreaker: rows inserted in the same monitor cycle can
    # share a timestamp even at microsecond precision under heavy load, and
    # without a tiebreak "most recent" silently drops to storage order.
    return run_readonly_query(f"SELECT * FROM {table} ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,))


def get_last_snapshot(table: str, key_column: str, key_value) -> dict | None:
    """Fetch the most recent row for a given key (e.g. last snapshot for a PID)."""
    if not table.replace("_", "").isalnum() or not key_column.replace("_", "").isalnum():
        raise ValueError("Unsafe identifier")
    sql = f"SELECT * FROM {table} WHERE {key_column} = ? ORDER BY timestamp DESC LIMIT 1"
    rows = run_readonly_query(sql, (key_value,))
    return rows[0] if rows else None


def update_process_baseline(process_name: str, cpu_pct: float):
    """
    Simple incremental moving average per process name — this is the
    'AI anomaly detection' baseline: no ML model needed to get real value,
    just a running average we compare new samples against.
    """
    conn = get_connection()
    with _lock:
        row = conn.execute(
            "SELECT avg_cpu_pct, sample_count FROM process_baselines WHERE process_name = ?",
            (process_name,),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO process_baselines (process_name, avg_cpu_pct, sample_count, updated_at) VALUES (?, ?, 1, ?)",
                (process_name, cpu_pct, now_iso()),
            )
        else:
            old_avg, count = row["avg_cpu_pct"], row["sample_count"]
            new_count = min(count + 1, 500)  # cap so baseline can still adapt over time
            new_avg = old_avg + (cpu_pct - old_avg) / new_count
            conn.execute(
                "UPDATE process_baselines SET avg_cpu_pct=?, sample_count=?, updated_at=? WHERE process_name=?",
                (new_avg, new_count, now_iso(), process_name),
            )
        conn.commit()


def get_process_baseline(process_name: str):
    rows = run_readonly_query(
        "SELECT avg_cpu_pct, sample_count FROM process_baselines WHERE process_name = ?",
        (process_name,),
    )
    return rows[0] if rows else None
