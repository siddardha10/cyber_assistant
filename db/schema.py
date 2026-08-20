"""
db/schema.py
All CREATE TABLE / CREATE INDEX statements live here, in one place, so the
LLM query planner (query/llm.py) can be given this exact schema and never
guess at column names.
"""

SCHEMA_STATEMENTS = [
    # --- process activity ---
    """
    CREATE TABLE IF NOT EXISTS process_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        pid INTEGER NOT NULL,
        ppid INTEGER,
        name TEXT,
        exe_path TEXT,
        username TEXT,
        cmdline TEXT,
        cpu_pct REAL,
        mem_mb REAL,
        status TEXT,
        event TEXT  -- 'new', 'update', 'terminated'
    );
    """,

    # --- ports ---
    """
    CREATE TABLE IF NOT EXISTS port_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        port INTEGER NOT NULL,
        pid INTEGER,
        process_name TEXT,
        state TEXT,
        protocol TEXT,
        remote_ip TEXT,
        remote_port INTEGER,
        event TEXT  -- 'opened', 'closed'
    );
    """,

    # --- usb ---
    """
    CREATE TABLE IF NOT EXISTS usb_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        device_name TEXT,
        vendor_id TEXT,
        product_id TEXT,
        serial_number TEXT,
        drive_letter TEXT,
        action TEXT  -- 'inserted', 'removed'
    );
    """,

    # --- logins (windows event log) ---
    """
    CREATE TABLE IF NOT EXISTS login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_id INTEGER,
        username TEXT,
        source_ip TEXT,
        logon_type INTEGER,
        success INTEGER,  -- 1 or 0
        raw_record_id INTEGER
    );
    """,

    # --- browser downloads ---
    """
    CREATE TABLE IF NOT EXISTS downloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        browser TEXT,
        filename TEXT,
        url TEXT,
        filesize INTEGER,
        target_path TEXT
    );
    """,

    # --- installed software ---
    """
    CREATE TABLE IF NOT EXISTS installed_software (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        name TEXT,
        version TEXT,
        publisher TEXT,
        install_date TEXT,
        action TEXT  -- 'installed', 'removed'
    );
    """,

    # --- startup entries ---
    """
    CREATE TABLE IF NOT EXISTS startup_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        name TEXT,
        command TEXT,
        location TEXT,
        action TEXT  -- 'added', 'removed'
    );
    """,

    # --- services ---
    """
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        name TEXT,
        display_name TEXT,
        start_mode TEXT,
        status TEXT,
        action TEXT  -- 'new', 'changed', 'removed'
    );
    """,

    # --- scheduled tasks ---
    """
    CREATE TABLE IF NOT EXISTS scheduled_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        name TEXT,
        path TEXT,
        next_run TEXT,
        action TEXT  -- 'new', 'removed'
    );
    """,

    # --- filesystem events ---
    """
    CREATE TABLE IF NOT EXISTS filesystem_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        path TEXT,
        event_type TEXT,  -- 'created','deleted','modified'
        watched_dir TEXT,
        size_bytes INTEGER
    );
    """,

    # --- network / dns ---
    """
    CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        size INTEGER,
        pid INTEGER,
        event_type TEXT  -- 'packet','port_scan','arp_spoof'
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS dns_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        domain TEXT,
        pid INTEGER,
        process_name TEXT
    );
    """,

    # --- alerts ---
    # `reason` explains WHY this pattern matters in general (independent of the
    # specific message) — e.g. why an executable download is worth noticing.
    # `dedup_key` + `occurrence_count` + `last_seen` implement alert
    # deduplication: a repeated identical condition bumps a counter instead of
    # inserting a new row every cycle, which otherwise floods the alerts table
    # and misrepresents the threat level.
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        category TEXT,
        severity TEXT,   -- 'LOW','MEDIUM','HIGH'
        message TEXT,
        reason TEXT,
        source_table TEXT,
        source_id INTEGER,
        acknowledged INTEGER DEFAULT 0,
        dedup_key TEXT,
        occurrence_count INTEGER DEFAULT 1,
        last_seen TEXT
    );
    """,

    # --- system health (for baselines / anomaly detection) ---
    """
    CREATE TABLE IF NOT EXISTS system_health (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        cpu_pct REAL,
        mem_pct REAL,
        disk_pct REAL
    );
    """,

    # --- per-process CPU baseline (rolling average for anomaly detection) ---
    """
    CREATE TABLE IF NOT EXISTS process_baselines (
        process_name TEXT PRIMARY KEY,
        avg_cpu_pct REAL,
        sample_count INTEGER,
        updated_at TEXT
    );
    """,

    # --- query audit log ---
    """
    CREATE TABLE IF NOT EXISTS query_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        question TEXT,
        sql_generated TEXT,
        live_check INTEGER,
        answer TEXT,
        source TEXT  -- 'offline' or 'llm'
    );
    """,
]

INDEX_STATEMENTS = [
    "CREATE INDEX IF NOT EXISTS idx_process_ts ON process_snapshots(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_process_pid ON process_snapshots(pid);",
    "CREATE INDEX IF NOT EXISTS idx_port_ts ON port_snapshots(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_port_num ON port_snapshots(port);",
    "CREATE INDEX IF NOT EXISTS idx_usb_ts ON usb_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_login_ts ON login_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_downloads_ts ON downloads(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_software_ts ON installed_software(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_startup_ts ON startup_entries(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_services_ts ON services(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_tasks_ts ON scheduled_tasks(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_fs_ts ON filesystem_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_net_ts ON network_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key);",
    "CREATE INDEX IF NOT EXISTS idx_health_ts ON system_health(timestamp);",
]

# Columns added after the original schema shipped. Applied via
# "ALTER TABLE ... ADD COLUMN" against existing databases at startup
# (db.database.migrate_db) so upgrading never requires deleting your data.
# Each entry is (table, column, type_and_default_sql). Safe to re-run —
# failures (column already exists) are swallowed.
MIGRATIONS = [
    ("alerts", "reason", "TEXT"),
    ("alerts", "dedup_key", "TEXT"),
    ("alerts", "occurrence_count", "INTEGER DEFAULT 1"),
    ("alerts", "last_seen", "TEXT"),
]

# Whitelist used by query/sql_guard.py — the LLM (or offline engine) may only
# ever SELECT from these tables. Anything else is rejected before execution.
ALLOWED_TABLES = {
    "process_snapshots", "port_snapshots", "usb_events", "login_events",
    "downloads", "installed_software", "startup_entries", "services",
    "scheduled_tasks", "filesystem_events", "network_events", "dns_queries",
    "alerts", "system_health", "process_baselines",
}

# Human-readable schema text handed to the LLM system prompt verbatim.
SCHEMA_TEXT = """
process_snapshots(id, timestamp, pid, ppid, name, exe_path, username, cmdline, cpu_pct, mem_mb, status, event)
port_snapshots(id, timestamp, port, pid, process_name, state, protocol, remote_ip, remote_port, event)
usb_events(id, timestamp, device_name, vendor_id, product_id, serial_number, drive_letter, action)
login_events(id, timestamp, event_id, username, source_ip, logon_type, success, raw_record_id)
downloads(id, timestamp, browser, filename, url, filesize, target_path)
installed_software(id, timestamp, name, version, publisher, install_date, action)
startup_entries(id, timestamp, name, command, location, action)
services(id, timestamp, name, display_name, start_mode, status, action)
scheduled_tasks(id, timestamp, name, path, next_run, action)
filesystem_events(id, timestamp, path, event_type, watched_dir, size_bytes)
network_events(id, timestamp, src_ip, dst_ip, protocol, size, pid, event_type)
dns_queries(id, timestamp, domain, pid, process_name)
alerts(id, timestamp, category, severity, message, source_table, source_id, acknowledged)
system_health(id, timestamp, cpu_pct, mem_pct, disk_pct)
process_baselines(process_name, avg_cpu_pct, sample_count, updated_at)
""".strip()
