"""
query/offline.py

Smart regex-driven templates covering a wide range of natural-language questions.
Works offline with zero API cost — tried before the LLM path.

KEY DESIGN RULES:
  - MORE SPECIFIC patterns are registered first (USB before generic ports)
  - Each handler returns None to skip (lets the engine fall through)
  - All data comes from real DB queries, never invented
"""

import re
from datetime import datetime, timedelta

from db import database as db

_TEMPLATES = []


def template(pattern):
    """Register a regex pattern + handler. Order matters — first match wins."""
    def deco(fn):
        _TEMPLATES.append((re.compile(pattern, re.IGNORECASE), fn))
        return fn
    return deco


def _since(minutes=None, hours=None, days=None):
    delta = timedelta(minutes=minutes or 0, hours=hours or 0, days=days or 0)
    return (datetime.now().astimezone() - delta).isoformat(timespec="seconds")


# ═══════════════════════════════════════════════════════════════════════════════
# 1) USB DEVICES  (must come BEFORE generic "ports" so "usb ports" matches here)
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"usb|flash drive|external drive|thumb drive|pen drive|"
    r"plugged in|peripherals?|devices?\s*(connected|attached|plugged)"
    r"|headphone|headset|mouse\b.*connect|keyboard\b.*connect"
    r"|what.*(device|gadget|accessory)|connected\s*device"
)
def _usb_devices(match, question):
    rows = db.get_recent("usb_events", limit=20)
    if not rows:
        return (
            "No USB device events recorded yet.\n"
            "Note: The USB monitor requires `pip install wmi pywin32` "
            "to be enabled on Windows."
        )
    lines = []
    for r in rows:
        name = r.get("device_name") or "Unknown device"
        action = r.get("action") or "?"
        ts = (r.get("timestamp") or "")[:16]
        drive = r.get("drive_letter")
        extra = f" ({drive}:)" if drive else ""
        lines.append(f"  {action.upper()}: {name}{extra}  ({ts})")
    return f"{len(rows)} USB event(s) recorded:\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 2) SPECIFIC PORT LOOKUP (port 8080, port 443, etc.)
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(?:which\s*process|who|what).*(open|own|using|listen).+port\s*(\d+)"
    r"|port\s+(\d+)\s*.*(open|safe|owned|used|listen|who)"
    r"|is\s+port\s+(\d+)"
)
def _port_lookup(match, question):
    port = next((g for g in match.groups() if g and g.isdigit()), None)
    if not port:
        return None
    rows = db.run_readonly_query(
        "SELECT * FROM port_snapshots WHERE port = ? ORDER BY timestamp DESC LIMIT 1",
        (int(port),),
    )
    if not rows or rows[0]["event"] == "closed":
        return f"Port {port} is not currently open on this machine."
    r = rows[0]
    return (
        f"Port {port} is open.\n"
        f"  Process: {r['process_name'] or 'unknown'} (PID {r['pid']})\n"
        f"  State: {r['state']}\n"
        f"  Protocol: {r['protocol'] or '?'}\n"
        f"  Since: {r['timestamp']}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3) LIST OPEN NETWORK PORTS (generic "open ports", "listening ports", etc.)
#    Excludes USB-related questions via negative lookahead
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(?!.*usb)(?:"
    r"(list|show|what|which|all|how many)\s*.*(network\s*)?port"
    r"|(open|listening|active)\s*port"
    r"|port\s*scan|port\s*list|tcp\s*port|udp\s*port"
    r")"
)
def _list_ports(match, question):
    rows = db.run_readonly_query(
        """
        SELECT port, pid, process_name, state, protocol, timestamp
        FROM port_snapshots
        WHERE event = 'opened'
        AND id IN (SELECT MAX(id) FROM port_snapshots GROUP BY port, pid)
        ORDER BY port ASC
        LIMIT 40
        """
    )
    if not rows:
        return "No open ports recorded in the current snapshot yet."
    lines = []
    for r in rows:
        proc = r["process_name"] or f"PID {r['pid']}"
        proto = r["protocol"] or "?"
        lines.append(f"  Port {r['port']}/{proto} - {proc} ({r['state']})")
    return f"{len(rows)} currently open network port(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 4) THREATS / ALERTS / SECURITY ISSUES
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"threat|alert|warning|danger|risk|vulnerab|attack|suspicious"
    r"|security\s*(issue|status|problem|report|concern|check)"
    r"|anything\s*wrong|what.*(wrong|issue|problem)"
    r"|am\s*i\s*(safe|secure|at risk|hacked|compromised)"
    r"|breach|intrusion|malware|virus|hack"
    r"|show\s*(alert|threat|warning|issue)"
)
def _threats(match, question):
    since = _since(hours=24)
    rows = db.run_readonly_query(
        "SELECT timestamp, category, severity, message, reason, occurrence_count FROM alerts "
        "WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 25",
        (since,),
    )
    if not rows:
        return "No alerts in the last 24 hours. Your system looks clean."

    high   = [r for r in rows if (r["severity"] or "").upper() == "HIGH"]
    medium = [r for r in rows if (r["severity"] or "").upper() == "MEDIUM"]
    low    = [r for r in rows if (r["severity"] or "").upper() == "LOW"]

    lines = [f"Found {len(rows)} alert(s) in the last 24 hours:\n"]
    for r in rows[:12]:
        ts = (r["timestamp"] or "")[:16]
        occ = f" (x{r['occurrence_count']})" if (r.get("occurrence_count") or 1) > 1 else ""
        lines.append(f"  [{r['severity']}] {r['category']} - {r['message']}{occ}  ({ts})")
        if r.get("reason"):
            lines.append(f"      why: {r['reason']}")
    if len(rows) > 12:
        lines.append(f"  ...and {len(rows) - 12} more.")

    parts = []
    if high:   parts.append(f"{len(high)} HIGH")
    if medium: parts.append(f"{len(medium)} MEDIUM")
    if low:    parts.append(f"{len(low)} LOW")
    lines.append(f"\nSeverity breakdown: {', '.join(parts) or 'none'}.")

    if high:
        lines.append("\nAction needed: You have HIGH severity alerts that may need immediate attention.")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 5) LOGIN EVENTS
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(failed|bad|wrong|invalid|unauthorized)\s*(login|logon|sign.?in|access|password)"
    r"|login\s*(attempt|failure|log|history|event|yesterday|today)"
    r"|(who|someone|anyone)\s*(logged|signed)\s*in"
    r"|logon\s*event|brute\s*force"
    r"|login.*(failed|attempt|unauthorized|suspicious)"
)
def _login_check(match, question):
    q_lower = question.lower()
    window = _since(hours=48) if "yesterday" in q_lower else _since(hours=24)
    label = "48 hours" if "yesterday" in q_lower else "24 hours"

    failed = db.run_readonly_query(
        "SELECT * FROM login_events WHERE timestamp >= ? AND success = 0 "
        "ORDER BY timestamp DESC",
        (window,),
    )
    success = db.run_readonly_query(
        "SELECT * FROM login_events WHERE timestamp >= ? AND success = 1 "
        "ORDER BY timestamp DESC LIMIT 5",
        (window,),
    )

    parts = []
    if failed:
        lines = [
            f"  {r['timestamp'][:16]} - user '{r['username'] or 'unknown'}' "
            f"from {r['source_ip'] or 'local'}"
            for r in failed[:10]
        ]
        parts.append(
            f"{len(failed)} FAILED login attempt(s) in the last {label}:\n"
            + "\n".join(lines)
        )
    else:
        parts.append(f"No failed login attempts in the last {label}.")

    if success:
        lines = [
            f"  {r['timestamp'][:16]} - {r['username'] or 'unknown'}"
            for r in success[:5]
        ]
        parts.append(
            f"\n{len(success)} successful login(s):\n" + "\n".join(lines)
        )

    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# 6) CPU / MEMORY / PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"cpu\b|memory\b|ram\b|resource|performance"
    r"|why.*slow|slow.*(computer|pc|laptop|machine|system)"
    r"|lagg?(ing|y)|freez(e|ing)|hang(s|ing)"
    r"|high\s*(usage|load|utilization)"
    r"|what.*(eating|consuming|hogging|using)\s*(memory|cpu|ram|resource)"
    r"|top\s*process|heaviest\s*process|resource\s*hog"
    r"|speed|bottleneck|overload"
)
def _cpu_memory(match, question):
    health = db.run_readonly_query(
        "SELECT cpu_pct, mem_pct, disk_pct, timestamp FROM system_health "
        "ORDER BY timestamp DESC LIMIT 1"
    )
    procs = db.run_readonly_query(
        "SELECT name, cpu_pct, mem_mb, pid, timestamp FROM process_snapshots "
        "WHERE timestamp >= ? ORDER BY cpu_pct DESC LIMIT 8",
        (_since(minutes=15),),
    )

    parts = []
    if health:
        h = health[0]
        parts.append(
            f"Current system health:\n"
            f"  CPU: {h['cpu_pct']:.0f}%\n"
            f"  Memory: {h['mem_pct']:.0f}%\n"
            f"  Disk: {h['disk_pct']:.0f}%"
        )
    if procs:
        lines = [
            f"  {r['name']} (PID {r['pid']}) - {r['cpu_pct']:.0f}% CPU, "
            f"{r['mem_mb']:.0f} MB RAM"
            for r in procs
        ]
        parts.append(
            f"\nTop resource consumers (last 15 min):\n" + "\n".join(lines)
        )
    if not parts:
        return "Not enough data yet to report on CPU or memory usage."
    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# 7) PROCESSES
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(list|show|what|which)\s*.*(process|program|app|application|task)\s*(is\s*)?"
    r"(running|active|open|executing)?"
    r"|running\s*(process|program|app|task)"
    r"|task\s*manager|background\s*(process|app|task)"
    r"|what\s*is\s*running|all\s*process"
)
def _list_processes(match, question):
    rows = db.run_readonly_query(
        """
        SELECT name, pid, cpu_pct, mem_mb, username, status, timestamp
        FROM process_snapshots
        WHERE timestamp >= ?
        ORDER BY cpu_pct DESC
        LIMIT 20
        """,
        (_since(minutes=60),),
    )
    if not rows:
        return "No process data collected yet. The monitor runs every 30 seconds."
    lines = [
        f"  {r['name']} (PID {r['pid']}) - "
        f"{r['cpu_pct']:.0f}% CPU, {r['mem_mb']:.0f} MB, {r['status']}"
        for r in rows
    ]
    return f"Top {len(rows)} processes by CPU (last hour):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 8) NETWORK / OUTBOUND CONNECTIONS
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(internet|outbound|inbound)\s*(connection|traffic|activity)"
    r"|what.*(connect|talking|communicat).*(internet|network|outside|web)"
    r"|network\s*(activity|traffic|connection|status)"
    r"|who.*(calling|contacting|connecting)\s*(home|out|internet)"
    r"|bandwidth|data\s*transfer|phone\s*home"
    r"|any\s*(network|internet)\s*activity"
)
def _network(match, question):
    rows = db.run_readonly_query(
        "SELECT DISTINCT process_name, remote_ip, remote_port "
        "FROM port_snapshots "
        "WHERE event='opened' AND remote_ip IS NOT NULL "
        "ORDER BY timestamp DESC LIMIT 15"
    )
    if not rows:
        return "No active outbound connections found in the latest snapshot."
    lines = [
        f"  {r['process_name'] or 'unknown'} -> "
        f"{r['remote_ip']}:{r['remote_port']}"
        for r in rows
    ]
    return f"{len(rows)} outbound connection(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 9) DOWNLOADS
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"download|what.*(download|i\s*download)"
    r"|browser\s*history|recent\s*file"
    r"|what\s*did\s*i\s*(get|save|download)"
    r"|downloaded\s*file"
)
def _downloads(match, question):
    # Fetch the most recent N per browser (via ROW_NUMBER partitioned by
    # browser), THEN merge and sort — this guarantees every browser that has
    # downloads is represented, instead of one global "ORDER BY timestamp
    # DESC LIMIT 20" letting whichever browser happened to be scanned last
    # in a monitor cycle dominate the result (this was the actual bug: ties
    # within one scan cycle buried Chrome under Edge/Opera).
    rows = db.run_readonly_query(
        """
        SELECT browser, filename, url, timestamp FROM (
            SELECT browser, filename, url, timestamp,
                   ROW_NUMBER() OVER (PARTITION BY browser ORDER BY timestamp DESC, id DESC) AS rn
            FROM downloads
        ) ranked
        WHERE rn <= 8
        ORDER BY timestamp DESC
        LIMIT 25
        """
    )
    if not rows:
        return "No downloads recorded in the database yet."

    counts = db.run_readonly_query(
        "SELECT browser, COUNT(*) as c FROM downloads GROUP BY browser ORDER BY c DESC"
    )
    breakdown = ", ".join(f"{c['browser']}: {c['c']}" for c in counts)

    lines = [
        f"  {r.get('browser','?')} - "
        f"{r.get('filename') or r.get('url') or '?'}  "
        f"({(r.get('timestamp') or '')[:16]})"
        for r in rows
    ]
    return (
        f"{len(rows)} recent download(s) across all browsers ({breakdown}):\n"
        + "\n".join(lines)
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 10) INSTALLED SOFTWARE
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(new|recent|latest)\s*(software|application|program|app)\s*(install)?"
    r"|what.*(install|uninstall|added|removed)\s*(software|app|program)?"
    r"|installed\s*(software|app|program|recently)"
    r"|software\s*(list|inventory|installed)"
    r"|any\s*new\s*(software|app|program)"
)
def _software(match, question):
    rows = db.run_readonly_query(
        "SELECT * FROM installed_software WHERE timestamp >= ? "
        "ORDER BY timestamp DESC",
        (_since(days=7),),
    )
    if not rows:
        return "No software installation or removal events in the last 7 days."
    lines = [
        f"  [{r.get('action','?')}] {r.get('name','?')} "
        f"({r.get('version') or '?'}) - {(r.get('timestamp') or '')[:16]}"
        for r in rows[:15]
    ]
    return f"{len(rows)} software event(s) in the last 7 days:\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 11) STARTUP / AUTORUN
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"startup|autostart|auto.?run|boot\s*(program|entry|item)"
    r"|what\s*(starts|runs|loads|launches)\s*(at|on|during)\s*(boot|startup|login)"
    r"|startup\s*(entry|item|program|list)"
    r"|run\s*at\s*(boot|startup|login)"
)
def _startup(match, question):
    rows = db.get_recent("startup_entries", limit=25)
    if not rows:
        return "No startup entry changes recorded (baseline matches current state)."
    lines = [
        f"  [{r.get('action','?')}] {r.get('name','?')} - "
        f"{(r.get('command') or '?')[:55]}  ({(r.get('timestamp') or '')[:16]})"
        for r in rows
    ]
    return f"{len(rows)} startup entry event(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 12) SERVICES
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"(windows\s*)?service|daemon"
    r"|what\s*service.*(running|active|stopped|changed)"
    r"|service\s*(status|list|running|stopped|changed)"
    r"|background\s*service"
)
def _services(match, question):
    rows = db.get_recent("services", limit=25)
    if not rows:
        return "No service change events recorded. All services match the baseline."
    lines = [
        f"  [{r.get('action','?')}] {r.get('display_name') or r.get('name','?')} "
        f"- {r.get('status','?')} ({r.get('start_mode','?')})"
        for r in rows
    ]
    return f"{len(rows)} service event(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 13) SCHEDULED TASKS
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"scheduled\s*task|cron\s*job|task\s*scheduler"
    r"|what\s*(is\s*)?scheduled|pending\s*task"
    r"|timer|recurring\s*task"
)
def _scheduled_tasks(match, question):
    rows = db.get_recent("scheduled_tasks", limit=20)
    if not rows:
        return "No scheduled task changes recorded."
    lines = [
        f"  [{r.get('action','?')}] {r.get('name','?')} - "
        f"path: {(r.get('path') or '?')[:50]}  next: {r.get('next_run','?')}"
        for r in rows
    ]
    return f"{len(rows)} scheduled task event(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 14) FILE CHANGES
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"file\s*(change|modif|creat|delet|alter|watch)"
    r"|filesystem|what\s*file.*(changed|modified|created|deleted)"
    r"|recent\s*file\s*(change|modification|activity)"
    r"|file\s*monitor"
)
def _file_changes(match, question):
    rows = db.get_recent("filesystem_events", limit=20)
    if not rows:
        return (
            "No filesystem events recorded.\n"
            "Note: The filesystem monitor requires `pip install watchdog` to enable."
        )
    lines = [
        f"  {r.get('event_type','?')} - {r.get('path','?')}  "
        f"({(r.get('timestamp') or '')[:16]})"
        for r in rows
    ]
    return f"{len(rows)} file event(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 15) DNS QUERIES
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"dns\b|domain\s*(lookup|query|request|resolution)"
    r"|what\s*(domain|website|site|dns).*(lookup|quer|resolve|access)"
    r"|name\s*resolution"
)
def _dns(match, question):
    rows = db.get_recent("dns_queries", limit=20)
    if not rows:
        return "No DNS queries recorded. The network sniffer may be disabled."
    lines = [
        f"  {r.get('domain','?')} by {r.get('process_name') or 'PID '+str(r.get('pid','?'))}"
        f"  ({(r.get('timestamp') or '')[:16]})"
        for r in rows
    ]
    return f"{len(rows)} recent DNS lookup(s):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 16) SYSTEM HEALTH / STATUS / DISK
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"system\s*(health|status|info|overview)"
    r"|how.*(system|machine|computer|pc)\s*(doing|running|performing|status)"
    r"|disk\s*(space|usage|full|capacity|storage)"
    r"|storage|how\s*much\s*space"
    r"|health\s*(check|status|report)"
)
def _system_health(match, question):
    rows = db.run_readonly_query(
        "SELECT * FROM system_health ORDER BY timestamp DESC LIMIT 1"
    )
    if not rows:
        return "No system health data collected yet."
    h = rows[0]
    cpu = h.get("cpu_pct")
    mem = h.get("mem_pct")
    disk = h.get("disk_pct")

    lines = ["Current system health:"]
    if cpu is not None:
        status = "CRITICAL" if cpu > 80 else "elevated" if cpu > 50 else "normal"
        lines.append(f"  CPU: {cpu:.0f}% ({status})")
    if mem is not None:
        status = "CRITICAL" if mem > 85 else "elevated" if mem > 65 else "normal"
        lines.append(f"  Memory: {mem:.0f}% ({status})")
    if disk is not None:
        status = "CRITICAL" if disk > 90 else "elevated" if disk > 75 else "normal"
        lines.append(f"  Disk: {disk:.0f}% ({status})")
    lines.append(f"  Last checked: {(h.get('timestamp') or '')[:19]}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 17) WHO USED THIS MACHINE
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"who\s*(has\s*)?(been\s*)?(using|used|logged|accessed)\s*(my\s*|this\s*|the\s*)?"
    r"(machine|computer|pc|laptop|system)"
    r"|user\s*(activity|session|account)"
    r"|active\s*user"
)
def _who_used(match, question):
    rows = db.run_readonly_query(
        "SELECT DISTINCT username, MAX(timestamp) as last_seen "
        "FROM login_events WHERE timestamp >= ? "
        "GROUP BY username ORDER BY last_seen DESC",
        (_since(days=7),),
    )
    if not rows:
        return "No login activity recorded in the last 7 days."
    lines = [
        f"  {r['username'] or 'unknown user'} - last seen {r['last_seen']}"
        for r in rows
    ]
    return f"Users seen on this machine (last 7 days):\n" + "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 18) DAILY SUMMARY / ANYTHING WEIRD
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"anything\s*(weird|suspicious|unusual|abnormal|off)"
    r"|should\s*i\s*(be\s*)?(worried|concerned)"
    r"|summar(y|ize)|overview|report|today.*(activity|summary|recap)"
    r"|what\s*(happened|changed|occurred|is\s*new)"
    r"|daily\s*(report|summary|recap|review)"
    r"|catch\s*me\s*up|brief\s*me|sitrep|status\s*report"
)
def _summary(match, question):
    since = _since(hours=24)
    alerts = db.run_readonly_query(
        "SELECT category, severity, message FROM alerts "
        "WHERE timestamp >= ? ORDER BY timestamp DESC",
        (since,),
    )
    new_procs = db.run_readonly_query(
        "SELECT COUNT(*) as c FROM process_snapshots "
        "WHERE event='new' AND timestamp >= ?",
        (since,),
    )[0]["c"]
    new_ports = db.run_readonly_query(
        "SELECT COUNT(*) as c FROM port_snapshots "
        "WHERE event='opened' AND timestamp >= ?",
        (since,),
    )[0]["c"]
    failed_logins = db.run_readonly_query(
        "SELECT COUNT(*) as c FROM login_events "
        "WHERE success=0 AND timestamp >= ?",
        (since,),
    )[0]["c"]

    lines = [
        "24-hour summary:",
        f"  New processes: {new_procs}",
        f"  Ports opened: {new_ports}",
        f"  Failed logins: {failed_logins}",
    ]
    if alerts:
        high = sum(1 for a in alerts if (a["severity"] or "").upper() == "HIGH")
        med = sum(1 for a in alerts if (a["severity"] or "").upper() == "MEDIUM")
        lines.append(f"  Alerts: {len(alerts)} total ({high} high, {med} medium)")
        top = alerts[0]
        lines.append(
            f"  Most recent: [{top['severity']}] {top['category']} - {top['message']}"
        )
    else:
        lines.append("  Alerts: 0 - all clear.")

    if failed_logins > 0:
        lines.append("\nNote: Failed login attempts detected. Run 'any failed logins?' for details.")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 19) GREETINGS / SMALL TALK
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"^(hi|hello|hey|greetings|good\s*(morning|afternoon|evening)|yo|sup)\b"
    r"|^how\s*are\s*you|^what's?\s*up"
)
def _greeting(match, question):
    health = db.run_readonly_query(
        "SELECT cpu_pct, mem_pct FROM system_health ORDER BY timestamp DESC LIMIT 1"
    )
    alerts = db.run_readonly_query(
        "SELECT COUNT(*) as c FROM alerts WHERE timestamp >= ?",
        (_since(hours=24),),
    )[0]["c"]

    status = "All clear" if alerts == 0 else f"{alerts} alert(s) in the last 24h"
    if health:
        h = health[0]
        return (
            f"Hello! System is running at {h['cpu_pct']:.0f}% CPU, "
            f"{h['mem_pct']:.0f}% memory. {status}.\n"
            f"Ask me about threats, ports, processes, USB devices, logins, "
            f"downloads, or anything else I monitor."
        )
    return (
        f"Hello! {status}.\n"
        f"Ask me about threats, ports, processes, USB devices, logins, "
        f"downloads, or anything else I monitor."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 20) HELP / CAPABILITIES
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"help|what\s*can\s*you|what\s*do\s*you|how\s*(do\s*i|to)\s*use"
    r"|what\s*(can|should)\s*i\s*ask"
    r"|what\s*(do\s*)?you\s*(know|monitor|watch|track|support|do)"
    r"|your\s*capabilit|feature|command"
    r"|what\s*question|example\s*question"
)
def _help(match, question):
    return (
        "Here is what I can answer from the data I collect:\n\n"
        "  Threats & alerts - 'what are the threats?', 'am I safe?', 'any warnings?'\n"
        "  USB devices - 'what USB devices are connected?', 'any USB activity?'\n"
        "  Network ports - 'list open ports', 'who is using port 8080?'\n"
        "  Processes - 'what processes are running?', 'why is CPU high?'\n"
        "  Network - 'what is talking to the internet?', 'outbound connections'\n"
        "  Logins - 'any failed logins?', 'who used this machine?'\n"
        "  Downloads - 'what did I download?', 'recent downloads'\n"
        "  Software - 'any new software installed?', 'software list'\n"
        "  Startup - 'show startup entries', 'what runs at boot?'\n"
        "  Services - 'windows services', 'service status'\n"
        "  Files - 'any file changes?', 'filesystem events'\n"
        "  DNS - 'dns queries', 'domain lookups'\n"
        "  Health - 'system health', 'disk space', 'how is my system?'\n"
        "  Summary - 'anything weird today?', 'daily report', 'brief me'\n\n"
        "Set ANTHROPIC_API_KEY in .env to unlock free-form natural language questions."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 21) THANK YOU / ACKNOWLEDGMENT
# ═══════════════════════════════════════════════════════════════════════════════
@template(
    r"^(thanks?|thank\s*you|thx|ty|cheers|great|good\s*job|nice|awesome|cool)\b"
)
def _thanks(match, question):
    return "You are welcome! Let me know if you need anything else about your system."


# ═══════════════════════════════════════════════════════════════════════════════
# DISPATCHER
# ═══════════════════════════════════════════════════════════════════════════════
def try_offline(question: str):
    """Returns an answer string if a template matched, else None (fall through to LLM)."""
    for pattern, fn in _TEMPLATES:
        m = pattern.search(question)
        if m:
            try:
                result = fn(m, question)
                if result:
                    return result
            except Exception:
                continue   # try next pattern instead of returning None
    return None
