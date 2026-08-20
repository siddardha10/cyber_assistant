"""
monitors/logins.py

Reads the Windows Security event log for logon activity:
  4624 = successful logon
  4625 = failed logon
  4648 = explicit credential logon (e.g. "Run as different user")
  4672 = special privileges assigned (admin logon)

Requirements this monitor depends on (documented, not assumed):
  - Must run as Administrator to open the Security log.
  - Windows must have "Audit Logon Events" / "Audit Logon" enabled in
    Local Security Policy (auditpol) — it's on by default on most modern
    Windows builds, but not guaranteed on every edition/config.

StringInserts field positions for 4624/4625 vary slightly across Windows
versions — the indices below match current Windows 10/11 layouts. If your
build differs, `raw_record_id` is still stored so nothing is lost; only the
parsed username/IP might come back as None.
"""

import threading

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.logins")

try:
    import win32evtlog
    import win32evtlogutil
    _WINEVT_AVAILABLE = True
except ImportError:
    _WINEVT_AVAILABLE = False

_TARGET_EVENT_IDS = {4624, 4625, 4648, 4672}

_last_record_number = None


def _extract_field(inserts, index, default=None):
    try:
        val = inserts[index]
        return val if val else default
    except (IndexError, TypeError):
        return default


def _parse_event(event) -> dict | None:
    event_id = event.EventID & 0xFFFF  # mask off qualifier bits
    if event_id not in _TARGET_EVENT_IDS:
        return None

    inserts = event.StringInserts or []
    username = _extract_field(inserts, 5)
    logon_type = _extract_field(inserts, 8)
    source_ip = _extract_field(inserts, 18) or _extract_field(inserts, 19)

    return {
        "timestamp": db.now_iso(),
        "event_id": event_id,
        "username": username,
        "source_ip": source_ip,
        "logon_type": int(logon_type) if logon_type and str(logon_type).isdigit() else None,
        "success": 1 if event_id in (4624, 4672) else 0,
        "raw_record_id": event.RecordNumber,
    }


def _check_brute_force(events_this_cycle: list):
    failures = [e for e in events_this_cycle if e["success"] == 0]
    if len(failures) >= config.FAILED_LOGIN_ALERT_COUNT:
        usernames = sorted({f["username"] or "unknown" for f in failures})
        db.insert_alert(
            category="failed_login_burst",
            severity="HIGH",
            message=f"{len(failures)} failed login attempts in this check cycle (user(s): {', '.join(usernames)})",
            reason=(
                f"{config.FAILED_LOGIN_ALERT_COUNT}+ failed logins in a short window is the classic "
                "signature of a brute-force or credential-guessing attempt rather than someone simply "
                "mistyping a password once or twice. Worth checking the source IP and whether it's you."
            ),
            source_table="login_events",
            # dedup by username so a sustained attack against one account collapses
            # into a rising occurrence count instead of a wall of separate alerts.
            dedup_key=f"failed_login_burst:{'+'.join(usernames)}",
        )


def _cycle():
    global _last_record_number
    handle = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    new_events = []
    try:
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            stop = False
            for event in records:
                if _last_record_number is not None and event.RecordNumber <= _last_record_number:
                    stop = True
                    break
                parsed = _parse_event(event)
                if parsed:
                    new_events.append(parsed)
            if stop:
                break
            if len(new_events) > 500:  # safety cap per cycle
                break
    finally:
        win32evtlog.CloseEventLog(handle)

    if new_events:
        _last_record_number = max(e["raw_record_id"] for e in new_events)
        for e in reversed(new_events):  # store oldest-first
            db.insert("login_events", e)
        _check_brute_force(new_events)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS:
        log.info("Login monitor skipped — not running on Windows")
        return
    if not _WINEVT_AVAILABLE:
        log.warning("Login monitor disabled: `pip install pywin32` to enable it")
        return

    log.info("Login monitor started (interval=%ss). Requires admin privileges.", config.INTERVAL_LOGINS)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Login monitor cycle failed (are you running as Administrator?) — continuing")
        stop_event.wait(config.INTERVAL_LOGINS)
