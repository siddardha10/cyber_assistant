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

4624 and 4625 use different StringInserts layouts. The event-specific offsets
below match current Windows 10/11 layouts. If a build differs, `raw_record_id`
is still stored so nothing is lost; only parsed details may be unavailable.
"""

import ctypes
import re
import subprocess
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
_prerequisite_status = None


def check_prerequisites() -> dict:
    """Check whether Windows can provide the logon events this monitor needs."""
    global _prerequisite_status
    if not config.IS_WINDOWS:
        _prerequisite_status = {
            "checked": True, "ready": False, "admin": False,
            "audit_policy": False, "issues": ["Login event monitoring requires Windows."],
        }
        return _prerequisite_status

    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        is_admin = False

    audit_policy = None
    policy_detail = None
    try:
        result = subprocess.run(
            ["auditpol.exe", "/get", "/subcategory:Logon"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        policy_text = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
        lowered = policy_text.lower()
        if result.returncode == 0:
            has_success = re.search(r"\bsuccess\b", lowered) is not None
            has_failure = re.search(r"\bfailure\b", lowered) is not None
            audit_policy = has_success and has_failure and "no auditing" not in lowered
            if audit_policy is False:
                policy_detail = "Logon success and failure auditing are not both enabled."
        else:
            policy_detail = policy_text or f"auditpol exited with code {result.returncode}."
    except (OSError, subprocess.TimeoutExpired) as exc:
        policy_detail = f"Could not run auditpol: {exc}"

    issues = []
    if not is_admin:
        issues.append(
            "CyberSentinel is not running as Administrator. Close it, then right-click "
            "the terminal or shortcut and choose 'Run as administrator'."
        )
    if audit_policy is not True:
        if policy_detail and audit_policy is None:
            issues.append(
                "The Security log audit policy could not be verified. Run an elevated "
                "terminal and enable both logon events with: "
                'auditpol /set /subcategory:"Logon" /success:enable /failure:enable. '
                f"Check detail: {policy_detail}"
            )
        else:
            issues.append(
                "Security log auditing for successful and failed logons is not enabled. "
                'Run an elevated terminal: auditpol /set /subcategory:"Logon" '
                "/success:enable /failure:enable."
            )
    if not _WINEVT_AVAILABLE:
        issues.append("The Windows event-log reader is missing. Install pywin32 in this environment.")

    _prerequisite_status = {
        "checked": True,
        "ready": is_admin and audit_policy is True and _WINEVT_AVAILABLE,
        "admin": is_admin,
        "audit_policy": audit_policy,
        "issues": issues,
    }
    return _prerequisite_status


def get_prerequisite_status() -> dict:
    """Return the latest startup check for display in the API/UI."""
    if _prerequisite_status is None:
        return {
            "checked": False,
            "ready": False,
            "admin": None,
            "audit_policy": None,
            "issues": ["Login monitor prerequisites have not been checked yet."],
        }
    return dict(_prerequisite_status)


def _extract_field(inserts, index, default=None):
    try:
        val = inserts[index]
        return val if val and str(val).strip() not in {"-", "N/A", "NULL"} else default
    except (IndexError, TypeError):
        return default


def _parse_event(event) -> dict | None:
    event_id = event.EventID & 0xFFFF  # mask off qualifier bits
    if event_id not in _TARGET_EVENT_IDS:
        return None

    inserts = event.StringInserts or []
    if event_id == 4624:
        username, logon_type_index, source_ip_index = 5, 8, 20
    elif event_id == 4625:
        username, logon_type_index, source_ip_index = 5, 10, 19
    elif event_id == 4648:
        username, logon_type_index, source_ip_index = 5, None, 12
    else:  # 4672: special privileges assigned
        username, logon_type_index, source_ip_index = 1, None, None

    username = _extract_field(inserts, username)
    logon_type = _extract_field(inserts, logon_type_index) if logon_type_index is not None else None
    source_ip = _extract_field(inserts, source_ip_index) if source_ip_index is not None else None
    if event_id in (4624, 4625) and not username and not source_ip:
        log.debug(
            "Event %s (record %s) has no parsed username/IP; raw StringInserts=%r",
            event_id, event.RecordNumber, inserts,
        )

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
        for e in reversed(new_events):  # store oldest-first
            db.insert("login_events", e)
        _last_record_number = max(e["raw_record_id"] for e in new_events)
        _check_brute_force(new_events)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS:
        log.info("Login monitor skipped — not running on Windows")
        return
    prerequisites = check_prerequisites()
    for issue in prerequisites["issues"]:
        log.warning("Login monitor prerequisite: %s", issue)
    if not _WINEVT_AVAILABLE:
        log.warning("Login monitor disabled: `pip install pywin32` to enable it")
        return
    if not prerequisites["ready"]:
        log.warning("Login monitor disabled until its Administrator/audit-policy prerequisites are met.")
        return

    log.info("Login monitor started (interval=%ss).", config.INTERVAL_LOGINS)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Login monitor cycle failed (are you running as Administrator?) — continuing")
        stop_event.wait(config.INTERVAL_LOGINS)
