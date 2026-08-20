"""
alerts/notifier.py

Polls the alerts table for new HIGH severity rows and fires a desktop
notification (via `plyer`, cross-platform) so the user notices without
having to have the CLI/UI open. Falls back to a log line if plyer isn't
installed — never crashes the daemon over a missing optional dependency.
"""

import threading

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("alerts.notifier")

try:
    from plyer import notification
    _PLYER_AVAILABLE = True
except ImportError:
    _PLYER_AVAILABLE = False

_last_seen_id = 0


def _notify(alert: dict):
    title = f"CyberSentinel — {alert['severity']} alert"
    message = alert["message"]
    if _PLYER_AVAILABLE and config.ENABLE_DESKTOP_NOTIFICATIONS:
        try:
            notification.notify(title=title, message=message, app_name="CyberSentinel", timeout=8)
            return
        except Exception:
            log.exception("Desktop notification failed, falling back to log")
    log.warning("%s: %s", title, message)


def _cycle():
    global _last_seen_id
    rows = db.run_readonly_query(
        "SELECT id, timestamp, category, severity, message FROM alerts "
        "WHERE id > ? AND severity = 'HIGH' ORDER BY id ASC",
        (_last_seen_id,),
    )
    for row in rows:
        _notify(row)
        _last_seen_id = max(_last_seen_id, row["id"])


def run_forever(stop_event: threading.Event):
    log.info("Alert notifier started")
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Alert notifier cycle failed — continuing")
        stop_event.wait(10)
