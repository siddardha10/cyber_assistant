"""
monitors/services.py

Uses psutil.win_service_iter() (Windows-only API) to snapshot all services
and diff against the previous scan — flags new services and any service
that flips to automatic start, since that's the classic persistence
mechanism for malware and worth a LOW/MEDIUM alert either way.
"""

import threading

import psutil

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.services")

_previous = {}  # name -> (display_name, start_mode, status)


def _scan() -> dict:
    entries = {}
    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
            entries[info["name"]] = (info["display_name"], info["start_type"], info["status"])
        except Exception:
            continue
    return entries


def _cycle():
    current = _scan()
    now = db.now_iso()

    added = set(current.keys()) - set(_previous.keys())
    removed = set(_previous.keys()) - set(current.keys())
    common = set(current.keys()) & set(_previous.keys())

    for name in added:
        display_name, start_mode, status = current[name]
        db.insert("services", {
            "timestamp": now, "name": name, "display_name": display_name,
            "start_mode": start_mode, "status": status, "action": "new",
        })
        if _previous and start_mode == "automatic":
            db.insert_alert(
                category="new_service",
                severity="MEDIUM",
                message=f"New auto-start service: {display_name} ({name})",
                reason=(
                    "A service set to start automatically runs every boot without you launching "
                    "anything — the classic way both legitimate software and malware establish "
                    "persistence. Most of the time this is just a normal app you installed."
                ),
                source_table="services",
                dedup_key=f"new_service:{name}",
            )

    for name in removed:
        display_name, start_mode, status = _previous[name]
        db.insert("services", {
            "timestamp": now, "name": name, "display_name": display_name,
            "start_mode": start_mode, "status": status, "action": "removed",
        })

    for name in common:
        old = _previous[name]
        new = current[name]
        if old != new:
            display_name, start_mode, status = new
            db.insert("services", {
                "timestamp": now, "name": name, "display_name": display_name,
                "start_mode": start_mode, "status": status, "action": "changed",
            })
            if old[1] != "automatic" and start_mode == "automatic":
                db.insert_alert(
                    category="service_start_mode_change",
                    severity="MEDIUM",
                    message=f"Service changed to auto-start: {display_name} ({name})",
                    reason=(
                        "This service used to require a manual start and now starts on its own every "
                        "boot. That switch is worth noticing on its own, separate from the service's "
                        "install — it's a common step in setting up persistence."
                    ),
                    source_table="services",
                    dedup_key=f"service_start_mode_change:{name}",
                )

    _previous.clear()
    _previous.update(current)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS:
        log.info("Services monitor skipped — not running on Windows")
        return
    log.info("Services monitor started (interval=%ss)", config.INTERVAL_SERVICES)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Services monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_SERVICES)
