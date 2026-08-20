"""
monitors/scheduled_tasks.py

Windows Task Scheduler has no clean Python stdlib API, so we shell out to
the built-in `schtasks /query` command (present on every Windows install,
no extra dependency needed) and parse its CSV output. This is diffed
against the previous scan the same way as the other monitors.
"""

import csv
import io
import subprocess
import threading

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.scheduled_tasks")

_previous = {}  # task_name -> next_run


def _scan() -> dict:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/nh"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}

    entries = {}
    if result.returncode != 0:
        return entries

    reader = csv.reader(io.StringIO(result.stdout))
    for row in reader:
        if len(row) < 3:
            continue
        task_name, next_run, status = row[0], row[1], row[2]
        entries[task_name] = next_run
    return entries


def _cycle():
    current = _scan()
    now = db.now_iso()

    added = set(current.keys()) - set(_previous.keys())
    removed = set(_previous.keys()) - set(current.keys())

    for name in added:
        db.insert("scheduled_tasks", {
            "timestamp": now, "name": name, "path": name,
            "next_run": current[name], "action": "new",
        })
        if _previous:
            db.insert_alert(
                category="new_scheduled_task",
                severity="MEDIUM",
                message=f"New scheduled task created: {name}",
                reason=(
                    "Scheduled tasks run code at a set time or trigger without you doing anything in "
                    "the moment — a common persistence mechanism, but also how normal software "
                    "handles background updates and maintenance."
                ),
                source_table="scheduled_tasks",
                dedup_key=f"new_scheduled_task:{name}",
            )

    for name in removed:
        db.insert("scheduled_tasks", {
            "timestamp": now, "name": name, "path": name,
            "next_run": _previous[name], "action": "removed",
        })

    _previous.clear()
    _previous.update(current)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS:
        log.info("Scheduled tasks monitor skipped — not running on Windows")
        return
    log.info("Scheduled tasks monitor started (interval=%ss)", config.INTERVAL_SCHEDULED_TASKS)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Scheduled tasks monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_SCHEDULED_TASKS)
