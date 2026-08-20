"""
monitors/health.py

Lightweight system-wide vitals, sampled frequently. Powers the "is my
system healthy" question and the live dashboard metrics in the UI.
"""

import threading

import psutil

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.health")


_DISK_ROOT = "C:\\" if config.IS_WINDOWS else "/"


def _cycle():
    db.insert("system_health", {
        "timestamp": db.now_iso(),
        "cpu_pct": psutil.cpu_percent(interval=1),
        "mem_pct": psutil.virtual_memory().percent,
        "disk_pct": psutil.disk_usage(_DISK_ROOT).percent,
    })


def run_forever(stop_event: threading.Event):
    log.info("Health monitor started (interval=%ss)", config.INTERVAL_HEALTH)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Health monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_HEALTH)
