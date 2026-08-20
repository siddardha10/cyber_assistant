"""
monitors/processes.py

Watches running processes every INTERVAL_PROCESSES seconds. Detects:
  - new processes since last snapshot
  - processes that have terminated
  - CPU anomalies vs each process's own rolling baseline (simple statistical
    anomaly detection — no ML model needed for this to be genuinely useful)

Delta detection: we keep an in-memory dict of {pid: last_seen_info} so we
only write rows on change, not every cycle — this is what keeps the DB from
being spammed with a full process table every 30 seconds forever.
"""

import threading
import time

import psutil

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.processes")

_previous = {}  # pid -> dict snapshot


def _safe_proc_info(p: psutil.Process) -> dict | None:
    try:
        with p.oneshot():
            return {
                "pid": p.pid,
                "ppid": p.ppid(),
                "name": p.name(),
                "exe_path": _safe(p.exe),
                "username": _safe(p.username),
                "cmdline": " ".join(_safe(p.cmdline) or []),
                "cpu_pct": p.cpu_percent(interval=None),
                "mem_mb": round(p.memory_info().rss / (1024 * 1024), 2),
                "status": p.status(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _safe(fn):
    try:
        return fn()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _check_cpu_anomaly(info: dict):
    baseline = db.get_process_baseline(info["name"])
    cpu = info["cpu_pct"] or 0.0

    # Only alert once we have enough samples to trust the baseline, and only
    # if this process is actually consuming meaningful CPU (skip idle noise).
    if cpu >= config.CPU_SPIKE_THRESHOLD_PCT:
        if baseline and baseline["sample_count"] >= 5:
            if cpu >= baseline["avg_cpu_pct"] * config.CPU_SPIKE_BASELINE_MULTIPLIER:
                db.insert_alert(
                    category="cpu_anomaly",
                    severity="MEDIUM",
                    message=(
                        f"{info['name']} (PID {info['pid']}) at {cpu:.0f}% CPU — "
                        f"baseline is {baseline['avg_cpu_pct']:.1f}%"
                    ),
                    reason=(
                        f"{info['name']} normally sits around {baseline['avg_cpu_pct']:.1f}% CPU on this "
                        f"machine, so {cpu:.0f}% is a real outlier rather than a static threshold being "
                        "crossed. This is flagged relative to its own history — one process can safely run "
                        "hot while another at the same raw percentage would be worth investigating."
                    ),
                    source_table="process_snapshots",
                    # dedup by process name: a spike that's still ongoing next cycle should
                    # bump one alert's occurrence count, not create a new row every 30s.
                    dedup_key=f"cpu_anomaly:{info['name']}",
                )
    db.update_process_baseline(info["name"], cpu)


def _cycle():
    current = {}
    for p in psutil.process_iter():
        info = _safe_proc_info(p)
        if info is None:
            continue
        current[info["pid"]] = info

    now = db.now_iso()

    # new processes
    for pid, info in current.items():
        if pid not in _previous:
            db.insert("process_snapshots", {**info, "timestamp": now, "event": "new"})
            # Flag executables launching from suspicious locations
            exe = (info.get("exe_path") or "").lower()
            if any(s in exe for s in ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/")):
                db.insert_alert(
                    category="suspicious_location",
                    severity="MEDIUM",
                    message=f"{info['name']} (PID {pid}) launched from a temp directory: {exe}",
                    reason=(
                        "Temp folders are writable by almost anything and are cleared automatically, "
                        "which makes them a common staging location for malware and installer droppers. "
                        "Legitimate installers do sometimes run briefly from here too — this is a "
                        "'worth a look' signal, not a confirmed problem."
                    ),
                    source_table="process_snapshots",
                    dedup_key=f"suspicious_location:{info['name']}:{exe}",
                )
        _check_cpu_anomaly(info)

    # terminated processes
    for pid, info in _previous.items():
        if pid not in current:
            db.insert("process_snapshots", {**info, "timestamp": now, "cpu_pct": 0.0, "event": "terminated"})

    _previous.clear()
    _previous.update(current)


def run_forever(stop_event: threading.Event):
    log.info("Process monitor started (interval=%ss)", config.INTERVAL_PROCESSES)
    # prime cpu_percent() — first call always returns 0.0
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass
    time.sleep(1)

    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Process monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_PROCESSES)
