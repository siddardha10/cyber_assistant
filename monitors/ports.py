"""
monitors/ports.py

Watches active network connections (listening + established) and maps each
one back to the owning process via PID, exactly the way the project brief
describes: psutil.net_connections() -> cross-reference PID -> process name.

Delta detection keeps a set of "currently open" (port, pid) tuples in memory
so we only insert a row when something actually opens or closes.
"""

import socket
import threading

import psutil

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.ports")

_previous_keys = set()  # set of (local_port, pid, protocol)


def _proc_name(pid):
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _cycle():
    current = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        log.warning("Port monitor needs elevated privileges to see all connections on this OS")
        return

    for c in conns:
        if not c.laddr:
            continue
        key = (c.laddr.port, c.pid, c.type)
        current[key] = {
            "port": c.laddr.port,
            "pid": c.pid,
            "process_name": _proc_name(c.pid),
            "state": c.status,
            "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "remote_ip": c.raddr.ip if c.raddr else None,
            "remote_port": c.raddr.port if c.raddr else None,
        }

    now = db.now_iso()

    opened = set(current.keys()) - _previous_keys
    closed = _previous_keys - set(current.keys())

    for key in opened:
        row = current[key]
        db.insert("port_snapshots", {**row, "timestamp": now, "event": "opened"})

    for key in closed:
        port, pid, _ = key
        db.insert("port_snapshots", {
            "timestamp": now, "port": port, "pid": pid,
            "process_name": _proc_name(pid), "state": "CLOSED",
            "protocol": None, "remote_ip": None, "remote_port": None,
            "event": "closed",
        })

    _previous_keys.clear()
    _previous_keys.update(current.keys())


def run_forever(stop_event: threading.Event):
    log.info("Port monitor started (interval=%ss)", config.INTERVAL_PORTS)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Port monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_PORTS)
