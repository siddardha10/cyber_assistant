"""
main.py

Entry point. Starts the background monitor daemon (all monitors run in
their own thread, each isolated so one crashing doesn't take down the
others), then hands control to either the CLI REPL or the Flask API server.

Usage:
    python main.py --mode cli        # terminal REPL (default)
    python main.py --mode api        # web API for the HTML UI
    python main.py --mode daemon     # monitors only, no interface (for a service/task)
"""

import argparse
import signal
import sys
import threading

from db import database as db
from utils.logger import get_logger
from alerts import notifier
from monitors import (
    processes, ports, usb, logins, browser, startup,
    installed_software, services, scheduled_tasks, filesystem, network, health,
)

log = get_logger("main")

_ALL_MONITORS = [
    ("processes", processes.run_forever),
    ("ports", ports.run_forever),
    ("usb", usb.run_forever),
    ("logins", logins.run_forever),
    ("browser", browser.run_forever),
    ("startup", startup.run_forever),
    ("installed_software", installed_software.run_forever),
    ("services", services.run_forever),
    ("scheduled_tasks", scheduled_tasks.run_forever),
    ("filesystem", filesystem.run_forever),
    ("network", network.run_forever),
    ("health", health.run_forever),
    ("alert_notifier", notifier.run_forever),
]


def start_monitors(stop_event: threading.Event) -> list[threading.Thread]:
    threads = []
    for name, target in _ALL_MONITORS:
        t = threading.Thread(target=target, args=(stop_event,), name=f"monitor-{name}", daemon=True)
        t.start()
        threads.append(t)
        log.info("Launched monitor thread: %s", name)
    return threads


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel — personal cyber assistant")
    parser.add_argument("--mode", choices=["cli", "api", "daemon"], default="cli")
    args = parser.parse_args()

    log.info("CyberSentinel starting in '%s' mode", args.mode)
    db.init_db()

    stop_event = threading.Event()
    start_monitors(stop_event)

    def _shutdown(signum, frame):
        log.info("Shutdown signal received, stopping monitors...")
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)

    if args.mode == "cli":
        from cli import repl
        try:
            repl.run()
        finally:
            stop_event.set()
    elif args.mode == "api":
        from api import server
        try:
            server.run()
        finally:
            stop_event.set()
    else:  # daemon
        log.info("Running in daemon-only mode. Press Ctrl+C to stop.")
        try:
            while not stop_event.is_set():
                stop_event.wait(5)
        except KeyboardInterrupt:
            stop_event.set()


if __name__ == "__main__":
    main()
