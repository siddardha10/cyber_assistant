"""
monitors/filesystem.py

Watches configured folders (Downloads, Desktop by default) for file
creation/modification/deletion using the `watchdog` library, and flags
newly-created executables/scripts the same way the browser monitor does.
This is event-driven (not polling), so it's cheap to run continuously.
"""

import os
import threading
from pathlib import Path

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.filesystem")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG_AVAILABLE = True
except ImportError:
    _WATCHDOG_AVAILABLE = False

_RISKY_EXTENSIONS = (".exe", ".msi", ".bat", ".ps1", ".vbs", ".scr", ".jar")


if _WATCHDOG_AVAILABLE:
    class _Handler(FileSystemEventHandler):
        def __init__(self, watched_dir):
            self.watched_dir = watched_dir

        def _record(self, path, event_type):
            try:
                size = os.path.getsize(path) if os.path.exists(path) else None
            except OSError:
                size = None
            db.insert("filesystem_events", {
                "timestamp": db.now_iso(),
                "path": path,
                "event_type": event_type,
                "watched_dir": self.watched_dir,
                "size_bytes": size,
            })
            if event_type == "created" and path.lower().endswith(_RISKY_EXTENSIONS):
                db.insert_alert(
                    category="risky_file_created",
                    severity="LOW",
                    message=f"Executable/script appeared in watched folder: {path}",
                    reason=(
                        "A new executable or script showing up in Downloads or Desktop is worth "
                        "tracking the same way a browser download is — this often catches files that "
                        "arrive by means other than the browser (extracted from an archive, copied "
                        "from USB, etc.)."
                    ),
                    source_table="filesystem_events",
                    dedup_key=f"risky_file_created:{path.lower()}",
                )

        def on_created(self, event):
            if not event.is_directory:
                self._record(event.src_path, "created")

        def on_deleted(self, event):
            if not event.is_directory:
                self._record(event.src_path, "deleted")

        def on_modified(self, event):
            if not event.is_directory:
                self._record(event.src_path, "modified")


def run_forever(stop_event: threading.Event):
    if not config.ENABLE_FILESYSTEM_WATCH:
        log.info("Filesystem monitor disabled via config")
        return
    if not _WATCHDOG_AVAILABLE:
        log.warning("Filesystem monitor disabled: `pip install watchdog` to enable it")
        return

    observer = Observer()
    watched_any = False
    for folder in config.FS_WATCH_PATHS:
        p = Path(folder)
        if p.exists():
            observer.schedule(_Handler(str(p)), str(p), recursive=False)
            watched_any = True
        else:
            log.warning("Watched folder does not exist, skipping: %s", folder)

    if not watched_any:
        log.warning("No valid folders to watch — filesystem monitor idle")
        return

    observer.start()
    log.info("Filesystem monitor started for: %s", config.FS_WATCH_PATHS)
    try:
        while not stop_event.is_set():
            stop_event.wait(1)
    finally:
        observer.stop()
        observer.join(timeout=5)
