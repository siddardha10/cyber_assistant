"""
monitors/startup.py

Watches the classic Windows autorun surfaces:
  - HKCU/HKLM ...\\Run and ...\\RunOnce registry keys
  - The Startup folder (shell:startup) for both the user and all users

Diffs against the previous snapshot (kept in memory) so we only log actual
additions/removals, not the whole list every cycle.
"""

import threading
from pathlib import Path

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.startup")

try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:
    _WINREG_AVAILABLE = False

_REGISTRY_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER if _WINREG_AVAILABLE else None,
     r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_LOCAL_MACHINE if _WINREG_AVAILABLE else None,
     r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_CURRENT_USER if _WINREG_AVAILABLE else None,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
]

_STARTUP_FOLDERS = [
    Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
]

_previous = {}  # name -> (command, location)


def _read_registry_entries() -> dict:
    entries = {}
    for hive, subkey, label in _REGISTRY_LOCATIONS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries[f"{label}:{name}"] = (value, label)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
        except Exception:
            log.exception("Failed reading registry key %s", label)
    return entries


def _read_startup_folders() -> dict:
    entries = {}
    for folder in _STARTUP_FOLDERS:
        if not folder.exists():
            continue
        for item in folder.iterdir():
            entries[f"folder:{item.name}"] = (str(item), str(folder))
    return entries


def _cycle():
    current = {}
    current.update(_read_registry_entries())
    current.update(_read_startup_folders())

    now = db.now_iso()
    added = set(current.keys()) - set(_previous.keys())
    removed = set(_previous.keys()) - set(current.keys())

    for key in added:
        command, location = current[key]
        name = key.split(":", 1)[1]
        db.insert("startup_entries", {
            "timestamp": now, "name": name, "command": command,
            "location": location, "action": "added",
        })
        if _previous:  # don't alert on the very first baseline scan
            db.insert_alert(
                category="new_startup_entry",
                severity="MEDIUM",
                message=f"New startup entry: {name} ({location}) -> {command}",
                reason=(
                    "Anything in a startup location runs automatically every time you log in without "
                    "you launching it — the same persistence trick services and scheduled tasks use. "
                    "Usually this is a legitimate app asking to auto-launch (Discord, updaters, etc.)."
                ),
                source_table="startup_entries",
                dedup_key=f"new_startup_entry:{name}",
            )

    for key in removed:
        command, location = _previous[key]
        name = key.split(":", 1)[1]
        db.insert("startup_entries", {
            "timestamp": now, "name": name, "command": command,
            "location": location, "action": "removed",
        })

    _previous.clear()
    _previous.update(current)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS or not _WINREG_AVAILABLE:
        log.info("Startup monitor skipped — not running on Windows")
        return
    log.info("Startup monitor started (interval=%ss)", config.INTERVAL_STARTUP)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Startup monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_STARTUP)
