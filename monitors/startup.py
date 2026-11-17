"""
monitors/startup.py

Watches the classic Windows autorun surfaces:
  - HKCU/HKLM ...\\Run and ...\\RunOnce registry keys
  - The Startup folder (shell:startup) for both the user and all users

Persists a complete initial baseline, then logs actual additions/removals.
Generated registration hashes are grouped as one logical startup entry.
"""

import threading
import re
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

_previous = {}  # logical identity -> (command, location, raw name)
_BASELINE_STATE_KEY = "startup_baseline_complete"


def normalize_startup_name(name: str) -> str:
    """Hide volatile GUID/hash suffixes for well-known auto-generated entries."""
    return re.sub(
        r"^(MicrosoftEdgeAutoLaunch)_[0-9a-f-]{8,}$",
        r"\1",
        name or "",
        flags=re.IGNORECASE,
    )


def _entry_identity(name: str, location: str) -> str:
    normalized_name = normalize_startup_name(name).casefold()
    if location.startswith(("HKCU", "HKLM")):
        return f"{location.casefold()}:{normalized_name}"
    return f"folder:{normalized_name}"


def _group_current_entries(entries: dict) -> dict:
    grouped = {}
    for key, (command, location) in entries.items():
        name = key.split(":", 1)[1]
        grouped[_entry_identity(name, location)] = (command, location, name)
    return grouped


def _load_previous_snapshot() -> dict:
    rows = db.run_readonly_query(
        "SELECT name, command, location, action FROM startup_entries ORDER BY id"
    )
    current = {}
    for row in rows:
        name = row.get("name") or ""
        identity = _entry_identity(name, row.get("location") or "")
        if row.get("action") == "removed":
            current.pop(identity, None)
        else:
            current[identity] = (
                row.get("command") or "",
                row.get("location") or "",
                name,
            )
    return current


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
    current_logical = _group_current_entries(current)
    baseline = db.run_readonly_query(
        "SELECT value FROM monitor_state WHERE key = ?",
        (_BASELINE_STATE_KEY,),
    )

    if not baseline:
        for key, (command, location) in current.items():
            name = key.split(":", 1)[1]
            db.insert("startup_entries", {
                "timestamp": now, "name": name, "command": command,
                "location": location, "action": "baseline",
            })
        db.insert("monitor_state", {"key": _BASELINE_STATE_KEY, "value": now})
        _previous.clear()
        _previous.update(current_logical)
        log.info("Startup baseline recorded: %d existing raw entries.", len(current))
        return

    if not _previous:
        _previous.update(_load_previous_snapshot())

    added = set(current_logical.keys()) - set(_previous.keys())
    removed = set(_previous.keys()) - set(current_logical.keys())

    for key in added:
        command, location, name = current_logical[key]
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
                dedup_key=f"new_startup_entry:{normalize_startup_name(name)}",
            )

    for key in removed:
        command, location, name = _previous[key]
        db.insert("startup_entries", {
            "timestamp": now, "name": name, "command": command,
            "location": location, "action": "removed",
        })

    for key in set(current_logical) & set(_previous):
        command, location, name = current_logical[key]
        previous_name = _previous[key][2]
        if name != previous_name and normalize_startup_name(name) == normalize_startup_name(previous_name):
            db.insert("startup_entries", {
                "timestamp": now, "name": name, "command": command,
                "location": location, "action": "observed",
            })

    _previous.clear()
    _previous.update(current_logical)


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
