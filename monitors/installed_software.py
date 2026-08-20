"""
monitors/installed_software.py

Reads the standard "Add/Remove Programs" registry locations and diffs
against the previous scan to detect installs/uninstalls.
"""

import threading

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.software")

try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:
    _WINREG_AVAILABLE = False

_UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE if _WINREG_AVAILABLE else None,
     r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE if _WINREG_AVAILABLE else None,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER if _WINREG_AVAILABLE else None,
     r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]

_previous = {}  # display_name -> (version, publisher, install_date)


def _read_key_value(key, name, default=None):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return default


def _scan() -> dict:
    entries = {}
    for hive, path in _UNINSTALL_KEYS:
        try:
            with winreg.OpenKey(hive, path) as root:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root, subkey_name) as sk:
                            name = _read_key_value(sk, "DisplayName")
                            if not name:
                                continue
                            entries[name] = (
                                _read_key_value(sk, "DisplayVersion"),
                                _read_key_value(sk, "Publisher"),
                                _read_key_value(sk, "InstallDate"),
                            )
                    except OSError:
                        continue
        except FileNotFoundError:
            continue
        except Exception:
            log.exception("Failed scanning uninstall key %s", path)
    return entries


def _cycle():
    current = _scan()
    now = db.now_iso()

    added = set(current.keys()) - set(_previous.keys())
    removed = set(_previous.keys()) - set(current.keys())

    for name in added:
        version, publisher, install_date = current[name]
        db.insert("installed_software", {
            "timestamp": now, "name": name, "version": version,
            "publisher": publisher, "install_date": install_date, "action": "installed",
        })
        if _previous:
            db.insert_alert(
                category="software_installed",
                severity="LOW",
                message=f"New software installed: {name} ({version or 'unknown version'})",
                reason=(
                    "Logged as LOW severity because installing software is routine — this is "
                    "informational so you have a record of what changed, not a signal that anything "
                    "is wrong. Worth a look mainly if you don't remember installing it."
                ),
                source_table="installed_software",
                dedup_key=f"software_installed:{name}",
            )

    for name in removed:
        version, publisher, install_date = _previous[name]
        db.insert("installed_software", {
            "timestamp": now, "name": name, "version": version,
            "publisher": publisher, "install_date": install_date, "action": "removed",
        })

    _previous.clear()
    _previous.update(current)


def run_forever(stop_event: threading.Event):
    if not config.IS_WINDOWS or not _WINREG_AVAILABLE:
        log.info("Software monitor skipped — not running on Windows")
        return
    log.info("Installed software monitor started (interval=%ss)", config.INTERVAL_SOFTWARE)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Software monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_SOFTWARE)
