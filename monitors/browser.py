"""
monitors/browser.py

Reads download history directly from each browser's local SQLite database.

IMPORTANT BUG FIX vs. the original project brief: Chrome/Edge lock their
`History` file with an exclusive lock while the browser process is running,
so opening it directly will raise "database is locked". We copy it to a
temp file first and query the copy — this is the standard workaround and
the only reliable one without shelling out to the browser itself.
"""

import shutil
import sqlite3
import tempfile
import threading
from pathlib import Path

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.browser")

_seen_ids = {"chrome": set(), "edge": set(), "brave": set(), "opera": set(), "firefox": set()}

# Tracks which browsers have completed their first scan. On that first scan,
# every pre-existing download in history looks "new" (it isn't in _seen_ids
# yet) — without this guard, a machine with months of download history would
# have its ENTIRE backlog alerted as "risky" in one burst the moment the
# daemon starts, which is exactly what happened previously (140 of ~200
# alerts in one existing database turned out to be this). We still WANT the
# backlog stored in `downloads` (it's useful history to query), just not
# treated as a fresh security event.
_baseline_done = {"chrome": False, "edge": False, "brave": False, "opera": False, "firefox": False}

# ── Chromium-family browser User Data directories ──
_CHROMIUM_BROWSERS = {
    "chrome": Path.home() / "AppData/Local/Google/Chrome/User Data",
    "edge":   Path.home() / "AppData/Local/Microsoft/Edge/User Data",
    "brave":  Path.home() / "AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "opera":  Path.home() / "AppData/Roaming/Opera Software/Opera Stable",
}
_FIREFOX_PROFILES_DIR = Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles"

_logged_missing = set()   # avoids spamming "not found" every cycle


def _copy_and_query(db_path: Path, query: str):
    if not db_path.exists():
        return []
    # Use full parent path in temp name to avoid collisions between profiles
    safe_name = db_path.parent.as_posix().replace("/", "_").replace(":", "")
    tmp_path = Path(tempfile.gettempdir()) / f"cybersentinel_{safe_name}_{db_path.name}.tmp"
    try:
        shutil.copy2(db_path, tmp_path)
    except (PermissionError, OSError) as e:
        log.debug("Could not copy %s: %s", db_path, e)
        return []

    rows = []
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(query).fetchall()]
        conn.close()
    except sqlite3.Error as e:
        log.debug("Query failed against %s copy: %s", db_path, e)
    finally:
        tmp_path.unlink(missing_ok=True)
    return rows


def _find_chromium_profiles(user_data_dir: Path):
    """Return all profile directories that contain a History file."""
    if not user_data_dir.exists():
        return []
    profiles = []
    # Chrome/Edge/Brave: profiles live in Default, Profile 1, Profile 2, …
    for child in user_data_dir.iterdir():
        history = child / "History"
        if child.is_dir() and history.exists():
            profiles.append(history)
    # Opera keeps History directly in the user data dir
    top_level = user_data_dir / "History"
    if top_level.exists() and top_level not in profiles:
        profiles.append(top_level)
    return profiles


def _chrome_family_downloads(browser_key: str, history_path: Path):
    """Read downloads from a single Chromium profile's History DB."""
    profile_name = history_path.parent.name   # e.g. "Default", "Profile 1"
    query = """
        SELECT d.id, d.target_path, d.received_bytes, d.start_time,
               (SELECT url FROM downloads_url_chains WHERE downloads_url_chains.id = d.id ORDER BY chain_index DESC LIMIT 1) AS url
        FROM downloads d
        ORDER BY d.start_time DESC
        LIMIT 25
    """
    rows = _copy_and_query(history_path, query)
    # Use composite key (profile_name, id) to avoid collisions across profiles
    new_rows = [r for r in rows if (profile_name, r["id"]) not in _seen_ids[browser_key]]
    if new_rows:
        log.info("Browser '%s' profile '%s': found %d new download(s)", browser_key, profile_name, len(new_rows))
    is_baseline = not _baseline_done[browser_key]
    for r in new_rows:
        db.insert("downloads", {
            "timestamp": db.now_iso(),
            "browser": browser_key,
            "filename": Path(r["target_path"] or "").name,
            "url": r.get("url"),
            "filesize": r.get("received_bytes"),
            "target_path": r.get("target_path"),
        })
        if not is_baseline:
            _flag_if_risky(r.get("target_path") or "", browser_key)
        _seen_ids[browser_key].add((profile_name, r["id"]))


def _scan_chromium_browser(browser_key: str, user_data_dir: Path):
    """Scan all profiles for a Chromium-family browser."""
    if not user_data_dir.exists():
        if browser_key not in _logged_missing:
            log.info("Browser '%s' not found at %s — skipping", browser_key, user_data_dir)
            _logged_missing.add(browser_key)
        return
    profiles = _find_chromium_profiles(user_data_dir)
    if profiles and browser_key in _logged_missing:
        _logged_missing.discard(browser_key)
    if profiles:
        log.info("Browser '%s': scanning %d profile(s)", browser_key, len(profiles))
    for history_path in profiles:
        _chrome_family_downloads(browser_key, history_path)
    _baseline_done[browser_key] = True


def _firefox_downloads():
    if not _FIREFOX_PROFILES_DIR.exists():
        if "firefox" not in _logged_missing:
            log.info("Firefox not found at %s — skipping", _FIREFOX_PROFILES_DIR)
            _logged_missing.add("firefox")
        return
    for profile_dir in _FIREFOX_PROFILES_DIR.glob("*"):
        places = profile_dir / "places.sqlite"
        if not places.exists():
            continue
        # Firefox stores download destinations as an annotation on the place.
        query = """
            SELECT p.id, p.url, a.content AS dest_path, p.last_visit_date
            FROM moz_places p
            JOIN moz_annos a ON a.place_id = p.id
            JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id
            WHERE attr.name = 'downloads/destinationFileURI'
            ORDER BY p.last_visit_date DESC
            LIMIT 25
        """
        rows = _copy_and_query(places, query)
        new_rows = [r for r in rows if r["id"] not in _seen_ids["firefox"]]
        is_baseline = not _baseline_done["firefox"]
        for r in new_rows:
            filename = Path(r.get("dest_path") or "").name
            db.insert("downloads", {
                "timestamp": db.now_iso(),
                "browser": "firefox",
                "filename": filename,
                "url": r.get("url"),
                "filesize": None,
                "target_path": r.get("dest_path"),
            })
            if not is_baseline:
                _flag_if_risky(filename, "firefox")
            _seen_ids["firefox"].add(r["id"])
    _baseline_done["firefox"] = True


_RISKY_EXTENSIONS = (".exe", ".msi", ".bat", ".ps1", ".vbs", ".scr", ".jar", ".apk")


def _flag_if_risky(path_or_name: str, browser_key: str):
    lower = path_or_name.lower()
    ext = next((e for e in _RISKY_EXTENSIONS if lower.endswith(e)), None)
    if ext:
        db.insert_alert(
            category="risky_download",
            severity="MEDIUM",
            message=f"{path_or_name} downloaded via {browser_key}",
            reason=(
                f"'{ext}' files can run code directly on your machine, which is why they're the most "
                "common way malware gets installed. This isn't necessarily malicious — installers you "
                "meant to download look identical — but it's worth a second glance if you don't "
                "recognize it."
            ),
            source_table="downloads",
            # dedup on the exact file, not just the category — re-downloading the same
            # installer twice within the window shouldn't create two separate alerts.
            dedup_key=f"risky_download:{lower}",
        )


def _cycle():
    for browser_key, user_data_dir in _CHROMIUM_BROWSERS.items():
        _scan_chromium_browser(browser_key, user_data_dir)
    _firefox_downloads()


def run_forever(stop_event: threading.Event):
    log.info("Browser monitor started (interval=%ss)", config.INTERVAL_BROWSER)
    while not stop_event.is_set():
        try:
            _cycle()
        except Exception:
            log.exception("Browser monitor cycle failed — continuing")
        stop_event.wait(config.INTERVAL_BROWSER)
