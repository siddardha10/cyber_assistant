"""
config.py
Central configuration for CyberSentinel.
Reads from a .env file if present (via python-dotenv), falls back to sane defaults.
Never hardcode secrets here — everything sensitive comes from environment variables.
"""

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv is optional. If missing, we just rely on real env vars.
    pass

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_PATH = os.getenv("CS_DB_PATH", str(BASE_DIR / "data" / "cybersentinel.db"))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Monitor intervals (seconds)
# ---------------------------------------------------------------------------
INTERVAL_PROCESSES = int(os.getenv("CS_INTERVAL_PROCESSES", "30"))
INTERVAL_PORTS = int(os.getenv("CS_INTERVAL_PORTS", "30"))
INTERVAL_LOGINS = int(os.getenv("CS_INTERVAL_LOGINS", "60"))
INTERVAL_BROWSER = int(os.getenv("CS_INTERVAL_BROWSER", "120"))
INTERVAL_STARTUP = int(os.getenv("CS_INTERVAL_STARTUP", "300"))
INTERVAL_SERVICES = int(os.getenv("CS_INTERVAL_SERVICES", "300"))
INTERVAL_SOFTWARE = int(os.getenv("CS_INTERVAL_SOFTWARE", "600"))
INTERVAL_SCHEDULED_TASKS = int(os.getenv("CS_INTERVAL_SCHEDULED_TASKS", "600"))
INTERVAL_HEALTH = int(os.getenv("CS_INTERVAL_HEALTH", "15"))
INTERVAL_USB_POLL = int(os.getenv("CS_INTERVAL_USB_POLL", "5"))  # only used as WMI watcher fallback

# ---------------------------------------------------------------------------
# Feature toggles
# ---------------------------------------------------------------------------
ENABLE_NETWORK_SNIFFER = os.getenv("CS_ENABLE_SNIFFER", "false").lower() == "true"
ENABLE_FILESYSTEM_WATCH = os.getenv("CS_ENABLE_FS_WATCH", "true").lower() == "true"
ENABLE_DESKTOP_NOTIFICATIONS = os.getenv("CS_ENABLE_NOTIFY", "true").lower() == "true"

FS_WATCH_PATHS = [
    p for p in os.getenv(
        "CS_FS_WATCH_PATHS",
        str(Path.home() / "Downloads") + "," + str(Path.home() / "Desktop")
    ).split(",") if p.strip()
]

# ---------------------------------------------------------------------------
# LLM (Ollama — local OpenAI-compatible endpoint)
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL = os.getenv("CS_OLLAMA_BASE_URL", "http://localhost:11434/v1/chat/completions")
LLM_MODEL = os.getenv("CS_LLM_MODEL", "qwen2.5:3b")
LLM_ENABLED = os.getenv("CS_LLM_ENABLED", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Alert thresholds
# ---------------------------------------------------------------------------
CPU_SPIKE_THRESHOLD_PCT = float(os.getenv("CS_CPU_SPIKE_PCT", "50"))
CPU_SPIKE_BASELINE_MULTIPLIER = float(os.getenv("CS_CPU_BASELINE_MULT", "4"))
FAILED_LOGIN_ALERT_COUNT = int(os.getenv("CS_FAILED_LOGIN_COUNT", "3"))
FAILED_LOGIN_WINDOW_MIN = int(os.getenv("CS_FAILED_LOGIN_WINDOW_MIN", "15"))
PORT_SCAN_PORT_COUNT = int(os.getenv("CS_PORT_SCAN_COUNT", "5"))
PORT_SCAN_WINDOW_SEC = int(os.getenv("CS_PORT_SCAN_WINDOW_SEC", "3"))

# A repeated alert with the same dedup_key within this window is folded into
# the existing row (occurrence_count++) instead of creating a new one.
ALERT_DEDUP_WINDOW_MIN = int(os.getenv("CS_ALERT_DEDUP_WINDOW_MIN", "15"))

# ---------------------------------------------------------------------------
# API server
# ---------------------------------------------------------------------------
API_HOST = os.getenv("CS_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("CS_API_PORT", "5055"))

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
IS_WINDOWS = sys.platform.startswith("win")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_DIR = os.getenv("CS_LOG_DIR", str(BASE_DIR / "logs"))
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
LOG_LEVEL = os.getenv("CS_LOG_LEVEL", "INFO")
