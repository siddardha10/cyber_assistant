"""
commands/executor.py

Runs validated commands and logs every execution to the database.
This is the ONLY place in the entire app that calls subprocess.

Security invariants:
  1. Only accepts pre-validated command_parts from translator.py (which got
     them from templates.py's build_command).
  2. DESTRUCTIVE commands refuse to run unless `confirmed=True`.
  3. Every execution is logged with full context to `command_logs`.
  4. Subprocess runs with `shell=False` — no shell interpretation of params.
  5. Output is captured and truncated to prevent memory issues.

Network-command handling:
  - Templates tagged with is_network=True have per-template timeouts.
  - Failures distinguish "timed out", "unreachable", "invalid host", "DNS
    resolution failed" rather than a generic error.
"""

import re
import subprocess
from pathlib import Path
from db import database as db
from commands.templates import TEMPLATES
from utils.logger import get_logger

log = get_logger("commands.executor")

# Maximum output size we'll capture (prevent runaway stdout from eating RAM)
_MAX_OUTPUT_BYTES = 50_000
_DEFAULT_TIMEOUT = 45


def _classify_network_failure(
    template_id: str,
    stdout: str,
    stderr: str,
    timed_out: bool,
) -> str:
    """
    For network commands, produce a specific human-readable failure reason
    instead of a generic error. Returns None if the output doesn't match
    a known failure pattern (fallthrough to stderr).
    """
    combined = (stdout + " " + stderr).lower()

    if timed_out:
        return f"Command timed out — the remote host did not respond within the allowed time."

    # ── ping ──
    if template_id == "ping":
        if "could not find host" in combined or "ping request could not find" in combined:
            return "DNS resolution failed — the hostname could not be resolved. Check spelling."
        if "request timed out" in combined or "100% loss" in combined:
            return "Host is unreachable — all ping packets were lost (100% packet loss)."
        if "destination host unreachable" in combined:
            return "Destination host unreachable — no route to the target from this network."
        if "general failure" in combined:
            return "Network general failure — check that your network adapter is connected."

    # ── tracert ──
    if template_id == "tracert":
        if "unable to resolve" in combined or "could not find host" in combined:
            return "DNS resolution failed — the hostname could not be resolved. Check spelling."
        if "request timed out" in combined and "unable to resolve" not in combined:
            # tracert shows * * * for timed-out hops — that's normal; only flag
            # if literally every hop timed out (likely unreachable)
            timeout_hops = combined.count("request timed out")
            if timeout_hops >= 5:
                return (
                    f"Host appears unreachable — {timeout_hops} consecutive hops timed out. "
                    f"The trace could not reach the destination."
                )

    # ── nslookup ──
    if template_id == "nslookup":
        if "non-existent domain" in combined or "can't find" in combined:
            return "DNS lookup failed — the domain does not exist (NXDOMAIN)."
        if "request timed out" in combined or "dns request timed out" in combined:
            return "DNS server did not respond — the lookup timed out."
        if "server failed" in combined:
            return "DNS server returned an error — SERVFAIL."

    return None


def execute(
    template_id: str,
    tier: str,
    params: dict,
    command_parts: list[str],
    display_command: str,
    natural_input: str,
    confirmed: bool = False,
) -> dict:
    """
    Execute a pre-validated command.

    Returns:
        {
            "executed": True/False,
            "stdout": str,
            "stderr": str,
            "exit_code": int or None,
            "success": bool,
            "error": str or None,
            "failure_reason": str or None (specific reason for network failures),
            "command_log_id": int (DB row ID for this execution),
        }
    """
    # DESTRUCTIVE commands MUST be confirmed — no exceptions
    if tier == "DESTRUCTIVE" and not confirmed:
        log.warning("Blocked unconfirmed DESTRUCTIVE command: %s", display_command)
        # Still log the attempt (confirmed=0)
        log_id = db.insert("command_logs", {
            "timestamp": db.now_iso(),
            "natural_input": natural_input,
            "translated_command": display_command,
            "template_id": template_id,
            "tier": tier,
            "confirmed": 0,
            "stdout": None,
            "stderr": None,
            "exit_code": None,
            "success": 0,
        })
        return {
            "executed": False,
            "stdout": None,
            "stderr": None,
            "exit_code": None,
            "success": False,
            "error": "This is a DESTRUCTIVE command. Explicit confirmation required before execution.",
            "failure_reason": None,
            "command_log_id": log_id,
        }

    # Determine timeout: per-template override → default
    template = TEMPLATES.get(template_id, {})
    timeout = template.get("timeout_seconds", _DEFAULT_TIMEOUT)
    is_network = template.get("is_network", False)
    timed_out = False

    # Use native filesystem APIs for these paths so spaces and shell parsing
    # cannot redirect an operation away from the requested location.
    try:
        if template_id == "list_directory":
            directory = Path(params["path"]).expanduser()
            entries = sorted(directory.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
            stdout = "\n".join(item.name for item in entries)[:_MAX_OUTPUT_BYTES]
            stderr, exit_code, success = "", 0, True
        elif template_id == "create_directory":
            directory = Path(params["path"]).expanduser()
            directory.mkdir(parents=True, exist_ok=False)
            stdout = f"Created directory: {directory}"
            stderr, exit_code, success = "", 0, True
        elif template_id == "create_file":
            file_path = Path(params["path"]).expanduser()
            with file_path.open("x", encoding="utf-8", newline="") as file:
                file.write(params["content"])
            stdout = f"Created file: {file_path}"
            stderr, exit_code, success = "", 0, True
        else:
            log.info("Executing [%s] %s: %s (timeout=%ds)", tier, template_id, display_command, timeout)
            result = subprocess.run(
                command_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = (result.stdout or "")[:_MAX_OUTPUT_BYTES]
            stderr = (result.stderr or "")[:_MAX_OUTPUT_BYTES]
            exit_code = result.returncode
            success = exit_code == 0

    except subprocess.TimeoutExpired:
        timed_out = True
        log.warning("Command timed out after %ds: %s", timeout, display_command)
        stdout = ""
        stderr = f"Command timed out after {timeout} seconds."
        exit_code = -1
        success = False

    except FileExistsError as e:
        log.warning("Refusing to overwrite existing file: %s", e.filename)
        stdout, stderr, exit_code, success = "", f"File already exists: {e.filename}", -1, False

    except FileNotFoundError as e:
        log.warning("Command not found: %s — %s", display_command, e)
        stdout, stderr, exit_code, success = "", f"Command not found: {e}", -1, False

    except Exception as e:
        log.exception("Unexpected error executing command: %s", display_command)
        stdout, stderr, exit_code, success = "", f"Execution error: {e}", -1, False

    # For network commands, classify the failure specifically
    failure_reason = None
    if is_network and not success:
        failure_reason = _classify_network_failure(template_id, stdout, stderr, timed_out)

    # Log every execution to the database
    log_id = db.insert("command_logs", {
        "timestamp": db.now_iso(),
        "natural_input": natural_input,
        "translated_command": display_command,
        "template_id": template_id,
        "tier": tier,
        "confirmed": 1 if confirmed else 0,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "success": 1 if success else 0,
    })

    return {
        "executed": True,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "success": success,
        "error": (failure_reason or stderr) if not success else None,
        "failure_reason": failure_reason,
        "command_log_id": log_id,
    }
