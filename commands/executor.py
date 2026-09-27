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
"""

import subprocess
from db import database as db
from utils.logger import get_logger

log = get_logger("commands.executor")

# Maximum output size we'll capture (prevent runaway stdout from eating RAM)
_MAX_OUTPUT_BYTES = 50_000
_TIMEOUT_SECONDS = 45


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
            "command_log_id": log_id,
        }

    # Execute the command
    try:
        log.info("Executing [%s] %s: %s", tier, template_id, display_command)
        result = subprocess.run(
            command_parts,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            # shell=False is the default — command_parts is a list, not a string
            # This prevents shell interpretation of any parameter values
        )
        stdout = (result.stdout or "")[:_MAX_OUTPUT_BYTES]
        stderr = (result.stderr or "")[:_MAX_OUTPUT_BYTES]
        exit_code = result.returncode
        success = exit_code == 0

    except subprocess.TimeoutExpired:
        log.warning("Command timed out after %ds: %s", _TIMEOUT_SECONDS, display_command)
        stdout, stderr, exit_code, success = "", f"Command timed out after {_TIMEOUT_SECONDS} seconds.", -1, False

    except FileNotFoundError as e:
        log.warning("Command not found: %s — %s", display_command, e)
        stdout, stderr, exit_code, success = "", f"Command not found: {e}", -1, False

    except Exception as e:
        log.exception("Unexpected error executing command: %s", display_command)
        stdout, stderr, exit_code, success = "", f"Execution error: {e}", -1, False

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
        "error": stderr if not success else None,
        "command_log_id": log_id,
    }
