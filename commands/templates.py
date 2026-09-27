"""
commands/templates.py

The command template whitelist — the core safety mechanism for Goal 2.
Every system command the assistant can execute must map to a template here.
No raw shell strings are ever constructed from user/LLM output.

Each template specifies:
  - id: unique identifier (used in LLM ↔ executor communication)
  - tier: SAFE (read-only) or DESTRUCTIVE (modifies state)
  - cmd: list of command parts with {param} placeholders
  - params: ordered list of parameter names
  - description: human-readable (shown to user + fed to translator LLM)
  - validators: optional dict of param_name → validator function

Adding new command coverage = adding an entry to TEMPLATES. No restructuring.

SECURITY INVARIANTS:
  1. Shell metacharacters (;  &&  ||  |  `  $( )  >  <  &) are stripped
     from ALL parameter values before substitution — no exceptions.
  2. Parameters are validated per-template before the command is built.
  3. subprocess.run is called with shell=False where possible.
"""

import os
import re
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# Parameter validators
# ═══════════════════════════════════════════════════════════════════

# Characters that could chain/redirect commands — rejected in ALL params
_SHELL_META = re.compile(r'[;&|`$><\n\r]')
# Double-ampersand and double-pipe as explicit patterns
_CHAIN_PATTERNS = re.compile(r'&&|\|\|')


def sanitize_param(value: str) -> str:
    """Strip shell metacharacters from any parameter value.
    Raises ValueError if dangerous patterns are detected."""
    if _CHAIN_PATTERNS.search(value):
        raise ValueError(f"Rejected: command chaining detected in parameter: {value!r}")
    if _SHELL_META.search(value):
        raise ValueError(f"Rejected: shell metacharacter in parameter: {value!r}")
    return value.strip()


def validate_path(value: str) -> str:
    """Validate a filesystem path parameter."""
    value = sanitize_param(value)
    # Normalize and resolve — but don't require existence (user may be creating)
    # Just ensure it looks like a real path, not injection
    if not value:
        raise ValueError("Path parameter cannot be empty")
    return value


def validate_name(value: str) -> str:
    """Validate a process/service/host name."""
    value = sanitize_param(value)
    if not value:
        raise ValueError("Name parameter cannot be empty")
    if len(value) > 260:
        raise ValueError("Name parameter too long")
    return value


def validate_integer(value: str) -> str:
    """Validate an integer parameter (PID, port, count, etc.)."""
    value = sanitize_param(value)
    if not value.isdigit():
        raise ValueError(f"Expected integer, got: {value!r}")
    return value


def validate_hostname(value: str) -> str:
    """Validate a hostname/IP for network commands."""
    value = sanitize_param(value)
    if not re.match(r'^[a-zA-Z0-9._:-]+$', value):
        raise ValueError(f"Invalid hostname: {value!r}")
    return value


def validate_search_term(value: str) -> str:
    """Validate a search string (for findstr, etc.)."""
    value = sanitize_param(value)
    if not value:
        raise ValueError("Search term cannot be empty")
    return value


def validate_env_var(value: str) -> str:
    """Validate an environment variable name."""
    value = sanitize_param(value)
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', value):
        raise ValueError(f"Invalid environment variable name: {value!r}")
    return value


def validate_service_action(value: str) -> str:
    """Validate a service action (start/stop)."""
    value = sanitize_param(value).lower()
    if value not in ("start", "stop"):
        raise ValueError(f"Service action must be 'start' or 'stop', got: {value!r}")
    return value


# ═══════════════════════════════════════════════════════════════════
# Template definitions
# ═══════════════════════════════════════════════════════════════════

TEMPLATES = {
    # ─── File/Folder Operations ─── SAFE ──────────────────────────
    "list_directory": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "dir", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "List files and folders in a directory",
    },
    "list_directory_recursive": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "dir", "/s", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Recursively list all files under a directory",
    },
    "tree_directory": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tree", "/f", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Show directory tree structure with files",
    },
    "view_file": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "type", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Display the contents of a text file",
    },
    "search_in_files": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "findstr", "/s", "/i", "{term}", "{path}"],
        "params": ["term", "path"],
        "validators": {"term": validate_search_term, "path": validate_path},
        "description": "Search for a text string inside files",
    },
    "find_file": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "where", "/r", "{path}", "{name}"],
        "params": ["path", "name"],
        "validators": {"path": validate_path, "name": validate_name},
        "description": "Find a file by name under a directory",
    },
    "file_attributes": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "attrib", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Show file attributes (read-only, hidden, system, archive)",
    },

    # ─── File/Folder Operations ─── DESTRUCTIVE ──────────────────
    "create_directory": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "mkdir", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Create a new directory (folder)",
    },
    "delete_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "del", "/p", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Delete a file",
    },
    "delete_directory": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "rmdir", "/s", "/q", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Delete a directory and all its contents",
    },
    "copy_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "copy", "{source}", "{dest}"],
        "params": ["source", "dest"],
        "validators": {"source": validate_path, "dest": validate_path},
        "description": "Copy a file to a new location",
    },
    "move_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "move", "{source}", "{dest}"],
        "params": ["source", "dest"],
        "validators": {"source": validate_path, "dest": validate_path},
        "description": "Move a file or folder to a new location",
    },
    "rename_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "ren", "{path}", "{new_name}"],
        "params": ["path", "new_name"],
        "validators": {"path": validate_path, "new_name": validate_name},
        "description": "Rename a file or folder",
    },

    # ─── System Info ─── SAFE ─────────────────────────────────────
    "hostname": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "hostname"],
        "params": [],
        "validators": {},
        "description": "Show the computer's hostname",
    },
    "whoami": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "whoami"],
        "params": [],
        "validators": {},
        "description": "Show the current logged-in user",
    },
    "systeminfo": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "systeminfo"],
        "params": [],
        "validators": {},
        "description": "Show detailed system information (OS, hardware, uptime, etc.)",
    },
    "os_version": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "ver"],
        "params": [],
        "validators": {},
        "description": "Show the Windows version",
    },
    "env_variable": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "echo", "%{var}%"],
        "params": ["var"],
        "validators": {"var": validate_env_var},
        "description": "Show the value of an environment variable",
    },
    "all_env_variables": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "set"],
        "params": [],
        "validators": {},
        "description": "List all environment variables",
    },

    # ─── Process Management ─── SAFE ──────────────────────────────
    "list_processes": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tasklist"],
        "params": [],
        "validators": {},
        "description": "List all running processes",
    },
    "list_processes_verbose": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tasklist", "/v"],
        "params": [],
        "validators": {},
        "description": "List all running processes with detailed info (memory, status, CPU time)",
    },
    "find_process": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tasklist", "/fi", "IMAGENAME eq {name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Find a specific process by name",
    },

    # ─── Process Management ─── DESTRUCTIVE ──────────────────────
    "kill_process_by_name": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "taskkill", "/im", "{name}", "/f"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Force kill a process by its name",
    },
    "kill_process_by_pid": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "taskkill", "/pid", "{pid}", "/f"],
        "params": ["pid"],
        "validators": {"pid": validate_integer},
        "description": "Force kill a process by its PID",
    },

    # ─── Service Management ─── SAFE ─────────────────────────────
    "list_services": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "sc", "query", "type=", "service", "state=", "all"],
        "params": [],
        "validators": {},
        "description": "List all Windows services and their status",
    },
    "query_service": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "sc", "query", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Check the status of a specific Windows service",
    },

    # ─── Service Management ─── DESTRUCTIVE ──────────────────────
    "start_service": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "net", "start", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Start a Windows service",
    },
    "stop_service": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "net", "stop", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Stop a Windows service",
    },

    # ─── Network Diagnostics ─── SAFE ────────────────────────────
    "ping": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "ping", "-n", "4", "{host}"],
        "params": ["host"],
        "validators": {"host": validate_hostname},
        "description": "Ping a host to check connectivity (4 packets)",
    },
    "ipconfig": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "ipconfig", "/all"],
        "params": [],
        "validators": {},
        "description": "Show all network adapter configuration (IP, gateway, DNS)",
    },
    "tracert": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tracert", "-d", "{host}"],
        "params": ["host"],
        "validators": {"host": validate_hostname},
        "description": "Trace the network route to a host",
    },
    "nslookup": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "nslookup", "{host}"],
        "params": ["host"],
        "validators": {"host": validate_hostname},
        "description": "Look up the DNS record for a hostname",
    },
    "netstat": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "netstat", "-ano"],
        "params": [],
        "validators": {},
        "description": "Show all active network connections and listening ports with PIDs",
    },
    "arp_table": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "arp", "-a"],
        "params": [],
        "validators": {},
        "description": "Show the ARP cache (IP-to-MAC mappings on the local network)",
    },
    "route_table": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "route", "print"],
        "params": [],
        "validators": {},
        "description": "Show the IP routing table",
    },
    "flush_dns": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "ipconfig", "/flushdns"],
        "params": [],
        "validators": {},
        "description": "Flush the DNS resolver cache",
    },

    # ─── Disk Info ─── SAFE ───────────────────────────────────────
    "disk_info": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "wmic", "logicaldisk", "get", "name,size,freespace,filesystem,volumename"],
        "params": [],
        "validators": {},
        "description": "Show disk drives with size, free space, and filesystem type",
    },
    "disk_usage_dir": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "dir", "/s", "/a", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Calculate total size of a directory",
    },

    # ─── Scheduled Tasks ─── SAFE ────────────────────────────────
    "list_scheduled_tasks": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "schtasks", "/query", "/fo", "TABLE"],
        "params": [],
        "validators": {},
        "description": "List all scheduled tasks",
    },
    "query_scheduled_task": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "schtasks", "/query", "/tn", "{name}", "/v", "/fo", "LIST"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Show details of a specific scheduled task",
    },

    # ─── Startup Programs ─── SAFE ───────────────────────────────
    "list_startup_programs": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "wmic", "startup", "get", "name,command,location"],
        "params": [],
        "validators": {},
        "description": "List programs that run at Windows startup",
    },

    # ─── Network Share & User Info ─── SAFE ──────────────────────
    "net_users": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "net", "user"],
        "params": [],
        "validators": {},
        "description": "List all local user accounts",
    },
    "net_user_detail": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "net", "user", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Show detailed information about a local user account",
    },
    "net_shares": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "net", "share"],
        "params": [],
        "validators": {},
        "description": "List all network shares on this machine",
    },

    # ─── Power / Shutdown ─── DESTRUCTIVE ────────────────────────
    "shutdown": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "shutdown", "/s", "/t", "30"],
        "params": [],
        "validators": {},
        "description": "Shut down the computer (30 second delay)",
    },
    "restart": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "shutdown", "/r", "/t", "30"],
        "params": [],
        "validators": {},
        "description": "Restart the computer (30 second delay)",
    },
    "cancel_shutdown": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "shutdown", "/a"],
        "params": [],
        "validators": {},
        "description": "Cancel a pending shutdown or restart",
    },

    # ─── Battery / Power ─── SAFE ────────────────────────────────
    "battery_status": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "WMIC", "PATH", "Win32_Battery", "Get", "BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,Status"],
        "params": [],
        "validators": {},
        "description": "Show current battery status, charge percentage, and estimated run time",
    },
    "battery_report": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/batteryreport", "/output", "%TEMP%\\battery-report.html"],
        "params": [],
        "validators": {},
        "description": "Generate a detailed battery health report (saved as HTML)",
    },
    "power_scheme": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/getactivescheme"],
        "params": [],
        "validators": {},
        "description": "Show the currently active power plan/scheme",
    },
    "power_schemes_list": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/list"],
        "params": [],
        "validators": {},
        "description": "List all available power plans/schemes",
    },
    "system_power_state": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/systempowerreport", "/output", "%TEMP%\\power-report.html"],
        "params": [],
        "validators": {},
        "description": "Generate a system power/sleep diagnostics report (saved as HTML)",
    },
}


def get_template(template_id: str) -> dict | None:
    """Look up a template by ID. Returns None if not found."""
    return TEMPLATES.get(template_id)


def build_command(template_id: str, params: dict) -> list[str]:
    """
    Build a validated command list from a template + params.
    Raises ValueError if the template doesn't exist or params fail validation.
    """
    template = TEMPLATES.get(template_id)
    if not template:
        raise ValueError(f"Unknown command template: {template_id}")

    # Validate every expected param
    validated = {}
    for pname in template["params"]:
        raw = params.get(pname)
        if raw is None:
            raise ValueError(f"Missing required parameter: {pname}")
        validator = template["validators"].get(pname, sanitize_param)
        validated[pname] = validator(str(raw))

    # Build the command list with validated params substituted
    cmd_parts = []
    for part in template["cmd"]:
        for pname, pval in validated.items():
            part = part.replace("{" + pname + "}", pval)
        cmd_parts.append(part)

    return cmd_parts


def display_command(template_id: str, params: dict) -> str:
    """
    Build a human-readable command string for display purposes.
    Shows exactly what will run — the user sees this before execution.
    """
    parts = build_command(template_id, params)
    # Skip 'cmd /c' prefix for cleaner display
    display_parts = parts[2:] if len(parts) > 2 and parts[:2] == ["cmd", "/c"] else parts
    # Quote parts containing spaces
    return " ".join(f'"{p}"' if " " in p else p for p in display_parts)


def get_template_catalog_for_llm() -> str:
    """
    Produce a compact text catalog of all templates, suitable for including
    in the LLM system prompt so it knows what commands are available.
    """
    lines = []
    for tid, t in TEMPLATES.items():
        params_str = ", ".join(t["params"]) if t["params"] else "(no params)"
        lines.append(f"  {tid} [{t['tier']}] — {t['description']} — params: {params_str}")
    return "\n".join(lines)
