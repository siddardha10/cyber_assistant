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
  - example_phrasings: natural-language examples for the catalog / LLM prompt
  - timeout_seconds: per-command timeout (defaults to 45)
  - is_network: True for commands that hit the network (UI shows "running…")

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


def validate_file_content(value: str) -> str:
    """Accept literal text content without treating it as a shell parameter."""
    if len(value) > 1_000_000:
        raise ValueError("File content cannot exceed 1,000,000 characters")
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
        "description": "List files and folders in a directory (dir)",
        "example_phrasings": [
            "list files in my Downloads folder",
            "show what's in C:\\Users",
            "dir my Desktop",
            "what files are in this folder",
            "list contents of a folder",
        ],
    },
    "list_directory_recursive": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "dir", "/s", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Recursively list all files under a directory",
        "example_phrasings": [
            "list all files recursively in Downloads",
            "show every file under C:\\Projects",
        ],
    },
    "change_directory": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "cd", "/d", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Change the current working directory (cd)",
        "example_phrasings": [
            "change directory to C:\\Users",
            "cd to my Documents folder",
            "go to C:\\Windows",
            "navigate to Desktop",
        ],
    },
    "tree_directory": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tree", "/f", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Show directory tree structure with files (tree)",
        "example_phrasings": [
            "show folder structure of C:\\Projects",
            "tree my Downloads",
            "show directory tree",
            "display folder hierarchy",
        ],
    },
    "view_file": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "type", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Display the contents of a text file (type)",
        "example_phrasings": [
            "show contents of readme.txt",
            "type C:\\config.ini",
            "view file contents",
            "cat this file",
            "read the file",
        ],
    },
    "search_in_files": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "findstr", "/s", "/i", "{term}", "{path}"],
        "params": ["term", "path"],
        "validators": {"term": validate_search_term, "path": validate_path},
        "description": "Search for a text string inside files (findstr)",
        "example_phrasings": [
            "search for 'password' in C:\\logs",
            "find text 'error' inside files",
            "findstr config in my project",
            "grep for TODO in source files",
        ],
    },
    "find_file": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "where", "/r", "{path}", "{name}"],
        "params": ["path", "name"],
        "validators": {"path": validate_path, "name": validate_name},
        "description": "Find a file by name under a directory",
        "example_phrasings": [
            "find readme.txt in C:\\Projects",
            "search for a file named config.yaml",
            "where is setup.exe",
        ],
    },
    "file_attributes": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "attrib", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Show file attributes (read-only, hidden, system, archive)",
        "example_phrasings": [
            "show attributes of this file",
            "is this file read-only",
            "check file attributes",
        ],
    },

    # ─── File/Folder Operations ─── DESTRUCTIVE ──────────────────
    "create_directory": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "mkdir", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Create a new directory / folder (mkdir)",
        "example_phrasings": [
            "create a folder called test",
            "mkdir new_project",
            "make a new directory",
            "create folder C:\\backup",
        ],
    },
    "create_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["file", "create", "{path}"],
        "params": ["path", "content"],
        "validators": {"path": validate_path, "content": validate_file_content},
        "description": "Create a new UTF-8 text file without overwriting an existing file",
        "example_phrasings": [
            "create a file named notes.txt in my Documents folder",
            "create report.json at C:\\temp with content {\"ok\": true}",
            "make a new .md file containing these notes",
        ],
    },
    "remove_empty_directory": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "rmdir", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Remove an empty directory (rmdir)",
        "example_phrasings": [
            "remove the empty folder temp",
            "rmdir old_folder",
            "delete the empty directory",
        ],
    },
    "delete_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "del", "/p", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Delete a file (del) — DESTRUCTIVE",
        "example_phrasings": [
            "delete the file test.txt",
            "remove old_log.txt",
            "del C:\\temp\\junk.dat",
            "erase this file",
        ],
    },
    "delete_directory": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "rmdir", "/s", "/q", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Delete a directory and all its contents (rmdir /s /q) — DESTRUCTIVE",
        "example_phrasings": [
            "delete the folder and everything in it",
            "remove directory recursively",
            "rmdir /s old_project",
        ],
    },
    "copy_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "copy", "{source}", "{dest}"],
        "params": ["source", "dest"],
        "validators": {"source": validate_path, "dest": validate_path},
        "description": "Copy a file to a new location (copy / cp)",
        "example_phrasings": [
            "copy report.docx to my Desktop",
            "cp config.ini to C:\\backup",
            "duplicate this file",
            "copy a file",
        ],
    },
    "move_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "move", "{source}", "{dest}"],
        "params": ["source", "dest"],
        "validators": {"source": validate_path, "dest": validate_path},
        "description": "Move a file or folder to a new location (move / mv)",
        "example_phrasings": [
            "move report.docx to C:\\archive",
            "mv old_logs to backup folder",
            "relocate this file",
        ],
    },
    "rename_file": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "ren", "{path}", "{new_name}"],
        "params": ["path", "new_name"],
        "validators": {"path": validate_path, "new_name": validate_name},
        "description": "Rename a file or folder (ren / rename)",
        "example_phrasings": [
            "rename old.txt to new.txt",
            "change filename from report to report_final",
            "ren config.bak config.ini",
        ],
    },

    # ─── System Info ─── SAFE ─────────────────────────────────────
    "hostname": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "hostname"],
        "params": [],
        "validators": {},
        "description": "Show the computer's hostname",
        "example_phrasings": [
            "what's my computer name",
            "hostname",
            "show machine name",
            "what is this PC called",
        ],
    },
    "whoami": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "whoami"],
        "params": [],
        "validators": {},
        "description": "Show the current logged-in user",
        "example_phrasings": [
            "who am I",
            "whoami",
            "what user am I logged in as",
            "show current user",
        ],
    },
    "systeminfo": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "systeminfo"],
        "params": [],
        "validators": {},
        "description": "Show detailed system information (OS, hardware, uptime, etc.)",
        "timeout_seconds": 60,
        "example_phrasings": [
            "show system information",
            "systeminfo",
            "what OS am I running",
            "system details",
            "tell me about this computer",
            "show uptime",
        ],
    },
    "os_version": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "ver"],
        "params": [],
        "validators": {},
        "description": "Show the Windows version (ver)",
        "example_phrasings": [
            "what version of Windows",
            "Windows version",
            "ver",
            "OS version",
        ],
    },
    "current_date_time": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "echo", "%date% %time%"],
        "params": [],
        "validators": {},
        "description": "Show the current date and time",
        "example_phrasings": [
            "what time is it",
            "current date",
            "show the date and time",
            "what's today's date",
            "date",
            "time",
        ],
    },
    "env_variable": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "echo", "%{var}%"],
        "params": ["var"],
        "validators": {"var": validate_env_var},
        "description": "Show the value of an environment variable",
        "example_phrasings": [
            "show the PATH variable",
            "what is JAVA_HOME set to",
            "echo %USERPROFILE%",
        ],
    },
    "all_env_variables": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "set"],
        "params": [],
        "validators": {},
        "description": "List all environment variables (set)",
        "example_phrasings": [
            "show all environment variables",
            "list env vars",
            "set",
            "what environment variables are set",
        ],
    },

    # ─── Process Management ─── SAFE ──────────────────────────────
    "list_processes": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tasklist"],
        "params": [],
        "validators": {},
        "description": "List all running processes (tasklist)",
        "example_phrasings": [
            "list all running processes",
            "tasklist",
            "show running tasks",
            "what's running right now",
        ],
    },
    "list_processes_verbose": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tasklist", "/v"],
        "params": [],
        "validators": {},
        "description": "List all running processes with detailed info (memory, status, CPU time)",
        "example_phrasings": [
            "tasklist verbose",
            "detailed process list",
            "show processes with memory usage",
        ],
    },
    "find_process": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tasklist", "/fi", "IMAGENAME eq {name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Find a specific process by name",
        "example_phrasings": [
            "is chrome running",
            "find process notepad",
            "check if python.exe is running",
            "is notepad open",
        ],
    },

    # ─── Process Management ─── DESTRUCTIVE ──────────────────────
    "kill_process_by_name": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "taskkill", "/im", "{name}", "/f"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Force kill a process by its name (taskkill) — DESTRUCTIVE",
        "example_phrasings": [
            "kill notepad",
            "stop chrome",
            "end task notepad.exe",
            "force close the process",
            "taskkill notepad",
        ],
    },
    "kill_process_by_pid": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "taskkill", "/pid", "{pid}", "/f"],
        "params": ["pid"],
        "validators": {"pid": validate_integer},
        "description": "Force kill a process by its PID (taskkill /pid) — DESTRUCTIVE",
        "example_phrasings": [
            "kill process 1234",
            "kill PID 5678",
            "end task with PID 9999",
        ],
    },

    # ─── Launch Application ─── SAFE ─────────────────────────────
    "start_application": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "start", "", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Launch / open an application (start)",
        "example_phrasings": [
            "open notepad",
            "launch calculator",
            "start mspaint",
            "open command prompt",
            "run explorer",
        ],
    },

    # ─── Service Management ─── SAFE ─────────────────────────────
    "list_services": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "sc", "query", "type=", "service", "state=", "all"],
        "params": [],
        "validators": {},
        "description": "List all Windows services and their status (sc query)",
        "example_phrasings": [
            "list all Windows services",
            "sc query",
            "show services",
            "what services are running",
        ],
    },
    "query_service": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "sc", "query", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Check the status of a specific Windows service",
        "example_phrasings": [
            "check status of Windows Update service",
            "is the print spooler running",
            "sc query wuauserv",
            "query service Spooler",
        ],
    },

    # ─── Service Management ─── DESTRUCTIVE ──────────────────────
    "start_service": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "net", "start", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Start a Windows service (net start) — DESTRUCTIVE",
        "example_phrasings": [
            "start the print spooler service",
            "net start wuauserv",
            "enable Windows Update service",
        ],
    },
    "stop_service": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "net", "stop", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Stop a Windows service (net stop) — DESTRUCTIVE",
        "example_phrasings": [
            "stop the print spooler",
            "net stop Spooler",
            "disable Windows Update service",
        ],
    },

    # ─── Network Diagnostics ─── SAFE ────────────────────────────
    "ping": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "ping", "-n", "4", "-w", "2000", "{host}"],
        "params": ["host"],
        "validators": {"host": validate_hostname},
        "description": "Ping a host to check connectivity (4 packets, 2s per-packet timeout)",
        "timeout_seconds": 10,
        "is_network": True,
        "example_phrasings": [
            "ping google.com",
            "ping 8.8.8.8",
            "is google.com reachable",
            "check connectivity to example.com",
            "can I reach this host",
        ],
    },
    "ipconfig": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "ipconfig", "/all"],
        "params": [],
        "validators": {},
        "description": "Show all network adapter configuration (IP, gateway, DNS)",
        "example_phrasings": [
            "show my IP address",
            "ipconfig",
            "what's my IP",
            "network configuration",
            "show network adapters",
        ],
    },
    "tracert": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "tracert", "-d", "-w", "1000", "{host}"],
        "params": ["host"],
        "validators": {"host": validate_hostname},
        "description": "Trace the network route to a host (tracert)",
        "timeout_seconds": 30,
        "is_network": True,
        "example_phrasings": [
            "trace route to google.com",
            "tracert 8.8.8.8",
            "show network path to example.com",
            "how many hops to reach this host",
        ],
    },
    "nslookup": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "nslookup", "{host}"],
        "params": ["host"],
        "validators": {"host": validate_hostname},
        "description": "Look up the DNS record for a hostname (nslookup)",
        "timeout_seconds": 10,
        "is_network": True,
        "example_phrasings": [
            "lookup DNS for google.com",
            "nslookup example.com",
            "resolve this domain",
            "what IP does google.com point to",
        ],
    },
    "netstat": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "netstat", "-ano"],
        "params": [],
        "validators": {},
        "description": "Show all active network connections and listening ports with PIDs (netstat)",
        "example_phrasings": [
            "show active connections",
            "netstat",
            "what ports are listening",
            "list network connections",
            "show open network ports",
        ],
    },
    "arp_table": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "arp", "-a"],
        "params": [],
        "validators": {},
        "description": "Show the ARP cache (IP-to-MAC mappings on the local network)",
        "example_phrasings": [
            "show ARP table",
            "arp cache",
            "IP to MAC mappings",
        ],
    },
    "route_table": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "route", "print"],
        "params": [],
        "validators": {},
        "description": "Show the IP routing table",
        "example_phrasings": [
            "show routing table",
            "route print",
            "IP routes",
        ],
    },
    "flush_dns": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "ipconfig", "/flushdns"],
        "params": [],
        "validators": {},
        "description": "Flush the DNS resolver cache",
        "example_phrasings": [
            "flush DNS cache",
            "clear DNS",
            "ipconfig /flushdns",
        ],
    },

    # ─── Disk Info ─── SAFE ───────────────────────────────────────
    "disk_info": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "wmic", "logicaldisk", "get", "name,size,freespace,filesystem,volumename"],
        "params": [],
        "validators": {},
        "description": "Show disk drives with size, free space, and filesystem type",
        "example_phrasings": [
            "show disk space",
            "how much free space do I have",
            "disk usage",
            "drive sizes",
            "check storage",
            "free space on C drive",
        ],
    },
    "disk_usage_dir": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "dir", "/s", "/a", "{path}"],
        "params": ["path"],
        "validators": {"path": validate_path},
        "description": "Calculate total size of a directory (directory size)",
        "example_phrasings": [
            "how big is my Downloads folder",
            "directory size of C:\\Windows",
            "size of this folder",
        ],
    },

    # ─── Scheduled Tasks ─── SAFE ────────────────────────────────
    "list_scheduled_tasks": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "schtasks", "/query", "/fo", "TABLE"],
        "params": [],
        "validators": {},
        "description": "List all scheduled tasks (schtasks /query)",
        "example_phrasings": [
            "list scheduled tasks",
            "schtasks query",
            "show scheduled tasks",
            "what tasks are scheduled",
        ],
    },
    "query_scheduled_task": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "schtasks", "/query", "/tn", "{name}", "/v", "/fo", "LIST"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Show details of a specific scheduled task",
        "example_phrasings": [
            "show details of scheduled task X",
            "query task GoogleUpdateTaskMachineUA",
        ],
    },

    # ─── Startup Programs ─── SAFE ───────────────────────────────
    "list_startup_programs": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "wmic", "startup", "get", "name,command,location"],
        "params": [],
        "validators": {},
        "description": "List programs that run at Windows startup",
        "example_phrasings": [
            "list startup programs",
            "what runs at boot",
            "show startup entries",
            "autorun programs",
            "what launches at login",
        ],
    },

    # ─── Network Share & User Info ─── SAFE ──────────────────────
    "net_users": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "net", "user"],
        "params": [],
        "validators": {},
        "description": "List all local user accounts",
        "example_phrasings": [
            "list user accounts",
            "net user",
            "show all users",
            "who has accounts on this machine",
        ],
    },
    "net_user_detail": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "net", "user", "{name}"],
        "params": ["name"],
        "validators": {"name": validate_name},
        "description": "Show detailed information about a local user account",
        "example_phrasings": [
            "show details for user admin",
            "net user Administrator",
        ],
    },
    "net_shares": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "net", "share"],
        "params": [],
        "validators": {},
        "description": "List all network shares on this machine",
        "example_phrasings": [
            "list network shares",
            "net share",
            "shared folders",
        ],
    },

    # ─── Power / Shutdown ─── DESTRUCTIVE ────────────────────────
    "shutdown": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "shutdown", "/s", "/t", "30"],
        "params": [],
        "validators": {},
        "description": "Shut down the computer (30 second delay)",
        "example_phrasings": [
            "shut down the computer",
            "power off",
            "shutdown",
        ],
    },
    "restart": {
        "tier": "DESTRUCTIVE",
        "cmd": ["cmd", "/c", "shutdown", "/r", "/t", "30"],
        "params": [],
        "validators": {},
        "description": "Restart the computer (30 second delay)",
        "example_phrasings": [
            "restart the computer",
            "reboot",
        ],
    },
    "cancel_shutdown": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "shutdown", "/a"],
        "params": [],
        "validators": {},
        "description": "Cancel a pending shutdown or restart",
        "example_phrasings": [
            "cancel shutdown",
            "abort shutdown",
            "stop restart",
        ],
    },

    # ─── Battery / Power ─── SAFE ────────────────────────────────
    "battery_status": {
        "tier": "SAFE",
        "cmd": ["powershell", "-NoProfile", "-Command", "$b=Get-CimInstance -ClassName Win32_Battery; if($null -eq $b){'No battery detected'}else{$b | Select-Object BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,Status | Format-List}"],
        "params": [],
        "validators": {},
        "description": "Show current battery status, charge percentage, and estimated run time",
        "example_phrasings": [
            "battery status",
            "how much battery",
            "battery percentage",
        ],
    },
    "battery_report": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/batteryreport", "/output", "%TEMP%\\battery-report.html"],
        "params": [],
        "validators": {},
        "description": "Generate a detailed battery health report (saved as HTML)",
        "example_phrasings": [
            "generate battery report",
            "battery health",
        ],
    },
    "battery_charging": {
        "tier": "SAFE",
        "cmd": ["powershell", "-NoProfile", "-Command", "$b=Get-CimInstance -ClassName Win32_Battery; if($null -eq $b){'No battery detected'}else{$state=switch($b.BatteryStatus){1{'Discharging'} 2{'On AC power'} 3{'Fully charged'} 4{'Low'} 5{'Critical'} 6{'Charging'} 7{'Charging (high)'} 8{'Charging (low)'} 9{'Charging (critical)'} 11{'Partially charged'} default{'Unknown'}}; \"$state - $($b.EstimatedChargeRemaining)%\"}"],
        "params": [],
        "validators": {},
        "description": "Show whether the battery is charging and its current charge percentage",
        "example_phrasings": [
            "is my battery charging",
            "am I charging",
            "charging",
        ],
    },
    "power_scheme": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/getactivescheme"],
        "params": [],
        "validators": {},
        "description": "Show the currently active power plan/scheme",
        "example_phrasings": [
            "what power plan am I on",
            "active power scheme",
        ],
    },
    "power_schemes_list": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/list"],
        "params": [],
        "validators": {},
        "description": "List all available power plans/schemes",
        "example_phrasings": [
            "list power plans",
            "available power schemes",
        ],
    },
    "system_power_state": {
        "tier": "SAFE",
        "cmd": ["cmd", "/c", "powercfg", "/systempowerreport", "/output", "%TEMP%\\power-report.html"],
        "params": [],
        "validators": {},
        "description": "Generate a system power/sleep diagnostics report (saved as HTML)",
        "example_phrasings": [
            "power diagnostics report",
            "system sleep report",
        ],
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
    Includes example phrasings to help the model match user intent.
    """
    lines = []
    for tid, t in TEMPLATES.items():
        params_str = ", ".join(t["params"]) if t["params"] else "(no params)"
        phrasings = t.get("example_phrasings", [])
        phrasings_str = " | ".join(phrasings[:3]) if phrasings else ""
        line = f"  {tid} [{t['tier']}] — {t['description']} — params: {params_str}"
        if phrasings_str:
            line += f" — examples: \"{phrasings_str}\""
        lines.append(line)
    return "\n".join(lines)
