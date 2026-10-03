"""
commands/translator.py

Translates natural language into a validated command template + parameters
via a single LLM call.  Never constructs raw shell strings — the output
must map to a known template in commands/templates.py, and all parameters
are validated through that template's validators before any command is built.

Flow:
  1. User says: "show me what's in my Downloads folder"
  2. LLM receives the template catalog + the user's request
  3. LLM returns: {"template_id": "list_directory", "params": {"path": "C:\\Users\\...\\Downloads"}}
  4. We validate template_id exists, validate all params, build the command
  5. For process-targeting commands, resolve name → actual running PID via psutil
  6. Return the structured result (never a raw string)
"""

import json
import os
import re
from pathlib import Path

import requests

import config
from commands.templates import (
    TEMPLATES,
    get_template,
    build_command,
    display_command,
    get_template_catalog_for_llm,
)
from utils.logger import get_logger

log = get_logger("commands.translator")

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)

# The user's home directory, resolved at import time for the LLM prompt
_USER_HOME = str(os.path.expanduser("~"))

_LIST_PATH_RE = re.compile(
    r"^(?:please\s+)?(?:list|show|display|view)\s+(?:me\s+)?(?:the\s+)?"
    r"(?:files|contents|items|folders|directory|folder)\s+(?:in|of|under|on|at)\s+(.+?)\??$",
    re.IGNORECASE,
)
_CREATE_FOLDER_RE = re.compile(
    r"^(?:please\s+)?(?:create|make)\s+(?:a\s+)?(?:new\s+)?"
    r"(?:folder|directory)\s+(?:called|named)\s+"
    r"(?:\"([^\"]+)\"|'([^']+)'|(.+?))\s+(?:on|in|under|at)\s+(.+?)\??$",
    re.IGNORECASE,
)
_CREATE_FILE_RE = re.compile(
    r"^(?:please\s+)?(?:create|make|write)\s+(?:a\s+)?(?:new\s+)?file\s+"
    r"(?:named|called)\s+(?P<name>\"[^\"]+\"|'[^']+'|.+?)\s+"
    r"(?:in|under|at)\s+(?P<parent>.+?)"
    r"(?:\s+with\s+(?:the\s+)?(?:content|text)\s*:?\s*(?P<content>.*))?$",
    re.IGNORECASE,
)
_DRIVE_RE = re.compile(r"^(?:local\s+)?(?:disk|drive)\s+([a-z])\s*:?$|^([a-z])\s+drive$", re.IGNORECASE)
_KNOWN_FOLDERS = {
    "desktop": "Desktop",
    "downloads": "Downloads",
    "documents": "Documents",
    "my documents": "Documents",
    "pictures": "Pictures",
    "music": "Music",
    "videos": "Videos",
    "home": "",
    "home folder": "",
    "user profile": "",
}
_KNOWN_FOLDER_REGISTRY_VALUES = {
    "desktop": "Desktop",
    "downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "documents": "Personal",
    "pictures": "My Pictures",
    "music": "My Music",
    "videos": "My Video",
}


def _get_known_folder_path(name: str) -> str | None:
    """Read the user's actual Windows known-folder location, including redirects."""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ) as key:
            value, _ = winreg.QueryValueEx(key, _KNOWN_FOLDER_REGISTRY_VALUES[name])
        return os.path.expandvars(value)
    except (ImportError, OSError):
        return None


def _resolve_path_reference(reference: str) -> str:
    """Resolve common Windows locations and preserve explicitly supplied paths."""
    reference = re.sub(r"^(?:(?:the|my)\s+)?(?:folder|directory)\s+", "", reference.strip(), flags=re.IGNORECASE)
    reference = reference.strip().strip("\\\"'").rstrip("?.")
    normalized = re.sub(r"\s+", " ", reference).lower()
    normalized = re.sub(r"^(?:the|my)\s+", "", normalized)
    normalized = re.sub(r"\s+(?:folder|directory)$", "", normalized)

    drive_match = _DRIVE_RE.fullmatch(normalized)
    if drive_match:
        drive = drive_match.group(1) or drive_match.group(2)
        return f"{drive.upper()}:\\"

    if normalized in _KNOWN_FOLDERS:
        if normalized in _KNOWN_FOLDER_REGISTRY_VALUES:
            known_path = _get_known_folder_path(normalized)
            if known_path:
                return known_path
        return str(Path.home() / _KNOWN_FOLDERS[normalized])

    expanded = os.path.expandvars(os.path.expanduser(reference))
    if re.fullmatch(r"[a-zA-Z]:", expanded):
        expanded += "\\"
    return str(Path(expanded))


def _local_path_request(natural_input: str) -> dict | None:
    """Translate straightforward filesystem requests without an LLM call."""
    question = natural_input.strip()
    match = _LIST_PATH_RE.fullmatch(question)
    if match:
        return {"template_id": "list_directory", "params": {"path": _resolve_path_reference(match.group(1))}}

    match = _CREATE_FOLDER_RE.fullmatch(question)
    if match:
        name = next(value for value in match.group(1, 2, 3) if value is not None).strip()
        parent = _resolve_path_reference(match.group(4))
        return {
            "template_id": "create_directory",
            "params": {"path": str(Path(parent) / name)},
        }
    return None


def _local_request(natural_input: str) -> dict | None:
    """Translate common local commands where intent should not depend on the LLM."""
    path_request = _local_path_request(natural_input)
    if path_request:
        return path_request

    question = natural_input.strip()
    file_match = _CREATE_FILE_RE.fullmatch(question)
    if file_match:
        name = file_match.group("name").strip().strip("\"'")
        parent = _resolve_path_reference(file_match.group("parent"))
        return {
            "template_id": "create_file",
            "params": {
                "path": str(Path(parent) / name),
                "content": file_match.group("content") or "",
            },
        }

    normalized = re.sub(r"[?.!]+$", "", question.lower()).strip()
    power_requests = (
        (r"(?:please\s+)?(?:restart|reboot)(?:\s+(?:the\s+)?(?:computer|pc|system|machine))?", "restart"),
        (r"(?:please\s+)?(?:shut\s*down|shutdown|power\s+off|turn\s+off)(?:\s+(?:the\s+)?(?:computer|pc|system|machine))?", "shutdown"),
        (r"(?:please\s+)?(?:battery\s+health|battery\s+report|health\s+of\s+(?:my\s+)?battery)", "battery_report"),
        (r"(?:please\s+)?(?:is\s+(?:my\s+)?battery\s+charging|am\s+i\s+charging|battery\s+charging|charging)", "battery_charging"),
        (r"(?:please\s+)?(?:battery\s+status|battery\s+percentage|how\s+much\s+battery|battery\s+level|battery)", "battery_status"),
    )
    for pattern, template_id in power_requests:
        if re.fullmatch(pattern, normalized):
            return {"template_id": template_id, "params": {}}
    return None


def is_local_path_request(natural_input: str) -> bool:
    """Return whether a common local command is handled deterministically."""
    return _local_request(natural_input) is not None

_TRANSLATOR_SYSTEM_PROMPT = f"""You are a command translator for a Windows system administration assistant.
The user will describe what they want to do in plain English. Your job is to
pick the correct command template and fill in the parameters.

Available command templates:
{get_template_catalog_for_llm()}

Current user home directory: {_USER_HOME}

Respond with ONLY a JSON object, no other text:
{{"template_id": "<one of the template IDs above>",
  "params": {{"<param_name>": "<value>", ...}},
  "reasoning": "<one sentence explaining your choice>"}}

Rules:
- Only use template IDs from the list above. Never invent new ones.
- Fill in parameter values based on what the user asked for.
- For file paths, use full absolute paths. If the user says "my Downloads folder",
  expand it to the likely absolute path (e.g. {_USER_HOME}\\Downloads).
- If the user asks to kill/stop a process, use the process image name WITH the .exe
  extension (e.g. "notepad.exe" not "notepad"). If they just say the base name,
  append .exe automatically.
- If the user's request doesn't match ANY template, respond with:
  {{"template_id": null, "params": {{}}, "reasoning": "explain why"}}
- Never include shell metacharacters in parameter values.
- For create_file, pass the requested file text literally as the content parameter;
    file content is written as data and is not executed as a command.
- Prefer the simplest template that does what the user asked.
"""


def _extract_json(raw: str) -> dict | None:
    """Extract a JSON object from LLM output, handling markdown fences."""
    stripped = raw.strip().strip("`")
    if stripped.lower().startswith("json"):
        stripped = stripped[4:].strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK_RE.search(raw)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _resolve_process_name(name: str) -> dict:
    """
    Resolve a user-supplied process name against actually running processes
    via psutil. Returns {"resolved": True, "name": str, "pid": int|None}
    or {"resolved": False, "error": str, "candidates": list[str]}.

    This prevents the LLM from guessing at process names that don't exist,
    and catches ambiguous matches (e.g. user says "chrome" but there are
    multiple chrome processes).
    """
    try:
        import psutil
    except ImportError:
        # psutil not installed — fall through without resolution
        return {"resolved": True, "name": name, "pid": None}

    name_lower = name.lower().replace(".exe", "")
    matches = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pname = proc.info["name"] or ""
            if pname.lower().replace(".exe", "") == name_lower:
                matches.append({"pid": proc.info["pid"], "name": pname})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not matches:
        # No running process found — return a useful error
        # Check for close matches
        all_names = set()
        for proc in psutil.process_iter(["name"]):
            try:
                all_names.add(proc.info["name"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        close = [n for n in all_names if name_lower in n.lower()][:5]
        return {
            "resolved": False,
            "error": f"No running process found matching '{name}'.",
            "candidates": close,
        }

    # Found — return the actual image name (with .exe) from the system
    return {
        "resolved": True,
        "name": matches[0]["name"],  # actual system name with correct casing
        "pid": matches[0]["pid"],
        "count": len(matches),
    }


def translate(natural_input: str) -> dict:
    """
    Translate a natural language command request into a validated template.

    Returns:
        {
            "success": True/False,
            "template_id": str or None,
            "tier": "SAFE" or "DESTRUCTIVE" or None,
            "params": dict,
            "display_command": str (the exact command that will run),
            "description": str (template description),
            "command_parts": list[str] (validated command parts for executor),
            "is_network": bool,
            "error": str or None,
        }
    """
    parsed = _local_request(natural_input)

    if parsed is None and not config.LLM_ENABLED:
        return {
            "success": False,
            "template_id": None,
            "tier": None,
            "params": {},
            "display_command": None,
            "description": None,
            "command_parts": None,
            "is_network": False,
            "error": "LLM not configured. Make sure Ollama is running (`ollama serve`) and CS_LLM_ENABLED=true.",
        }

    if parsed is None:
        # Ask the LLM to pick a template for requests outside local path handling.
        try:
            payload = {
                "model": config.LLM_MODEL,
                "messages": [
                    {"role": "system", "content": _TRANSLATOR_SYSTEM_PROMPT},
                    {"role": "user", "content": natural_input},
                ],
                "temperature": 0.3,
                "top_p": 0.95,
                "max_tokens": 300,
                "stream": False,
            }
            headers = {"Content-Type": "application/json"}
            resp = requests.post(config.OLLAMA_BASE_URL, headers=headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            raw = data["choices"][0]["message"]["content"]
        except Exception:
            log.exception("Command translator LLM call failed")
            return {
                "success": False,
                "template_id": None, "tier": None, "params": {},
                "display_command": None, "description": None, "command_parts": None,
                "is_network": False,
                "error": "Couldn't reach the language model. Try again in a moment.",
            }

        parsed = _extract_json(raw)
        if parsed is None:
            log.warning("Translator returned unparseable output: %s", raw[:200])
            return {
                "success": False,
                "template_id": None, "tier": None, "params": {},
                "display_command": None, "description": None, "command_parts": None,
                "is_network": False,
                "error": "I couldn't work out a command for that request.",
            }

    template_id = parsed.get("template_id")
    params = parsed.get("params", {})
    reasoning = parsed.get("reasoning", "")

    # LLM said "can't match a template" → unsupported
    if template_id is None:
        return {
            "success": False,
            "template_id": None, "tier": None, "params": params,
            "display_command": None, "description": None, "command_parts": None,
            "is_network": False,
            "error": f"Unsupported — I don't have a command for that. {reasoning}",
        }

    # Validate the template exists
    template = get_template(template_id)
    if template is None:
        log.warning("LLM returned unknown template_id: %s", template_id)
        return {
            "success": False,
            "template_id": template_id, "tier": None, "params": params,
            "display_command": None, "description": None, "command_parts": None,
            "is_network": False,
            "error": f"Unsupported — the command template '{template_id}' doesn't exist.",
        }

    # ── Process name resolution (kill / find process commands) ──
    if template_id in ("kill_process_by_name", "find_process") and "name" in params:
        resolution = _resolve_process_name(params["name"])
        if not resolution["resolved"]:
            candidates = resolution.get("candidates", [])
            hint = ""
            if candidates:
                hint = " Did you mean: " + ", ".join(candidates[:3]) + "?"
            return {
                "success": False,
                "template_id": template_id, "tier": template["tier"], "params": params,
                "display_command": None, "description": template["description"],
                "command_parts": None,
                "is_network": False,
                "error": f"{resolution['error']}{hint}",
            }
        # Use the system-resolved name (correct casing, .exe extension)
        params["name"] = resolution["name"]

    # Build and validate the command via the template system
    try:
        command_parts = build_command(template_id, params)
        cmd_display = display_command(template_id, params)
    except ValueError as e:
        log.warning("Parameter validation failed for %s: %s", template_id, e)
        return {
            "success": False,
            "template_id": template_id, "tier": template["tier"], "params": params,
            "display_command": None, "description": template["description"],
            "command_parts": None,
            "is_network": False,
            "error": f"Parameter validation failed: {e}",
        }

    return {
        "success": True,
        "template_id": template_id,
        "tier": template["tier"],
        "params": params,
        "display_command": cmd_display,
        "description": template["description"],
        "command_parts": command_parts,
        "is_network": template.get("is_network", False),
        "error": None,
    }
