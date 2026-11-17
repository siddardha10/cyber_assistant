"""
commands/translator.py

Translates natural language into a validated template using goal-first
parsing, action retrieval, and live entity resolution.

Flow:
  1. User says: "show me what's in my Downloads folder"
  2. The local router retrieves the five closest action definitions.
  3. The model returns strict goal/target/slots JSON and selects one candidate.
  4. We validate template_id exists, validate all params, build the command
  5. For process-targeting commands, resolve name → actual running PID via psutil
  6. Return the structured result (never a raw string)
"""

import os
import re
from pathlib import Path

import config
from commands.templates import (
    get_template,
    build_command,
    display_command,
)
from commands.path_resolver import prepare_command_paths, resolve_folder_for_display
from commands.entity_resolver import (
    get_entity_choices,
    resolve_context_entity,
    resolve_entity,
)
from commands.intent_router import parse_goal, web_fallback_category
from commands.templates import get_command_tier
from utils.logger import get_logger

log = get_logger("commands.translator")


# The user's home directory, resolved at import time for the LLM prompt
_LIST_PATH_RE = re.compile(
    r"^(?:please\s+)?(?:list|show|display|view)\s+(?:me\s+)?(?:the\s+)?"
    r"(?:files|contents|items|folders|directory|folder)\s+(?:in|of|under|on|at)\s+(.+?)\??$",
    re.IGNORECASE,
)
_CREATE_FOLDER_RE = re.compile(
    r"^(?:please\s+)?(?:create|make)\s+(?:(?:a|the)\s+)?(?:new\s+)?"
    r"(?:folder|directory)\s+(?:(?:called|named)\s+)?"
    r"(?P<name>\"[^\"]+\"|'[^']+'|.+?)\s+"
    r"(?:on|in|under|at)\s+(?P<parent>.+?)\??$",
    re.IGNORECASE,
)
_CREATE_FILE_RE = re.compile(
    r"^(?:please\s+)?(?:create|make|write)\s+(?:(?:a|the)\s+)?(?:new\s+)?"
    r"(?:(?:python|text|markdown|json|csv)\s+)?file\s+"
    r"(?:(?:named|called)\s+(?P<name_before>\"[^\"]+\"|'[^']+'|.+?)\s+"
    r"(?:in|under|at)\s+(?P<parent_after>.+?)|"
    r"(?:in|under|at)\s+(?P<parent_before>.+?)\s+"
    r"(?:named|called)\s+(?P<name_after>\"[^\"]+\"|'[^']+'|.+?))"
    r"(?:\s+with\s+(?:the\s+)?(?:content|text)\s*:?\s*(?P<content>.*))?$",
    re.IGNORECASE,
)
_OPEN_FILE_RE = re.compile(
    r"^(?:please\s+)?(?:open|launch)\s+(?:the\s+)?"
    r"(?:(?P<file_word>file)\s+)?(?P<path>.+?)\??$",
    re.IGNORECASE,
)
_OPEN_APPLICATION_RE = re.compile(
    r"^(?:please\s+)?(?:open|launch|start|run)\s+(?:the\s+)?"
    r"(?:(?:app|application|program)\s+)?"
    r"(?P<name>\"[^\"]+\"|'[^']+'|[a-z0-9][a-z0-9 ._-]*?)\s*[?.!]*$",
    re.IGNORECASE,
)
_DELETE_FILE_RE = re.compile(
    r"^(?:please\s+)?(?:delete|remove|erase)\s+(?:the\s+)?(?:a\s+)?"
    r"(?:file\s+(?:(?:named|called)\s+)?(?P<file_name>\"[^\"]+\"|'[^']+'|.+?)|"
    r"(?P<bare_name>\"[^\"]+\"|'[^']+'|.+?))"
    r"(?:\s+file)?\s+(?:from|in|under|on|at)\s+(?P<parent>.+?)\??$",
    re.IGNORECASE,
)
_DELETE_FOLDER_RE = re.compile(
    r"^(?:please\s+)?(?:delete|remove)\s+(?:the\s+)?"
    r"(?:folder|directory)\s+(?:(?:named|called)\s+)?"
    r"(?:\"([^\"]+)\"|'([^']+)'|(.+?))\s+"
    r"(?:from|in|under|on|at)\s+(.+?)\??$",
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
    nested_match = re.fullmatch(
        r"(?P<child>\"[^\"]+\"|'[^']+'|.+?)\s+(?:(?:folder|directory)\s+)?"
        r"(?:on|in|under)\s+(?:(?:the|my)\s+)?"
        r"(?P<known>desktop|downloads|documents)",
        reference,
        re.IGNORECASE,
    )
    if nested_match:
        child = re.sub(
            r"\s+(?:folder|directory)$",
            "",
            nested_match.group("child").strip().strip("\"'"),
            flags=re.IGNORECASE,
        ).strip()
        if child:
            base = _resolve_path_reference(nested_match.group("known"))
            return str(Path(base) / child)

    normalized = re.sub(r"\s+", " ", reference).lower()
    normalized = re.sub(r"^(?:the|my)\s+", "", normalized)
    normalized = re.sub(r"\s+(?:folder|directory)$", "", normalized)

    drive_match = _DRIVE_RE.fullmatch(normalized)
    if drive_match:
        drive = drive_match.group(1) or drive_match.group(2)
        return f"{drive.upper()}:\\"

    if normalized in _KNOWN_FOLDERS:
        if normalized in ("desktop", "downloads", "documents"):
            return resolve_folder_for_display(normalized)
        if normalized in _KNOWN_FOLDER_REGISTRY_VALUES:
            known_path = _get_known_folder_path(normalized)
            if known_path:
                return known_path
        return str(Path.home() / _KNOWN_FOLDERS[normalized])

    expanded = os.path.expandvars(os.path.expanduser(reference))
    if re.fullmatch(r"[a-zA-Z]:", expanded):
        expanded += "\\"
    return str(Path(expanded))


def _attach_local_goal(
    parsed: dict,
    action_id: str,
    goal: str,
    target_phrase: str,
    target_type: str,
    interpretation: str,
) -> dict:
    parsed["reasoning"] = interpretation
    parsed["_goal"] = {
        "action_id": action_id,
        "goal": goal,
        "target_phrase": target_phrase,
        "target_type": target_type,
        "slots": parsed["params"],
        "confidence": 1.0,
        "interpretation": interpretation,
        "candidates": [],
        "local_latency_ms": None,
        "cloud_latency_ms": None,
    }
    return parsed


def _local_path_request(natural_input: str) -> dict | None:
    """Translate straightforward filesystem requests without an LLM call."""
    question = natural_input.strip()
    match = _LIST_PATH_RE.fullmatch(question)
    if match:
        path = _resolve_path_reference(match.group(1))
        return _attach_local_goal(
            {"template_id": "list_directory", "params": {"path": path}},
            "list_directory", "inspect", path, "folder",
            f"List the contents of '{path}'.",
        )

    match = _CREATE_FOLDER_RE.fullmatch(question)
    if match:
        name = match.group("name").strip().strip("\"'")
        parent = _resolve_path_reference(match.group("parent"))
        path = str(Path(parent) / name)
        return _attach_local_goal(
            {"template_id": "create_directory", "params": {"path": path}},
            "create_directory", "create", name, "folder",
            f"Create folder '{name}' in '{parent}'.",
        )
    return None


def _local_request(natural_input: str) -> dict | None:
    """Translate common local commands where intent should not depend on the LLM."""
    network_request = _network_diagnostic_request(natural_input)
    if network_request:
        return network_request

    path_request = _local_path_request(natural_input)
    if path_request:
        return path_request

    question = natural_input.strip()
    file_match = _CREATE_FILE_RE.fullmatch(question)
    if file_match:
        name = (file_match.group("name_before") or file_match.group("name_after"))
        parent = (file_match.group("parent_after") or file_match.group("parent_before"))
        name = name.strip().strip("\"'")
        parent = _resolve_path_reference(parent)
        path = str(Path(parent) / name)
        return _attach_local_goal(
            {
                "template_id": "create_file",
                "params": {
                    "path": path,
                    "content": file_match.group("content") or "",
                },
            },
            "create_file", "create", name, "file",
            f"Create file '{name}' in '{parent}'.",
        )

    open_file_match = _OPEN_FILE_RE.fullmatch(question)
    if open_file_match:
        reference = open_file_match.group("path").strip()
        unquoted = reference.strip("\"'")
        if (
            open_file_match.group("file_word")
            or "\\" in unquoted
            or "/" in unquoted
            or Path(unquoted).suffix
        ):
            return {
                "template_id": "open_file",
                "params": {"path": _resolve_path_reference(reference)},
            }

    application_match = _OPEN_APPLICATION_RE.fullmatch(question)
    if application_match:
        name = application_match.group("name").strip().strip("\"'")
        return _attach_local_goal(
            {"template_id": "start_application", "params": {"name": name}},
            "start_application", "launch", name, "application",
            f"Launch the '{name}' application.",
        )

    delete_file_match = _DELETE_FILE_RE.fullmatch(question)
    if delete_file_match:
        name = (delete_file_match.group("file_name") or delete_file_match.group("bare_name"))
        name = name.strip().strip("\"'")
        parent = _resolve_path_reference(delete_file_match.group("parent"))
        return {
            "template_id": "delete_file",
            "params": {"path": str(Path(parent) / name)},
        }

    delete_match = _DELETE_FOLDER_RE.fullmatch(question)
    if delete_match:
        name = next(value for value in delete_match.group(1, 2, 3) if value is not None).strip()
        parent = _resolve_path_reference(delete_match.group(4))
        return {
            "template_id": "delete_directory",
            "params": {"path": str(Path(parent) / name)},
        }

    normalized = re.sub(r"[?.!]+$", "", question.lower()).strip()
    power_requests = (
        (r"(?:please\s+)?(?:restart|reboot)(?:\s+(?:the\s+)?(?:computer|pc|system|machine))?", "restart"),
        (r"(?:please\s+)?(?:shut\s*down|shutdown|power\s+off|turn\s+off)(?:\s+(?:the\s+)?(?:computer|pc|system|machine))?", "shutdown"),
        (r"(?:(?:please\s+)?(?:(?:tell|show|check|give)\s+(?:me\s+)?|what(?:'s| is)\s+)?(?:my\s+|the\s+|current\s+|pc\s+|computer\s+)*battery\s+(?:health|report))", "battery_report"),
        (r"(?:please\s+)?(?:is\s+(?:my\s+)?battery\s+charging|am\s+i\s+charging|battery\s+charging|charging)", "battery_charging"),
        (r"(?:please\s+)?(?:battery\s+status|battery\s+percentage|how\s+much\s+battery|battery\s+level|battery)", "battery_status"),
    )
    for pattern, template_id in power_requests:
        if re.fullmatch(pattern, normalized):
            battery_goal = {
                "battery_report": ("battery", "Generate a detailed battery health report."),
                "battery_status": ("battery status", "Show current battery charge and runtime."),
                "battery_charging": ("battery charging status", "Check whether the battery is charging."),
            }
            target_phrase, interpretation = battery_goal.get(
                template_id,
                (template_id.replace("_", " "), f"Run the {template_id.replace('_', ' ')} action."),
            )
            return _attach_local_goal(
                {"template_id": template_id, "params": {}},
                template_id,
                "inspect",
                target_phrase,
                "none",
                interpretation,
            )
    return None


def _network_diagnostic_request(natural_input: str) -> dict | None:
    """Route explicit network diagnostics deterministically to safe templates."""
    question = re.sub(r"[?.!]+$", "", natural_input.strip())
    direct = re.match(r"^(ping|tracert|traceroute|nslookup)\s+([a-zA-Z0-9._:-]+)(?:\s+.*)?$", question, re.I)
    if direct:
        command = direct.group(1).lower()
        template_id = "tracert" if command == "traceroute" else command
        host = direct.group(2)
        return {"template_id": template_id, "params": {"host": host}}

    command = question.split(None, 1)[0].lower() if question else ""
    if command in {"ipconfig", "netstat"}:
        return {"template_id": command, "params": {}}

    if re.match(r"^(?:show|display|check)\s+(?:my\s+)?(?:ip(?:\s+address)?|network\s+configuration|network\s+adapters)\b", question, re.I):
        return {"template_id": "ipconfig", "params": {}}
    if re.match(r"^(?:show|list)\s+(?:the\s+)?(?:active\s+)?(?:network\s+)?connections\b", question, re.I):
        return {"template_id": "netstat", "params": {}}
    lookup = re.match(r"^(?:lookup\s+dns\s+for|resolve\s+(?:this\s+domain|dns\s+for))\s+([a-zA-Z0-9._:-]+)$", question, re.I)
    if lookup:
        return {"template_id": "nslookup", "params": {"host": lookup.group(1)}}
    return None


def is_network_diagnostic_request(natural_input: str) -> bool:
    """Return whether an explicit network diagnostic is a command request."""
    return _network_diagnostic_request(natural_input) is not None


def is_local_path_request(natural_input: str) -> bool:
    """Return whether a common local command is handled deterministically."""
    return _local_request(natural_input) is not None

def _normalize_phrase(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _correction_context(
    natural_input: str, context: list | None,
) -> tuple[str | None, str | None]:
    corrected = re.match(
        r"^(?:no[, ]+)?(?:i meant|i mean|actually)\s+(.+)$",
        natural_input.strip(),
        re.I,
    )
    if not corrected:
        return None, None
    previous = str(context[-1].get("question") or "").strip() if context else ""
    return (previous, corrected.group(1).strip()) if previous else (None, None)


_CONTEXT_REFERENCE_RE = re.compile(
    r"\b(?:it|that one|the same|same one|again|that process|that app|that service)\b",
    re.IGNORECASE,
)
_GENERIC_ENTITY_RE = re.compile(
    r"\b(?:app|application|process|service|browser|program)\b",
    re.IGNORECASE,
)
_RESOURCE_TARGET_RE = re.compile(
    r"\b(?:most memory|highest memory|hogging my ram|most ram|most cpu|hogging cpu|"
    r"resource hog|biggest file|largest file)\b",
    re.IGNORECASE,
)
_GENERIC_ENTITY_NAMES = {
    "a", "an", "app", "application", "browser", "it", "my", "process",
    "program", "service", "that", "the", "this", "one",
}


def _needs_entity_clarification(
    natural_input: str, entity_phrase: str,
) -> bool:
    if _RESOURCE_TARGET_RE.search(natural_input):
        return False
    if _CONTEXT_REFERENCE_RE.search(natural_input):
        return False
    if not _GENERIC_ENTITY_RE.search(natural_input):
        return False
    target = Path(entity_phrase.strip().strip("\"'")).stem
    target_tokens = set(_normalize_phrase(target).split())
    return not target_tokens or target_tokens <= _GENERIC_ENTITY_NAMES or not any(
        token in _normalize_phrase(natural_input).split()
        for token in target_tokens
        if token not in _GENERIC_ENTITY_NAMES
    )


def translate(natural_input: str, context: list | None = None) -> dict:
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
    if (
        parsed is None
        and _CONTEXT_REFERENCE_RE.search(natural_input)
        and re.search(r"\b(?:close|kill|stop|end|terminate)\b", natural_input, re.I)
    ):
        parsed = {
            "template_id": "kill_process_by_name",
            "params": {"name": natural_input},
            "reasoning": "Close the uniquely identified process from recent context.",
        }
    goal_result = parsed.pop("_goal", None) if parsed else None
    phrase_to_correct, correction_phrase = _correction_context(natural_input, context)
    from db import database as db
    correction = db.get_intent_correction(_normalize_phrase(natural_input))

    if parsed is None and not config.LLM_ENABLED and not correction:
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
        if correction:
            parsed = {
                "template_id": correction["action_id"],
                "params": {},
                "reasoning": "Using your saved correction.",
            }
        else:
            try:
                goal_result = parse_goal(correction_phrase or natural_input, context)
            except Exception:
                log.exception("Goal-first action parsing failed.")
                goal_result = None
            if goal_result is None:
                return {
                    "success": False,
                    "template_id": None, "tier": None, "params": {},
                    "display_command": None, "description": None, "command_parts": None,
                    "is_network": False, "confidence": 0,
                    "interpretation": None, "candidates": [],
                    "web_fallback_category": web_fallback_category(natural_input),
                    "error": "I couldn't confidently match that to an available local action.",
                }
    if parsed is None:
        parsed = {
            "template_id": (
                correction["action_id"] if correction
                else goal_result.get("action_id") if goal_result else None
            ),
            "params": goal_result.get("slots", {}) if goal_result else {},
            "reasoning": goal_result.get("interpretation", "") if goal_result else "",
        }

    template_id = parsed.get("template_id")
    params = parsed.get("params", {})
    reasoning = parsed.get("reasoning", "")
    confidence = 1.0 if correction else (goal_result["confidence"] if goal_result else 1.0)

    if correction:
        parsed["template_id"] = correction["action_id"]
        template_id = correction["action_id"]
        if correction.get("target_phrase") and goal_result:
            goal_result["target_phrase"] = correction["target_phrase"]

    # LLM said "can't match a template" → unsupported
    if template_id is None:
        return {
            "success": False,
            "template_id": None, "tier": None, "params": params,
            "display_command": None, "description": None, "command_parts": None,
            "is_network": False,
            "confidence": confidence,
            "interpretation": reasoning,
            "candidates": goal_result.get("candidates", []) if goal_result else [],
            "web_fallback_category": (
                web_fallback_category(natural_input)
                if confidence < 0.55 else None
            ),
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
            "confidence": confidence,
            "interpretation": reasoning,
            "candidates": goal_result.get("candidates", []) if goal_result else [],
            "error": f"Unsupported — the command template '{template_id}' doesn't exist.",
        }

    if correction:
        if not goal_result or goal_result.get("action_id") != template_id:
            params = {}
        target_phrase = correction.get("target_phrase")
        if target_phrase and "name" in template["params"] and not params.get("name"):
            params["name"] = target_phrase

    if template_id == "copy_file":
        explicitly_replaces = bool(re.search(
            r"\b(overwrite|replace|substitute)\b",
            natural_input,
            re.IGNORECASE,
        ))
        params["overwrite"] = explicitly_replaces

    if template_id == "create_file" and params.get("content") is None:
        params["content"] = ""

    # Resolve dynamic system entities against live local state before building
    # any command, including targets selected by the model.
    entity_kind = None
    if template_id in {"kill_process_by_name", "find_process"} and "name" in params:
        entity_kind = "process"
    elif template_id in {"kill_process_by_name", "find_process"}:
        entity_kind = "process"
        params["name"] = (
            (goal_result or {}).get("target_phrase")
            or natural_input
        )
    elif template_id in {"query_service", "start_service", "stop_service"} and "name" in params:
        entity_kind = "service"
    elif template_id in {"query_service", "start_service", "stop_service"}:
        entity_kind = "service"
        params["name"] = (
            (goal_result or {}).get("target_phrase")
            or natural_input
        )
    elif template_id == "start_application" and "name" in params:
        entity_kind = "application"
    elif template_id == "start_application":
        entity_kind = "application"
        params["name"] = (
            (goal_result or {}).get("target_phrase")
            or natural_input
        )
    if template_id == "kill_process_by_pid" and "pid" in params:
        entity_kind = "process"
        params["name"] = str(params["pid"])
    if entity_kind:
        entity_phrase = str(params["name"])
        contextual_match = None
        if _CONTEXT_REFERENCE_RE.search(natural_input):
            contextual = resolve_context_entity(context, entity_kind)
            if contextual["status"] != "match":
                question = (
                    f"Which {entity_kind} did you mean?"
                    if contextual["status"] == "ambiguous"
                    else f"Which {entity_kind} should I use?"
                )
                return {
                    "success": False, "clarification": True,
                    "template_id": template_id, "tier": template["tier"],
                    "params": params, "display_command": None,
                    "description": template["description"], "command_parts": None,
                    "is_network": False, "confidence": min(confidence, 0.54),
                    "interpretation": reasoning,
                    "candidates": contextual["choices"] or get_entity_choices(entity_kind),
                    "error": question,
                }
            contextual_match = contextual["match"]
            entity_phrase = str(
                contextual_match.get("name") or contextual_match.get("value")
            )
            params["name"] = str(
                contextual_match.get("value") or contextual_match.get("name")
            )
        elif _needs_entity_clarification(natural_input, entity_phrase):
            return {
                "success": False, "clarification": True,
                "template_id": template_id, "tier": template["tier"],
                "params": params, "display_command": None,
                "description": template["description"], "command_parts": None,
                "is_network": False, "confidence": min(confidence, 0.54),
                "interpretation": reasoning,
                "candidates": get_entity_choices(entity_kind),
                "error": f"Which {entity_kind} do you mean?",
            }
        if entity_kind == "process" and any(
            term in natural_input.casefold()
            for term in ("most memory", "highest memory", "hogging my ram", "most ram", "most cpu", "hogging cpu")
        ):
            entity_phrase = natural_input
        resolution = (
            {
                "status": "match",
                "match": contextual_match,
                "choices": [contextual_match],
            }
            if contextual_match
            else resolve_entity(entity_phrase, entity_kind)
        )
        if resolution["status"] == "no_match":
            return {
                "success": False, "clarification": True,
                "template_id": template_id, "tier": template["tier"], "params": params,
                "display_command": None, "description": template["description"],
                "command_parts": None,
                "is_network": False,
                "confidence": confidence,
                "interpretation": reasoning,
                "candidates": resolution["choices"],
                "error": f"I couldn't find a matching {entity_kind} for '{params['name']}'.",
            }
        if resolution["status"] == "ambiguous":
            return {
                "success": False, "clarification": True,
                "template_id": template_id, "tier": template["tier"], "params": params,
                "display_command": None, "description": template["description"],
                "command_parts": None, "is_network": False,
                "confidence": min(confidence, 0.54),
                "interpretation": reasoning,
                "candidates": resolution["choices"],
                "error": f"Which {entity_kind} did you mean?",
            }
        entity = resolution["match"]
        if entity.get("protected") and template_id in {
            "kill_process_by_name", "kill_process_by_pid",
        }:
            return {
                "success": False, "template_id": template_id, "tier": "DESTRUCTIVE",
                "params": params, "display_command": None,
                "description": template["description"], "command_parts": None,
                "is_network": False, "confidence": confidence,
                "interpretation": reasoning, "candidates": [],
                "error": f"'{entity['name']}' is a protected system process and cannot be stopped.",
            }
        if template_id == "kill_process_by_pid":
            params["pid"] = str(entity["pid"])
            params.pop("name", None)
        elif (
            entity_kind == "process"
            and template_id == "kill_process_by_name"
            and entity.get("pid")
        ):
            template_id = "kill_process_by_pid"
            template = get_template(template_id)
            params = {"pid": str(entity["pid"])}
        else:
            params["name"] = entity["value"]

    if correction_phrase and goal_result and goal_result.get("action_id"):
        db.save_intent_correction(
            _normalize_phrase(phrase_to_correct),
            goal_result["action_id"],
            goal_result.get("target_type"),
            goal_result.get("target_phrase"),
        )

    missing_params = [
        parameter for parameter in template["params"]
        if params.get(parameter) is None
    ]
    if missing_params:
        if template_id == "create_file" and missing_params == ["content"]:
            params["content"] = ""
        else:
            target = missing_params[0]
            question = (
                "Where should I create the folder?"
                if template_id == "create_directory" and target == "path"
                else f"What {target.replace('_', ' ')} should I use?"
            )
            return {
                "success": False, "clarification": True,
                "template_id": template_id, "tier": get_command_tier(template_id, params),
                "params": params, "display_command": None,
                "description": template["description"], "command_parts": None,
                "is_network": template.get("is_network", False),
                "confidence": min(confidence, 0.54),
                "interpretation": reasoning,
                "candidates": goal_result.get("candidates", []) if goal_result else [],
                "error": question,
            }

    # Resolve Desktop/Documents/Downloads against the user's real known folders
    # and report missing inputs before constructing a command.
    params, path_error = prepare_command_paths(template_id, params)
    if path_error:
        return {
            "success": False,
            "clarification": "already exists" in path_error.lower(),
            "template_id": template_id, "tier": template["tier"], "params": params,
            "display_command": None, "description": template["description"],
            "command_parts": None, "is_network": template.get("is_network", False),
            "confidence": confidence,
            "interpretation": reasoning,
            "candidates": goal_result.get("candidates", []) if goal_result else [],
            "error": path_error,
        }

    if template_id == "copy_file" and params.get("overwrite"):
        # Explicit replacement remains DESTRUCTIVE and is never automatic.
        confidence = min(confidence, 1.0)

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
            "confidence": confidence,
            "interpretation": reasoning,
            "candidates": goal_result.get("candidates", []) if goal_result else [],
            "error": f"Parameter validation failed: {e}",
        }

    tier = get_command_tier(template_id, params)
    return {
        "success": True,
        "template_id": template_id,
        "tier": tier,
        "params": params,
        "display_command": cmd_display,
        "description": template["description"],
        "command_parts": command_parts,
        "is_network": template.get("is_network", False),
        "confidence": confidence,
        "goal": goal_result.get("goal") if goal_result else None,
        "target_phrase": goal_result.get("target_phrase") if goal_result else None,
        "target_type": goal_result.get("target_type") if goal_result else None,
        "interpretation": reasoning,
        "candidates": goal_result.get("candidates", []) if goal_result else [],
        "local_latency_ms": goal_result.get("local_latency_ms") if goal_result else None,
        "cloud_latency_ms": goal_result.get("cloud_latency_ms") if goal_result else None,
        "error": None,
    }
