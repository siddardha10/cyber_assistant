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
  5. Return the structured result (never a raw string)
"""

import json
import re

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

_TRANSLATOR_SYSTEM_PROMPT = f"""You are a command translator for a Windows system administration assistant.
The user will describe what they want to do in plain English. Your job is to
pick the correct command template and fill in the parameters.

Available command templates:
{get_template_catalog_for_llm()}

Current user home directory: {config.BASE_DIR.parent if hasattr(config, 'BASE_DIR') else 'C:\\\\Users\\\\User'}

Respond with ONLY a JSON object, no other text:
{{"template_id": "<one of the template IDs above>",
  "params": {{"<param_name>": "<value>", ...}},
  "reasoning": "<one sentence explaining your choice>"}}

Rules:
- Only use template IDs from the list above. Never invent new ones.
- Fill in parameter values based on what the user asked for.
- For file paths, use full absolute paths. If the user says "my Downloads folder",
  expand it to the likely absolute path (e.g. C:\\Users\\<username>\\Downloads).
- If the user's request doesn't match ANY template, respond with:
  {{"template_id": null, "params": {{}}, "reasoning": "explain why"}}
- Never include shell metacharacters in parameter values.
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
            "error": str or None,
        }
    """
    if not config.LLM_ENABLED:
        return {
            "success": False,
            "template_id": None,
            "tier": None,
            "params": {},
            "display_command": None,
            "description": None,
            "command_parts": None,
            "error": "LLM not configured (no NVIDIA_API_KEY). Cannot translate commands.",
        }

    # Ask the LLM to pick a template
    try:
        payload = {
            "model": config.LLM_MODEL,
            "messages": [
                {"role": "system", "content": _TRANSLATOR_SYSTEM_PROMPT},
                {"role": "user", "content": natural_input},
            ],
            "temperature": 0.7,
            "top_p": 0.95,
            "max_tokens": 300,
            "stream": False,
        }
        headers = {
            "Authorization": f"Bearer {config.NVIDIA_API_KEY}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        resp = requests.post(config.NVIDIA_BASE_URL, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        raw = data["choices"][0]["message"]["content"]
    except Exception:
        log.exception("Command translator LLM call failed")
        return {
            "success": False,
            "template_id": None, "tier": None, "params": {},
            "display_command": None, "description": None, "command_parts": None,
            "error": "Couldn't reach the language model. Try again in a moment.",
        }

    # Parse the LLM's JSON response
    parsed = _extract_json(raw)
    if parsed is None:
        log.warning("Translator returned unparseable output: %s", raw[:200])
        return {
            "success": False,
            "template_id": None, "tier": None, "params": {},
            "display_command": None, "description": None, "command_parts": None,
            "error": "I couldn't work out a command for that request.",
        }

    template_id = parsed.get("template_id")
    params = parsed.get("params", {})
    reasoning = parsed.get("reasoning", "")

    # LLM said "can't match a template"
    if template_id is None:
        return {
            "success": False,
            "template_id": None, "tier": None, "params": params,
            "display_command": None, "description": None, "command_parts": None,
            "error": f"I don't have a command template for that. {reasoning}",
        }

    # Validate the template exists
    template = get_template(template_id)
    if template is None:
        log.warning("LLM returned unknown template_id: %s", template_id)
        return {
            "success": False,
            "template_id": template_id, "tier": None, "params": params,
            "display_command": None, "description": None, "command_parts": None,
            "error": f"The AI suggested an unknown command template '{template_id}'. Try rephrasing.",
        }

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
        "error": None,
    }
