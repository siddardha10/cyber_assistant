"""
query/llm.py

CyberSentinel v2 — LLM-first intent classification + query engine.

Architecture (v2):
  Every incoming message goes through intent classification FIRST:
    1. classify_intent()  → DATA_QUERY | SYSTEM_COMMAND | CONVERSATIONAL | OUT_OF_SCOPE
    2. Route to the appropriate handler:
       - DATA_QUERY       → SQL planner + explainer (existing two-call flow, extended)
       - SYSTEM_COMMAND   → command translator (commands/translator.py)
       - CONVERSATIONAL   → direct response using real capabilities list
       - OUT_OF_SCOPE     → polite refusal with scope description

  The offline pattern matcher (query/offline.py) is still consulted FIRST as a
  fast/free cache for exact-match phrasings — but it's a cache optimization,
  not the primary path. If offline misses, the LLM classifies intent.

Conversation context: the UI sends recent Q&A turns so follow-up questions
("what about yesterday?") resolve correctly across the conversation.
"""

import json
import re

import requests

import config
from db import database as db
from db.schema import SCHEMA_TEXT
from query.sql_guard import validate, SQLValidationError
from utils.logger import get_logger

log = get_logger("query.llm")

# ═══════════════════════════════════════════════════════════════════
# Capabilities list — pulled from code, not from the model's knowledge.
# This is what the CONVERSATIONAL handler uses to answer "what can you do?"
# ═══════════════════════════════════════════════════════════════════
CAPABILITIES = {
    "monitoring": [
        "Processes — tracks new, terminated, and resource-hogging processes with CPU baselines",
        "Network ports — detects new listening ports, outbound connections, and potential port scans",
        "USB devices — logs every USB insert/remove event (drives, peripherals)",
        "Logins — monitors successful and failed login attempts from Windows event logs",
        "Browser downloads — scans download history from Chrome, Edge, Brave, Opera, Firefox",
        "Installed software — detects new installs and uninstalls",
        "Startup entries — watches autorun registry keys and startup folders for changes",
        "Windows services — detects new, changed, or removed services",
        "Scheduled tasks — monitors Task Scheduler for new or removed tasks",
        "File system — watches Downloads and Desktop for file creates/deletes/modifications",
        "DNS queries — logs domain lookups (when network sniffer is enabled)",
        "System health — tracks CPU, memory, and disk usage every 15 seconds",
    ],
    "queries": [
        "Ask questions about any monitored data in plain English",
        "Follow-up questions within a conversation (e.g. 'what about yesterday?')",
        "Threat and alert summaries with severity breakdown and reasons",
        "Daily activity summaries across all monitors",
        "Process, port, and network connection lookups",
        "Login history and failed login analysis",
        "Download history across all browsers",
        "Software, startup, service, and scheduled task change history",
    ],
    "commands": [
        "Run Windows commands described in plain English",
        "File operations — list, view, search, copy, move, rename, delete files and folders",
        "System info — hostname, whoami, systeminfo, OS version, environment variables",
        "Process management — list processes, find a process, kill a process",
        "Service management — list, query, start, stop Windows services",
        "Network diagnostics — ping, ipconfig, tracert, nslookup, netstat, arp, routes",
        "Disk info — drive sizes, free space, directory sizes",
        "Scheduled tasks — list and query Task Scheduler entries",
        "Startup programs — list programs that run at boot",
        "User accounts — list users, user details, network shares",
        "All destructive commands require explicit confirmation before running",
    ],
}

CAPABILITIES_TEXT = ""
for category, items in CAPABILITIES.items():
    CAPABILITIES_TEXT += f"\n{category.upper()}:\n"
    for item in items:
        CAPABILITIES_TEXT += f"  • {item}\n"

# ═══════════════════════════════════════════════════════════════════
# System prompts
# ═══════════════════════════════════════════════════════════════════

_CLASSIFIER_SYSTEM_PROMPT = """You are an intent classifier for a personal cybersecurity monitoring assistant \
running on the user's own Windows machine.

Classify the user's message into EXACTLY ONE of these categories:

1. DATA_QUERY — a question answerable from the monitoring database \
(processes, ports, logins, downloads, alerts, USB devices, services, \
startup entries, scheduled tasks, file changes, DNS queries, system health, \
command execution history — anything about what this machine has done or is doing).

2. SYSTEM_COMMAND — a request to actually DO something on the machine \
(run a command, list files, ping a host, kill a process, check IP, create \
a folder, delete a file, start/stop a service, check disk space, etc.) \
— the user wants to EXECUTE an action, not just query stored data.

3. CONVERSATIONAL — greetings, thanks, meta-questions about what the assistant \
can do, how to use it, or other social/conversational messages.

4. OUT_OF_SCOPE — anything unrelated to this machine, its security, or \
system administration. General trivia, coding help, math, world facts, \
creative writing, etc.

You may be given recent conversation turns for context — use them to understand \
follow-ups like "what about yesterday?" or "do that for port 443 too".

Respond with ONLY a JSON object:
{"intent": "<DATA_QUERY|SYSTEM_COMMAND|CONVERSATIONAL|OUT_OF_SCOPE>", \
"confidence": <0.0 to 1.0>, \
"reasoning": "<one short sentence>"}

IMPORTANT DISTINCTIONS:
- "show me open ports" = DATA_QUERY (asking about monitored data)
- "run netstat" = SYSTEM_COMMAND (asking to execute a command)
- "list files in my Downloads" = SYSTEM_COMMAND (asking to run 'dir')
- "what did I download?" = DATA_QUERY (asking about browser download history from DB)
- "any failed logins?" = DATA_QUERY (asking about stored login event data)
- "ping google.com" = SYSTEM_COMMAND
- "what commands have I run?" = DATA_QUERY (querying the command_logs table)
- "what's the capital of France?" = OUT_OF_SCOPE
- "hello" = CONVERSATIONAL
"""

_PLANNER_SYSTEM_PROMPT = f"""You are a query planner for a personal cybersecurity monitoring assistant \
running on the user's own machine.

You have access to this SQLite schema (read-only):
{SCHEMA_TEXT}

The `alerts` table has a `reason` column explaining WHY a category of alert matters in general, and
`occurrence_count` showing how many times a deduplicated condition has repeated — include these when
a question is about threats/alerts/danger.

The `command_logs` table records every system command that has been executed through this assistant —
use it when users ask about their command history.

Current time: {{now}}

You may be given the last few turns of conversation for context (a user asking "what about yesterday?"
right after asking about failed logins today is asking about failed logins yesterday — resolve
pronouns and implicit references like this using the conversation, the same way a human assistant would).

Respond with ONLY a JSON object, no other text, no markdown fences, no commentary before or after:
{{"sql": "<a single read-only SELECT statement, or null if not needed>",
  "live_check": <true if this needs a live system check instead of/in addition to history, else false>,
  "reasoning": "<one short sentence>"}}

Rules:
- Only ever write SELECT statements. Never write, alter, or delete anything.
- Only reference tables/columns that exist in the schema above.
- If the question can't be answered from this schema, set "sql" to null and explain why in "reasoning".
- Never invent column names.
"""

_EXPLAINER_SYSTEM_PROMPT = """You are a security assistant explaining monitoring data to the machine's owner.

Rules:
- Only answer using the data provided below. Never invent facts, numbers, or events not present in it.
- If the data is empty, say clearly what you checked and that nothing was found — do not speculate.
- Be concise and direct, like a knowledgeable colleague, not a report generator.
- Never claim certainty about intent (e.g. "you are being hacked") — describe what the data shows and let the user judge.
- If alert rows include a "reason" field, weave it in naturally to explain WHY something matters, not just what happened.
- If alert rows include "occurrence_count" > 1, mention that it's a repeated/ongoing condition rather than a one-off.
"""

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _call_llm(system: str, messages: list, max_tokens: int = 500) -> str:
    """
    Call the NVIDIA API (OpenAI-compatible chat completions endpoint).
    Prepends the system prompt as a system message.
    Retries up to 3 times with exponential backoff on transient failures.
    """
    import time

    full_messages = [{"role": "system", "content": system}] + messages
    payload = {
        "model": config.LLM_MODEL,
        "messages": full_messages,
        "temperature": 0.7,
        "top_p": 0.95,
        "max_tokens": max_tokens,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {config.NVIDIA_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    last_err = None
    for attempt in range(3):
        try:
            resp = requests.post(config.NVIDIA_BASE_URL, headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except (requests.exceptions.RequestException, KeyError, IndexError) as e:
            last_err = e
            if attempt < 2:
                wait = 2 ** attempt  # 1s, 2s
                log.warning("NVIDIA API attempt %d failed (%s), retrying in %ds...", attempt + 1, e, wait)
                time.sleep(wait)

    raise last_err


def _extract_json(raw: str) -> dict | None:
    """
    Models occasionally wrap JSON in prose or markdown fences despite
    instructions not to. Try a strict parse first, then fall back to pulling
    out the first {...} block.
    """
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


def _build_context_messages(question: str, context: list | None) -> list:
    """
    `context` is a list of {"question": ..., "answer": ...} dicts from the
    UI's current session, most recent last. Folded into calls as prior turns
    so follow-up questions resolve correctly.
    """
    messages = []
    for turn in (context or [])[-4:]:  # last 4 turns is enough context
        q, a = turn.get("question"), turn.get("answer")
        if q:
            messages.append({"role": "user", "content": q})
        if a:
            messages.append({"role": "assistant", "content": a[:600]})
    messages.append({"role": "user", "content": question})
    return messages


# ═══════════════════════════════════════════════════════════════════
# Intent Classification (v2 — the core new piece)
# ═══════════════════════════════════════════════════════════════════

def classify_intent(question: str, context: list | None = None) -> dict:
    """
    Classify user intent into DATA_QUERY, SYSTEM_COMMAND, CONVERSATIONAL, or OUT_OF_SCOPE.
    Returns {"intent": str, "confidence": float, "reasoning": str}.
    """
    if not config.LLM_ENABLED:
        return {"intent": None, "confidence": 0, "reasoning": "LLM not configured"}

    try:
        raw = _call_llm(
            _CLASSIFIER_SYSTEM_PROMPT,
            _build_context_messages(question, context),
            max_tokens=150,
        )
    except Exception:
        log.exception("Intent classifier call failed")
        return {"intent": None, "confidence": 0, "reasoning": "LLM call failed"}

    parsed = _extract_json(raw)
    if parsed is None:
        log.warning("Classifier returned unparseable output: %s", raw[:200])
        return {"intent": None, "confidence": 0, "reasoning": "Unparseable classifier output"}

    intent = parsed.get("intent", "").upper()
    if intent not in ("DATA_QUERY", "SYSTEM_COMMAND", "CONVERSATIONAL", "OUT_OF_SCOPE"):
        log.warning("Classifier returned unknown intent: %s", intent)
        return {"intent": None, "confidence": 0, "reasoning": f"Unknown intent: {intent}"}

    return {
        "intent": intent,
        "confidence": parsed.get("confidence", 0.5),
        "reasoning": parsed.get("reasoning", ""),
    }


# ═══════════════════════════════════════════════════════════════════
# Intent Handlers
# ═══════════════════════════════════════════════════════════════════

def handle_data_query(question: str, context: list | None = None) -> dict:
    """
    Handle DATA_QUERY intent — the existing SQL planner + explainer flow.
    Returns {"answer": str, "sql": str|None, "source": str, "intent": "DATA_QUERY"}.
    """
    if not config.LLM_ENABLED:
        return {
            "answer": "The LLM query engine isn't configured (no NVIDIA_API_KEY set).",
            "sql": None, "source": "llm_unavailable", "intent": "DATA_QUERY",
        }

    # Call 1: SQL planner
    try:
        plan_raw = _call_llm(
            _PLANNER_SYSTEM_PROMPT.replace("{now}", db.now_iso()),
            _build_context_messages(question, context),
            max_tokens=300,
        )
    except Exception:
        log.exception("LLM planner call failed")
        return {
            "answer": "I couldn't reach the language model just now. Try again in a moment.",
            "sql": None, "source": "llm_error", "intent": "DATA_QUERY",
        }

    plan = _extract_json(plan_raw)
    if plan is None:
        log.warning("Planner returned unparseable output: %s", plan_raw[:200])
        return {
            "answer": "I couldn't work out how to answer that from the collected data.",
            "sql": None, "source": "llm", "intent": "DATA_QUERY",
        }

    sql = plan.get("sql")
    data_rows = []
    validated_sql = None

    if sql:
        try:
            validated_sql = validate(sql)
            data_rows = db.run_readonly_query(validated_sql)
        except SQLValidationError as e:
            log.warning("Rejected LLM-generated SQL (%s): %s", e, sql)
            return {
                "answer": "I generated a query for that but it didn't pass safety validation, so I won't run it. "
                          "Try rephrasing the question.",
                "sql": sql, "source": "llm_rejected", "intent": "DATA_QUERY",
            }
    else:
        reasoning = plan.get("reasoning")
        if reasoning and not plan.get("live_check"):
            answer = reasoning
            db.insert("query_logs", {
                "timestamp": db.now_iso(), "question": question, "sql_generated": None,
                "live_check": 0, "answer": answer, "source": "llm",
            })
            return {"answer": answer, "sql": None, "source": "llm", "intent": "DATA_QUERY"}

    # Call 2: Explainer
    explanation_input = json.dumps({
        "question": question,
        "sql_used": validated_sql,
        "rows_returned": len(data_rows),
        "data": data_rows[:50],
    }, default=str)

    try:
        answer = _call_llm(
            _EXPLAINER_SYSTEM_PROMPT,
            [{"role": "user", "content": explanation_input}],
            max_tokens=400,
        )
    except Exception:
        log.exception("LLM explainer call failed")
        return {
            "answer": "I found the data but couldn't generate an explanation just now. Try again in a moment.",
            "sql": validated_sql, "source": "llm_error", "intent": "DATA_QUERY",
        }

    db.insert("query_logs", {
        "timestamp": db.now_iso(),
        "question": question,
        "sql_generated": validated_sql,
        "live_check": 1 if plan.get("live_check") else 0,
        "answer": answer,
        "source": "llm",
    })

    return {"answer": answer, "sql": validated_sql, "source": "llm", "intent": "DATA_QUERY"}


def handle_conversational(question: str) -> dict:
    """
    Handle CONVERSATIONAL intent — greetings, thanks, capability questions.
    Uses the real CAPABILITIES list from code, not the model's general knowledge.
    """
    if not config.LLM_ENABLED:
        # Even without the LLM, give a decent static response
        return {
            "answer": f"Hello! I'm CyberSentinel, your local security monitor.\n\n"
                      f"Here's what I can do:\n{CAPABILITIES_TEXT}\n"
                      f"Ask me anything about this machine, or tell me what command to run.",
            "sql": None, "source": "conversational", "intent": "CONVERSATIONAL",
        }

    try:
        system = f"""You are CyberSentinel, a friendly local security monitoring assistant. \
Answer the user's conversational message briefly and naturally.

Here are your REAL, ACTUAL capabilities — only describe these, never overclaim:
{CAPABILITIES_TEXT}

Rules:
- Be concise, warm, and helpful.
- If the user asks what you can do, describe your real capabilities from the list above.
- Never claim abilities not listed above.
- If greeting, include a quick system status mention if natural.
- If thanked, acknowledge briefly.
"""
        answer = _call_llm(system, [{"role": "user", "content": question}], max_tokens=300)
    except Exception:
        log.exception("Conversational handler failed")
        answer = "Hello! I can answer questions about your system's security and run commands. Ask me anything!"

    return {"answer": answer, "sql": None, "source": "conversational", "intent": "CONVERSATIONAL"}


def handle_out_of_scope(question: str) -> dict:
    """
    Handle OUT_OF_SCOPE intent — politely decline with scope description.
    """
    return {
        "answer": "That's outside what I monitor. I'm focused on this machine's security and "
                  "administration — I can help with processes, ports, network activity, logins, "
                  "files, downloads, services, and running system commands. "
                  "Try asking about something on this machine!",
        "sql": None,
        "source": "out_of_scope",
        "intent": "OUT_OF_SCOPE",
    }


def handle_system_command(question: str, context: list | None = None) -> dict:
    """
    Handle SYSTEM_COMMAND intent — translate to a command template and prepare for execution.
    Returns command data for the UI to display and (optionally) confirm.
    """
    from commands.translator import translate
    from commands.executor import execute

    result = translate(question)

    if not result["success"]:
        return {
            "answer": result["error"],
            "sql": None,
            "source": "command_error",
            "intent": "SYSTEM_COMMAND",
            "command_data": None,
        }

    command_data = {
        "template_id": result["template_id"],
        "tier": result["tier"],
        "params": result["params"],
        "display_command": result["display_command"],
        "description": result["description"],
        "command_parts": result["command_parts"],
    }

    # SAFE commands: execute immediately and return output
    if result["tier"] == "SAFE":
        exec_result = execute(
            template_id=result["template_id"],
            tier=result["tier"],
            params=result["params"],
            command_parts=result["command_parts"],
            display_command=result["display_command"],
            natural_input=question,
            confirmed=True,  # SAFE commands don't need confirmation
        )
        command_data["execution"] = exec_result
        output = exec_result.get("stdout", "") or ""
        stderr = exec_result.get("stderr", "") or ""

        if exec_result["success"]:
            answer = f"Executed: `{result['display_command']}`\n\n{output.strip()}"
        else:
            answer = f"Command failed: `{result['display_command']}`\n\n{stderr.strip() or output.strip()}"

        return {
            "answer": answer,
            "sql": None,
            "source": "command",
            "intent": "SYSTEM_COMMAND",
            "command_data": command_data,
        }

    # DESTRUCTIVE commands: return the command for confirmation, do NOT execute
    else:
        answer = (
            f"⚠️ This is a **DESTRUCTIVE** command that will modify your system.\n\n"
            f"Command: `{result['display_command']}`\n"
            f"Action: {result['description']}\n\n"
            f"Please confirm to execute, or cancel."
        )
        return {
            "answer": answer,
            "sql": None,
            "source": "command_pending",
            "intent": "SYSTEM_COMMAND",
            "command_data": command_data,
        }


# ═══════════════════════════════════════════════════════════════════
# Main entry point (called by engine.py)
# ═══════════════════════════════════════════════════════════════════

def ask(question: str, context: list | None = None) -> dict:
    """
    Main LLM entry point. Classifies intent first, then routes to handler.
    This is only called when the offline cache misses.
    """
    classification = classify_intent(question, context)
    intent = classification.get("intent")

    if intent is None:
        # Classification failed — fall back to DATA_QUERY as the safest default
        log.warning("Intent classification failed, falling back to DATA_QUERY")
        return handle_data_query(question, context)

    log.info("Intent classified as %s (%.0f%% confidence): %s",
             intent, classification.get("confidence", 0) * 100,
             classification.get("reasoning", ""))

    if intent == "DATA_QUERY":
        return handle_data_query(question, context)
    elif intent == "SYSTEM_COMMAND":
        return handle_system_command(question, context)
    elif intent == "CONVERSATIONAL":
        return handle_conversational(question)
    elif intent == "OUT_OF_SCOPE":
        return handle_out_of_scope(question)
    else:
        return handle_data_query(question, context)
