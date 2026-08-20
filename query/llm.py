"""
query/llm.py

Implements Approach A from the brief: the LLM turns an arbitrary natural
language question into SQL against our known schema, we run it (through
sql_guard first — always), and a second LLM call explains the results in
plain English. This is what gives the assistant its "no question ceiling"
property — anything answerable from the collected data can be asked in any
phrasing, not just the ~30 phrasings the offline regex layer recognizes.

Two calls, not one, and each is single-purpose:
  Call 1: schema + question (+ recent conversation) -> {sql, live_check, reasoning}
  Call 2: question + real data -> plain-English explanation   (grounded)

The system prompt for call 2 explicitly forbids the model from adding
anything not present in the data it was given, to prevent hallucination.

Conversation context: the UI keeps chat history client-side and sends the
last few Q&A pairs with each request. Without this, "what about yesterday?"
as a follow-up to "any failed logins today?" is unanswerable — the planner
has no idea what "yesterday" refers back to. This is real, not decorative:
it's what makes the assistant actually *understand language* across a
conversation rather than treat every message as an isolated query.
"""

import json
import re

import config
from db import database as db
from db.schema import SCHEMA_TEXT
from query.sql_guard import validate, SQLValidationError
from utils.logger import get_logger

log = get_logger("query.llm")

try:
    import anthropic
    _client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY) if config.LLM_ENABLED else None
except ImportError:
    _client = None

_PLANNER_SYSTEM_PROMPT = f"""You are a query planner for a personal cybersecurity monitoring assistant \
running on the user's own machine.

You have access to this SQLite schema (read-only):
{SCHEMA_TEXT}

The `alerts` table has a `reason` column explaining WHY a category of alert matters in general, and
`occurrence_count` showing how many times a deduplicated condition has repeated — include these when
a question is about threats/alerts/danger.

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
- If the question is conversational (greeting, thanks, unrelated to this machine), set "sql" to null.
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


def _call_claude(system: str, messages: list, max_tokens: int = 500) -> str:
    response = _client.messages.create(
        model=config.LLM_MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=messages,
    )
    return "".join(block.text for block in response.content if block.type == "text")


def _extract_json(raw: str) -> dict | None:
    """
    Models occasionally wrap JSON in prose or markdown fences despite
    instructions not to. Try a strict parse first, then fall back to pulling
    out the first {...} block, rather than failing the whole turn over
    formatting noise.
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
    UI's current session, most recent last. Folded into the planner call as
    prior turns so follow-up questions resolve correctly.
    """
    messages = []
    for turn in (context or [])[-4:]:  # last 4 turns is enough context, keeps the call cheap
        q, a = turn.get("question"), turn.get("answer")
        if q:
            messages.append({"role": "user", "content": q})
        if a:
            messages.append({"role": "assistant", "content": a[:600]})  # cap length
    messages.append({"role": "user", "content": question})
    return messages


def ask(question: str, context: list | None = None) -> dict:
    """
    Returns {"answer": str, "sql": str|None, "source": "llm"}.
    `context` — optional list of recent {"question","answer"} turns from the
    current chat session, used so follow-up questions are understood.
    """
    if _client is None:
        return {
            "answer": "The LLM query engine isn't configured (no ANTHROPIC_API_KEY set), "
                      "so I can only answer questions that match a known pattern. Add your key "
                      "to .env to unlock free-form natural language questions.",
            "sql": None,
            "source": "llm_unavailable",
        }

    try:
        plan_raw = _call_claude(
            _PLANNER_SYSTEM_PROMPT.format(now=db.now_iso()),
            _build_context_messages(question, context),
            max_tokens=300,
        )
    except Exception:
        log.exception("LLM planner call failed")
        return {"answer": "I couldn't reach the language model just now. Try again in a moment.",
                "sql": None, "source": "llm_error"}

    plan = _extract_json(plan_raw)
    if plan is None:
        log.warning("Planner returned unparseable output: %s", plan_raw[:200])
        return {"answer": "I couldn't work out how to answer that from the collected data.", "sql": None, "source": "llm"}

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
                "sql": sql,
                "source": "llm_rejected",
            }
    else:
        reasoning = plan.get("reasoning")
        if reasoning and not plan.get("live_check"):
            # Planner decided no DB query applies (e.g. small talk, or genuinely
            # unanswerable) — still worth a grounded, conversational reply.
            answer = reasoning
            db.insert("query_logs", {
                "timestamp": db.now_iso(), "question": question, "sql_generated": None,
                "live_check": 0, "answer": answer, "source": "llm",
            })
            return {"answer": answer, "sql": None, "source": "llm"}

    explanation_input = json.dumps({
        "question": question,
        "sql_used": validated_sql,
        "rows_returned": len(data_rows),
        "data": data_rows[:50],  # cap payload size
    }, default=str)

    try:
        answer = _call_claude(_EXPLAINER_SYSTEM_PROMPT, [{"role": "user", "content": explanation_input}], max_tokens=400)
    except Exception:
        log.exception("LLM explainer call failed")
        return {"answer": "I found the data but couldn't generate an explanation just now. Try again in a moment.",
                "sql": validated_sql, "source": "llm_error"}

    db.insert("query_logs", {
        "timestamp": db.now_iso(),
        "question": question,
        "sql_generated": validated_sql,
        "live_check": 1 if plan.get("live_check") else 0,
        "answer": answer,
        "source": "llm",
    })

    return {"answer": answer, "sql": validated_sql, "source": "llm"}
