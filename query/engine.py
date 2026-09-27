"""
query/engine.py

The single entry point everything else (CLI, Flask API) calls.

v2 architecture:
  1. Try the offline pattern cache first — if a common question matches an
     exact-match regex template, answer instantly for free (no API call).
  2. If offline misses → LLM intent classification → route to the right handler.

The offline layer is now a CACHE, not the primary path. It catches the ~30
most common phrasings instantly, but anything new goes to the LLM — no
question is ever a dead end just because it doesn't match a regex.
"""

from db import database as db
from query import offline, llm
from utils.logger import get_logger

log = get_logger("query.engine")


def ask(question: str, context: list | None = None) -> dict:
    """
    `context` — optional list of recent {"question","answer"} turns from the
    current chat session (most recent last), forwarded to the LLM path so
    follow-up questions resolve correctly. The offline pattern matcher ignores
    context — it isn't conversational.
    """
    question = (question or "").strip()
    if not question:
        return {
            "answer": "Ask me something about this machine's processes, ports, network, "
                      "logins, or files — or tell me to run a command.",
            "source": "none", "sql": None, "intent": None,
        }

    # ── Fast/free cache: try offline templates for exact-match phrasings ──
    offline_answer = offline.try_offline(question)
    if offline_answer:
        db.insert("query_logs", {
            "timestamp": db.now_iso(),
            "question": question,
            "sql_generated": None,
            "live_check": 0,
            "answer": offline_answer,
            "source": "offline",
        })
        return {
            "answer": offline_answer,
            "source": "offline",
            "sql": None,
            "intent": "DATA_QUERY",  # offline templates are always data queries
        }

    # ── LLM path: intent classification → handler routing ──
    return llm.ask(question, context=context)
