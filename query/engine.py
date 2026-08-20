"""
query/engine.py

The single entry point everything else (CLI, Flask API) calls. Tries the
free/offline pattern matcher first; only reaches for the LLM if nothing
matched and a key is configured. This keeps the common questions instant
and free, while still giving the "ask literally anything" capability.
"""

from db import database as db
from query import offline, llm
from utils.logger import get_logger

log = get_logger("query.engine")


def ask(question: str, context: list | None = None) -> dict:
    """
    `context` — optional list of recent {"question","answer"} turns from the
    current chat session (most recent last), forwarded to the LLM path so
    follow-up questions ("what about yesterday?") resolve correctly. The
    offline pattern matcher ignores context — it isn't conversational.
    """
    question = (question or "").strip()
    if not question:
        return {"answer": "Ask me something about this machine's processes, ports, network, logins, or files.",
                "source": "none", "sql": None}

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
        return {"answer": offline_answer, "source": "offline", "sql": None}

    return llm.ask(question, context=context)
