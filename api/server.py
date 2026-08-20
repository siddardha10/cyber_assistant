"""
api/server.py

Thin Flask layer over the exact same query engine the CLI uses — nothing
about the backend changes to support the web UI, per the original plan.

Endpoints:
  GET  /                serves ui/index.html (so the UI avoids CORS issues)
  POST /api/ask         {"question": "..."} -> {"answer": ..., "source": ...}
  GET  /api/status      monitor + live health snapshot (for the sidebar/metrics)
  GET  /api/feed        recent raw events across all tables (for the pulse feed)
  GET  /api/alerts      recent alerts
  GET  /api/history     recent query_logs rows (for the session history sidebar)
"""

from pathlib import Path

from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS

import config
from db import database as db
from query import engine
from query.catalog import suggest as suggest_commands
from utils.logger import get_logger

log = get_logger("api.server")

UI_FILE = Path(__file__).resolve().parent.parent / "ui" / "index.html"

app = Flask(__name__)
CORS(app)  # required for file:// access during development; harmless for local use


@app.route("/")
def index():
    """Serve the UI with no-cache headers so edits are always reflected."""
    if UI_FILE.exists():
        resp = make_response(send_file(str(UI_FILE)))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    return (
        "<h2>UI not found</h2>"
        "<p>Expected <code>ui/index.html</code> next to this package. "
        "Run <code>python main.py --mode api</code> from the project root.</p>",
        404,
    )


@app.route("/api/ask", methods=["POST"])
def api_ask():
    body = request.get_json(silent=True) or {}
    question = body.get("question", "")
    if not question:
        return jsonify({"error": "Missing 'question'"}), 400
    # `context` — recent {"question","answer"} turns from the current chat
    # session, sent by the UI so follow-up questions ("what about
    # yesterday?") are understood by the LLM path instead of treated as
    # an isolated, context-free query.
    context = body.get("context")
    if context is not None and not isinstance(context, list):
        context = None
    result = engine.ask(question, context=context)
    return jsonify(result)


@app.route("/api/suggest", methods=["GET"])
def api_suggest():
    """
    Command-palette suggestions: as the user types, return matching example
    queries + descriptions so they can pick one instead of needing to know
    exact phrasing — the terminal-with-tab-completion behavior, but for
    natural language.
    """
    q = request.args.get("q", "")
    limit = int(request.args.get("limit", 6))
    return jsonify(suggest_commands(q, limit=limit))


@app.route("/api/status", methods=["GET"])
def api_status():
    # Latest health snapshot
    health = db.get_recent("system_health", limit=1)

    # ── Open ports: count ports whose most recent event is 'opened' ──────────
    # We use a subquery to find the latest event per (port, pid) pair and then
    # count only those that are still 'opened'.  This is correct even after
    # ports are closed, unlike a simple COUNT of all 'opened' rows.
    open_ports_rows = db.run_readonly_query(
        """
        SELECT COUNT(*) AS c FROM (
            SELECT port, pid, protocol,
                   event,
                   ROW_NUMBER() OVER (PARTITION BY port, pid ORDER BY timestamp DESC) AS rn
            FROM port_snapshots
        ) latest
        WHERE rn = 1 AND event = 'opened'
        """
    )

    alerts_24h = db.run_readonly_query(
        "SELECT COUNT(*) as c FROM alerts WHERE timestamp >= datetime('now', '-1 day')"
    )

    # Disk usage from most recent health row
    disk_pct = health[0]["disk_pct"] if health else None

    return jsonify({
        "cpu_pct":    health[0]["cpu_pct"] if health else None,
        "mem_pct":    health[0]["mem_pct"] if health else None,
        "disk_pct":   disk_pct,
        "open_ports": open_ports_rows[0]["c"] if open_ports_rows else 0,
        "alerts_24h": alerts_24h[0]["c"] if alerts_24h else 0,
        "llm_enabled": config.LLM_ENABLED,
    })


@app.route("/api/feed", methods=["GET"])
def api_feed():
    limit = int(request.args.get("limit", 40))
    tables = [
        "process_snapshots", "port_snapshots", "usb_events", "login_events",
        "downloads", "alerts", "startup_entries", "services",
        "filesystem_events", "dns_queries", "system_health",
    ]
    events = []
    for t in tables:
        try:
            for row in db.get_recent(t, limit=8):
                # Tag every row with its source table so the UI can render it
                events.append({"table": t, **row})
        except Exception:
            log.exception("Feed: failed to query %s", t)

    events.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return jsonify(events[:limit])


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    limit = int(request.args.get("limit", 20))
    return jsonify(db.get_recent("alerts", limit=limit))


@app.route("/api/history", methods=["GET"])
def api_history():
    """
    Returns recent query_log rows for the session history sidebar.
    Each row has at minimum: id, timestamp, question, answer, source.
    """
    limit = int(request.args.get("limit", 10))
    rows = db.run_readonly_query(
        """
        SELECT id, timestamp, question, answer, source
        FROM query_logs
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    )
    return jsonify(rows)


def run():
    log.info("API server starting on http://%s:%s", config.API_HOST, config.API_PORT)
    log.info("UI available at http://%s:%s/", config.API_HOST, config.API_PORT)
    app.run(host=config.API_HOST, port=config.API_PORT, debug=False, use_reloader=False)
