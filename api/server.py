"""
api/server.py

v2 — Extended with intent-aware responses and command execution endpoint.

Endpoints:
  GET  /                serves ui/index.html
  POST /api/ask         {question, context} -> {answer, source, intent, command_data}
  POST /api/execute     {command_data, confirmed} -> {executed, stdout, stderr, ...}
  GET  /api/suggest     command-palette suggestions (now includes ⚡ Run items)
  GET  /api/status      monitor + live health snapshot
  GET  /api/feed        recent raw events across all tables
  GET  /api/alerts      recent alerts
  GET  /api/history     recent query_logs rows
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
    # session, sent by the UI so follow-up questions are understood.
    context = body.get("context")
    if context is not None and not isinstance(context, list):
        context = None
    result = engine.ask(question, context=context)
    return jsonify(result)


@app.route("/api/execute", methods=["POST"])
def api_execute():
    """
    Execute a previously-translated command after user confirmation.
    Used for DESTRUCTIVE commands that require explicit confirmation.

    Expects: {"command_data": {...}, "confirmed": true}
    The command_data must include template_id, tier, params, command_parts, display_command.
    """
    body = request.get_json(silent=True) or {}
    command_data = body.get("command_data")
    confirmed = body.get("confirmed", False)

    if not command_data:
        return jsonify({"error": "Missing 'command_data'"}), 400

    template_id = command_data.get("template_id")
    tier = command_data.get("tier")
    params = command_data.get("params", {})
    command_parts = command_data.get("command_parts")
    display_command = command_data.get("display_command")
    natural_input = command_data.get("natural_input", "")

    if not template_id or not command_parts:
        return jsonify({"error": "Invalid command_data — missing template_id or command_parts"}), 400

    if tier == "DESTRUCTIVE" and not confirmed:
        return jsonify({"error": "DESTRUCTIVE commands require confirmed=true"}), 400

    # Re-validate the template exists and params are clean
    from commands.templates import get_template, build_command
    template = get_template(template_id)
    if template is None:
        return jsonify({"error": f"Unknown template: {template_id}"}), 400

    try:
        validated_parts = build_command(template_id, params)
    except ValueError as e:
        return jsonify({"error": f"Parameter validation failed: {e}"}), 400

    # Execute
    from commands.executor import execute
    result = execute(
        template_id=template_id,
        tier=tier,
        params=params,
        command_parts=validated_parts,
        display_command=display_command,
        natural_input=natural_input,
        confirmed=confirmed,
    )
    return jsonify(result)


@app.route("/api/suggest", methods=["GET"])
def api_suggest():
    """
    Command-palette suggestions: as the user types, return matching example
    queries + descriptions. v2 adds system command suggestions with type="command".
    """
    q = request.args.get("q", "")
    limit = int(request.args.get("limit", 6))
    return jsonify(suggest_commands(q, limit=limit))


@app.route("/api/status", methods=["GET"])
def api_status():
    # Latest health snapshot
    health = db.get_recent("system_health", limit=1)

    # ── Open ports: count ports whose most recent event is 'opened' ──────────
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
