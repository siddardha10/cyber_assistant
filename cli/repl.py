"""
cli/repl.py

Interactive terminal shell. Runs alongside the background monitor threads
(started by main.py) in the same process.
"""

from rich.console import Console
from rich.panel import Panel

from query import engine
from db import database as db

console = Console()

_HELP = """
Commands:
  help              show this message
  alerts            show active (undismissed) alerts
  dismiss <id>      mark an alert as handled — it drops from threat level
  clear             clear the screen
  exit / quit       stop CyberSentinel

Otherwise, type a question or a command in plain English, e.g.:
  which process opened port 8080?
  did anyone try to login yesterday?
  ping google.com
  anything weird today?
"""

_CONTEXT_TURNS = 4


def _print_banner():
    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — local machine watch\n"
        "Type a question, or 'help' for commands.",
        border_style="cyan",
    ))


def _show_alerts():
    rows = db.run_readonly_query(
        """
        SELECT id, timestamp, category, severity, message, reason
        FROM alerts
        WHERE COALESCE(acknowledged, 0) = 0
        ORDER BY timestamp DESC, id DESC
        LIMIT 10
        """
    )
    if not rows:
        console.print("[dim]No active alerts.[/dim]")
        return
    for r in rows:
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(r["severity"], "white")
        console.print(
            f"[{color}]#{r['id']} {r['timestamp']} [{r['severity']}] "
            f"{r['category']}[/{color}] — {r['message']}"
        )
    console.print("[dim]Dismiss with: dismiss <id>[/dim]")


def _dismiss_alert(alert_id: int):
    if db.acknowledge_alert(alert_id):
        console.print(f"[cyan]Alert #{alert_id} dismissed — it no longer counts toward threat level.[/cyan]")
    else:
        console.print(f"[red]No alert with id {alert_id}.[/red]")


def _run_confirmed(command_data: dict) -> dict:
    from commands.templates import get_template, build_command
    from commands.executor import execute

    template_id = command_data.get("template_id")
    if get_template(template_id) is None:
        return {"success": False, "error": f"Unknown template: {template_id}"}
    try:
        validated_parts = build_command(template_id, command_data.get("params") or {})
    except ValueError as e:
        return {"success": False, "error": str(e)}
    return execute(
        template_id=template_id,
        tier=command_data.get("tier"),
        params=command_data.get("params") or {},
        command_parts=validated_parts,
        display_command=command_data.get("display_command"),
        natural_input=command_data.get("natural_input") or "",
        confirmed=True,
    )


def _handle_pending_command(result: dict) -> str:
    cd = result.get("command_data") or {}
    display = cd.get("display_command") or ""
    console.print(Panel(
        f"[bold red]DESTRUCTIVE[/bold red] — this will modify the system.\n\n"
        f"[bold]{display}[/bold]\n{cd.get('description') or ''}\n\n"
        f"Type [bold]yes[/bold] to execute, anything else to cancel.",
        border_style="red",
        title="confirmation required",
    ))
    try:
        reply = console.input("[bold red]confirm>[/bold red] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Cancelled.[/dim]")
        return "Command cancelled."
    if reply not in ("y", "yes"):
        console.print("[dim]Cancelled.[/dim]")
        return "Command cancelled."
    with console.status("[cyan]executing…[/cyan]", spinner="dots"):
        exec_result = _run_confirmed(cd)
    if exec_result.get("success"):
        out = (exec_result.get("stdout") or "").strip() or "(no output)"
        return f"Executed: `{display}`\n\n{out}"
    err = exec_result.get("failure_reason") or exec_result.get("stderr") or exec_result.get("error") or "failed"
    return f"Command failed: `{display}`\n\n{err}"


def run():
    _print_banner()
    context: list[dict] = []
    while True:
        try:
            question = console.input("\n[bold cyan]you>[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting.[/dim]")
            break

        if not question:
            continue
        lowered = question.lower()

        if lowered in ("exit", "quit"):
            console.print("[dim]Exiting.[/dim]")
            break
        if lowered == "help":
            console.print(_HELP)
            continue
        if lowered == "clear":
            console.clear()
            continue
        if lowered == "alerts":
            _show_alerts()
            continue
        if lowered.startswith("dismiss "):
            raw_id = lowered.split(None, 1)[1].strip().lstrip("#")
            if raw_id.isdigit():
                _dismiss_alert(int(raw_id))
            else:
                console.print("[red]Usage: dismiss <alert id>[/red]")
            continue

        with console.status("[cyan]thinking…[/cyan]", spinner="dots"):
            result = engine.ask(question, context=context[-_CONTEXT_TURNS:] or None)

        answer = result.get("answer") or ""
        source = result.get("source") or ""

        if source == "command_pending" and result.get("command_data"):
            answer = _handle_pending_command(result)
            source = "command"

        console.print(Panel(answer, border_style="green", title=f"[dim]{source}[/dim]", title_align="right"))
        context.append({"question": question, "answer": answer})
        if len(context) > _CONTEXT_TURNS * 2:
            context = context[-_CONTEXT_TURNS:]
