"""
cli/repl.py

Interactive terminal shell. Runs alongside the background monitor threads
(started by main.py) in the same process.
"""

from rich.console import Console
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live

from query import engine
from db import database as db

console = Console()

_HELP = """
Commands:
  help              show this message
  alerts            show the 10 most recent alerts
  clear             clear the screen
  exit / quit       stop CyberSentinel

Otherwise, just type your question in plain English, e.g.:
  which process opened port 8080?
  did anyone try to login yesterday?
  anything weird today?
"""


def _print_banner():
    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — local machine watch\n"
        "Type a question, or 'help' for commands.",
        border_style="cyan",
    ))


def _show_alerts():
    rows = db.get_recent("alerts", limit=10)
    if not rows:
        console.print("[dim]No alerts recorded yet.[/dim]")
        return
    for r in rows:
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(r["severity"], "white")
        console.print(f"[{color}]{r['timestamp']} [{r['severity']}] {r['category']}[/{color}] — {r['message']}")


def run():
    _print_banner()
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

        with console.status("[cyan]thinking…[/cyan]", spinner="dots"):
            result = engine.ask(question)

        console.print(Panel(result["answer"], border_style="green", title=f"[dim]{result['source']}[/dim]", title_align="right"))
