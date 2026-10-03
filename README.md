# CyberSentinel — Personal Cyber Assistant

A continuously-running local security monitor for Windows that answers
plain-English questions about your own machine — "which process opened
port 8080", "did anyone try to login yesterday", "anything weird today" —
grounded entirely in data it actually collected, never invented.

Think of it as two systems working together:

```
┌─────────────────────────────────────────────────┐
│                Background Daemon                │
│  processes · ports · usb · logins · browser      │
│  startup · services · scheduled tasks · fs        │
│  network (optional) · health                      │
│                     ↓                             │
│               SQLite Database                    │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│                 Query Engine                     │
│  offline pattern match → LLM (SQL + explain) →   │
│  sql_guard validation → grounded answer          │
└─────────────────────────────────────────────────┘
                     ↓
        CLI (terminal)   or   Flask API (web UI)
```

## Install

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt --break-system-packages   # or without the flag in a venv
copy .env.example .env         # optional — only needed for the LLM query engine
```

Some monitors need extra setup:

| Monitor | Requirement |
|---|---|
| Logins | Run as **Administrator**; Windows Security auditing must be enabled |
| USB | `pip install wmi pywin32` |
| Services / Startup / Software / Scheduled tasks | Windows only, uses `winreg` / `psutil.win_service_iter` / `schtasks` |
| Network sniffer (optional, off by default) | `pip install scapy`, Npcap installed, Administrator |
| Filesystem watch | `pip install watchdog` (already in requirements.txt) |
| Desktop notifications | `pip install plyer` (already in requirements.txt) |

Every monitor is written to **fail gracefully**: if a dependency or
permission is missing, that one monitor logs a warning and sits idle —
it never crashes the rest of the daemon. Check `logs/cybersentinel.log`.

## Run

```bash
python main.py --mode cli       # terminal REPL — ask questions directly
python main.py --mode api       # starts the Flask API on :5055 for the web UI
python main.py --mode daemon    # monitors only, no interface (e.g. run as a scheduled task)
```

To use the web UI: run `--mode api`, then open
http://127.0.0.1:5055/ in the browser (the API also serves `ui/index.html`).
The UI talks to `/api/ask`, `/api/status`, `/api/feed`, `/api/alerts`,
`/api/suggest`, and `/api/execute`.

## How questions get answered

1. **Offline pattern matching** (`query/offline.py`) — regex templates for
   the ~10 most common questions, answered instantly with zero API cost.
2. **LLM query planning** (`query/llm.py`, only if `NVIDIA_API_KEY` is
   set) — for anything else, the LLM is given the exact schema and turns
   your question into SQL. This is what removes the "question ceiling":
   any phrasing, as long as the data exists, gets answered.
3. **`query/sql_guard.py`** — every LLM-generated query is validated before
   it ever touches the database: SELECT-only, single statement, whitelisted
   tables only. This is a hard security boundary, not a suggestion to the model.

## Anomaly detection (the ML component)

Rather than a heavyweight model, `process_baselines` keeps a rolling
average CPU% per process name. A new sample is flagged only once it both
crosses an absolute threshold (default 50%) **and** exceeds several times
its own historical baseline — this is what tells the difference between
"Chrome always uses 40%" and "svchost.exe never uses more than 3% and is
suddenly at 60%." Simple, explainable, and genuinely useful — a good
foundation to later swap in an Isolation Forest or z-score model per your
original ARIA-style plans without changing anything else.

## Known limitations / what to check before demoing

- **Login event field offsets** (`monitors/logins.py`) are based on current
  Windows 10/11 `StringInserts` layout. If your build differs, events are
  still stored, but `username`/`source_ip` may come back `None` — check a
  few live rows against Event Viewer once and adjust the indices if needed.
- **Network sniffer is off by default.** It's the most invasive monitor
  (raw packets, needs Npcap + admin) — turn it on with
  `CS_ENABLE_SNIFFER=true` once everything else is working.
- **DNS queries from the sniffer aren't attributed to a PID** — correlating
  a raw packet to a process requires OS-level socket-to-process mapping in
  real time, which is a meaningfully bigger feature; noted as a clean next
  step rather than silently faked.
- Chrome/Edge history files are **copied before reading** to avoid the
  "database is locked" error — if antivirus flags the temp copy, add an
  exclusion for your temp directory.

## Project structure

```
cybersentinel/
├── main.py
├── config.py
├── db/            schema.py, database.py
├── monitors/       processes, ports, usb, logins, browser, startup,
│                  installed_software, services, scheduled_tasks,
│                  filesystem, network, health
├── query/          engine.py, offline.py, llm.py, sql_guard.py
├── alerts/         notifier.py
├── cli/            repl.py
├── api/            server.py
└── utils/          logger.py
```

## Sample questions

```
which process opened port 8080?
did anyone try to login yesterday?
what's talking to the internet right now?
anything weird today?
what did I install this week?
who has been using my machine?
is port 3000 safe?
summarize today's activity
```
