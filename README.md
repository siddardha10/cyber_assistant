# CyberSentinel

CyberSentinel is a local personal cyber assistant for Windows. It continuously
collects system activity, stores it in a local database, and lets you ask
plain-English questions such as:

- Which process opened port 8080?
- Did anyone try to log in yesterday?
- What changed on my machine today?
- Is anything suspicious running right now?
- What software did I install this week?

The project is designed to answer questions using data it has actually
collected on your machine instead of guessing.

## What it does

CyberSentinel runs background monitors for common security and system signals,
including:

- running processes
- open ports
- USB device activity
- login events
- browser activity
- startup entries
- installed software
- services and scheduled tasks
- filesystem changes
- network activity (optional)
- health checks and alerts

It stores the collected data in a SQLite database and answers questions through
an offline query system and optional LLM-backed query planning.

## How it works

CyberSentinel combines:

1. Offline detection for common questions
2. Optional local LLM query planning for more flexible natural-language
   questions
3. Query validation to restrict database access to safe SQL patterns
4. A CLI and a web UI for interaction

## Project layout

```text
cyber_assistant/
├── main.py
├── config.py
├── requirements.txt
├── .env.example
├── README.md
├── alerts/
├── api/
├── cli/
├── commands/
├── db/
├── monitors/
├── query/
├── ui/
├── utils/
├── test_command_engine.py
├── test_intent_router.py
├── test_ollama_queries.py
├── test_reliability.py
└── data/
```

## Requirements

- Python 3.10+
- Windows 10/11 (recommended)
- Administrator rights for some monitors (login auditing, service and system
  collection, certain Windows APIs)

## Installation

Open a terminal in the project folder and run:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

The `.env` file is optional, but it is useful if you want to enable or adjust
advanced settings such as the LLM model, API port, filesystem watch, alerts, and
monitor intervals.

## Optional setup for advanced features

Some monitors and features need extra setup:

- Logins: run as Administrator and enable Windows logon auditing:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

- USB / Windows-specific integrations: these are handled by Windows packages in
  the requirements file and may require admin access.
- Filesystem watcher: already included in the requirements file.
- Desktop notifications: already included in the requirements file.
- Raw packet capture for network monitoring: optional and disabled by default;
  requires Npcap and Administrator rights.
- Local LLM support: install and run Ollama, then pull the required models:

```bash
ollama serve
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
```

## Running the app

Start the app in CLI mode:

```bash
python main.py --mode cli
```

Start the web API and UI:

```bash
python main.py --mode api
```

Then open:

```text
http://127.0.0.1:5055/
```

Run the monitors without an interface:

```bash
python main.py --mode daemon
```

## Example questions

```text
which process opened port 8080?
did anyone try to login yesterday?
what's talking to the internet right now?
anything weird today?
what did I install this week?
who has been using my machine?
```

## Environment configuration

A sample configuration is included in `.env.example`. It defines settings for:

- database path
- API host and port
- LLM endpoint and model choice
- feature toggles
- monitor intervals
- alert thresholds
- logging behavior

If you do not want to use an LLM, CyberSentinel still runs in offline mode using
its built-in logic and local rules.

## Notes

- The app is intended for personal/local use.
- Some features depend on Windows-specific permissions and APIs.
- The project is designed to fail gracefully: if a monitor is unavailable or a
  dependency is missing, it logs a warning instead of crashing the rest of the
  system.

## License

This project is distributed as-is for local security and monitoring use. Check
your environment and legal requirements before running monitoring tools on any
machine that is not yours or that you do not have permission to inspect.
