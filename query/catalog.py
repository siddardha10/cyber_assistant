"""
query/catalog.py

Powers the command-palette suggestion dropdown. v2 adds system command
suggestions alongside data query suggestions, with distinct labels so the
user always knows whether a suggestion will QUERY data or RUN a command.

Each entry has:
  - category: display category
  - text: the example phrase
  - desc: short description
  - type: "query" (data question) or "command" (system command)
"""

import difflib

CATALOG = [
    # ── Data Queries (📊 Ask) ─────────────────────────────────────
    {"category": "Threats", "text": "what are the threats?", "desc": "Full alert summary with severity breakdown and why each matters", "type": "query"},
    {"category": "Threats", "text": "am I safe right now?", "desc": "Quick security status check", "type": "query"},
    {"category": "Ports", "text": "list open ports", "desc": "Every currently listening port and its owning process", "type": "query"},
    {"category": "Ports", "text": "which process opened port 8080?", "desc": "Trace a specific port to the process that owns it", "type": "query"},
    {"category": "Ports", "text": "is port 3000 safe?", "desc": "Check whether a specific port is open and what's using it", "type": "query"},
    {"category": "Processes", "text": "what processes are running?", "desc": "Current process list with CPU and memory", "type": "query"},
    {"category": "Processes", "text": "why is my CPU high?", "desc": "Top resource-consuming processes right now", "type": "query"},
    {"category": "Processes", "text": "any CPU anomalies?", "desc": "Processes running hot relative to their own baseline", "type": "query"},
    {"category": "Network", "text": "what's talking to the internet right now?", "desc": "Live outbound connections by process", "type": "query"},
    {"category": "Network", "text": "recent DNS queries", "desc": "Domains this machine has resolved recently", "type": "query"},
    {"category": "Logins", "text": "did anyone try to login yesterday?", "desc": "Failed and successful login attempts for a given day", "type": "query"},
    {"category": "Logins", "text": "any failed logins?", "desc": "Recent failed login attempts, flagged if it looks like a burst", "type": "query"},
    {"category": "Logins", "text": "who has been using my machine?", "desc": "Users seen logging in over the last 7 days", "type": "query"},
    {"category": "USB", "text": "any USB devices connected?", "desc": "Recent USB insert/remove events", "type": "query"},
    {"category": "Downloads", "text": "what did I download?", "desc": "Recent downloads across every browser", "type": "query"},
    {"category": "Downloads", "text": "any risky downloads?", "desc": "Executables or scripts downloaded recently", "type": "query"},
    {"category": "Software", "text": "what did I install this week?", "desc": "New software installed in the last 7 days", "type": "query"},
    {"category": "Startup", "text": "show startup entries", "desc": "Everything set to launch automatically at boot/login", "type": "query"},
    {"category": "Services", "text": "windows services", "desc": "Services that changed recently, especially new auto-start ones", "type": "query"},
    {"category": "Files", "text": "any file changes?", "desc": "Recent activity in watched folders (Downloads, Desktop)", "type": "query"},
    {"category": "Scheduled tasks", "text": "any new scheduled tasks?", "desc": "Tasks added to Windows Task Scheduler recently", "type": "query"},
    {"category": "Health", "text": "is my system healthy?", "desc": "Current CPU, memory, and disk usage", "type": "query"},
    {"category": "Summary", "text": "anything weird today?", "desc": "Full daily activity summary across every monitor", "type": "query"},
    {"category": "Summary", "text": "summarize today's activity", "desc": "New processes, ports, logins, and alerts in the last 24h", "type": "query"},
    {"category": "History", "text": "what commands have I run recently?", "desc": "Recent command execution log", "type": "query"},
    {"category": "Help", "text": "what can you do?", "desc": "Full list of capabilities this assistant has", "type": "query"},

    # ── System Commands (⚡ Run) ──────────────────────────────────
    {"category": "⚡ Files", "text": "list files in my Downloads folder", "desc": "Run 'dir' on your Downloads directory", "type": "command"},
    {"category": "⚡ Files", "text": "show the contents of a file", "desc": "Display a text file with 'type'", "type": "command"},
    {"category": "⚡ Files", "text": "search for a file by name", "desc": "Find files using 'where /r'", "type": "command"},
    {"category": "⚡ Files", "text": "search inside files for a string", "desc": "Search with 'findstr'", "type": "command"},
    {"category": "⚡ System", "text": "what's my computer name?", "desc": "Run 'hostname'", "type": "command"},
    {"category": "⚡ System", "text": "show system information", "desc": "Run 'systeminfo' for hardware and OS details", "type": "command"},
    {"category": "⚡ System", "text": "who am I logged in as?", "desc": "Run 'whoami'", "type": "command"},
    {"category": "⚡ Network", "text": "ping google.com", "desc": "Test network connectivity with ping", "type": "command"},
    {"category": "⚡ Network", "text": "show my IP address", "desc": "Run 'ipconfig /all'", "type": "command"},
    {"category": "⚡ Network", "text": "trace route to a host", "desc": "Run 'tracert' to map the network path", "type": "command"},
    {"category": "⚡ Network", "text": "lookup DNS for a domain", "desc": "Run 'nslookup'", "type": "command"},
    {"category": "⚡ Network", "text": "show active connections", "desc": "Run 'netstat -ano'", "type": "command"},
    {"category": "⚡ Processes", "text": "list all running processes", "desc": "Run 'tasklist'", "type": "command"},
    {"category": "⚡ Processes", "text": "find a process by name", "desc": "Run 'tasklist /fi'", "type": "command"},
    {"category": "⚡ Processes", "text": "kill a process by name", "desc": "Run 'taskkill' (requires confirmation)", "type": "command"},
    {"category": "⚡ Services", "text": "list all Windows services", "desc": "Run 'sc query'", "type": "command"},
    {"category": "⚡ Services", "text": "check status of a service", "desc": "Query a specific Windows service", "type": "command"},
    {"category": "⚡ Disk", "text": "show disk space", "desc": "Show drive sizes and free space", "type": "command"},
    {"category": "⚡ Tasks", "text": "list scheduled tasks", "desc": "Run 'schtasks /query'", "type": "command"},
]


def suggest(query: str, limit: int = 6) -> list:
    """
    Returns up to `limit` catalog entries ranked by relevance to `query`.
    Empty/short query returns a default "starter" set spanning categories.
    """
    query = (query or "").strip().lower()
    if len(query) < 2:
        # Mix of query and command suggestions for the empty state
        seen_categories = set()
        starters = []
        for entry in CATALOG:
            if entry["category"] not in seen_categories:
                starters.append(entry)
                seen_categories.add(entry["category"])
            if len(starters) >= limit:
                break
        return starters

    scored = []
    query_words = query.split()
    for entry in CATALOG:
        text_lower = entry["text"].lower()
        haystack = f"{entry['category']} {text_lower} {entry['desc']}".lower()
        entry_words = haystack.split()

        if query in text_lower:
            score = 1.0
        else:
            score = difflib.SequenceMatcher(None, query, haystack).ratio()
            for qw in query_words:
                if len(qw) < 3:
                    continue
                if qw in haystack:
                    score += 0.2
                else:
                    close = difflib.get_close_matches(qw, entry_words, n=1, cutoff=0.75)
                    if close:
                        score += 0.15
        scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = [entry for score, entry in scored if score > 0.25][:limit]
    return results or CATALOG[:limit]
