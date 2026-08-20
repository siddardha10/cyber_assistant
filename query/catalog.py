"""
query/catalog.py

Powers the "command prompt" style suggestion feature: as the user types,
the UI shows matching example queries with a short description of what
each does — like a terminal's tab-completion, but for natural language
instead of exact command syntax. The user never needs to know exact
phrasing; they can type a fragment of what they mean and pick a suggestion,
or just keep typing their own words (both paths reach query/engine.py).

Kept as a plain Python list rather than pulling categories out of
offline.py's docstrings so this can be curated independently — not every
regex pattern makes a good suggestion (some are meant to catch phrasing
variants, not be shown to the user).
"""

import difflib

CATALOG = [
    {"category": "Threats", "text": "what are the threats?", "desc": "Full alert summary with severity breakdown and why each matters"},
    {"category": "Threats", "text": "am I safe right now?", "desc": "Quick security status check"},
    {"category": "Ports", "text": "list open ports", "desc": "Every currently listening port and its owning process"},
    {"category": "Ports", "text": "which process opened port 8080?", "desc": "Trace a specific port to the process that owns it"},
    {"category": "Ports", "text": "is port 3000 safe?", "desc": "Check whether a specific port is open and what's using it"},
    {"category": "Processes", "text": "what processes are running?", "desc": "Current process list with CPU and memory"},
    {"category": "Processes", "text": "why is my CPU high?", "desc": "Top resource-consuming processes right now"},
    {"category": "Processes", "text": "any CPU anomalies?", "desc": "Processes running hot relative to their own baseline"},
    {"category": "Network", "text": "what's talking to the internet right now?", "desc": "Live outbound connections by process"},
    {"category": "Network", "text": "recent DNS queries", "desc": "Domains this machine has resolved recently"},
    {"category": "Logins", "text": "did anyone try to login yesterday?", "desc": "Failed and successful login attempts for a given day"},
    {"category": "Logins", "text": "any failed logins?", "desc": "Recent failed login attempts, flagged if it looks like a burst"},
    {"category": "Logins", "text": "who has been using my machine?", "desc": "Users seen logging in over the last 7 days"},
    {"category": "USB", "text": "any USB devices connected?", "desc": "Recent USB insert/remove events"},
    {"category": "Downloads", "text": "what did I download?", "desc": "Recent downloads across every browser (Chrome, Edge, Brave, Opera, Firefox)"},
    {"category": "Downloads", "text": "any risky downloads?", "desc": "Executables or scripts downloaded recently"},
    {"category": "Software", "text": "what did I install this week?", "desc": "New software installed in the last 7 days"},
    {"category": "Startup", "text": "show startup entries", "desc": "Everything set to launch automatically at boot/login"},
    {"category": "Services", "text": "windows services", "desc": "Services that changed recently, especially new auto-start ones"},
    {"category": "Files", "text": "any file changes?", "desc": "Recent activity in watched folders (Downloads, Desktop)"},
    {"category": "Scheduled tasks", "text": "any new scheduled tasks?", "desc": "Tasks added to Windows Task Scheduler recently"},
    {"category": "Health", "text": "is my system healthy?", "desc": "Current CPU, memory, and disk usage"},
    {"category": "Summary", "text": "anything weird today?", "desc": "Full daily activity summary across every monitor"},
    {"category": "Summary", "text": "summarize today's activity", "desc": "New processes, ports, logins, and alerts in the last 24h"},
    {"category": "Help", "text": "what can you answer?", "desc": "Full list of question categories this assistant understands"},
]


def suggest(query: str, limit: int = 6) -> list:
    """
    Returns up to `limit` catalog entries ranked by relevance to `query`.
    Empty/short query returns a default "starter" set spanning categories
    rather than nothing, so the palette is useful even before typing.
    """
    query = (query or "").strip().lower()
    if len(query) < 2:
        # one representative example per major category, for the empty-input state
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
            score = 1.0  # substring match in the actual phrase — best signal
        else:
            score = difflib.SequenceMatcher(None, query, haystack).ratio()
            for qw in query_words:
                if len(qw) < 3:
                    continue
                if qw in haystack:
                    score += 0.2
                else:
                    # typo tolerance: does this query word closely match any word in the entry?
                    close = difflib.get_close_matches(qw, entry_words, n=1, cutoff=0.75)
                    if close:
                        score += 0.15
        scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = [entry for score, entry in scored if score > 0.25][:limit]
    return results or CATALOG[:limit]
