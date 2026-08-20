# CyberSentinel — Update Changelog

This update addresses 5 requested changes plus 3 real bugs found while
testing against your actual `data/cybersentinel.db`. Every fix below was
verified by running real code against your real data or a live headless
browser — not just read through.

---

## 1. Recents show history, but you can't continue typing into them

**Before:** viewing a past chat quietly started a brand-new session the
moment you typed anything — easy to miss, and you could end up "continuing"
a conversation you thought was historical.

**Now:** clicking a history item locks the input box (`disabled`, greyed
placeholder: *"Viewing a past chat — click 'New inquiry' to ask a
question"*) and disables the send button. A **"Start a new inquiry"**
button appears at the bottom of the history view. You cannot type into a
past conversation — full stop, not just discouraged.

Files: `ui/index.html` (`showSessionChat`, `newSession`, `sendMsg`)

---

## 2. Downloads now show every browser, not just Edge

**Root cause found:** `db.now_iso()` only had second-level timestamp
precision. Every download inserted during one monitor cycle shared the same
timestamp, so `ORDER BY timestamp DESC` fell back to storage order for
ties — and since Chrome (194 downloads) was scanned before Edge/Opera in
the monitor loop, Edge/Opera's later-inserted rows won the `LIMIT 20` cutoff
every time. Confirmed by querying your actual database directly.

**Fixes:**
- `db.now_iso()` now uses microsecond precision — ties across an entire
  monitor cycle are far less likely.
- `db.get_recent()` adds `id DESC` as an explicit tiebreaker everywhere.
- The `_downloads` offline query template now fetches the top N **per
  browser** (via `ROW_NUMBER() OVER (PARTITION BY browser ...)`) and merges
  the results, so every browser with downloads is guaranteed to appear —
  not just whichever one happened to be scanned last. It also reports an
  explicit per-browser breakdown, e.g. *"chrome: 194, edge: 50, opera: 2"*.

Tested against your real database — confirmed Chrome, Edge, and Opera all
now appear correctly.

Files: `db/database.py`, `query/offline.py`

---

## 3. Real AI/NLU integration

**Finding:** `query/llm.py` was already fully built, but **inactive** — no
`.env` file existed, so every answer was regex pattern-matching against
`query/offline.py`'s ~30 templates, not real language understanding.
Anything phrased differently than those templates got a dead end.

**What changed:**
- The LLM path (`query/llm.py`) now accepts **conversation context** — the
  UI sends your last 4 Q&A turns with each request, so follow-ups like
  *"what about yesterday?"* right after asking about failed logins today
  are actually understood, not treated as an isolated question.
- More robust JSON parsing — if the model wraps its response in prose or
  markdown fences despite instructions, a fallback extractor pulls the JSON
  block out instead of failing the whole turn.
- Conversational questions (greetings, "thanks", genuinely unanswerable
  questions) now get a direct grounded reply instead of an empty query.
- **To activate:** copy `.env.example` to `.env` and add your
  `ANTHROPIC_API_KEY`. Until then, offline patterns still work exactly as
  before — this doesn't remove any existing functionality.

Files: `query/llm.py`, `query/engine.py`, `api/server.py`, `ui/index.html`

---

## 4. Threat level now shows *why*

**Two real problems found in your data, not just a missing feature:**

- **140 of your 197 stored alerts were false positives.** The very first
  browser monitor scan treated your entire historical download backlog
  (months of old installers) as "new," alerting every `.exe`/`.msi` as
  risky in one burst. `browser.py` was missing the baseline-scan guard that
  `startup.py`/`processes.py` already had correctly.
- **No alert deduplication existed anywhere.** A sustained CPU spike fired
  a brand-new alert row every single monitor cycle it remained true — one
  real event visually became many, inflating the threat level.

**Fixes:**
- `alerts` table gains `reason`, `dedup_key`, `occurrence_count`,
  `last_seen` columns, applied via automatic migration — **your existing
  database upgrades in place, no data loss.**
- Every `insert_alert()` call across all 9 monitors now includes a `reason`
  — the general "why this category of event matters," separate from the
  specific message (e.g. not just "new auto-start service: X" but *why*
  auto-start services are worth noticing at all).
- Repeated alerts with the same `dedup_key` within a 15-minute window
  (configurable via `CS_ALERT_DEDUP_WINDOW_MIN`) collapse into one row with
  a rising `occurrence_count` instead of flooding the table. Verified: 5
  simulated repeats of the same condition correctly collapsed to 1 row.
- `browser.py` no longer alerts on the first-scan historical backlog (still
  stores it — that's useful download history — just doesn't treat it as a
  fresh security event).
- The UI's threat tooltip now shows a **"Why:"** line under each alert, and
  an occurrence badge (×N) when a condition has repeated.

Files: `db/schema.py`, `db/database.py`, all files in `monitors/`,
`query/offline.py`, `ui/index.html`

---

## 5. Command-prompt style: type naturally, or get suggestions

New: a live suggestion dropdown appears above the input as you type —
terminal tab-completion, but for natural language instead of exact syntax.

- New `query/catalog.py` — a curated list of ~25 example queries with
  descriptions across every category (ports, processes, network, logins,
  USB, downloads, software, startup, services, files, scheduled tasks,
  health, summaries).
- New `/api/suggest?q=...` endpoint — fuzzy-matches your partial input
  against the catalog, **including typo tolerance** (tested: "downlod" →
  still surfaces "any risky downloads?" and "what did I download?").
- Keyboard-driven, like a real command palette: **↑/↓** to browse, **Enter**
  on a highlighted suggestion runs it immediately, **Tab** fills without
  sending, **Esc** dismisses. Focusing an empty input shows a starter set
  spanning every category.
- A small `>` prompt glyph was added to the input for the command-line feel
  you asked for, without changing the overall Claude-style layout.

You never need exact commands — plain language always works via the
existing offline/LLM engine; the palette is a faster path when you want it.

Files: `query/catalog.py` (new), `api/server.py`, `ui/index.html`

---

## Verification performed

Every change above was tested for real, not just read through:
- All Python files pass `py_compile`.
- The embedded JS passes `node --check`.
- SQL injection / destructive-query attempts confirmed blocked by
  `sql_guard.py` (unchanged, still solid).
- Schema migration run against a **copy of your actual database** —
  confirmed it adds the new columns without data loss.
- Alert dedup tested live: 5 repeated alerts → 1 row, `occurrence_count: 5`.
- Downloads fix tested against your real data: now correctly shows
  Chrome, Edge, and Opera with an explicit breakdown.
- Full UI interaction tested in a real headless browser (Playwright):
  command palette open/filter/keyboard-nav/send, and history lock/resume,
  both confirmed working end-to-end against a live Flask server.

## Other things worth doing next (not yet implemented)

- **Alert acknowledgment UI** — the `acknowledged` column exists in the
  schema but nothing sets it; a "dismiss" button on tooltip alerts would
  let old/handled alerts stop counting toward the threat level.
- **PID-to-DNS attribution** — `network.py`'s sniffer currently logs DNS
  queries without knowing which process made them; real attribution needs
  OS-level socket correlation, a bigger feature than this pass covered.
- **Login monitor field offsets** — still based on current Windows 10/11
  event log layout; worth a one-time check against Event Viewer on your
  actual machine if usernames/IPs come back empty.
- **Anomaly detection beyond CPU** — the `process_baselines` table only
  tracks CPU right now; memory and network-volume baselines per process
  would extend the same pattern.
- **Consider moving the LLM planner+explainer to one call** using
  structured tool-calling instead of two round-trips, if latency becomes
  noticeable once you enable the API key.
