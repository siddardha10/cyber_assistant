"""
test_ollama_queries.py

Smoke test — verifies the local Ollama (qwen2.5:3b) integration works
for all LLM call paths:
  1. Intent classification
  2. Data query (SQL planner + explainer)
  3. Conversational handler
  4. Out-of-scope handler
  5. Command translation
"""

import sys
import os
import io

# Fix Windows console encoding for unicode characters
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Make sure the project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

import config
from query.llm import classify_intent, handle_data_query, handle_conversational, ask
from commands.translator import translate

PASS = 0
FAIL = 0

def test(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {label}")
    else:
        FAIL += 1
        print(f"  ❌ {label}  —  {detail}")


def divider(label):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")


# ── 0. Config sanity ──
divider("0. Config check")
print(f"  LLM_ENABLED  = {config.LLM_ENABLED}")
print(f"  LLM_MODEL    = {config.LLM_MODEL}")
print(f"  OLLAMA_URL   = {config.OLLAMA_BASE_URL}")
test("LLM is enabled", config.LLM_ENABLED, "CS_LLM_ENABLED is false")
test("Model is qwen2.5:3b", config.LLM_MODEL == "qwen2.5:3b", f"Got: {config.LLM_MODEL}")


# ── 1. Intent classification ──
divider("1. Intent Classification")

# DATA_QUERY
r = classify_intent("show me all open ports")
print(f"  'show me all open ports' → {r}")
test("DATA_QUERY intent detected", r["intent"] == "DATA_QUERY", f"Got: {r['intent']}")

# SYSTEM_COMMAND
r = classify_intent("ping google.com")
print(f"  'ping google.com' → {r}")
test("SYSTEM_COMMAND intent detected", r["intent"] == "SYSTEM_COMMAND", f"Got: {r['intent']}")

# CONVERSATIONAL
r = classify_intent("hello, what can you do?")
print(f"  'hello, what can you do?' → {r}")
test("CONVERSATIONAL intent detected", r["intent"] == "CONVERSATIONAL", f"Got: {r['intent']}")

# OUT_OF_SCOPE
r = classify_intent("what is the capital of France?")
print(f"  'capital of France' → {r}")
test("OUT_OF_SCOPE intent detected", r["intent"] == "OUT_OF_SCOPE", f"Got: {r['intent']}")


# ── 2. Conversational handler ──
divider("2. Conversational Handler")
r = handle_conversational("hi, what are you?")
print(f"  answer: {r['answer'][:150]}")
test("Got a non-empty answer", len(r["answer"]) > 10, "Answer was empty/too short")
test("Source is conversational", r["source"] == "conversational", f"Got: {r['source']}")


# ── 3. Data query handler (SQL planner) ──
divider("3. Data Query Handler (SQL planner)")
r = handle_data_query("are there any alerts?")
print(f"  answer: {r['answer'][:150]}")
print(f"  sql: {r.get('sql')}")
test("Got a non-empty answer", len(r["answer"]) > 5, "Answer was empty/too short")
test("Source is llm-related", r["source"] in ("llm", "llm_error", "llm_sql_error"), f"Got: {r['source']}")


# ── 4. Full ask() routing ──
divider("4. Full ask() routing")
r = ask("what processes are using the most CPU?")
print(f"  intent: {r.get('intent')}")
print(f"  answer: {r['answer'][:150]}")
test("Got intent in response", r.get("intent") is not None, "No intent")
test("Got a non-empty answer", len(r["answer"]) > 5, "Answer was empty")


# ── 5. Command translation ──
divider("5. Command Translation")
r = translate("list files in my Downloads folder")
print(f"  success={r['success']}  template_id={r.get('template_id')}  tier={r.get('tier')}")
print(f"  display_command={r.get('display_command')}")
test("Translation succeeded", r["success"], f"Error: {r.get('error')}")
test("Got a template_id", r.get("template_id") is not None, "No template_id")
test("Tier is SAFE", r.get("tier") == "SAFE", f"Got: {r.get('tier')}")


# ── Summary ──
divider("SUMMARY")
total = PASS + FAIL
print(f"\n  {PASS}/{total} tests passed")
if FAIL:
    print(f"  {FAIL} test(s) failed")
    sys.exit(1)
else:
    print("  All tests passed! 🎉 Ollama + qwen2.5:3b is working.")
