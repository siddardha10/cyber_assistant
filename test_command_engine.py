"""
test_command_engine.py

End-to-end test of the Universal Command Execution Engine.
Tests one command from each category, plus destructive confirmation flow,
network failure paths, and unsupported request handling.

Runs against the live API server at http://127.0.0.1:5055
"""

import json
import sys
import requests

API = "http://127.0.0.1:5055"

def ask(question):
    """Send a question to /api/ask and return the parsed response."""
    r = requests.post(f"{API}/api/ask", json={"question": question}, timeout=120)
    r.raise_for_status()
    return r.json()

def execute_confirmed(command_data):
    """Send a confirmed execution to /api/execute."""
    r = requests.post(f"{API}/api/execute", json={
        "command_data": {**command_data, "natural_input": "test"},
        "confirmed": True,
    }, timeout=120)
    r.raise_for_status()
    return r.json()

def divider(label):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")

def show_result(label, result):
    source = result.get("source", "?")
    intent = result.get("intent", "?")
    answer = result.get("answer", "")[:200]
    cd = result.get("command_data")
    print(f"\n[{label}]")
    print(f"  source={source}  intent={intent}")
    print(f"  answer: {answer}")
    if cd:
        print(f"  template_id={cd.get('template_id')}  tier={cd.get('tier')}")
        print(f"  display_command={cd.get('display_command')}")
        exec_r = cd.get("execution", {})
        if exec_r:
            print(f"  executed={exec_r.get('executed')}  success={exec_r.get('success')}")
            fr = exec_r.get("failure_reason")
            if fr:
                print(f"  failure_reason={fr}")
            stdout = (exec_r.get("stdout") or "")[:150]
            if stdout:
                print(f"  stdout: {stdout}")
    return result


# ═══════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════

results = {}

# 1. FILE category — list directory
divider("1. FILE: list files (dir)")
results["file"] = show_result("dir", ask("list files in C:\\Windows\\System32\\drivers\\etc"))

# 2. PROCESS category — tasklist
divider("2. PROCESS: list processes (tasklist)")
results["process"] = show_result("tasklist", ask("list all running processes"))

# 3. SYSTEM INFO — hostname
divider("3. SYSTEM INFO: hostname")
results["sysinfo"] = show_result("hostname", ask("what is my computer name"))

# 4. SYSTEM INFO — date/time
divider("4. SYSTEM INFO: date and time")
results["datetime"] = show_result("date/time", ask("what time is it"))

# 5. SERVICE — list services (sc query)
divider("5. SERVICE: list services (sc query)")
results["service"] = show_result("sc query", ask("list all Windows services"))

# 6. NETWORK — ping (successful)
divider("6. NETWORK: ping google.com")
results["ping"] = show_result("ping", ask("ping google.com"))

# 7. NETWORK — ipconfig
divider("7. NETWORK: ipconfig")
results["ipconfig"] = show_result("ipconfig", ask("show my IP address"))

# 8. DISK — disk space
divider("8. DISK: disk space")
results["disk"] = show_result("disk", ask("show disk space"))

# 9. SCHEDULED TASKS
divider("9. SCHEDULED TASKS: schtasks /query")
results["tasks"] = show_result("schtasks", ask("list scheduled tasks"))

# 10. DESTRUCTIVE — mkdir (should return command_pending for confirmation)
divider("10. DESTRUCTIVE: mkdir (pending confirmation)")
r = ask("create a folder called C:\\Users\\dvsns\\test_sentinel_folder")
show_result("mkdir pending", r)
results["destructive_pending"] = r
# Verify it returned command_pending
if r.get("source") == "command_pending":
    print("  ✅ DESTRUCTIVE command correctly blocked pending confirmation")
    # Now confirm and execute
    cd = r.get("command_data")
    if cd:
        divider("10b. DESTRUCTIVE: mkdir (executing after confirm)")
        exec_r = execute_confirmed(cd)
        print(f"  executed={exec_r.get('executed')}  success={exec_r.get('success')}")
        stdout = (exec_r.get("stdout") or "")[:100]
        if stdout:
            print(f"  stdout: {stdout}")
        results["destructive_executed"] = exec_r
        # Clean up — delete the test folder
        import subprocess
        subprocess.run(["cmd", "/c", "rmdir", r"C:\Users\dvsns\test_sentinel_folder"], capture_output=True)
else:
    print("  ❌ Expected source='command_pending' but got:", r.get("source"))

# 11. NETWORK FAILURE — ping unreachable host
divider("11. NETWORK FAILURE: ping unreachable host")
results["ping_fail"] = show_result("ping fail", ask("ping 192.0.2.1"))

# 12. UNSUPPORTED — out-of-scope command
divider("12. UNSUPPORTED: request with no registry match")
results["unsupported"] = show_result("unsupported", ask("format my hard drive and install Linux"))

# 13. COMMAND HISTORY — query the log
divider("13. COMMAND HISTORY: what commands have I run")
results["history"] = show_result("history", ask("what commands have I run recently"))


# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
divider("SUMMARY")
total = 0
passed = 0
for k, r in results.items():
    total += 1
    src = r.get("source", "?") if isinstance(r, dict) and "source" in r else "exec"
    ok = src not in ("error", "llm_error", "llm_unavailable")
    if k == "unsupported":
        ok = src in ("unsupported", "out_of_scope", "command_error")
    if k == "destructive_pending":
        ok = src == "command_pending"
    if k == "destructive_executed":
        ok = r.get("executed", False)
    if k == "ping_fail":
        # Should have a failure_reason or answer mentioning unreachable/timeout
        cd = r.get("command_data", {})
        exec_d = cd.get("execution", {}) if cd else {}
        ok = exec_d.get("failure_reason") is not None or "unreachable" in r.get("answer", "").lower() or "timed out" in r.get("answer", "").lower()
    status = "✅ PASS" if ok else "❌ FAIL"
    if ok:
        passed += 1
    print(f"  {status}: {k} (source={src})")

print(f"\n  {passed}/{total} tests passed")
