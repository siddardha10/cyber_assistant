"""Evaluate intent parsing without executing any system action."""

import json
import re
import time

import config
from commands.translator import translate
from commands.templates import TEMPLATES
from query.llm import classify_intent


def _normalized(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def build_evaluation_cases() -> list[dict]:
    cases = []
    for action_id, template in TEMPLATES.items():
        examples = template.get("example_phrasings", [])
        if examples:
            cases.append({
                "question": examples[0],
                "intent": "SYSTEM_COMMAND",
                "action_id": action_id,
                "target": None,
                "variant": "registry example",
            })
    target_cases = [
        ("create the folder alpha beta in Documents", "create_directory", "alpha beta"),
        ("create a file named release notes.txt in Documents", "create_file", "release notes.txt"),
        ("ping 127.0.0.1", "ping", "127.0.0.1"),
        ("find process python", "find_process", "python"),
        ("stop the print spooler service", "stop_service", "print spooler"),
        ("delete file temp notes.txt from Documents", "delete_file", "temp notes.txt"),
        ("copy report draft.txt to Documents", "copy_file", "report draft.txt"),
        ("trace the network route to 127.0.0.1", "tracert", "127.0.0.1"),
        ("show the status of Windows Update service", "query_service", "Windows Update"),
        ("find the largest file in Downloads", "find_file", "Downloads"),
    ]
    for question, action_id, target in target_cases:
        cases.append({
            "question": question,
            "intent": "SYSTEM_COMMAND",
            "action_id": action_id,
            "target": target,
            "variant": "target annotated",
        })

    variants = [
        ("create the folder weekend plans in Documents", "create_directory", "unquoted multi-word"),
        ("is chrome runing", "find_process", "typo"),
        ("could you get rid of whatever is hogging my RAM", "kill_process_by_name", "indirect"),
        ("close it", "kill_process_by_name", "follow-up"),
        ("stop the app", "kill_process_by_name", "underspecified"),
        ("list files in my Downloads folder", "list_directory", "unquoted"),
        ("make a folder called project notes under Documents", "create_directory", "unquoted multi-word"),
        ("copy the notes file to Documents", "copy_file", "indirect"),
        ("what is using the most memory right now", "list_processes_verbose", "underspecified"),
        ("check if python is running", "find_process", "typo"),
    ]
    for question, action_id, variant in variants:
        cases.append({
            "question": question,
            "intent": "SYSTEM_COMMAND",
            "action_id": action_id,
            "target": None,
            "variant": variant,
        })
    for question in (
        "What did I install this week?",
        "Any failed logins since yesterday?",
        "Which process opened port 443?",
        "Summarize today's activity.",
        "Did I download any risky files?",
        "Hello there",
        "Thanks, that helps",
        "What can you do?",
        "Write a poem about the moon",
        "What is the capital of France?",
        "Explain how to write a web scraper",
        "Tell me a joke",
    ):
        intent = (
            "CONVERSATIONAL" if question.casefold().startswith(("hello", "thanks", "what can you"))
            else "OUT_OF_SCOPE" if question.casefold().startswith(("write", "what is the capital", "explain", "tell me"))
            else "DATA_QUERY"
        )
        cases.append({
            "question": question,
            "intent": intent,
            "action_id": None,
            "target": None,
            "variant": "non-command",
        })

    if len(cases) < 100:
        examples = [
            (action_id, phrase)
            for action_id, template in TEMPLATES.items()
            for phrase in template.get("example_phrasings", [])[1:]
        ]
        for action_id, phrase in examples:
            variants_for_example = [
                phrase.replace('"', "").replace("'", ""),
                f"Could you help me {phrase[0].lower() + phrase[1:]}",
            ]
            for index, question in enumerate(variants_for_example):
                cases.append({
                    "question": question,
                    "intent": "SYSTEM_COMMAND",
                    "action_id": action_id,
                    "target": None,
                    "variant": "unquoted" if index == 0 else "indirect",
                })
                if len(cases) >= 100:
                    return cases
    return cases


def _target_present(result: dict, target: str) -> bool:
    values = [result.get("target_phrase", "")]
    values.extend(str(value) for value in result.get("slots", {}).values())
    values.extend(str(value) for value in result.get("params", {}).values())
    expected = _normalized(target)
    return any(expected and expected in _normalized(value) for value in values)


def evaluate() -> dict:
    cases = build_evaluation_cases()
    intent_correct = 0
    action_correct = 0
    annotated_targets = 0
    target_correct = 0
    clarify_count = 0
    local_latencies = []
    cloud_latencies = []

    for case in cases:
        if case["intent"] == "SYSTEM_COMMAND":
            parsed = translate(case["question"])
            predicted_intent = (
                "SYSTEM_COMMAND" if parsed.get("template_id") else "UNCERTAIN"
            )
            if predicted_intent == "SYSTEM_COMMAND":
                actual_action = parsed["template_id"]
                expected_action = case["action_id"]
                action_correct += (
                    actual_action == expected_action
                    or {actual_action, expected_action}
                    <= {"kill_process_by_name", "kill_process_by_pid"}
                )
                if case["target"]:
                    annotated_targets += 1
                    target_correct += _target_present(parsed, case["target"])
                confidence = parsed.get("confidence", 0)
                if (
                    parsed.get("clarification")
                    or confidence < 0.55
                    or 0.55 <= confidence < 0.82
                ):
                    clarify_count += 1
                if parsed.get("local_latency_ms") is not None:
                    local_latencies.append(parsed["local_latency_ms"])
                if parsed.get("cloud_latency_ms") is not None:
                    cloud_latencies.append(parsed["cloud_latency_ms"])
            else:
                clarify_count += 1
        else:
            started = time.perf_counter()
            parsed = classify_intent(case["question"])
            local_latencies.append(round((time.perf_counter() - started) * 1000, 2))
            predicted_intent = parsed.get("intent") or "UNCERTAIN"
            if parsed.get("confidence", 0) < 0.55:
                clarify_count += 1
        intent_correct += predicted_intent == case["intent"]

    count = len(cases)
    return {
        "cases": count,
        "intent_accuracy": round(intent_correct / count, 4) if count else 0,
        "action_accuracy": round(action_correct / max(1, sum(
            case["intent"] == "SYSTEM_COMMAND" for case in cases
        )), 4),
        "correct_target_rate": (
            round(target_correct / annotated_targets, 4)
            if annotated_targets else None
        ),
        "annotated_target_cases": annotated_targets,
        "clarify_rate": round(clarify_count / count, 4) if count else 0,
        "wrong_execution_rate": 0.0,
        "execution_note": "Evaluation mode translates/classifies only; no command is executed.",
        "local_latency_ms_avg": (
            round(sum(local_latencies) / len(local_latencies), 2) if local_latencies else None
        ),
        "cloud_latency_ms_avg": (
            round(sum(cloud_latencies) / len(cloud_latencies), 2) if cloud_latencies else None
        ),
        "cloud_fallback_enabled": getattr(config, "CLOUD_LLM_ENABLED", False),
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
