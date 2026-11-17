"""Local semantic action retrieval and strict goal-first parsing."""

import hashlib
import json
import math
import re
import time
import difflib
from urllib.parse import urlparse

import requests

import config
from commands.templates import TEMPLATES
from utils.logger import get_logger

log = get_logger("commands.intent_router")

_EMBEDDING_CACHE = {}
_EMBEDDING_REGISTRY_HASH = None
_EMBEDDING_FAILURE_UNTIL = 0.0
_TARGET_TYPES = {
    "process", "service", "application", "file", "folder", "drive",
    "port", "adapter", "host", "none",
}


def _action_target_type(action_id: str, fallback: str) -> str:
    """Keep the model's target guess aligned with registry action semantics."""
    action = TEMPLATES[action_id]
    parameters = set(action.get("params", []))
    lowered = action_id.casefold()
    if "process" in lowered or "pid" in parameters:
        return "process"
    if "service" in lowered:
        return "service"
    if "application" in lowered or lowered == "start_application":
        return "application"
    if "directory" in lowered or "folder" in lowered:
        return "folder"
    if "file" in lowered or parameters.intersection({"source", "dest"}):
        return "file"
    if "drive" in lowered:
        return "drive"
    if "port" in lowered:
        return "port"
    if "adapter" in lowered:
        return "adapter"
    if "host" in parameters:
        return "host"
    return fallback


def _registry_entries() -> list[dict]:
    return [
        {
            "action_id": action_id,
            "description": action.get("description", ""),
            "examples": action.get("example_phrasings", []),
            "tier": action.get("tier", "SAFE"),
            "parameters": action.get("params", []),
        }
        for action_id, action in TEMPLATES.items()
    ]


def _document(entry: dict) -> str:
    examples = " ".join(entry["examples"])
    return f"{entry['action_id']}. {entry['description']}. Examples: {examples}"


def _embed_url() -> str:
    base = config.OLLAMA_BASE_URL
    marker = "/v1/chat/completions"
    if marker in base:
        return base.split(marker, 1)[0] + "/api/embed"
    return base.rsplit("/", 1)[0] + "/api/embed"


def _get_embeddings(texts: list[str]) -> list[list[float]] | None:
    global _EMBEDDING_FAILURE_UNTIL
    if time.monotonic() < _EMBEDDING_FAILURE_UNTIL:
        return None
    model = getattr(config, "OLLAMA_EMBED_MODEL", "nomic-embed-text")
    try:
        response = requests.post(
            _embed_url(),
            json={"model": model, "input": texts},
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()
        vectors = payload.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise ValueError("Embedding service returned an unexpected response.")
        _EMBEDDING_FAILURE_UNTIL = 0
        return vectors
    except (requests.RequestException, ValueError, KeyError, TypeError):
        _EMBEDDING_FAILURE_UNTIL = time.monotonic() + 60
        log.warning("Local action embeddings unavailable; using lexical retrieval.")
        return None


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.casefold()))


def web_fallback_category(question: str) -> str:
    """Map an unsupported in-scope request to a generic web-search category."""
    value = question.casefold()
    if re.search(r"\b(file|folder|directory|document|download|path)\b", value):
        return "files"
    if re.search(r"\b(process|memory|ram|cpu|task|application|app)\b", value):
        return "processes" if re.search(r"\b(process|memory|ram|cpu|task)\b", value) else "applications"
    if re.search(r"\b(service|daemon)\b", value):
        return "services"
    if re.search(r"\b(network|adapter|connection|port|dns|ip)\b", value):
        return "network"
    return "general"


def _lexical_score(query: str, document: str) -> float:
    query_tokens = _tokens(query)
    doc_tokens = _tokens(document)
    if not query_tokens or not doc_tokens:
        return 0.0
    overlap = len(query_tokens & doc_tokens) / len(query_tokens | doc_tokens)
    phrase_match = 0.35 if query.casefold() in document.casefold() else 0.0
    typo_match = max(
        (
            difflib.SequenceMatcher(None, query_token, doc_token).ratio()
            for query_token in query_tokens
            for doc_token in doc_tokens
            if len(query_token) >= 4 and len(doc_token) >= 4
        ),
        default=0.0,
    )
    return min(1.0, overlap + phrase_match + max(0.0, typo_match - 0.72) * 0.2)


def _cosine(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if not left_norm or not right_norm:
        return 0.0
    return dot / (left_norm * right_norm)


def retrieve_actions(question: str, limit: int = 5) -> list[dict]:
    """Retrieve the most relevant actions from the current template registry."""
    global _EMBEDDING_REGISTRY_HASH, _EMBEDDING_CACHE
    entries = _registry_entries()
    documents = [_document(entry) for entry in entries]
    registry_hash = hashlib.sha256("\n".join(documents).encode("utf-8")).hexdigest()
    vectors = None

    if _EMBEDDING_REGISTRY_HASH != registry_hash:
        _EMBEDDING_CACHE = {}
        _EMBEDDING_REGISTRY_HASH = registry_hash
    if not _EMBEDDING_CACHE:
        embedded = _get_embeddings(documents)
        if embedded is not None:
            _EMBEDDING_CACHE = dict(zip((entry["action_id"] for entry in entries), embedded))
    if _EMBEDDING_CACHE:
        query_vector = _get_embeddings([question])
        if query_vector is not None:
            vectors = query_vector[0]

    scored = []
    for entry, document in zip(entries, documents):
        lexical = _lexical_score(question, document)
        if vectors is not None:
            score = 0.8 * _cosine(vectors, _EMBEDDING_CACHE[entry["action_id"]]) + 0.2 * lexical
        else:
            score = lexical
        scored.append((score, entry))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [{**entry, "score": round(score, 4)} for score, entry in scored[:limit]]


def _sanitize_cloud_text(question: str) -> str:
    """Remove common machine identifiers before an opt-in cloud retry."""
    value = re.sub(r"[A-Za-z]:\\(?:[^\s\"']+)", "[local path]", question)
    value = re.sub(r"\\\\[^\s\\]+\\[^\s\"']+", "[network path]", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[email]", value)
    value = re.sub(r"\b[\w-]+\.(?:com|net|org|io|dev|local)\b", "[host]", value, flags=re.I)
    return value


def _model_result(
    endpoint: str,
    model: str,
    api_key: str,
    message: str,
    context: list | None,
    system: str,
    candidates: list[dict],
    source: str,
) -> dict | None:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    try:
        started = time.perf_counter()
        response = requests.post(
            endpoint,
            headers=headers,
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps({
                        "context": (context or [])[-4:],
                        "message": message,
                    })},
                ],
                "temperature": 0,
                "max_tokens": 350,
                "stream": False,
                "response_format": {"type": "json_object"},
            },
            timeout=45,
        )
        response.raise_for_status()
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result = json.loads(response.json()["choices"][0]["message"]["content"].strip())
    except (requests.RequestException, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        log.warning("%s goal parser failed: %s", source, error)
        return None

    expected = {
        "goal", "target_phrase", "target_type", "slots",
        "confidence", "interpretation", "action_id",
    }
    allowed_ids = {entry["action_id"] for entry in candidates}
    if set(result) != expected:
        log.warning("%s goal parser returned an invalid JSON shape.", source)
        return None
    confidence = result["confidence"]
    action_id = result["action_id"]
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(confidence)
        or not 0 <= confidence <= 1
        or not isinstance(result["goal"], str)
        or not isinstance(result["target_phrase"], str)
        or result["target_type"] not in _TARGET_TYPES
        or not isinstance(result["slots"], dict)
        or not isinstance(result["interpretation"], str)
        or (action_id is not None and action_id not in allowed_ids)
        or (
            action_id is not None
            and not set(result["slots"]).issubset(TEMPLATES[action_id]["params"])
        )
    ):
        log.warning("%s goal parser returned invalid field values.", source)
        return None
    result["confidence"] = float(confidence)
    if action_id is not None:
        result["target_type"] = _action_target_type(action_id, result["target_type"])
    result["candidates"] = candidates
    result["model_source"] = source
    result["latency_ms"] = latency_ms
    return result


def parse_goal(question: str, context: list | None = None) -> dict | None:
    """Ask the local model for strict JSON using only the retrieved five actions."""
    if not config.LLM_ENABLED:
        return None
    context_for_retrieval = " ".join(
        str(turn.get(key) or "")[:600]
        for turn in (context or [])[-2:]
        for key in ("question", "answer")
    )
    retrieval_question = f"{question} {context_for_retrieval}".strip()
    candidates = retrieve_actions(retrieval_question, 5)
    allowed_ids = {entry["action_id"] for entry in candidates}
    prompt = {
        "goal": "one verb category such as query, inspect, create, copy, delete, stop, launch",
        "target_phrase": "the exact target words from the user, or empty string",
        "target_type": "one of process, service, application, file, folder, drive, port, adapter, host, none",
        "slots": "object containing only parameter values required by the selected action",
        "confidence": "number from 0 to 1",
        "interpretation": "one concise sentence describing what the user means",
        "action_id": "one candidate action_id or null",
    }
    candidate_text = json.dumps(candidates, ensure_ascii=False)
    system = (
        "Parse the user's goal before selecting an action. Return one strict JSON object "
        "with exactly these fields: " + json.dumps(prompt) + ". "
        "Select action_id only from the candidates below. If unclear, use null and low confidence. "
        "Never invent a target. Use the conversation only to resolve references. "
        "Candidates: " + candidate_text
    )
    local_result = _model_result(
        config.OLLAMA_BASE_URL,
        config.LLM_MODEL,
        "",
        question,
        context,
        system,
        candidates,
        "local",
    )
    local_latency_ms = None
    if local_result is not None:
        local_latency_ms = local_result.pop("latency_ms", None)
    if local_result is not None and local_result["confidence"] >= 0.55:
        local_result["local_latency_ms"] = local_latency_ms
        local_result["cloud_latency_ms"] = None
        return local_result

    if (
        not getattr(config, "CLOUD_LLM_ENABLED", False)
        or not getattr(config, "CLOUD_LLM_BASE_URL", "")
        or not getattr(config, "CLOUD_LLM_MODEL", "")
        or not getattr(config, "CLOUD_LLM_API_KEY", "")
        or urlparse(config.CLOUD_LLM_BASE_URL).scheme != "https"
    ):
        if local_result is not None:
            local_result["local_latency_ms"] = local_latency_ms
            local_result["cloud_latency_ms"] = None
        return local_result

    cloud_result = _model_result(
        config.CLOUD_LLM_BASE_URL,
        config.CLOUD_LLM_MODEL,
        config.CLOUD_LLM_API_KEY,
        _sanitize_cloud_text(question),
        None,
        system,
        candidates,
        "cloud",
    )
    if cloud_result is not None and (
        local_result is None or cloud_result["confidence"] > local_result["confidence"]
    ):
        cloud_latency = cloud_result.pop("latency_ms", None)
        cloud_result["local_latency_ms"] = local_latency_ms
        cloud_result["cloud_latency_ms"] = cloud_latency
        return cloud_result
    if local_result is not None:
        local_result["local_latency_ms"] = local_latency_ms
        local_result["cloud_latency_ms"] = (
            cloud_result.get("latency_ms") if cloud_result else None
        )
    return local_result
