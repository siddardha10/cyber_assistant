"""Resolve user-mentioned entities against live local system state."""

import difflib
import os
import re
import shutil
from pathlib import Path


_PROTECTED_PROCESS_NAMES = {
    "csrss", "lsass", "services", "smss", "system", "wininit", "winlogon",
}
_TOP_RESOURCE_TERMS = (
    "most memory", "highest memory", "hogging my ram", "using the most ram",
    "most cpu", "highest cpu", "hogging cpu", "resource hog",
)


def _normalize(value: str) -> str:
    value = Path(value).stem if value.lower().endswith(".exe") else value
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _live_candidates(entity_type: str, phrase: str = "") -> list[dict]:
    candidates = []
    if entity_type == "process":
        import psutil

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = proc.info.get("name") or ""
                if name:
                    candidates.append({
                        "name": name,
                        "description": proc.info.get("exe") or Path(name).stem,
                        "value": name,
                        "pid": proc.info["pid"],
                        "protected": (
                            _normalize(name) in _PROTECTED_PROCESS_NAMES
                            or proc.info["pid"] <= 4
                        ),
                        "memory_bytes": proc.memory_info().rss,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
    elif entity_type == "service":
        import psutil

        try:
            services = psutil.win_service_iter()
        except (AttributeError, OSError):
            services = ()
        for service in services:
            try:
                info = service.as_dict()
                candidates.append({
                    "name": info.get("display_name") or info.get("name") or "",
                    "description": info.get("name") or "",
                    "value": info.get("name") or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
    elif entity_type in {"file", "folder", "path"}:
        from commands.path_resolver import resolve_folder_for_display

        roots = []
        for folder in ("desktop", "documents", "downloads"):
            root = Path(resolve_folder_for_display(folder))
            if root.is_dir():
                roots.append(root)
        for root in roots:
            try:
                for entry in root.iterdir():
                    if entity_type == "file" and not entry.is_file():
                        continue
                    if entity_type == "folder" and not entry.is_dir():
                        continue
                    candidate = {"name": entry.name, "value": str(entry)}
                    if entry.is_file():
                        try:
                            candidate["size_bytes"] = entry.stat().st_size
                        except OSError:
                            continue
                    candidates.append(candidate)
            except OSError:
                continue
    elif entity_type == "drive":
        import psutil

        for partition in psutil.disk_partitions(all=False):
            candidates.append({"name": partition.device, "value": partition.device})
    elif entity_type == "port":
        import psutil

        try:
            connections = psutil.net_connections(kind="inet")
        except (OSError, psutil.AccessDenied):
            connections = ()
        for connection in connections:
            if connection.laddr:
                port = str(connection.laddr.port)
                candidates.append({
                    "name": port,
                    "description": f"{connection.type} socket, PID {connection.pid}",
                    "value": port,
                    "pid": connection.pid,
                })
    elif entity_type == "adapter":
        import psutil

        candidates = [
            {"name": name, "value": name}
            for name in psutil.net_if_addrs()
        ]
    elif entity_type == "host":
        import socket

        candidates.append({"name": socket.gethostname(), "value": socket.gethostname()})
    elif entity_type == "application":
        executable = shutil.which(phrase) if phrase else None
        if executable:
            candidates.append({
                "name": Path(executable).stem,
                "description": executable,
                "value": executable,
            })
        start_menu_roots = (
            Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
            / "Microsoft/Windows/Start Menu/Programs",
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            / "Microsoft/Windows/Start Menu/Programs",
        )
        for root in start_menu_roots:
            if root.is_dir():
                try:
                    for shortcut in root.rglob("*.lnk"):
                        candidates.append({
                            "name": shortcut.stem,
                            "description": str(shortcut),
                            "value": str(shortcut),
                        })
                except OSError:
                    continue
        try:
            import winreg

            uninstall_paths = (
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            )
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for uninstall_path in uninstall_paths:
                    try:
                        with winreg.OpenKey(hive, uninstall_path) as root:
                            subkey_count = winreg.QueryInfoKey(root)[0]
                            for index in range(subkey_count):
                                try:
                                    subkey_name = winreg.EnumKey(root, index)
                                    with winreg.OpenKey(root, subkey_name) as app_key:
                                        display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                        try:
                                            display_icon, _ = winreg.QueryValueEx(app_key, "DisplayIcon")
                                        except OSError:
                                            display_icon = ""
                                    candidates.append({
                                        "name": display_name,
                                        "description": display_icon,
                                        "value": display_icon.strip('"').split(",")[0] or display_name,
                                    })
                                except OSError:
                                    continue
                    except OSError:
                        continue
        except ImportError:
            pass

    deduped = {}
    for candidate in candidates:
        if candidate.get("name"):
            key = (candidate["name"].casefold(), candidate.get("value"))
            deduped[key] = candidate
    return list(deduped.values())


def _rank(phrase: str, candidates: list[dict]) -> list[dict]:
    query = _normalize(phrase)
    query_tokens = set(query.split())
    exact, prefix, overlap, similar = [], [], [], []
    for candidate in candidates:
        name = str(candidate.get("name", ""))
        haystack = _normalize(name + " " + str(candidate.get("description", "")))
        tokens = set(haystack.split())
        if (
            query == _normalize(name)
            or query == _normalize(str(candidate.get("value", "")))
            or query == str(candidate.get("pid", ""))
        ):
            exact.append((1.0, candidate))
        elif haystack.startswith(query) or query.startswith(_normalize(name)):
            prefix.append((0.9, candidate))
        elif query_tokens and query_tokens.issubset(tokens):
            overlap.append((0.8, candidate))
        else:
            score = max(
                difflib.SequenceMatcher(None, query, haystack).ratio(),
                len(query_tokens & tokens) / max(1, len(query_tokens | tokens)),
            )
            if score >= 0.6:
                similar.append((score, candidate))
    ranked = (
        exact or prefix or overlap
        or sorted(similar, reverse=True, key=lambda item: item[0])
        or sorted(
            (
                (
                    max(
                        difflib.SequenceMatcher(
                            None, query, _normalize(
                                str(candidate.get("name", ""))
                                + " " + str(candidate.get("description", ""))
                            )
                        ).ratio(),
                        len(query_tokens & set(_normalize(
                            str(candidate.get("name", ""))
                            + " " + str(candidate.get("description", ""))
                        ).split())) / max(1, len(query_tokens)),
                    ),
                    candidate,
                )
                for candidate in candidates
            ),
            reverse=True,
            key=lambda item: item[0],
        )
    )
    return [
        {**candidate, "score": round(score, 3)}
        for score, candidate in ranked[:8]
    ]


def resolve_entity(phrase: str, entity_type: str) -> dict:
    """Return a unique match, ranked choices, or closest candidates."""
    if not phrase or not phrase.strip():
        return {"status": "no_match", "match": None, "choices": []}

    candidates = _live_candidates(entity_type, phrase)
    lowered = phrase.casefold()
    if entity_type == "process" and any(term in lowered for term in _TOP_RESOURCE_TERMS):
        ranked_by_memory = sorted(
            candidates,
            key=lambda candidate: candidate.get("memory_bytes", 0),
            reverse=True,
        )
        if ranked_by_memory:
            top = ranked_by_memory[:5]
            lead = top[0].get("memory_bytes", 0)
            next_value = top[1].get("memory_bytes", 0) if len(top) > 1 else 0
            ranked = [
                {
                    **candidate,
                    "score": round(candidate.get("memory_bytes", 0) / max(lead, 1), 3),
                }
                for candidate in top
            ]
            if lead > next_value * 1.2:
                return {"status": "match", "match": ranked[0], "choices": ranked}
            return {"status": "ambiguous", "match": None, "choices": ranked}
    if entity_type == "file" and any(term in lowered for term in ("largest", "biggest", "big file")):
        ranked_by_size = sorted(
            (candidate for candidate in candidates if "size_bytes" in candidate),
            key=lambda candidate: candidate["size_bytes"],
            reverse=True,
        )
        if ranked_by_size:
            ranked = [
                {**candidate, "score": round(candidate["size_bytes"] / max(ranked_by_size[0]["size_bytes"], 1), 3)}
                for candidate in ranked_by_size[:5]
            ]
            if len(ranked) == 1 or ranked[0]["size_bytes"] > ranked[1]["size_bytes"] * 1.2:
                return {"status": "match", "match": ranked[0], "choices": ranked}
            return {"status": "ambiguous", "match": None, "choices": ranked}
    if entity_type in {"file", "folder", "path"}:
        expanded = os.path.expandvars(os.path.expanduser(phrase.strip().strip("\"'")))
        path = Path(expanded)
        if path.exists():
            candidates.append({"name": path.name, "value": str(path), "exact_path": True})

    ranked = _rank(phrase.strip(), candidates)
    if not ranked:
        return {"status": "no_match", "match": None, "choices": []}
    if ranked[0]["score"] < 0.6:
        return {"status": "no_match", "match": None, "choices": ranked[:5]}
    if len(ranked) == 1 or ranked[0]["score"] - ranked[1]["score"] >= 0.12:
        return {"status": "match", "match": ranked[0], "choices": ranked}
    return {"status": "ambiguous", "match": None, "choices": ranked}


def resolve_context_entity(context: list | None, entity_type: str) -> dict:
    """Resolve a follow-up reference only when recent turns identify one live entity."""
    if not context:
        return {"status": "no_match", "match": None, "choices": []}
    conversation = " ".join(
        str(turn.get(key) or "")
        for turn in context[-2:]
        for key in ("question", "answer")
        if isinstance(turn, dict)
    )
    normalized = f" {_normalize(conversation)} "
    matches = {}
    for candidate in _live_candidates(entity_type):
        names = {
            _normalize(str(candidate.get("name", ""))),
            _normalize(Path(str(candidate.get("value", ""))).name),
        }
        if any(
            name and f" {name} " in normalized
            for name in names
        ):
            identity = candidate.get("pid", candidate.get("value", candidate.get("name")))
            matches[identity] = {**candidate, "score": 1.0}
    choices = sorted(matches.values(), key=lambda item: str(item.get("name", "")).casefold())[:5]
    if len(matches) == 1:
        return {"status": "match", "match": choices[0], "choices": choices}
    if matches:
        return {"status": "ambiguous", "match": None, "choices": choices}
    return {"status": "no_match", "match": None, "choices": []}


def get_entity_choices(entity_type: str, limit: int = 5) -> list[dict]:
    """Return live, safe-to-present entity choices for a clarification prompt."""
    candidates = _live_candidates(entity_type)
    if entity_type == "process":
        candidates = [candidate for candidate in candidates if not candidate.get("protected")]
    candidates.sort(key=lambda item: str(item.get("name", "")).casefold())
    choices = []
    seen = set()
    for candidate in candidates:
        name = str(candidate.get("name", "")).strip()
        if name and name.casefold() not in seen:
            seen.add(name.casefold())
            choices.append({**candidate, "score": 0.0})
            if len(choices) >= limit:
                break
    return choices
