"""Resolve Windows known folders and validate filesystem command targets."""

import difflib
import os
import re
from pathlib import Path

_KNOWN_FOLDER_REGISTRY_VALUES = {
    "desktop": "Desktop",
    "documents": "Personal",
    "downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
}
_KNOWN_FOLDER_NAMES = {
    "desktop": "Desktop",
    "documents": "Documents",
    "downloads": "Downloads",
}

_EXISTING_PATH_TEMPLATES = {
    "list_directory", "list_directory_recursive", "change_directory",
    "tree_directory", "view_file", "open_file", "search_in_files", "find_file",
    "file_attributes", "remove_empty_directory", "delete_file",
    "delete_directory", "rename_file", "disk_usage_dir",
}
_NEW_PATH_TEMPLATES = {"create_directory", "create_file"}
_RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def _expand(value: str) -> str:
    return os.path.expanduser(os.path.expandvars(value.strip().strip("\"'")))


def _folder_candidates(name: str) -> tuple[str | None, list[str]]:
    """Return the registry-resolved location and OneDrive/local fallbacks."""
    key_name = _KNOWN_FOLDER_REGISTRY_VALUES[name]
    configured = None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ) as key:
            value, _ = winreg.QueryValueEx(key, key_name)
        configured = _expand(value)
    except (ImportError, OSError):
        pass

    profile = Path.home()
    folder_name = _KNOWN_FOLDER_NAMES[name]
    one_drive_roots = [
        os.environ.get("OneDrive"),
        os.environ.get("OneDriveConsumer"),
        os.environ.get("OneDriveCommercial"),
        str(profile / "OneDrive"),
    ]
    candidates = []
    for root in one_drive_roots:
        if root:
            candidate = str(Path(_expand(root)) / folder_name)
            if candidate not in candidates:
                candidates.append(candidate)
    local = str(profile / folder_name)
    if local not in candidates:
        candidates.append(local)
    return configured, candidates


def _resolve_known_folder(name: str) -> tuple[str, list[str]]:
    configured, candidates = _folder_candidates(name)
    if configured and Path(configured).is_dir():
        return configured, candidates
    for candidate in candidates:
        if Path(candidate).is_dir():
            return candidate, candidates
    return configured or candidates[0], candidates


def _known_folder_path(value: str) -> tuple[str, str | None, list[str]]:
    """Resolve a known-folder reference at the start of a path."""
    expanded = _expand(value)
    normalized = expanded.replace("/", "\\")
    home = str(Path.home()).replace("/", "\\").rstrip("\\")
    prefixes = [(folder.lower(), folder) for folder in _KNOWN_FOLDER_NAMES.values()]

    for folder_lower, folder_name in prefixes:
        candidates = [folder_lower, f"my {folder_lower}"]
        if folder_lower == "documents":
            candidates.append("my documents")
        for prefix in candidates:
            if normalized.lower() == prefix or normalized.lower().startswith(prefix + "\\"):
                base, tried = _resolve_known_folder(folder_lower)
                remainder = normalized[len(prefix):].lstrip("\\")
                return str(Path(base) / remainder) if remainder else base, folder_name, tried

    home_prefix = home.lower() + "\\"
    if normalized.lower().startswith(home_prefix):
        remainder = normalized[len(home_prefix):]
        for folder_lower, folder_name in prefixes:
            if remainder.lower() == folder_lower or remainder.lower().startswith(folder_lower + "\\"):
                base, tried = _resolve_known_folder(folder_lower)
                child = remainder[len(folder_lower):].lstrip("\\")
                return str(Path(base) / child) if child else base, folder_name, tried

    return expanded, None, []


def _missing_path_message(path: Path, folder_label: str | None, is_directory: bool, fallbacks: list[str]) -> str:
    kind = "folder" if is_directory else "file"
    label = folder_label or str(path.parent)
    nearby = []
    if path.parent.is_dir():
        try:
            nearby = [
                entry.name for entry in path.parent.iterdir()
                if entry.is_dir() == is_directory
            ]
        except OSError:
            nearby = []
    matches = difflib.get_close_matches(path.name, nearby, n=1, cutoff=0.6)
    suggestion = f" Did you mean '{matches[0]}'?" if matches else ""
    attempted = ""
    if fallbacks and not path.parent.exists():
        attempted = " Checked: " + ", ".join(fallbacks) + "."
    message = f"No {kind} named '{path.name}' found in {label}.{suggestion}{attempted}"
    return f"{message}\nResolved target: {path}"


def _protected_path(path: Path) -> bool:
    resolved = path.resolve()
    protected_roots = [
        os.environ.get("SystemRoot", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    for root in protected_roots:
        if root:
            try:
                resolved.relative_to(Path(root).resolve())
                return True
            except ValueError:
                continue

    users_root = Path.home().parent
    try:
        relative = resolved.relative_to(users_root.resolve())
    except ValueError:
        return False
    return not relative.parts or relative.parts[0].casefold() != Path.home().name.casefold()


def _invalid_windows_name(path: Path) -> str | None:
    name = path.name
    if not name or name in {".", ".."}:
        return "The target name cannot be empty."
    if len(str(path)) > 240 or len(name) > 255:
        return "The target path is too long."
    if re.search(r'[<>:"/\\|?*\x00-\x1f]', name):
        return f"'{name}' contains characters that are not valid in a Windows name."
    if name.endswith((" ", ".")):
        return f"'{name}' cannot end with a space or period on Windows."
    if name.split(".", 1)[0].upper() in _RESERVED_WINDOWS_NAMES:
        return f"'{name}' is a reserved Windows device name."
    return None


def prepare_command_paths(template_id: str, params: dict) -> tuple[dict, str | None]:
    """Resolve known folders and fail early for missing source/parent paths."""
    resolved = dict(params)
    labels: dict[str, tuple[str | None, list[str]]] = {}
    for key in ("path", "source", "dest"):
        value = resolved.get(key)
        if not isinstance(value, str):
            continue
        path, label, fallbacks = _known_folder_path(value)
        resolved[key] = path
        labels[key] = (label, fallbacks)

    existing_keys = []
    if template_id in _EXISTING_PATH_TEMPLATES:
        existing_keys.append("path")
    elif template_id in ("copy_file", "move_file"):
        existing_keys.append("source")
    elif template_id == "rename_file":
        existing_keys.append("path")

    for key in existing_keys:
        raw_path = resolved.get(key)
        if not raw_path:
            continue
        target = Path(raw_path)
        if not target.exists():
            label, fallbacks = labels.get(key, (None, []))
            is_directory = template_id not in {"view_file", "open_file", "delete_file", "file_attributes"}
            return resolved, _missing_path_message(target, label, is_directory, fallbacks)
        if template_id in {
            "list_directory", "list_directory_recursive", "change_directory",
            "tree_directory", "remove_empty_directory", "delete_directory",
            "disk_usage_dir",
        } and not target.is_dir():
            return resolved, f"Expected a folder at '{target}', but that path is not a folder."
        if template_id in {"view_file", "open_file", "delete_file"} and not target.is_file():
            return resolved, f"Expected a file at '{target}', but that path is not a file."

    if template_id == "copy_file":
        source = Path(resolved["source"])
        destination = Path(resolved["dest"])
        if destination.is_dir():
            destination = destination / source.name
            resolved["dest"] = str(destination)
        if destination.exists() and not resolved.get("overwrite"):
            return resolved, f"A file already exists at '{destination}'. Choose a different name or explicitly request replacement."
        if not destination.exists():
            resolved["overwrite"] = False
        if not destination.parent.is_dir():
            return resolved, f"No destination folder found at '{destination.parent}'."
        if _protected_path(destination.parent):
            return resolved, f"Creating files in the protected location '{destination.parent}' is not allowed."
        invalid_name = _invalid_windows_name(destination)
        if invalid_name:
            return resolved, invalid_name
    elif template_id in _NEW_PATH_TEMPLATES:
        target = Path(resolved["path"])
        if target.exists():
            kind = "folder" if template_id == "create_directory" else "file"
            return resolved, f"A {kind} already exists at '{target}'."
        parent = target.parent
        if not parent.is_dir():
            label = labels.get("path", (None, []))[0]
            parent_name = label or str(parent)
            return resolved, f"No parent folder named '{parent.name}' found in {parent_name}."
        if _protected_path(parent):
            return resolved, f"Creating items in the protected location '{parent}' is not allowed."
        invalid_name = _invalid_windows_name(target)
        if invalid_name:
            return resolved, invalid_name
    elif template_id in ("copy_file", "move_file"):
        destination = Path(resolved["dest"])
        if not destination.parent.is_dir():
            return resolved, f"No destination folder found at '{destination.parent}'."

    return resolved, None


def resolve_folder_for_display(name: str) -> str:
    """Resolve a Desktop/Documents/Downloads location for diagnostics."""
    path, _ = _resolve_known_folder(name.lower())
    return path
