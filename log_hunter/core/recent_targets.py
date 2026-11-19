"""Same-target grouping for recent files and folders: one key per target across MRU, shortcut, Jump List and folder records."""
import re
from collections import defaultdict

RECENT_ARTIFACTS = ("mru", "lnk", "jumplist", "shellbag")
_PLACEHOLDER = re.compile(r"^\[\d+\]$")  # shell item without a readable name (folder record path parts)
_ABSOLUTE = re.compile(r"^(?:[a-z]:\\|\\\\)", re.IGNORECASE)


def normalize_target(path):
    """'C:\\Users\\alice\\a.txt' style text with unnamed shell items, doubled separators and a trailing separator
    removed, or None when nothing readable is left. Case is kept (shown); keys fold it."""
    if not path:
        return None
    text = str(path).replace("/", "\\").strip()
    unc = text.startswith("\\\\")
    parts = [p for p in text.split("\\") if p and not _PLACEHOLDER.match(p)]
    if not parts:
        return None
    if unc:
        return "\\\\" + "\\".join(parts)
    if re.match(r"^[a-z]:$", parts[0], re.IGNORECASE):
        return parts[0] + "\\" + "\\".join(parts[1:])
    return "\\".join(parts)


def target_key(event):
    """'path:<full path>' when the record names a full path, 'name:<last part>' when it only keeps a name
    (RecentDocs, some dialogs), None when it names nothing."""
    target = normalize_target(event.path)
    if not target:
        return None
    if _ABSOLUTE.match(target):
        return "path:" + target.rstrip("\\").casefold() if len(target) > 3 else "path:" + target.casefold()
    return "name:" + target.rsplit("\\", 1)[-1].casefold()


def attach_target_keys(events):
    """Set details target_key (this record) and target_group (the group it is shown in). A name-only record joins the
    one full-path group with that last name; with none or several candidates it stays its own group. The way it was
    joined is kept in target_match ('path' / 'name') so a name match is never shown as a confirmed same file."""
    recent = [e for e in events if e.artifact in RECENT_ARTIFACTS]
    by_name = defaultdict(set)
    for event in recent:
        key = target_key(event)
        event.details = dict(event.details or {})
        if key:
            event.details["target_key"] = key
            if key.startswith("path:"):
                by_name[key.rstrip("\\").rsplit("\\", 1)[-1]].add(key)
    for event in recent:
        key = event.details.get("target_key")
        if not key:
            continue
        group, match = key, "path"
        if key.startswith("name:"):
            candidates = by_name.get(key[5:], set())
            if len(candidates) == 1:
                group, match = next(iter(candidates)), "name"
            else:
                match = "name_only"
        event.details["target_group"] = group
        event.details["target_match"] = match
    return events


def target_label(key, events):
    """Shown name of a group: the longest recorded spelling of its target."""
    names = [normalize_target(e.path) for e in events if e.details.get("target_group") == key and e.path]
    return max((n for n in names if n), key=len, default=key.split(":", 1)[-1])
