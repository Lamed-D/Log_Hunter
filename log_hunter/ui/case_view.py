"""저장한 분석: recent list rows and save-folder checks for the open/save dialogs — without Tk."""
import os
from pathlib import Path
from types import SimpleNamespace

from log_hunter.core.labels import CASE_TEXT as T, UNKNOWN_VALUE
from log_hunter.image.live import is_live_path
from .record_fields import format_time

ROW_KEYS = ("name", "saved_at", "events", "source_state", "path")


def recent_rows(entries, exists=os.path.exists):
    """[(path, values in ROW_KEYS order, missing?)] for the recent list; a file that is gone is marked, not hidden."""
    rows = []
    for entry in entries:
        missing = not exists(entry["path"])
        name = entry.get("name") or Path(entry["path"]).parent.name or Path(entry["path"]).name
        state = T["missing"] if missing else T["source_states"].get(entry.get("source_state") or "",
                                                                    entry.get("source_state") or UNKNOWN_VALUE)
        events = entry.get("events")
        rows.append((entry["path"], (name, format_time(entry.get("saved_at")) if entry.get("saved_at") else UNKNOWN_VALUE,
                                     f"{events:,}" if isinstance(events, int) else UNKNOWN_VALUE, state, entry["path"]), missing))
    return rows


def is_case_file(path):
    return Path(str(path)).name.casefold() == "case.sqlite"


def save_folder_problem(folder, evidence_sources):
    """Why a folder cannot take a saved analysis (it holds original evidence), else None."""
    target = os.path.normcase(os.path.abspath(str(folder)))
    for source in evidence_sources:
        if os.path.normcase(os.path.abspath(os.path.dirname(str(source)))) == target:
            return T["same_as_evidence"]
    return None


PROBLEM_STATES = {"missing", "changed", "unavailable"}  # engine source states that need the examiner's attention


def info_dict(info):
    return info.to_dict() if hasattr(info, "to_dict") else dict(info or {})


def source_issues(info, derived=()):
    """[(path, shown state)] for original evidence that is missing, changed or could not be checked. `derived`: files
    copied out of a disk image for the analysis — temporary copies whose real original is the image, so skipped."""
    skip = {os.path.normcase(str(p)) for p in derived}
    issues = []
    for source in info_dict(info).get("sources") or ():
        if not isinstance(source, dict) or os.path.normcase(str(source.get("path") or "")) in skip:
            continue
        if is_live_path(source.get("path")) or is_live_path(source.get("resolved_path")):
            continue
        state = str(source.get("status") or source.get("state") or "")
        if state in PROBLEM_STATES:
            issues.append((str(source.get("path") or ""), T["source_states"].get(state, state or UNKNOWN_VALUE)))
    return issues


def source_state(info):
    """One state for the recent list: the image's (or files') first problem, else match / present_unverified / saved."""
    sources = [s for s in info_dict(info).get("sources") or () if isinstance(s, dict)]
    images = [s for s in sources if s.get("kind") == "image"] or sources
    states = ['live_unverified' if is_live_path(s.get('path')) or is_live_path(s.get('resolved_path'))
              else str(s.get("status") or s.get("state") or "") for s in images]
    if not states:
        return ""
    problem = next((state for state in states if state in PROBLEM_STATES), None)
    if problem:
        return problem
    if 'live_unverified' in states:
        return 'live_unverified'
    return "match" if all(state == "match" for state in states) else states[0] if states[0] in T["source_states"] else ""


def image_sources(info):
    """[(path, expected SHA-256, state)] of the disk images the analysis was saved from."""
    return [(str(s.get("path") or ""), s.get("expected_sha256"), str(s.get("status") or ""))
            for s in info_dict(info).get("sources") or () if isinstance(s, dict) and s.get("kind") == "image"
            and not is_live_path(s.get('path')) and not is_live_path(s.get('resolved_path'))]


def case_status(info, events, derived=()):
    """(window title, status line, warning lines) for an opened saved analysis; `derived` as in source_issues
    (engine warnings that only name such a temporary copy are left out too)."""
    d = info_dict(info)
    name = d.get("name") or Path(str(d.get("path") or "")).parent.name or UNKNOWN_VALUE
    status = T["loaded"].format(name=name, saved=format_time(d.get("created_at")) if d.get("created_at") else UNKNOWN_VALUE,
                                version=d.get("tool_version") or UNKNOWN_VALUE, events=events)
    if source_state(d) == 'live_unverified':
        status += ' · ' + T['source_states']['live_unverified']
    skip = [str(p) for p in derived]
    warnings = [str(w) for w in d.get("warnings") or () if w and not any(p and p in str(w) for p in skip)]
    if d.get("partial"):
        warnings.append(T["partial"])
    if d.get("missing_fields"):
        warnings.append(T["missing_fields"].format(fields=", ".join(map(str, d["missing_fields"]))))
    issues = source_issues(d, derived)
    if issues:
        warnings.append(T["source_problem"].format(items="; ".join(f"{state} — {path}" for path, state in issues)))
    return T["title"].format(name=name), status, warnings


def db_tree(counts):
    """Navigation roots built from saved-case aggregates (tree_counts), with the same node keys, kinds and values as
    the loaded tree so a node click can be answered by a database query. Folder levels below the data source names
    and per-device USB groups are only in the loaded tree."""
    from log_hunter.core.labels import RECENT_TEXT, SID_TEXT, artifact_label
    from log_hunter.core.sid_resolver import display_name
    from log_hunter.core.tree import ACTION_NODES, ARTIFACT_CATEGORIES, TreeNode, _artifact_groups
    artifacts = counts.get("artifacts") or {}
    actions = {(r["artifact"], r["action"]): r["records"] for r in counts.get("actions") or ()}
    sources = TreeNode("src", "데이터 출처", "source", None, counts.get("records") or 0)
    for row in counts.get("sources") or ():
        parts = tuple(row.get("parts") or ())
        sources.children.append(TreeNode("src:" + "\\".join((row["name"], *parts)), parts[-1] if parts else row["name"],
                                          "source", (row["name"], parts), row["records"]))
    found = TreeNode("art", "찾은 기록", "all", None, counts.get("records") or 0)
    for key, label, kinds in ARTIFACT_CATEGORIES:
        category = TreeNode(f"art:{key}", label, "artifacts", tuple(kinds), sum(artifacts.get(a, 0) for a in kinds))
        groups = _artifact_groups(list(kinds))
        if len(groups) > 1:
            category.children = [TreeNode(f"art:{key}:{g[0]}", artifact_label(g[0]), "artifacts", g,
                                          sum(artifacts.get(a, 0) for a in g)) for g in groups]
        for child in [category, *category.children]:
            if len(child.value) == 1 and child.value[0] in ACTION_NODES:
                artifact = child.value[0]
                child.children = [TreeNode(f"art:{key}:{artifact}:{name}", _action_labels(artifact)[name],
                                           "action_set", (artifact, acts), sum(actions.get((artifact, a), 0) for a in acts))
                                  for name, acts in ACTION_NODES[artifact]]
            if child.value == ("lnk",):
                child.children.append(TreeNode(f"art:{key}:lnk:shortcuts", RECENT_TEXT["nodes"]["shortcuts"], "lnk_shortcuts",
                                               None, counts.get("shortcuts") or 0))
        if key == "recent_documents":
            targets = counts.get("targets") or ()
            shared = sorted((t for t in targets if t["kinds"] > 1), key=lambda t: (-t["kinds"], -t["records"], t["group"]))
            node = TreeNode(f"art:{key}:targets", RECENT_TEXT["nodes"]["targets"], "target_groups", None,
                            sum(t["records"] for t in targets))
            node.children = [TreeNode(f"art:{key}:target:{t['group']}", RECENT_TEXT["group"].format(
                name=t["group"].split(":", 1)[-1], kinds=t["kinds"], count=t["records"]), "target_group", t["group"], t["records"])
                for t in shared]
            single = sum(t["records"] for t in targets if t["kinds"] == 1)
            if single:
                node.children.append(TreeNode(f"art:{key}:target:single", RECENT_TEXT["nodes"]["single"], "target_single",
                                              None, single))
            category.children.append(node)
        found.children.append(category)
    accounts = TreeNode("acct", "사용자 계정")
    for row in counts.get("users") or ():
        name = row.get("name") or display_name(row["sid"])
        accounts.children.append(TreeNode(f"acct:{row['sid']}", SID_TEXT["node"].format(name=name, sid=row["sid"]) if name
                                          else row["sid"], "account", row["sid"], row["records"]))
    return [sources, found, accounts]


def _action_labels(artifact):
    from log_hunter.core import labels
    table = {"jumplist": labels.JUMP_LIST_TEXT, "cache": labels.CACHE_TEXT, "history": labels.WEB_TEXT,
             "webcache": labels.WEB_TEXT, "mft": labels.FILE_INVENTORY_TEXT}[artifact]
    return table["nodes"]


def node_filter(node):
    """The database query form of a tree node ({"kind", "value"}), or None for nodes only the loaded tree knows."""
    if node is None or node.kind in ("all", "group"):
        return None
    if node.kind in ("artifacts", "action_set", "lnk_shortcuts", "target_groups", "target_group", "target_single",
                     "account", "source", "device_kind", "usb_hidden", "usb_device", "task_signals"):
        value = node.value
        if node.kind == "action_set":
            value = [value[0], list(value[1])]
        elif node.kind == "source" and value is not None:
            value = [value[0], list(value[1])]
        elif isinstance(value, tuple):
            value = list(value)
        return {"kind": node.kind, "value": value}
    return False


def db_page(path, filters, node, limit):
    """(records, total, warnings) of one tree node and filter bar from a saved analysis, first `limit` in time order."""
    from log_hunter.database.case_query import open_case_query
    query_filters = {k: v for k, v in filters.items() if v}
    shape = node_filter(node)
    if shape:
        query_filters["node"] = shape
    with open_case_query(path) as query:
        page = query.query_events(query_filters, limit=limit)
        return list(page.events), query.count_events(query_filters), list(query.warnings)


def quick_page(path, limit):
    """(first records in timeline order, total) read straight from a saved analysis with an up-to-date query index,
    or None (no index, damaged or older format: the normal full load shows it)."""
    from log_hunter.database.case_query import open_case_query
    from log_hunter.database.query_common import QueryInputError
    try:
        with open_case_query(path) as query:
            if not query.indexed or query.partial:
                return None
            page = query.query_events({}, limit=limit)
            return list(page.events), query.count_events({}), query.quick_counts()
    except (QueryInputError, OSError):
        return None


def saved_extractions(result):
    """The image extractions kept in a saved analysis (image path, image info, extracted file map), shaped like an
    extraction so records still show their place inside the image ("[case.E01] 볼륨 0\\...") after the copies are gone."""
    image = getattr(result, "image", None) or {}
    found = []
    for item in [image, *(image.get("additional_images") or [])]:
        if isinstance(item, dict) and item.get("image_path") and isinstance(item.get("files"), list):
            files = [f for f in item["files"] if isinstance(f, dict) and f.get("extracted") and f.get("image_path")]
            found.append(SimpleNamespace(image_path=item["image_path"], image=item.get("image") or {}, files=files))
    return found
