"""Consolidate task definitions only within the same acquired Windows tree."""
import copy
import ntpath
from collections import defaultdict

from log_hunter.parser.taskcache import task_path

TASK_ARTIFACTS = ("tasks", "taskcache")  # merged/task-file records and registrations without a task file


def task_location(source):
    path = str(source).replace("/", "\\")
    folded = path.casefold()
    marker = "\\system32\\tasks\\"
    if marker in folded:
        index = folded.index(marker)
        return folded[:index], task_path(path[index + len(marker):])
    marker = "\\system32\\config\\"
    if marker in folded:
        return folded[:folded.index(marker)], None
    marker = "\\system32\\winevt\\logs\\"
    if marker in folded:
        return folded[:folded.index(marker)], None
    # No guessed cohort for isolated files: the namespace alone cannot identify a host.
    return None, None


def _source(event, kind, hashes):
    return {"kind": kind, "source": event.source, "locator": event.locator,
            "sha256": hashes.get(event.source)}


def _commands(actions):
    return [(a.get("type"), (a.get("command") or a.get("class_id") or "").casefold(),
             a.get("arguments") or "", (a.get("working_directory") or "").casefold()) for a in actions]


def merge_tasks(events, evidence=()):
    hashes = {e.source: e.sha256 for e in evidence}
    xml, registry = defaultdict(list), defaultdict(list)
    for index, event in enumerate(events):
        if event.artifact not in ("tasks", "taskcache"):
            continue
        scope, namespace = task_location(event.source)
        namespace = namespace if event.artifact == "tasks" else event.details.get("task_path")
        event.details["task_path"] = namespace
        key = (scope, namespace.casefold() if namespace else None)
        if event.artifact == "tasks":
            xml[(key, event.source)].append(index)
        else:
            registry[key].append(index)
    xml_by_key = defaultdict(list)
    for (key, source), indices in xml.items():
        xml_by_key[key].append(indices)
    removed = set()
    for (key, source), indices in xml.items():
        first = events[indices[0]]
        originals = [copy.deepcopy(events[i].details) for i in indices]
        details = first.details
        details["xml_details"] = originals
        details["task_sources"] = [_source(first, "xml", hashes)]
        details["execution_confirmed"] = False
        details["com_handler_uuid"] = details.get("class_id")
        details["xml_hidden"] = details.get("settings", {}).get("hidden")
        details.setdefault("task_signals", [])
        details["task_name"] = (details.get("task_path") or ntpath.basename(source)).rsplit("\\", 1)[-1]
        candidates = registry.get(key, [])
        unique = bool(key[0] and key[1] and len(candidates) == 1 and len(xml_by_key[key]) == 1)
        selected = candidates[0] if unique else None
        if selected is not None and events[selected].details.get("identity_consistent"):
            registration = events[selected]
            rd = registration.details
            for field in ("task_guid", "launch_catalogs", "hidden_indicator", "registry_details",
                          "registration_time", "last_run_time", "last_completed_time", "time_semantics_verified"):
                details[field] = copy.deepcopy(rd.get(field))
            details["task_sources"].append(_source(registration, "registry", hashes))
            details["registry_details"]["source_locator"] = registration.locator
            details["com_handler_dll"] = rd.get("com_handler_dll")
            details["task_match_basis"] = "same_acquired_windows_root_full_path_consistent_tree_guid"
            details["task_signals"].extend(copy.deepcopy(rd.get("task_signals", [])))
            observed_actions = details["registry_details"]["actions"]
            xml_actions = [{"type": d.get("action_type"), "command": d.get("command"),
                            "arguments": d.get("arguments"), "class_id": d.get("class_id"),
                            "working_directory": d.get("working_directory")} for d in originals]
            if observed_actions["parse_state"] == "decoded" and _commands(observed_actions["actions"]) != _commands(xml_actions):
                details["task_signals"].append({"code": "actions_disagree", "reason": "Registered and XML action definitions differ"})
            removed.add(selected)
        else:
            details["task_signals"].append({"code": "registry_not_matched", "reason": "No unique consistent registration in this acquisition"})
            for field in ("registration_time", "last_run_time", "last_completed_time", "hidden_indicator"):
                details.setdefault(field, None)
            details["time_semantics_verified"] = False
        removed.update(indices[1:])
        if details["task_signals"] and first.status == "ok":
            first.status = "warning"
    for indices in registry.values():
        for index in indices:
            if index in removed:
                continue
            event = events[index]
            event.details["task_sources"] = [_source(event, "registry", hashes)]
            event.details["task_signals"].append({"code": "xml_not_matched", "reason": "No unique matching XML definition in this acquisition"})
            if event.status == "ok":
                event.status = "warning"
    return [event for index, event in enumerate(events) if index not in removed]


def task_log_relations(events, limit=10000):
    tasks, logs = defaultdict(list), defaultdict(list)
    for index, event in enumerate(events):
        scope, _ = task_location(event.source)
        if not scope:
            continue
        if event.artifact in ("tasks", "taskcache"):
            namespace = task_path(event.details.get("task_path"))
            if namespace:
                tasks[(scope, namespace.casefold())].append(index)
        elif (event.artifact == "evtx" and
              str(event.details.get("provider", "")).casefold() == "microsoft-windows-taskscheduler" and
              event.details.get("event_id") in (106, 140, 141, 200, 201)):
            data = event.details.get("event_data") or event.details.get("user_data") or {}
            namespace = task_path(data.get("TaskName") or data.get("TaskPath")) if isinstance(data, dict) else None
            if namespace:
                logs[(scope, namespace.casefold())].append(index)
    result = []
    for key, left in tasks.items():
        right = logs.get(key, [])
        count = len(left) * len(right)
        metadata = {"basis": "same_task_namespace", "confidence": "candidate",
                    "execution_confirmed": False, "task_path": key[1]}
        if count > limit:
            result.append({"type": "correlation_group", "relation_type": "task_log_correlation",
                           "event_indices": left + right, "left_event_indices": left,
                           "candidate_count": count, "pair_expansion_limit": limit, **metadata})
        else:
            for a in left:
                for b in right:
                    result.append({"type": "task_log_correlation", "left": a, "right": b, **metadata})
    return result
