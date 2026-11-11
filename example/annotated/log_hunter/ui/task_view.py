# ▶ 원본: log_hunter/ui/task_view.py
# ▶ 예약 작업의 기본 열, '예약 작업 상세'·'출처 비교' 탭 내용, 의심 신호(확정 아님)를 만듭니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""예약 작업: basic table columns, the extra detail and source comparison tabs, and signals — without Tk.

Fields follow the engine contract (#171/#172): task_path, command, run_user, registration_time, last_run_time,
last_completed_time, hidden_indicator, task_sources, task_signals, xml_details (one entry per task-file action),
registry_details (tree / dynamic_info / actions). Merged and task-file records are `tasks`, registrations without a
task file are `taskcache`; both are shown on the same screen. Older task-file-only records (task_name, uri,
principal, registration_date, suspicion_flags) are shown too.
"""
import json

from log_hunter.core.labels import TASK_TEXT as T, UNKNOWN_VALUE
from log_hunter.core.task_merge import TASK_ARTIFACTS
from .record_fields import format_time

COLUMNS = ("task_name", "task_command", "run_user", "registration_time", "last_run_time", "last_completed_time",
           "task_hidden", "task_source", "task_signals")
TIME_KEYS = {"registration_time": ("registration_time", "registration_date"),
             "last_run_time": ("last_run_time",), "last_completed_time": ("last_completed_time",)}
F = T["fields"]


def _d(event):
    return event.details or {}


def is_task(event):
    return event is not None and event.artifact in TASK_ARTIFACTS


def signals(event):
    """[(code, shown reason)] from the engine's signals, or the task-file parser's suspicion flags."""
    d = _d(event)
    items = []
    for signal in d.get("task_signals") or ():
        if isinstance(signal, dict):
            code = signal.get("code") or ""
            items.append((code, T["signals"].get(code) or signal.get("reason") or code))
    for flag in d.get("suspicion_flags") or ():
        items.append((str(flag), T["signals"].get(str(flag), str(flag))))
    return items


def source_kinds(event):
    kinds = {str(s.get("kind")) for s in _d(event).get("task_sources") or () if isinstance(s, dict) and s.get("kind")}
    # Records without the engine's source list: registrations come from the registry, the rest from the task file.
    return kinds or {"registry" if event.artifact == "taskcache" else "xml"}


def cell(key, event):
    if not is_task(event):
        return ""
    d = _d(event)
    if key == "task_name":
        return str(d.get("task_path") or d.get("uri") or d.get("task_name") or "")
    if key == "task_command":
        if d.get("com_handler_dll") or d.get("com_handler_uuid") or d.get("class_id"):
            return T["com"].format(dll=d.get("com_handler_dll") or UNKNOWN_VALUE,
                                   uuid=d.get("com_handler_uuid") or d.get("class_id") or "")
        command = " ".join(str(x) for x in (d.get("command"), d.get("arguments")) if x)
        return command or UNKNOWN_VALUE
    if key == "run_user":
        principal = d.get("principal") if isinstance(d.get("principal"), dict) else {}
        return str(d.get("run_user") or principal.get("user_id") or principal.get("group_id") or UNKNOWN_VALUE)
    if key in TIME_KEYS:
        value = next((d.get(k) for k in TIME_KEYS[key] if d.get(k)), None)
        return format_time(value)
    if key == "task_hidden":
        hidden = d.get("hidden_indicator")
        settings = d.get("settings") if isinstance(d.get("settings"), dict) else {}
        if hidden is None and (d.get("xml_hidden") is True or str(settings.get("hidden", "")).lower() in ("true", "1")):
            return T["hidden_xml"]
        return UNKNOWN_VALUE if hidden is None else (T["hidden_yes"] if hidden else T["hidden_no"])
    if key == "task_source":
        kinds = source_kinds(event)
        if {"registry", "xml"} <= kinds:
            return T["source_both"]
        return T["source_registry"] if "registry" in kinds else T["source_xml"]
    if key == "task_signals":
        found = signals(event)
        return ("⚠ " + "; ".join(reason for _c, reason in found) + " " + T["not_confirmed"]) if found else ""
    return ""


def _flat(value):
    if value is None or value == "" or value == [] or value == {}:
        return UNKNOWN_VALUE
    if isinstance(value, dict):
        shown = [f"{F.get(k, k)} {_flat(v)}" for k, v in value.items() if v not in (None, "", [], {})]
        return ", ".join(shown) or UNKNOWN_VALUE
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _xml_entries(d):
    """Task-file values per action: the engine's list, an older single dict, or the record's own fields."""
    xml = d.get("xml_details")
    if isinstance(xml, list):
        return [x for x in xml if isinstance(x, dict)]
    if isinstance(xml, dict):
        return [xml]
    if not any(s.get("kind") == "xml" for s in d.get("task_sources") or () if isinstance(s, dict)) and d.get("task_sources"):
        return []
    own = {k: d.get(k) for k in ("author", "description", "registration_date", "uri", "principal", "settings", "triggers",
                                 "action_type", "command", "arguments") if d.get(k)}
    return [own] if own else []


XML_KEYS = ("author", "description", "registration_date", "uri", "principal", "settings")
ACTION_KEYS = ("action_type", "type", "command", "arguments", "working_directory", "class_id", "com_handler_dll")


def _xml_lines(entries):
    if not entries:
        return [f"  {UNKNOWN_VALUE}"]
    first = entries[0]
    lines = [f"  {F.get(k, k)}: {_flat(first.get(k))}" for k in XML_KEYS if first.get(k) not in (None, "", {}, [])]
    for number, entry in enumerate(entries, 1):
        parts = [f"{F.get(k, k)} {entry[k]}" for k in ACTION_KEYS if entry.get(k)]
        if parts:
            lines.append(f"  {F['action_n'].format(n=number)}: " + " · ".join(parts))
    return lines or [f"  {UNKNOWN_VALUE}"]


def _registry_lines(registry, d):
    if not registry:
        return [f"  {T['no_registry']}"]
    if not any(k in registry for k in ("tree", "actions", "dynamic_info")) or not all(
            isinstance(registry.get(k), (dict, list, type(None))) for k in ("tree", "actions", "dynamic_info")):
        return [f"  {F.get(k, k)}: {_flat(v)}" for k, v in registry.items()]  # older flat shape
    lines = []
    if registry.get("path"):
        lines.append(f"  {F['task_path']}: {registry['path']}")
    for tree in registry.get("tree") or ():
        if isinstance(tree, dict):
            sd = tree.get("sd")
            sd_text = T["sd_absent"] if not sd else T["sd_present"].format(size=sd.get("size") if isinstance(sd, dict) else "?")
            lines.append(f"  {F['tree']}: {tree.get('path') or UNKNOWN_VALUE} · {F['task_guid']} {tree.get('id') or UNKNOWN_VALUE}"
                         f" · {F['index']} {_flat(tree.get('index'))} · {sd_text}"
                         f" · {F['key_last_write']} {format_time(tree.get('key_last_write'))}")
    actions = registry.get("actions") if isinstance(registry.get("actions"), dict) else {}
    if actions:
        if actions.get("execution_context"):
            lines.append(f"  {F['execution_context']}: {actions['execution_context']} {T['context_note']}")
        for number, action in enumerate(a for a in actions.get("actions") or () if isinstance(a, dict)):
            parts = [f"{F.get(k, k)} {action[k]}" for k in ACTION_KEYS if action.get(k)]
            lines.append(f"  {F['action_n'].format(n=number + 1)}: " + (" · ".join(parts) or UNKNOWN_VALUE))
        if actions.get("parse_state") not in (None, "decoded"):
            lines.append(f"  {F['actions']}: {T['not_decoded'].format(state=actions.get('parse_state'))}")
    dynamic = registry.get("dynamic_info") if isinstance(registry.get("dynamic_info"), dict) else {}
    for value in dynamic.get("time_values") or ():
        if isinstance(value, dict):
            meaning = value.get("meaning") or T["meaning_unknown"]
            lines.append(f"  {F['dynamic_time'].format(offset=value.get('offset'))}: "
                         f"{format_time(value.get('decoded_utc'))} — {meaning}")
    if dynamic and dynamic.get("parse_state") not in (None, "decoded"):
        lines.append(f"  {F['dynamic_info']}: {T['not_decoded'].format(state=dynamic.get('parse_state'))}")
    if registry.get("key_last_write"):
        lines.append(f"  {F['key_last_write']}: {format_time(registry['key_last_write'])}")
    if d.get("launch_catalogs"):
        lines.append(f"  {F['launch_catalogs']}: {', '.join(map(str, d['launch_catalogs']))}")
    return lines or [f"  {UNKNOWN_VALUE}"]


def detail_lines(event, origin=None):
    """예약 작업 상세: task file details, execution conditions, registry details, hashes and signals.
    `origin` maps an analyzed file path to where it really came from (image volume path), not the extracted copy."""
    d = _d(event)
    origin = origin or str
    entries = _xml_entries(d)
    lines = [f"[{T['xml']}]", *_xml_lines(entries)]
    triggers = next((e.get("triggers") for e in entries if e.get("triggers")), None) or d.get("triggers") or []
    lines.append(f"[{T['conditions']}]")
    kinds = [str(t.get("type")) for t in triggers if isinstance(t, dict) and t.get("type")]
    lines.append("  " + (", ".join(T["triggers"].get(k, k) for k in kinds) if kinds else UNKNOWN_VALUE))
    registry = d.get("registry_details") if isinstance(d.get("registry_details"), dict) else {}
    lines.append(f"[{T['registry']}]")
    lines += _registry_lines(registry, d)
    lines.append(f"[{T['execution']}]")
    lines.append("  " + (T["execution_unconfirmed"] if d.get("execution_confirmed") is not True else T["execution_confirmed"]))
    if d.get("time_semantics_verified") is False:
        lines.append("  " + T["time_unverified"])
    lines.append(f"[{T['hashes']}]")
    sources = [s for s in d.get("task_sources") or () if isinstance(s, dict)]
    lines += [f"  {T['kinds'].get(s.get('kind'), s.get('kind'))}: {origin(s.get('source', ''))} · SHA-256 {s.get('sha256') or UNKNOWN_VALUE}"
              for s in sources] or [f"  {UNKNOWN_VALUE}"]
    for code, reason in signals(event):
        evidence = next((s.get("evidence") for s in d.get("task_signals") or () if isinstance(s, dict) and s.get("code") == code), None)
        lines.append(f"  ⚠ {reason}" + (f" — {_flat(evidence)}" if evidence else ""))
    return lines


def _scalars(values):
    return {k: v for k, v in (values or {}).items() if not isinstance(v, (dict, list)) and v not in (None, "")}


def _verdict(a, b):
    if a is None:
        return T["only_xml"]
    if b is None:
        return T["only_registry"]
    return T["same"] if str(a).strip().casefold() == str(b).strip().casefold() else T["different"]


def _row(label, a, b):
    return (label, UNKNOWN_VALUE if a is None else str(a), UNKNOWN_VALUE if b is None else str(b), _verdict(a, b))


def _engine_pairs(registry, entries):
    """(label, registry value, task file value) from the engine's nested registry details and per-action task file list."""
    reg_actions = registry.get("actions") if isinstance(registry.get("actions"), dict) else {}
    left_actions = [a for a in reg_actions.get("actions") or () if isinstance(a, dict)]
    tree = next((t for t in registry.get("tree") or () if isinstance(t, dict)), {})
    first = entries[0] if entries else {}
    principal = first.get("principal") if isinstance(first.get("principal"), dict) else {}
    pairs = [(F["task_path"], registry.get("path") or tree.get("path"), first.get("uri") or first.get("task_path")),
             (F["action_count"], len(left_actions) if reg_actions else None, len(entries) if entries else None),
             (F["execution_context"], reg_actions.get("execution_context"), principal.get("principal_id"))]
    for number in range(max(len(left_actions), len(entries))):
        left = left_actions[number] if number < len(left_actions) else {}
        right = entries[number] if number < len(entries) else {}
        for key, right_key in (("type", "action_type"), ("command", "command"), ("arguments", "arguments"),
                               ("working_directory", "working_directory"), ("class_id", "class_id")):
            a, b = left.get(key) or None, right.get(right_key) or None
            if a is not None or b is not None:
                pairs.append((f"{F['action_n'].format(n=number + 1)} {F.get(right_key, key)}", a, b))
    return [p for p in pairs if p[1] is not None or p[2] is not None]


def compare_rows(event):
    """출처 비교: [(field, registry value, task file value, verdict)] when both the registry and a task file were read."""
    d = _d(event)
    registry = d.get("registry_details") if isinstance(d.get("registry_details"), dict) else None
    xml = d.get("xml_details")
    if registry is None or not xml:
        return []
    if isinstance(xml, dict):  # older flat shape: compare the simple values both sides have
        left, right = _scalars(registry), _scalars(xml)
        return [_row(F.get(k, k), left.get(k), right.get(k)) for k in sorted(left.keys() | right.keys())]
    return [_row(label, a, b) for label, a, b in _engine_pairs(registry, _xml_entries(d))]
