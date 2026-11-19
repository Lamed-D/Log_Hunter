"""Result table columns: the general timeline set, or a set that fits one record category."""
import csv
from dataclasses import dataclass

from log_hunter.core.export import csv_safe
from log_hunter.core import thumbcache_view, wifi_view
from log_hunter.core.labels import (ARTIFACT_DESCRIPTIONS, DEFENDER_TEXT, USB_BASIS_LABELS, USB_CONFIDENCE_LABELS, USB_DEVICE_KINDS, USB_GROUP_AUXILIARY, USB_GROUP_BASIS_LABELS, USB_GROUP_NOT_CONFIRMED,
                                    USB_KIND_CONFLICT, USB_NO_COMPOSITE_BASIS, USB_SERIAL_MAY_BE_GENERATED, WEB_TEXT, RECENT_TEXT, action_label,
                                    artifact_label, column_label, status_label, time_field_label)
from log_hunter.core.tree import category_of
from . import task_view
from log_hunter.core.sid_resolver import display_name


@dataclass(frozen=True)
class Column:
    key: str
    width: int


# The time comes first, then what kind of record it is; wide defaults so long paths stay readable.
DEFAULT = (Column("timestamp", 170), Column("artifact", 190), Column("time_field", 130), Column("action", 170),
           Column("path", 420), Column("user", 100), Column("sid", 150), Column("status", 80))
_HEAD = (Column("timestamp", 170), Column("artifact", 170))
_TAIL = (Column("user", 100), Column("time_field", 130), Column("origin", 340), Column("description", 320))
# USB records come from the system hive, so a user column would only ever be empty or misleading.
_TAIL_NO_USER = tuple(c for c in _TAIL if c.key != "user")
CATEGORY_COLUMNS = {
    "run_programs": (*_HEAD, Column("program", 380), *_TAIL),
    "installed_programs": (*_HEAD, Column("program", 380), Column("publisher", 170), Column("version", 100), *_TAIL),
    "recent_documents": (*_HEAD, Column("document", 420), *_TAIL),
    # 같은 대상 묶어 보기: the records of one target from every source, each with where it was read and what its time means.
    "recent_targets": (*_HEAD, Column("time_field", 260), Column("document", 360), Column("source_location", 380),
                       Column("target_match", 190), Column("user", 100), Column("origin", 300)),
    # 바로가기별: one row per shortcut file with all its times side by side.
    "shortcuts": (Column("lnk_file_created", 170), Column("document", 380), Column("lnk_file_modified", 170),
                  Column("lnk_target_created", 170), Column("lnk_target_written", 170), Column("lnk_target_accessed", 170),
                  Column("source_location", 340), Column("user", 100)),
    "recycle_bin": (*_HEAD, Column("original_path", 420), Column("file_size", 100), Column("recycle_pair", 300), *_TAIL),
    "shell_bags": (*_HEAD, Column("folder", 420), *_TAIL),
    # Kind is the engine's reading of recorded identifiers; the time is a key/property time, not a confirmed connection.
    "usb_devices": (Column("timestamp", 170), Column("device_kind_name", 140), Column("artifact", 150),
                    Column("device_name", 220), Column("physical_group", 260), Column("unknown_reason", 240), Column("device", 260), Column("vid_pid", 100), Column("usb_class", 150),
                    Column("install_class", 110), Column("serial", 220), Column("composite", 170),
                    Column("kind_basis", 300), *_TAIL_NO_USER),
    "web_history": (*_HEAD, Column("url", 460), *_TAIL),
    "web_visits": (Column("timestamp", 170), Column("web_title", 260), Column("url", 420), Column("referrer_url", 300),
                   Column("browser", 120), Column("user", 100), Column("time_field", 110), Column("origin", 340)),
    # One row per download; every URL keeps its role so the page that linked is not read as the file source.
    "web_downloads": (Column("download_start", 170), Column("download_file", 200), Column("download_save_path", 340),
                      Column("download_url", 320), Column("final_url", 320), Column("referrer_url", 280),
                      Column("download_end", 170), Column("download_size", 110), Column("download_state", 80),
                      Column("browser", 120), Column("user", 100), Column("origin", 340)),
    # A detection or reference is what the log says; execution and removal are never confirmed by it.
    "security_detections": (Column("timestamp", 170), Column("action", 190), Column("threat_name", 220),
                            Column("threat_target", 360), Column("defender_result", 260), Column("unconfirmed", 300),
                            Column("origin", 340), Column("description", 320)),
    "autostart": (*_HEAD, Column("entry", 260), Column("command", 380), *_TAIL),
    "commands": (*_HEAD, Column("command", 480), *_TAIL),
    # 예약 작업 (selected on its own): basic fields only; the rest is in the detail tabs.
    "scheduled_tasks": (Column("registration_time", 170), Column("task_name", 300), Column("task_command", 380),
                        Column("run_user", 150), Column("last_run_time", 170), Column("last_completed_time", 170),
                        Column("task_hidden", 160), Column("task_source", 220), Column("task_signals", 320),
                        Column("origin", 340)),
    # Wi-Fi: profile facts and the shared key state; a shown key is not a connection.
    "network": (*_HEAD, Column("network", 220), *(Column(key, width) for key, width in zip(
        wifi_view.COLUMNS, (180, 120, 100, 110, 180, 260, 220, 320))), *_TAIL),
    # Saved targets and hints only: the time is the key's last change, never a confirmed connection.
    "remote_desktop": (*_HEAD, Column("remote_host", 260), Column("username_hint", 170), Column("rank", 80), *_TAIL),
    # Cache metadata only: no source path, no time, the image is not decoded; a stored checksum is not verified.
    "thumbnail_cache": (*(Column(key, width) for key, width in zip(thumbcache_view.COLUMNS,
                                                                  (170, 120, 120, 220, 260, 120, 100, 170))),
                        Column("origin", 340), Column("description", 320), Column("status", 80)),
}
_SET_NAMES = {DEFAULT: "default", **{cols: name for name, cols in CATEGORY_COLUMNS.items()}}


def set_name(cols):
    """Stable name of a column set, used as the key of the saved order and widths."""
    return _SET_NAMES.get(cols, "default")


def ordered(cols, order):
    """`cols` in the saved `order`: unknown saved keys are ignored, columns missing from it keep their place at the end."""
    by_key = {c.key: c for c in cols}
    picked = [by_key[k] for k in order or () if k in by_key]
    seen = {c.key for c in picked}
    return tuple(picked + [c for c in cols if c.key not in seen])


def moved(order, key, before):
    """Order after dragging column `key` onto column `before` (dropping on a later column puts it after that one)."""
    order = list(order)
    if key not in order or before not in order or key == before:
        return order
    target = order.index(before)
    order.remove(key)
    order.insert(target, key)
    return order


def columns_for(node):
    """Columns for the selected tree node: a category's own set when every artifact under the
    node belongs to that category, otherwise the general timeline set."""
    if node is not None and (node.kind == "task_signals" or (node.kind == "artifacts" and node.value
                                                             and set(node.value) <= set(task_view.TASK_ARTIFACTS))):
        return CATEGORY_COLUMNS["scheduled_tasks"]
    if node is not None and node.kind in ("device_kind", "usb_device", "usb_hidden"):
        return CATEGORY_COLUMNS["usb_devices"]
    if node is not None and node.kind in ("target_groups", "target_group", "target_single"):
        return CATEGORY_COLUMNS["recent_targets"]
    if node is not None and node.kind == "lnk_shortcuts":
        return CATEGORY_COLUMNS["shortcuts"]
    if node is not None and node.kind == "action_set" and node.value[0] == "history":
        return CATEGORY_COLUMNS["web_downloads" if node.value[1] == ("download",) else "web_visits"]
    if node is None or node.kind != "artifacts":
        return DEFAULT
    categories = {category_of(a) for a in node.value}
    return CATEGORY_COLUMNS.get(categories.pop(), DEFAULT) if len(categories) == 1 else DEFAULT


def configure_tree(tree, cols, order, widths, on_sort):
    """Switch a Treeview to `cols` in the saved `order` and `widths`. The shown-column list is reset first:
    a list naming the previous set's columns would make Tk refuse the new columns."""
    tree.configure(displaycolumns="#all")
    tree.configure(columns=[c.key for c in cols])
    for column, header in zip(cols, headers(cols)):
        tree.heading(column.key, text=header, command=lambda k=column.key: on_sort(k))
        tree.column(column.key, width=widths.get(column.key, column.width))
    tree.configure(displaycolumns=[c.key for c in ordered(cols, order)])


def headers(columns):
    return [column_label(c.key) for c in columns]


def cell(key, event, sid_map, origins):
    details = event.details or {}
    target = event.path or event.process or event.url or details.get("command") or ""
    if key == "artifact":
        return artifact_label(event.artifact)
    if key == "timestamp":
        return event.timestamp or "알 수 없음"
    if key == "time_field":
        return time_field_label(event.time_field) if event.time_field else ""
    if key == "sid":
        return event.sid or ""
    if key == "user":
        return display_name(event.sid, sid_map)
    if key == "action":
        return action_label(event.action)
    if key == "status":
        return status_label(event.status)
    if key == "origin":
        return origins.text(event.source) if origins else str(event.source or "")
    if key == "description":
        return ARTIFACT_DESCRIPTIONS.get(event.artifact, artifact_label(event.artifact))
    if key in ("path", "program", "document", "folder", "entry", "target"):
        return target
    if key == "original_path":
        return details.get("original_path") or target
    if key == "device":
        return details.get("device") or target
    if key in _USB_CELLS:
        return _USB_CELLS[key](details) if event.artifact == "usb" else ""
    if key in ("threat_name", "threat_target", "defender_result", "unconfirmed") and event.artifact == "defender":
        return defender_cell(key, event)
    if key == "recycle_pair":
        from .recycle_view import pair_text
        return pair_text(details) if event.artifact == "recyclebin" else ""
    if key == "url":
        return event.url or target
    if key == "command":
        return details.get("command") or event.process or ""
    if key in task_view.COLUMNS:
        return task_view.cell(key, event)
    if key in wifi_view.COLUMNS:
        return wifi_view.cell(key, event)
    if key in thumbcache_view.COLUMNS:
        return thumbcache_view.cell(key, event)
    if key == "network":
        return details.get("profile_name") or details.get("ssid_name") or target
    if key == "source_location":
        return source_location(event, origins)
    if key == "target_match":
        return RECENT_TEXT["match"].get(details.get("target_match"), "")
    if key.startswith("lnk_file_") or key.startswith("lnk_target_"):
        return str((details.get("lnk_times") or {}).get(key) or "") if event.artifact == "lnk" else ""
    if key in _WEB_CELLS:
        return _WEB_CELLS[key](event, details) if event.artifact == "history" else ""
    value = details.get(key)
    return "" if value is None else str(value)


def source_location(event, origins=None):
    """Where a recent-file record was read: the registry key path, the shortcut file inside the image, or the
    Jump List file and the position inside it."""
    origin = origins.text(event.source) if origins else str(event.source or "")
    if event.artifact in ("mru", "shellbag"):
        key = (event.details or {}).get("registry_key") if event.artifact == "shellbag" else None
        return f"{RECENT_TEXT['where'][event.artifact]} {event.locator or key or ''}".strip()
    if event.artifact == "lnk":
        return f"{RECENT_TEXT['where']['lnk']} {origin}"
    if event.artifact == "jumplist":
        inner = str(event.locator or "").split(":", 1)[-1] if event.locator else ""
        return f"{RECENT_TEXT['where']['jumplist']} {origin}" + (f" @ {inner}" if inner else "")
    return origin


def _download_only(key):
    return lambda event, d: str(d.get(key) or "") if event.action == "download" else ""


def _download_state(event, d):
    state = d.get("download_state") if event.action == "download" else None
    return WEB_TEXT["states"].get(state, str(state)) if state else ""


_WEB_CELLS = {
    "web_title": lambda event, d: str(d.get("title") or ""),
    "browser": lambda event, d: str(d.get("browser") or ""),
    "referrer_url": lambda event, d: str(d.get("referrer_url") or ""),
    "download_file": lambda event, d: (str(d.get("download_save_path") or event.path or "").replace("/", "\\").rsplit("\\", 1)[-1]
                                       if event.action == "download" else ""),
    "download_state": _download_state,
    **{key: _download_only(key) for key in ("download_save_path", "download_url", "final_url", "tab_url",
                                            "tab_referrer_url", "site_url", "download_start", "download_end",
                                            "download_size")},
}


def defender_cell(key, event):
    """Cells of a 백신 파일 기록 row: threat name, target, recorded result and what stays unconfirmed."""
    d = event.details or {}
    if key == "threat_name":
        if d.get("threat_name"):
            return str(d["threat_name"])
        return DEFENDER_TEXT["name_raw"].format(raw=d["threat_name_raw"]) if d.get("threat_name_raw") else ""
    if key == "threat_target":
        return str(event.path or d.get("threat_resource") or d.get("resource_location") or "")
    if key == "defender_result":
        if d.get("defender_action_name"):
            return DEFENDER_TEXT["action_recorded"].format(name=d["defender_action_name"])
        by_action = {"defender_quarantine_metadata": "quarantine_unsupported", "defender_exclusion_reference": "exclusion",
                     "defender_scan_reference": "scan", "defender_log_reference": "reference",
                     "defender_history_record": "history"}
        if event.action in by_action:
            return DEFENDER_TEXT[by_action[event.action]]
        return DEFENDER_TEXT["no_remediation"] if d.get("remediation_confirmed") is False else ""
    return "; ".join(defender_unconfirmed(event))


def defender_unconfirmed(event):
    d = event.details or {}
    notes = []
    if d.get("log_time_invalid"):
        notes.append(DEFENDER_TEXT["time_invalid"].format(raw=d.get("log_time_raw", "")))
    elif d.get("timezone_known") is False:
        notes.append(DEFENDER_TEXT["time_zone_unknown"].format(raw=d.get("log_time_raw", "")))
    if d.get("time_meaning_verified") is False:
        notes.append(DEFENDER_TEXT["time_not_verified"])
    if d.get("threat_execution_confirmed") is False:
        notes.append(DEFENDER_TEXT["execution_unconfirmed"])
    if d.get("remediation_confirmed") is False:
        notes.append(DEFENDER_TEXT["no_remediation"])
    if event.status == "partial":
        notes.append(DEFENDER_TEXT["partial"])
    return notes


def _kind_name(details):
    kind = details.get("device_kind")
    name = details.get("device_kind_name") or (USB_DEVICE_KINDS.get(kind, kind) if kind else "")
    return f"{name} ({USB_KIND_CONFLICT})" if name and details.get("classification_conflict") else name


def _usb_class(details):
    interfaces = details.get("usb_interfaces") or []
    return "; ".join("/".join(str(i.get(k) or "-") for k in ("class", "subclass", "protocol"))
                     for i in interfaces if isinstance(i, dict))


def _serial(details):
    serial = str(details.get("serial") or "")
    return f"{serial} ({USB_SERIAL_MAY_BE_GENERATED})" if serial and details.get("serial_may_be_generated") else serial


def _composite(details):
    if details.get("composite_group"):
        return f"컨테이너 {details['composite_group']}"
    if details.get("interface_number"):
        return f"인터페이스 {details['interface_number']} · {USB_NO_COMPOSITE_BASIS}"
    return ""


def _kind_basis(details):
    basis = [b for b in details.get("device_classification_basis") or [] if isinstance(b, dict)]
    parts = [f"{USB_BASIS_LABELS.get(b.get('basis'), b.get('basis'))} {b.get('identifier', '')}".strip() for b in basis[:3]]
    if len(basis) > 3:
        parts.append(f"외 {len(basis) - 3}개")
    confidence = USB_CONFIDENCE_LABELS.get(details.get("classification_confidence"), "")
    return " · ".join(x for x in (confidence, "; ".join(parts)) if x)


def _physical_group(details):
    group = details.get("physical_device_id")
    if not group:
        return ""
    if details.get("auxiliary_device") or details.get("physical_observation") is False:
        return f"{group} · {USB_GROUP_AUXILIARY}"  # metadata/service entries are not physical devices
    basis = ", ".join(USB_GROUP_BASIS_LABELS.get(b, b) for b in details.get("physical_group_basis") or ())
    return f"{group} · {basis} · {USB_GROUP_NOT_CONFIRMED}" if basis else f"{group} · {USB_GROUP_NOT_CONFIRMED}"


_USB_CELLS = {
    "physical_group": _physical_group,
    "unknown_reason": lambda d: "; ".join(str(x) for x in d.get("unknown_reason_labels") or ()),
    "device_kind_name": _kind_name,
    "device_name": lambda d: str(d.get("friendlyname") or d.get("friendly_name") or d.get("devicedesc") or ""),
    "vid_pid": lambda d: f"{d['vid']}/{d.get('pid') or '-'}" if d.get("vid") else "",
    "usb_class": _usb_class,
    "install_class": lambda d: str(d.get("class") or ""),
    "serial": _serial,
    "composite": _composite,
    "kind_basis": _kind_basis,
}


def row(event, columns, sid_map, origins):
    return tuple(cell(c.key, event, sid_map, origins) for c in columns)


def save_csv(path, columns, rows):
    """Exactly what the table shows (shown headers, shown order), formula-safe."""
    with open(path, "w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow(headers(columns))
        for values in rows:
            writer.writerow([csv_safe(v) for v in values])
    return len(rows)
