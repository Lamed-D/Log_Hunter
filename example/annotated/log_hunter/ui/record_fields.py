# ▶ 원본: log_hunter/ui/record_fields.py
# ▶ 기록 더블클릭 속성 창에 보일 분류별 항목(데이터→화면 이름)과 시각·크기 표시 형식을 정합니다. 모르는 값은 '알 수 없음'.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Record properties: per-category field lists (data -> shown name) for the properties dialog, without Tk."""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath

from log_hunter.core.labels import (DEFENDER_TEXT, PROPERTY_LABELS as L, PROPERTY_TITLE, UNKNOWN_VALUE, action_label, artifact_label,
                                    time_field_label)
from log_hunter.core.sid_resolver import display_name
from .view_model import display_target

PREFETCH_RUN_LIMIT = 8
_VOLUME_GUID = re.compile(r"^\\VOLUME\{[0-9A-F]+-([0-9A-F]{8})\}$", re.IGNORECASE)


def format_time(value, tz=None):
    """'2026-10-30 17:42:15 (UTC)', 24-hour clock. `tz` = (offset minutes, name) adds the local time when it is known.
    A time without an offset is shown as recorded with '(시간대 미상)'; nothing at all is '알 수 없음'."""
    if not value:
        return UNKNOWN_VALUE
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        return f"{moment:%Y-%m-%d %H:%M:%S} (시간대 미상)"
    utc = moment.astimezone(timezone.utc)
    text = f"{utc:%Y-%m-%d %H:%M:%S} (UTC)"
    if tz:
        minutes, name = tz
        local = utc + timedelta(minutes=minutes)
        sign = "+" if minutes >= 0 else "-"
        text += f" / {local:%Y-%m-%d %H:%M:%S} ({name} {sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d})"
    return text


def size_text(value):
    if value is None or value == "":
        return UNKNOWN_VALUE
    try:
        return f"{int(value):,} 바이트"
    except (TypeError, ValueError):
        return str(value)


def _text(value):
    if value is None or value == "" or value == []:
        return UNKNOWN_VALUE
    return str(value)


@dataclass
class Context:
    """What the dialog knows beyond the record: sibling records of the same source item, the source file's
    times and size inside the image, the user name map and (Prefetch) whether the program file still exists."""
    siblings: list = field(default_factory=list)
    file_extra: dict = field(default_factory=dict)
    file_size: int = None
    sid_map: dict = field(default_factory=dict)
    exe_state: str = None
    tz: tuple = None
    source_text: str = None  # where the source file really is ("[image] volume path"), not the extracted copy
    origin: object = None  # maps any analyzed file path the same way (paths inside record details)


@dataclass
class Properties:
    title: str
    fields: list            # [(label, value)]
    tabs: list              # [(tab name, [lines], searchable)] shown by 자세히…
    check_label: str = None  # field filled in later by a background check (Prefetch program file)


def common_fields(event, ctx):
    user = display_name(event.sid, ctx.sid_map)
    return [
        (L["artifact"], artifact_label(event.artifact)),
        (L["action"], action_label(event.action)),
        (L["timestamp"], format_time(event.timestamp, ctx.tz)),
        (L["time_field"], time_field_label(event.time_field) if event.time_field else UNKNOWN_VALUE),
        (L["user"], f"{user} ({event.sid})" if user else _text(event.sid)),
        (L["target"], _text(display_target(event))),
        (L["source"], _text(ctx.source_text or event.source)),
    ]


def _raw_tab(event):
    return (L["raw_json"], json.dumps(event.to_dict(), ensure_ascii=False, indent=2, default=str).splitlines(), False)


def _exe_reference(event):
    """The referenced file that ends with the program name: the program's full path as Prefetch recorded it."""
    name = str(event.process or "").casefold()
    for ref in (event.details or {}).get("references") or ():
        if name and str(ref).casefold().endswith("\\" + name):
            return str(ref)
    return None


def prefetch_exe_target(event):
    """(volume serial low 8 hex digits, path parts inside the volume) of the program, or None when Prefetch
    does not tie the path to a volume serial."""
    ref = _exe_reference(event)
    if not ref:
        return None
    pieces = ref.split("\\")
    if len(pieces) < 3:
        return None
    if pieces[1].upper().startswith("VOLUME{"):
        prefix, parts = "\\" + pieces[1], pieces[2:]
    elif len(pieces) > 3 and pieces[1].upper() == "DEVICE":
        prefix, parts = "\\" + "\\".join(pieces[1:3]), pieces[3:]
    else:
        return None
    guid = _VOLUME_GUID.match(prefix)
    serial = guid.group(1) if guid else None
    for volume in (event.details or {}).get("volumes") or ():
        if isinstance(volume, dict) and str(volume.get("path", "")).casefold() == prefix.casefold():
            serial = str(volume.get("serial") or serial or "")
    if not serial or not parts:
        return None
    return serial.upper()[-8:], tuple(parts)


def prefetch_properties(event, ctx):
    details = event.details or {}
    runs = sorted({e.timestamp for e in ctx.siblings + [event] if e.timestamp}, reverse=True)
    extra = ctx.file_extra or {}
    fields = [
        (L["pf_name"], PureWindowsPath(str(event.source)).name or UNKNOWN_VALUE),
        (L["created"], format_time(extra.get("created"), ctx.tz)),
        (L["modified"], format_time(extra.get("modified"), ctx.tz)),
        (L["file_size"], size_text(ctx.file_size)),
        (L["exe_name"], _text(event.process)),
        (L["exe_path"], _text(_exe_reference(event))),
        (L["run_count"], _text(details.get("run_count"))),
        (L["last_run"], format_time(runs[0] if runs else None, ctx.tz)),
        (L["exe_exists"], ctx.exe_state or L["exe_unknown"]),
    ]
    volumes = []
    for volume in details.get("volumes") or ():
        if isinstance(volume, dict):
            volumes.append(f"{volume.get('path', UNKNOWN_VALUE)}  ·  {L['serial']} {volume.get('serial') or UNKNOWN_VALUE}"
                           f"  ·  {L['volume_created']} {format_time(volume.get('creation_time'), ctx.tz)}")
    tabs = [
        (L["previous_runs"], [f"{i}. {format_time(t, ctx.tz)}" for i, t in enumerate(runs[:PREFETCH_RUN_LIMIT], 1)]
         or [UNKNOWN_VALUE], False),
        (L["references"], [str(r) for r in details.get("references") or ()] or [UNKNOWN_VALUE], True),
        (L["volumes"], volumes or [UNKNOWN_VALUE], False),
        _raw_tab(event),
    ]
    return fields, tabs, L["exe_exists"]


def _usb_times(event, ctx):
    times = {}
    device = (event.details or {}).get("device"), (event.details or {}).get("serial")
    for other in ctx.siblings + [event]:
        d = other.details or {}
        if (d.get("device"), d.get("serial")) == device and other.time_field in ("first_install", "last_arrival",
                                                                                   "last_removal"):
            times[other.time_field] = max(times.get(other.time_field) or "", other.timestamp or "") or None
    return times


def usb_properties(event, ctx):
    d = event.details or {}
    times = _usb_times(event, ctx)
    vid_pid = f"{d['vid']} / {d.get('pid') or UNKNOWN_VALUE}" if d.get("vid") else UNKNOWN_VALUE
    fields = [
        (L["device_name"], _text(d.get("friendlyname") or d.get("friendly_name") or d.get("devicedesc"))),
        (L["device_kind"], _text(d.get("device_kind_name"))),
        (L["vid_pid"], vid_pid),
        (L["serial"], _text(d.get("serial"))),
        *[(time_field_label(key), format_time(times.get(key), ctx.tz))
          for key in ("first_install", "last_arrival", "last_removal")],
    ]
    return fields, [_raw_tab(event)], None


def recycle_properties(event, ctx):
    d = event.details or {}
    from .recycle_view import pair_text
    exists, info = d.get("r_file_exists"), d.get("recycle_pair") if isinstance(d.get("recycle_pair"), dict) else {}
    pair = pair_text(d) or (UNKNOWN_VALUE if exists is None else (L["pair_yes"] if exists else L["pair_no"]))
    fields = [
        (L["original_path"], _text(d.get("original_path"))),
        (L["deleted_at"], format_time(event.timestamp, ctx.tz)),
        (L["file_size"], size_text(d.get("file_size"))),
        (L["pair_file"], pair),
        (L["pair_where"], _text(info.get("image_path"))),
    ]
    return fields, [_raw_tab(event)], None


def web_properties(event, ctx):
    d = event.details or {}
    fields = [
        (L["title"], _text(d.get("title"))),
        (L["url"], _text(event.url or d.get("url"))),
        (L["visited_at"], format_time(event.timestamp, ctx.tz)),
        (L["visit_count"], _text(d.get("visit_count"))),
    ]
    return fields, [_raw_tab(event)], None


def defender_properties(event, ctx):
    from .columns import defender_cell, defender_unconfirmed
    d, F = event.details or {}, DEFENDER_TEXT["fields"]
    time = format_time(event.timestamp, ctx.tz)
    if not event.timestamp and d.get("log_time_raw"):
        time = DEFENDER_TEXT["time_raw"].format(unknown=UNKNOWN_VALUE, raw=d["log_time_raw"])
    where = ctx.source_text or event.source
    if d.get("line_number"):
        where = DEFENDER_TEXT["line"].format(where=where, line=d["line_number"])
    yes_no = lambda v: UNKNOWN_VALUE if v is None else (F["yes"] if v else F["no"])
    fields = [
        (F["threat_name"], _text(defender_cell("threat_name", event))),
        (F["target"], _text(defender_cell("threat_target", event))),
        (F["action"], action_label(event.action)),
        (F["time"], time),
        (F["result"], _text(defender_cell("defender_result", event))),
        (F["execution"], yes_no(d.get("threat_execution_confirmed"))),
        (F["remediation"], yes_no(d.get("remediation_confirmed"))),
        (F["detection_source"], _text(d.get("detection_source"))),
        (F["threat_id"], _text(d.get("threat_id"))),
        (F["unconfirmed"], _text("; ".join(defender_unconfirmed(event)))),
        (F["where"], _text(where)),
    ]
    tabs = [(F["log_line"], [str(d["log_line"])], False)] if d.get("log_line") else []
    return fields, tabs + [_raw_tab(event)], None


def wifi_properties(event, ctx):
    from log_hunter.core import wifi_view
    from log_hunter.core.labels import WIFI_TEXT, column_label
    d, F = event.details or {}, WIFI_TEXT["fields"]
    yes_no = lambda v: UNKNOWN_VALUE if v is None else (F["yes"] if v else F["no"])
    fields = [(F["profile_name"], _text(d.get("profile_name")))]
    fields += [(column_label(key), wifi_view.cell(key, event) or (F["no_candidates"] if key == "networklist" else UNKNOWN_VALUE))
               for key in wifi_view.COLUMNS]
    fields += [(F["password_stored_in_profile"], yes_no(d.get("password_stored_in_profile"))),
               (F["password_protected"], yes_no(d.get("password_protected"))),
               (F["password_decryption_error"], d.get("password_decryption_error") or F["none"]),
               (F["interface_guid"], _text(d.get("interface_guid"))),
               (L["source"], _text(ctx.source_text or event.source))]
    return fields, [_raw_tab(event)], None


def evtx_properties(event, ctx):
    """Event log record: provider, event ID, where it sits in the file, and whether its body was decoded."""
    from log_hunter.core.labels import DIAGNOSTIC_TEXT
    d, E = event.details or {}, DIAGNOSTIC_TEXT["event"]
    meaning = d.get("known_event")
    if not d.get("xml_decoded", True):
        registered = E["not_decoded"]
    elif meaning and not str(meaning).startswith("기타 이벤트"):
        registered = E["known"]
    else:
        registered = E["unknown"]
    warnings = d.get("binxml_value_warnings") or []
    decode = E["decoded"] if d.get("xml_decoded", True) else E["not_decoded"]
    if warnings:
        decode += " · " + E["value_warnings"].format(count=len(warnings))
    where = ctx.source_text or event.source
    fields = [
        (L["artifact"], artifact_label(event.artifact)), (L["action"], action_label(event.action)),
        (L["timestamp"], format_time(event.timestamp, ctx.tz)),
        (L["time_field"], time_field_label(event.time_field) if event.time_field else UNKNOWN_VALUE),
        (E["meaning"], _text(meaning)), (E["registered"], registered),
        (E["provider"], _text(d.get("provider"))), (E["event_id"], _text(d.get("event_id"))),
        (E["channel"], _text(d.get("channel"))), (E["computer"], _text(d.get("computer"))),
        (E["record"], _text(d.get("record_id"))), (E["decode"], decode),
        (E["where"], f"{where} @ {event.locator}" if event.locator else _text(where)),
    ]
    return fields, [_raw_tab(event)], None


def task_properties(event, ctx):
    """Basic fields only; 자세히… holds the detail and source comparison tabs."""
    from log_hunter.core.labels import TASK_TEXT, column_label
    from . import task_view
    fields = [(column_label(key), task_view.cell(key, event) or UNKNOWN_VALUE) for key in task_view.COLUMNS]
    fields.append((L["source"], _text(ctx.source_text or event.source)))
    compare = [f"{f}: {a}  |  {b}  →  {v}" for f, a, b, v in task_view.compare_rows(event)] or [TASK_TEXT["no_compare"]]
    return fields, [(TASK_TEXT["detail_tab"], task_view.detail_lines(event, ctx.origin), True),
                    (TASK_TEXT["compare_tab"], compare, False), _raw_tab(event)], None


CATEGORY_FIELDS = {"tasks": task_properties, "taskcache": task_properties, "evtx": evtx_properties, "wlan": wifi_properties, "defender": defender_properties, "prefetch": prefetch_properties, "usb": usb_properties, "recyclebin": recycle_properties,
                   "history": web_properties}


def properties(event, ctx=None):
    """Title, fields and 자세히… tabs for one record: the category's own field list, else the common items."""
    ctx = ctx or Context()
    builder = CATEGORY_FIELDS.get(event.artifact)
    if builder is None:
        fields, tabs, check = common_fields(event, ctx), [_raw_tab(event)], None
    else:
        fields, tabs, check = builder(event, ctx)
    return Properties(PROPERTY_TITLE.format(kind=artifact_label(event.artifact)), fields, tabs, check)


def check_exe(browser, target):
    """Worker thread: is the Prefetch program still in the image? Only the volume whose serial matches is searched."""
    serial, parts = target
    for volume in browser.volume_info():
        if not volume.get("browsable"):
            continue
        try:
            found = str(browser.volume_serial(volume["index"]) or "").upper()[-8:]
        except Exception:
            continue
        if found == serial:
            return L["exe_present"] if browser.exists(volume["index"], parts) else L["exe_missing"]
    return L["exe_no_volume"]
