"""Timeline export to CSV, JSON, JSON Lines, and Bodyfile formats."""
import csv
import json
from datetime import datetime
from pathlib import Path

from .labels import artifact_label
from .sid_resolver import display_name
from .timestamp import event_time_fields

CSV_ENCODING = "utf-8-sig"
COMMON_FIELDS = (
    "artifact", "artifact_label", "action", "timestamp_utc", "time_meaning", "time_basis",
    "timestamp_raw_local", "user", "sid", "target",
    "target_key", "source_path", "source_locator", "status", "details_json",
)

DEFAULT_FIELDS = (
    "timestamp", "artifact", "source", "action", "sid",
    "process", "path", "url", "status", "locator",
)


# Added after details_json so older readers that use column positions keep working. Download-only columns stay
# empty on other rows; referrer_url is also the referring page of a visit.
DOWNLOAD_FIELDS = ("download_save_path", "download_url", "final_url", "referrer_url", "tab_url", "tab_referrer_url",
                   "site_url", "download_state")
FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe(value):
    """Prefix ' so spreadsheet apps show evidence text instead of evaluating it as a formula
    (also when the formula hides behind leading spaces or a tab/CR/LF)."""
    if isinstance(value, str) and (value[:1] in ("\t", "\r", "\n") or value.lstrip()[:1] in FORMULA_PREFIXES):
        return "'" + value
    return value


def csv_source_paths(evidence):
    return {item.source: item.metadata["image_path"] for item in evidence
            if item.metadata.get("image_path")}


def check_timeline_destination(output_path, evidence, image=None):
    folder = Path(output_path).resolve().parent
    paths = [item.source for item in evidence]
    for manifest in [image or {}, *((image or {}).get("additional_images") or [])]:
        paths.extend((manifest.get("image") or {}).get("segments") or [manifest.get("image_path")])
    if any(Path(path).resolve().parent == folder for path in paths
           if path and not str(path).startswith(("\\\\.\\", "\\\\?\\"))):
        raise ValueError("원본 증거와 같은 폴더에는 저장할 수 없습니다. 다른 폴더를 고르세요.")


def _event_to_row(event, fields, sid_names, source_paths):
    d = event.to_dict()
    details = event.details
    d.update(event_time_fields(event))
    d.update(timestamp=d["timestamp_utc"],
             artifact_label=artifact_label(event.artifact),
             user=display_name(event.sid, sid_names),
             target=event.path or event.process or event.url,
             target_key=details.get("target_key"),
             source_path=details.get("source_path") or (source_paths or {}).get(event.source) or event.source,
             source_locator=details.get("source_locator") or event.locator)
    d["details_json"] = d["details"] = json.dumps(details, ensure_ascii=False)
    for key in DOWNLOAD_FIELDS:
        if event.action == "download" or key == "referrer_url":
            d[key] = details.get(key)
    return {field: csv_safe(d.get(field) or "") for field in fields}


def common_row(event, sid_names=None, source_paths=None):
    """The shared columns (COMMON_FIELDS, then the download columns) of one record, formula-safe: the screen CSVs
    append exactly these so a row there and in the timeline CSV carry the same values."""
    fields = list(dict.fromkeys([*COMMON_FIELDS, *DOWNLOAD_FIELDS]))
    return _event_to_row(event, fields, sid_names, source_paths)


def export_csv(events, output_path, fields=None, *, sid_names=None, source_paths=None, report=False):
    legacy = list(fields or DEFAULT_FIELDS)
    if not report:
        legacy.append("details_json")
        legacy.extend(DOWNLOAD_FIELDS)
    headers = list(dict.fromkeys([*legacy, *COMMON_FIELDS, *DOWNLOAD_FIELDS]))
    count = 0
    with Path(output_path).open("x", newline="", encoding=CSV_ENCODING) as stream:
        writer = csv.DictWriter(stream, fieldnames=headers)
        writer.writeheader()
        for event in events:
            writer.writerow(_event_to_row(event, headers, sid_names, source_paths))
            count += 1
    return count


def event_json_row(event):
    row = event.to_dict()
    row.update(event_time_fields(event))
    row["timestamp"] = row["timestamp_utc"]
    return row


def _serialize_event(event):
    return {k: v for k, v in event_json_row(event).items()
            if (v is not None and v != {}) or k == "timestamp_utc"}


def export_json(events, output_path, indent=2):
    output_path = Path(output_path)
    count = 0
    with output_path.open("w", encoding="utf-8") as stream:
        stream.write("[")
        for event in events:
            stream.write(",\n" if count else "\n")
            record = json.dumps(_serialize_event(event), ensure_ascii=False, indent=indent, default=str)
            prefix = " " * indent if isinstance(indent, int) else (indent or "")
            stream.write("\n".join(prefix + line for line in record.split("\n")))
            count += 1
        stream.write("\n]" if count else "]")
    return count


def export_jsonl(events, output_path):
    output_path = Path(output_path)
    count = 0
    with output_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(_serialize_event(event), ensure_ascii=False, default=str) + "\n")
            count += 1
    return count


def _ts_to_unix(ts_str):
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.utcoffset() is None:
            return None
        return int(dt.timestamp())
    except (ValueError, TypeError, OSError):
        return None


_TIME_FIELD_MAP = {
    "created": "crtime", "creation_time": "crtime", "si_created": "crtime", "fn_created": "crtime",
    "modified": "mtime", "last_written": "mtime", "write_time": "mtime", "mtime": "mtime",
    "si_modified": "mtime", "fn_modified": "mtime",
    "accessed": "atime", "last_access": "atime", "access_time": "atime", "si_accessed": "atime", "fn_accessed": "atime",
    "changed": "ctime", "entry_modified": "ctime", "si_mft_changed": "ctime", "fn_mft_changed": "ctime",
}
_BODY_COLUMNS = ("atime", "mtime", "ctime", "crtime")


def _body_text(value):
    """Percent-encode '|', '%' and control characters so evidence text cannot add fields or lines."""
    return "".join(f"%{ord(c):02X}" if c in "|%" or ord(c) < 0x20 or c == "\x7f" else c for c in str(value))


def export_bodyfile(events, output_path):
    """mactime-style bodyfile. File times fill their own MACB column; any other time meaning
    (key_lastwrite, last_execution, ...) goes in the M column only and is named in brackets."""
    output_path = Path(output_path)
    count = 0
    with output_path.open("w", encoding="utf-8") as f:
        for event in events:
            if event.details.get("timezone_known") is False:
                continue
            unix_ts = _ts_to_unix(event.timestamp)
            if unix_ts is None:
                continue
            time_field = (event.time_field or "").lower()
            mapped = _TIME_FIELD_MAP.get(time_field)
            name_parts = [f"{event.artifact}:{event.action}"]
            if not mapped:
                name_parts.append(f"[{time_field or 'unknown_time'}]")
            target = event.path or event.process or event.url or ""
            if target:
                name_parts.append(target)
            name = _body_text(" ".join(name_parts))
            uid = _body_text(event.sid or "0")
            times = {column: "0" for column in _BODY_COLUMNS}
            times[mapped or "mtime"] = str(unix_ts)
            f.write(f"0|{name}|0|0|{uid}|0|0|{times['atime']}|{times['mtime']}|{times['ctime']}|{times['crtime']}\n")
            count += 1
    return count
