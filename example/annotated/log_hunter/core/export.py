# ▶ 원본: log_hunter/core/export.py
# ▶ JSON·CSV·Bodyfile로 내보냅니다. CSV 수식 접두어와 시각의 의미를 보존합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Timeline export to CSV, JSON, JSON Lines, and Bodyfile formats."""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_FIELDS = (
    "timestamp", "artifact", "source", "action", "sid",
    "process", "path", "url", "status", "locator",
)


FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe(value):
    """Prefix ' so spreadsheet apps show evidence text instead of evaluating it as a formula
    (also when the formula hides behind leading spaces or a tab/CR/LF)."""
    if isinstance(value, str) and (value[:1] in ("\t", "\r", "\n") or value.lstrip()[:1] in FORMULA_PREFIXES):
        return "'" + value
    return value


def _event_to_row(event, fields):
    d = event.to_dict()
    row = {f: d.get(f) or "" for f in fields}
    row["details_json"] = json.dumps(d.get("details") or {}, ensure_ascii=False)
    return {key: csv_safe(value) for key, value in row.items()}


def export_csv(events, output_path, fields=None):
    fields = list(fields or DEFAULT_FIELDS)
    output_path = Path(output_path)
    headers = fields + ["details_json"]
    count = 0
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for event in events:
            writer.writerow(_event_to_row(event, fields))
            count += 1
    return count


def _serialize_event(event):
    d = event.to_dict()
    return {k: v for k, v in d.items() if v is not None and v != {}}


def export_json(events, output_path, indent=2):
    output_path = Path(output_path)
    records = []
    for event in events:
        records.append(_serialize_event(event))
    output_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=indent, default=str),
        encoding="utf-8",
    )
    return len(records)


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
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
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
