from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .labels import time_field_label

UTC = timezone.utc
EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def filetime_to_datetime(value: int) -> datetime | None:
    if value <= 0 or value == 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def filetime(value: int) -> str | None:
    result = filetime_to_datetime(value)
    return result.isoformat() if result else None


def chromium_timestamp(value: int) -> str | None:
    return filetime(value * 10)


def iso_utc(value: str) -> str:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("시각에 UTC offset이 필요합니다")
    return result.astimezone(UTC).isoformat()


def event_time_fields(event):
    """Canonical UTC fields shared by timeline exports and timestamp display."""
    details = event.details
    raw = details.get("timestamp_raw_local")
    stamp = None
    if event.timestamp:
        try:
            value = datetime.fromisoformat(event.timestamp)
            if value.utcoffset() is None or details.get("timezone_known") is False:
                raw = raw or value.replace(tzinfo=None).isoformat()
            else:
                stamp = value.astimezone(UTC).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
    return {
        "timestamp_utc": stamp,
        "timestamp_raw_local": raw,
        "time_meaning": time_field_label(event.time_field) if event.time_field else None,
        "time_basis": details.get("time_basis") or (
            "시간대 미상" if raw and not stamp else "key_lastwrite" if event.time_field == "key_lastwrite" else None),
    }


def display_event_time(event):
    time = event_time_fields(event)
    if time["timestamp_utc"]:
        return time["timestamp_utc"].removesuffix("+00:00").replace("T", " ") + " UTC"
    if time["timestamp_raw_local"]:
        return f'{time["timestamp_raw_local"]} (시간대 미상)'
    return ""


def normalize_event_timestamp(event):
    """Normalize a copy when a parser or an older case supplies a different clock format."""
    if not event.timestamp or event.timestamp.endswith("+00:00") and event.details.get("timezone_known") is not False:
        return event
    fields = event_time_fields(event)
    details = event.details
    if fields["timestamp_raw_local"] and not fields["timestamp_utc"]:
        details = {**details, "timestamp_raw_local": fields["timestamp_raw_local"],
                   "timezone_known": False, "time_basis": fields["time_basis"]}
    return replace(event, timestamp=fields["timestamp_utc"], details=details)
