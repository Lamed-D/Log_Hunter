from datetime import datetime, timedelta, timezone

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
