from datetime import datetime, timedelta, timezone

# (format, step to the next value at that precision)
FILTER_DATE_FORMATS = (("%Y-%m-%d %H:%M:%S", timedelta(seconds=1)), ("%Y-%m-%d %H:%M", timedelta(minutes=1)),
                       ("%Y-%m-%d", timedelta(days=1)), ("%Y/%m/%d", timedelta(days=1)))


def parse_filter_date(text, end=False):
    """Turn a typed start/end date into a bound for timeline(). An end bound covers the whole
    day/minute/second typed, so "2024-01-01" as the end keeps that day's records."""
    text = (text or "").strip()
    if not text:
        return None
    for fmt, step in FILTER_DATE_FORMATS:
        try:
            value = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if end:
            try:
                value = value + step - timedelta(microseconds=1)
            except OverflowError:
                value = datetime.max
        return value.isoformat()
    return text


def timeline(events, artifact=None, sid=None, start=None, end=None, query=None):
    """Order known clocks in UTC, then unknown clocks, invalid values and missing times.

    Naive bounds filter the displayed calendar (UTC for known clocks, wall time for
    unknown clocks). Offset-bearing bounds exclude unknown clocks. Sources stay intact.
    """
    cache = {}

    def clock(text):
        if text is None:
            return 3, None
        if not isinstance(text, str) or not text or len(text) > 128:
            return 2, None
        if text not in cache:
            try:
                value = datetime.fromisoformat(text)
                aware = value.tzinfo is not None
                if aware:
                    value = value.astimezone(timezone.utc).replace(tzinfo=None)
                cache[text] = (0 if aware else 1, value)
            except (ValueError, OverflowError):
                cache[text] = 2, None
        return cache[text]

    lower, upper = clock(start) if start else None, clock(end) if end else None
    if any(bound and bound[0] >= 2 for bound in (lower, upper)):
        return []
    result = []
    for event in events:
        if artifact and event.artifact != artifact:
            continue
        if sid and event.sid != sid:
            continue
        category, value = clock(event.timestamp)
        if lower and (value is None or lower[0] == 0 and category != 0 or value < lower[1]):
            continue
        if upper and (value is None or upper[0] == 0 and category != 0 or value > upper[1]):
            continue
        if query and query.casefold() not in str(event.to_dict()).casefold():
            continue
        result.append(((category, value or datetime.min, event.artifact, event.source, event.locator or ''), event))
    return [event for _, event in sorted(result, key=lambda item: item[0])]
