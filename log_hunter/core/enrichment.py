"""Event enrichment: activity classification, session grouping, and risk scoring."""

from datetime import datetime, timezone
from itertools import islice

from log_hunter.core.models import ForensicEvent

# Activity classification map: artifact -> class
_ACTIVITY_MAP = {
    "userassist": "user_activity",
    "bam": "user_activity",
    "history": "user_activity",
    "jumplist": "user_activity",
    "run": "system_config",
    "tasks": "system_config",
    "network": "system_config",
    "wlan": "system_config",
    "mft": "file_operation",
    "lnk": "file_operation",
    "recyclebin": "file_operation",
    "shellbag": "file_operation",
    "prefetch": "execution",
    "amcache": "execution",
    "psreadline": "execution",
    "evtx": "security",
    "defender": "security",
    "usb": "storage",
    "srum": "storage",
    "cache": "storage",
    "mru": "user_activity",
}

_SUSPICIOUS_KEYWORDS = [
    "encoded_command", "encodedcommand",
    "certutil", "bitsadmin",
    "powershell -e ", "powershell.exe -e ",
    "mimikatz", "procdump",
    "invoke-expression", "iex ",
    "downloadstring", "downloadfile",
    "net user", "net localgroup",
    "reg save", "reg export",
    "vssadmin delete", "wmic shadowcopy",
    "bcdedit", "wbadmin delete",
]

_SESSION_GAP_SECONDS = 1800  # 30 minutes
_AMBIGUOUS_KEYWORDS = ('bypass', 'hidden')


def _risk_texts(event):
    """Bound untrusted nested detail text without stringifying arbitrary objects."""
    nodes, remaining = 256, 65536

    def visit(value, depth):
        nonlocal nodes, remaining
        if nodes <= 0 or remaining <= 0 or depth > 4:
            return
        nodes -= 1
        if isinstance(value, str):
            text = value[:min(8192, remaining)]
            remaining -= len(text)
            yield text.casefold()
        elif isinstance(value, (dict, list, tuple)):
            children = value.values() if isinstance(value, dict) else value
            for child in islice(children, nodes):
                yield from visit(child, depth + 1)

    for value in (event.action, event.process, event.path, event.url, event.details):
        yield from visit(value, 0)


def _parse_timestamp(ts):
    """Parse an ISO timestamp string, returning a datetime or None."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _compute_risk(event, dt):
    """Compute risk score (0-100) for a single event."""
    score = 0
    # No case timezone is configured: UTC/unknown hours cannot establish local off-hours.

    # Status-based risk
    status = getattr(event, "status", "ok")
    if status in ("warning", "partial"):
        score += 10

    # Action content risk
    action_lower = (event.action or "").lower()
    if "cleartext" in action_lower or "password" in action_lower:
        score += 50

    texts = list(_risk_texts(event))
    if any(keyword in text for text in texts for keyword in _SUSPICIOUS_KEYWORDS):
        score += 30
    elif any(keyword in text for text in texts for keyword in _AMBIGUOUS_KEYWORDS):
        score += 5

    # Details-level checks (e.g. task risk_level, psreadline risk)
    details = event.details or {}
    if details.get("risk_level") == "high":
        score += 20
    if details.get("cleartext_password_found"):
        score += 50

    return min(score, 100)


def enrich_events(events):
    """Enrich a list of ForensicEvent objects with classification, session, and risk."""
    # --- Activity classification ---
    for event in events:
        cls = _ACTIVITY_MAP.get(event.artifact, "other")
        event.details["activity_class"] = cls

    # --- Risk scoring (done before session grouping so we can aggregate) ---
    parsed_times = []
    for event in events:
        dt = _parse_timestamp(event.timestamp)
        parsed_times.append(dt)
        event.details["risk_score"] = _compute_risk(event, dt)

    # --- Session grouping: SID + 30-min time proximity ---
    # Build per-SID sorted lists, assign session IDs
    sid_buckets = {}  # sid -> [(index, datetime)]
    for i, event in enumerate(events):
        sid = event.sid or "__no_sid__"
        dt = parsed_times[i]
        if sid not in sid_buckets:
            sid_buckets[sid] = []
        sid_buckets[sid].append((i, dt))

    session_counter = 0
    for sid, entries in sid_buckets.items():
        # Sort by timestamp (None last)
        entries.sort(key=lambda x: (x[1] is None, x[1] or datetime.min.replace(tzinfo=timezone.utc)))
        current_session = session_counter
        last_dt = None
        for idx, dt in entries:
            if dt is not None and last_dt is not None:
                # Compare naive-aware: make both offset-aware for diff
                a = last_dt if last_dt.tzinfo else last_dt.replace(tzinfo=timezone.utc)
                b = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                gap = abs((b - a).total_seconds())
                if gap > _SESSION_GAP_SECONDS:
                    session_counter += 1
                    current_session = session_counter
            elif dt is None and last_dt is not None:
                # No timestamp -> new session boundary
                session_counter += 1
                current_session = session_counter
            events[idx].details["session_id"] = current_session
            last_dt = dt
        session_counter += 1  # next SID starts a new session

    return events


def summarize_sessions(events):
    """Return a list of session summary dicts from enriched events."""
    sessions = {}  # session_id -> list of (event, dt)
    for event in events:
        sid = event.details.get("session_id")
        if sid is None:
            continue
        dt = _parse_timestamp(event.timestamp)
        if sid not in sessions:
            sessions[sid] = []
        sessions[sid].append((event, dt))

    summaries = []
    for session_id in sorted(sessions):
        items = sessions[session_id]
        timestamps = [dt for _, dt in items if dt is not None]
        artifacts = list({e.artifact for e, _ in items})
        risk_scores = [e.details.get("risk_score", 0) for e, _ in items]
        sids = [e.sid for e, _ in items if e.sid]

        if timestamps:
            # Make all offset-aware for comparison
            aware = []
            for t in timestamps:
                aware.append(t if t.tzinfo else t.replace(tzinfo=timezone.utc))
            start = min(aware)
            end = max(aware)
            duration = (end - start).total_seconds()
        else:
            start = None
            end = None
            duration = 0

        summaries.append({
            "session_id": session_id,
            "start_time": start.isoformat() if start else None,
            "end_time": end.isoformat() if end else None,
            "duration_seconds": duration,
            "event_count": len(items),
            "unique_artifacts": sorted(artifacts),
            "risk_score": max(risk_scores) if risk_scores else 0,
            "primary_sid": max(set(sids), key=sids.count) if sids else None,
        })

    return summaries
