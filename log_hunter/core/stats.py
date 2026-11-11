"""Forensic event statistics and anomaly detection."""
from collections import Counter
from datetime import datetime, timedelta


def _parse_ts(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def compute_stats(events):
    total = len(events)
    by_artifact = Counter()
    by_action = Counter()
    by_status = Counter()
    by_sid = Counter()
    sources = set()
    processes = set()
    risk = {"high": 0, "medium": 0, "low": 0}
    hourly = Counter()
    daily = Counter()
    timestamps = []

    for e in events:
        by_artifact[e.artifact] += 1
        by_action[e.action] += 1
        by_status[e.status] += 1
        if e.sid:
            by_sid[e.sid] += 1
        sources.add(e.source)
        if e.process:
            processes.add(e.process)
        details = e.details or {}
        rl = details.get("risk_level")
        if rl in risk:
            risk[rl] += 1
        elif details.get("suspicion_flags"):
            risk["high"] += 1
        dt = _parse_ts(e.timestamp)
        if dt:
            timestamps.append(dt)
            hourly[dt.hour] += 1
            daily[dt.strftime("%Y-%m-%d")] += 1

    time_range = None
    if timestamps:
        earliest = min(timestamps)
        latest = max(timestamps)
        time_range = {"earliest": earliest.isoformat(), "latest": latest.isoformat()}

    return {
        "total_events": total,
        "by_artifact": dict(by_artifact.most_common()),
        "by_action": dict(by_action.most_common(20)),
        "by_status": dict(by_status.most_common()),
        "by_sid": dict(by_sid.most_common()),
        "time_range": time_range,
        "unique_sources": len(sources),
        "unique_processes": len(processes),
        "risk_summary": risk,
        "hourly_distribution": dict(sorted(hourly.items())),
        "daily_distribution": dict(sorted(daily.items())),
    }


def format_stats_text(stats):
    lines = []
    lines.append(f"전체 이벤트: {stats['total_events']}건")
    lines.append(f"고유 소스 파일: {stats['unique_sources']}개")
    lines.append(f"고유 프로세스: {stats['unique_processes']}개")
    tr = stats.get("time_range")
    if tr:
        lines.append(f"시간 범위: {tr['earliest']} ~ {tr['latest']}")
    lines.append("")
    lines.append("아티팩트별:")
    for name, count in stats["by_artifact"].items():
        lines.append(f"  {name}: {count}건")
    risk = stats.get("risk_summary", {})
    if any(risk.values()):
        lines.append("")
        lines.append("위험도:")
        for level in ("high", "medium", "low"):
            if risk.get(level):
                label = {"high": "높음", "medium": "중간", "low": "낮음"}[level]
                lines.append(f"  {label}: {risk[level]}건")
    lines.append("")
    lines.append("상태별:")
    for status, count in stats["by_status"].items():
        lines.append(f"  {status}: {count}건")
    if stats["by_sid"]:
        lines.append("")
        lines.append("SID별:")
        for sid, count in list(stats["by_sid"].items())[:10]:
            lines.append(f"  {sid}: {count}건")
    if stats["hourly_distribution"]:
        lines.append("")
        lines.append("시간대별 분포:")
        for hour, count in stats["hourly_distribution"].items():
            bar = "#" * min(count, 40)
            lines.append(f"  {hour:02d}시: {count:>5}건 {bar}")
    return "\n".join(lines)


def detect_anomalies(events):
    anomalies = []
    parsed = []
    for e in events:
        dt = _parse_ts(e.timestamp)
        if dt:
            parsed.append((dt, e))
    if not parsed:
        return anomalies
    parsed.sort(key=lambda x: x[0])

    # Off-hours activity
    off_hours = [(dt, e) for dt, e in parsed if 0 <= dt.hour < 5]
    if off_hours:
        by_day = Counter()
        for dt, _ in off_hours:
            by_day[dt.strftime("%Y-%m-%d")] += 1
        for day, count in by_day.most_common(5):
            anomalies.append({
                "type": "off_hours",
                "description": f"{day} 새벽 시간대(00~05시) 활동 {count}건 감지",
                "timestamp": day + "T00:00:00",
                "severity": "info" if count < 10 else "warning",
            })

    # Burst detection: sliding window of 60 seconds
    if len(parsed) > 50:
        window_start = 0
        intervals = []
        for window_end in range(len(parsed)):
            while (parsed[window_end][0] - parsed[window_start][0]) > timedelta(seconds=60):
                window_start += 1
            window_size = window_end - window_start + 1
            if window_size > 50:
                if intervals and window_start <= intervals[-1][1]:
                    intervals[-1][1] = window_end
                    intervals[-1][2] = max(intervals[-1][2], window_size)
                else:
                    intervals.append([window_start, window_end, window_size])
        for start, end, peak in intervals:
            ts, end_ts = parsed[start][0], parsed[end][0]
            count = end - start + 1
            anomalies.append({
                "type": "burst",
                "description": f"{ts.isoformat()}~{end_ts.isoformat()} 집중 구간 {count}건 (1분 내 최대 {peak}건)",
                "timestamp": ts.isoformat(),
                "end_timestamp": end_ts.isoformat(),
                "event_count": count,
                "peak_window_count": peak,
                "severity": "warning" if peak < 200 else "high",
            })

    # Time gaps: >4 hours during an active day
    daily_events = {}
    for dt, e in parsed:
        day = dt.strftime("%Y-%m-%d")
        daily_events.setdefault(day, []).append(dt)
    for day, times in daily_events.items():
        if len(times) < 3:
            continue
        times.sort()
        for i in range(1, len(times)):
            gap = times[i] - times[i - 1]
            if gap > timedelta(hours=4):
                anomalies.append({
                    "type": "time_gap",
                    "description": f"{day} {times[i-1].strftime('%H:%M')}~{times[i].strftime('%H:%M')} 사이 {gap.seconds // 3600}시간 공백",
                    "timestamp": times[i - 1].isoformat(),
                    "severity": "info",
                })

    return anomalies


def find_duplicates(events):
    """Detect duplicate events by artifact+timestamp+target key."""
    seen = {}
    duplicates = []
    for i, e in enumerate(events):
        target = e.path or e.process or e.url or ""
        key = (e.artifact, e.timestamp or "", e.action, target)
        if not target and not e.timestamp:
            continue
        if key in seen:
            duplicates.append((seen[key], i, "exact_duplicate"))
        else:
            seen[key] = i
    return duplicates
