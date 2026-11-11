# Runtime source with the same executable tokens.
import ntpath
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import urlparse
from .normalization import normalize_executable_path


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _normalize_url(url):
    if not url:
        return None
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        path = (parsed.path or "/").rstrip("/") or "/"
        return f"{parsed.scheme}://{host}{path}"
    except (ValueError, TypeError):
        return None


def _time_position(value):
    """Integer microseconds on either an absolute or an unspecified local clock."""
    offset = value.utcoffset()
    position = ((value.toordinal() * 86400 + value.hour * 3600 + value.minute * 60 + value.second)
                * 1000000 + value.microsecond)
    if offset is not None:
        position -= (offset.days * 86400 + offset.seconds) * 1000000 + offset.microseconds
    return offset is not None, position


PAIR_GROUP_LIMIT = 10000


def _cross_artifact_pairs(group, result, relation_type, partition=lambda event: event.artifact, **metadata):
    """Count compatible candidates linearly; expand only bounded groups."""
    all_artifacts, known_artifacts = Counter(), Counter()
    known_sids = defaultdict(Counter)
    buckets = defaultdict(lambda: defaultdict(list))
    for entry in group:
        event = entry[1]
        artifact = partition(event)
        all_artifacts[artifact] += 1
        buckets[artifact][event.sid or None].append(entry)
        if event.sid:
            known_artifacts[artifact] += 1
            known_sids[event.sid][artifact] += 1
    def cross(counts):
        return (sum(counts.values()) ** 2 - sum(n * n for n in counts.values())) // 2
    count = cross(all_artifacts) - cross(known_artifacts) + sum(cross(c) for c in known_sids.values())
    if count > PAIR_GROUP_LIMIT:
        result.append({"type": "correlation_group", "relation_type": relation_type,
                       "basis": "candidate_group", "confidence": "candidate",
                       "execution_confirmed": False, "candidate_count": count,
                       "event_indices": [entry[0] for entry in group],
                       "pair_expansion_limit": PAIR_GROUP_LIMIT, **metadata})
        return
    if not count:
        return
    for left in group:
        candidates = []
        for artifact, by_sid in buckets.items():
            if artifact == partition(left[1]):
                continue
            compatible = (by_sid.get(left[1].sid, []), by_sid.get(None, [])) if left[1].sid else by_sid.values()
            for entries in compatible:
                candidates.extend(right for right in entries if right[0] > left[0])
        for right in sorted(candidates, key=lambda entry: entry[0]):
            yield left, right


def correlate(events):
    """Build relation candidates across artifact types.

    Relations are match candidates, never proof of execution or causation.
    Matching strategies:
      1. Exact normalized path match across artifacts
      2. Filename-only match (weaker)
      3. Time proximity — events within 60 seconds that share a filename/process
      4. URL domain+path matching across artifacts (history, cache, evtx, etc.)
      5. USB-file temporal correlation (300s window)
      6. Program group aggregation — groups events by the same executable
    SID conflicts suppress matches; absent SIDs remain unknown.
    """
    timestamp_cache = {}
    def parse_ts(value):
        if value not in timestamp_cache:
            timestamp_cache[value] = _parse_ts(value)
        return timestamp_cache[value]

    indexes = {}
    result = []
    for index, event in enumerate(events):
        target = event.path or event.process
        if target and event.artifact != "usb":
            normalized = normalize_executable_path(target)
            name = ntpath.basename(normalized)
            if name:
                indexes.setdefault(name, []).append((index, event, normalized))

    for group in indexes.values():
        for (left_id, left, left_path), (right_id, right, right_path) in _cross_artifact_pairs(group, result, "path_correlation", filename=ntpath.basename(group[0][2])):
            exact = left_path == right_path and (ntpath.isabs(left_path) or left_path.startswith("\\"))
            left_ts = parse_ts(left.timestamp)
            right_ts = parse_ts(right.timestamp)
            temporal = False
            delta_seconds = None
            if left_ts and right_ts and _time_position(left_ts)[0] == _time_position(right_ts)[0]:
                delta = abs((left_ts - right_ts).total_seconds())
                delta_seconds = round(delta, 3)
                temporal = delta <= 60.0
            relation = {
                "left": left_id, "right": right_id,
                "type": "path_correlation",
                "basis": "normalized_path" if exact else "filename_only",
                "confidence": "path_match" if exact else "filename_only",
                "execution_confirmed": False,
            }
            if delta_seconds is not None:
                relation["delta_seconds"] = delta_seconds
            if temporal:
                relation["temporal_proximity"] = True
            result.append(relation)

    # URL correlation
    url_index = defaultdict(list)
    for index, event in enumerate(events):
        if event.url:
            normalized = _normalize_url(event.url)
            if normalized:
                url_index[normalized].append((index, event))

    for normalized_url, group in url_index.items():
        if len(group) < 2:
            continue
        for (left_id, left), (right_id, right) in _cross_artifact_pairs(group, result, "url_correlation", url=normalized_url):
            left_ts = parse_ts(left.timestamp)
            right_ts = parse_ts(right.timestamp)
            delta_seconds = None
            if left_ts and right_ts and _time_position(left_ts)[0] == _time_position(right_ts)[0]:
                delta_seconds = round(abs((left_ts - right_ts).total_seconds()), 3)
            result.append({
                "left": left_id, "right": right_id,
                "type": "url_correlation",
                "basis": "url_match",
                "confidence": "url_match",
                "url": normalized_url,
                "execution_confirmed": False,
                **({"delta_seconds": delta_seconds} if delta_seconds is not None else {}),
            })

    # USB-file temporal correlation
    usb_events = [(i, e) for i, e in enumerate(events) if e.artifact == "usb"
                  and (e.details or {}).get('is_storage_device') is not False]
    file_events = [(i, e) for i, e in enumerate(events) if e.artifact != "usb" and e.path]
    file_clocks = {True: [], False: []}
    for file_idx, file_ev in file_events:
        stamp = parse_ts(file_ev.timestamp)
        if stamp:
            clock, position = _time_position(stamp)
            file_clocks[clock].append((position, file_idx, file_ev))
    for entries in file_clocks.values():
        entries.sort(key=lambda entry: (entry[0], entry[1]))
    file_positions = {clock: [entry[0] for entry in entries] for clock, entries in file_clocks.items()}
    usb_windows = []
    for usb_idx, usb_ev in usb_events:
        usb_ts = parse_ts(usb_ev.timestamp)
        if not usb_ts:
            continue
        clock, position = _time_position(usb_ts)
        lower = bisect_left(file_positions[clock], position - 300000000)
        upper = bisect_right(file_positions[clock], position + 300000000)
        if lower < upper:
            usb_windows.append((usb_idx, usb_ev, clock, position, lower, upper))
    usb_count = sum(upper - lower for _, _, _, _, lower, upper in usb_windows)
    if usb_count > PAIR_GROUP_LIMIT:
        indices = {entry[0] for entry in usb_windows}
        for clock in (False, True):
            ranges = sorted((lo, hi) for _, _, c, _, lo, hi in usb_windows if c == clock)
            last_end = 0
            for lower, upper in ranges:
                indices.update(file_clocks[clock][i][1] for i in range(max(lower, last_end), upper))
                last_end = max(last_end, upper)
        result.append({"type": "correlation_group", "relation_type": "usb_file_correlation",
                       "basis": "usb_temporal_window", "confidence": "candidate",
                       "execution_confirmed": False, "candidate_count": usb_count,
                       "event_indices": sorted(indices),
                       "left_event_indices": [entry[0] for entry in usb_windows],
                       "window_seconds": 300, "same_clock_required": True,
                       "signed_window_seconds": [-300, 300],
                       "signed_delta_basis": "file_time_minus_usb_time",
                       "pair_expansion_limit": PAIR_GROUP_LIMIT})
        usb_windows = []
    for usb_idx, usb_ev, clock, position, lower, upper in usb_windows:
        device = (usb_ev.details or {}).get("device", "")
        drive_letters = (usb_ev.details or {}).get("drive_letters", [])
        # Keep the established input order among candidates.
        candidates = sorted(file_clocks[clock][lower:upper], key=lambda entry: entry[1])
        for file_position, file_idx, file_ev in candidates:
            signed_delta = (file_position - position) / 1000000
            delta = abs(signed_delta)
            if delta <= 300:
                drive_match = False
                if drive_letters and file_ev.path:
                    drive_match = any(file_ev.path.upper().startswith(d.upper()) for d in drive_letters)
                result.append({
                    "left": usb_idx, "right": file_idx,
                    "type": "usb_file_correlation",
                    "basis": "usb_drive_match" if drive_match else "usb_temporal",
                    "confidence": "drive_match" if drive_match else "candidate",
                    "execution_confirmed": False,
                    "delta_seconds": round(delta, 3),
                    "signed_delta_seconds": round(signed_delta, 3),
                    "direction": "before" if signed_delta < 0 else "after" if signed_delta > 0 else "same",
                    "temporal_proximity": True,
                    "usb_device": device,
                    **({"drive_letters": drive_letters} if drive_letters else {}),
                })

    # Deletion correlation — match recyclebin events against other artifacts by filename
    deletion_groups = defaultdict(list)
    for index, event in enumerate(events):
        target = event.path if event.artifact == "recyclebin" else event.path or event.process
        if target:
            name = ntpath.basename(target).lower()
            if name:
                deletion_groups[name].append((index, event))
    deletion_pairs = []
    for name, group in deletion_groups.items():
        deleted = [index for index, event in group if event.artifact == "recyclebin"]
        if not deleted:
            continue
        pairs = _cross_artifact_pairs(group, result, "deletion_correlation",
                                      partition=lambda event: event.artifact == "recyclebin",
                                      left_event_indices=deleted, filename=name)
        for left, right in pairs:
            rb, other = (left, right) if left[1].artifact == "recyclebin" else (right, left)
            deletion_pairs.append((rb, other))
    for (rb_idx, rb_ev), (other_idx, other_ev) in sorted(deletion_pairs, key=lambda pair: (pair[0][0], pair[1][0])):
        rb_ts = parse_ts(rb_ev.timestamp)
        other_ts = parse_ts(other_ev.timestamp)
        delta_seconds = None
        temporal = False
        if rb_ts and other_ts and _time_position(rb_ts)[0] == _time_position(other_ts)[0]:
            delta = abs((rb_ts - other_ts).total_seconds())
            delta_seconds = round(delta, 3)
            temporal = delta <= 86400.0
        rel = {
            "left": rb_idx, "right": other_idx,
            "type": "deletion_correlation",
            "basis": "same_file",
            "confidence": "filename_match",
            "execution_confirmed": False,
        }
        if delta_seconds is not None:
            rel["delta_seconds"] = delta_seconds
        if temporal:
            rel["temporal_proximity"] = True
        result.append(rel)

    result.extend(_rdp_correlations(events, parse_ts))

    # Execution chain analysis
    chains = _build_execution_chains(events, parse_ts)
    result.extend(chains)

    # Program group aggregation
    program_groups = _build_program_groups(events)
    for group in program_groups:
        if len(group["event_indices"]) >= 3:
            for i, left_id in enumerate(group["event_indices"]):
                for right_id in group["event_indices"][i + 1:i + 4]:
                    result.append({
                        "left": left_id, "right": right_id,
                        "type": "program_group",
                        "basis": "same_executable",
                        "confidence": "program_cluster",
                        "execution_confirmed": False,
                        "program": group["program"],
                        "artifact_count": group["artifact_count"],
                        "total_events": len(group["event_indices"]),
                    })

    from .task_merge import task_log_relations
    result.extend(task_log_relations(events, PAIR_GROUP_LIMIT))
    from .relation_evidence import add_relation_evidence
    return add_relation_evidence(result, events, parse_ts)


def _rdp_account(value, domain=None):
    if not isinstance(value, str) or not value.strip():
        return None, None
    value = value.strip().casefold()
    domain = domain.strip().casefold() if isinstance(domain, str) and domain.strip() else None
    if '\\' in value:
        domain, value = value.split('\\', 1)
    elif '@' in value:
        value, domain = value.rsplit('@', 1)
    return value, domain


def _rdp_correlations(events, parse_ts):
    """Endpoint equality + user hint + nearby key modification are only candidates."""
    servers, logs, result = defaultdict(list), defaultdict(list), []
    providers = {'microsoft-windows-terminalservices-remoteconnectionmanager': {1149},
                 'microsoft-windows-terminalservices-localsessionmanager': {21, 24, 25}}
    for index, event in enumerate(events):
        details = event.details or {}
        stamp = parse_ts(event.timestamp)
        if stamp is None:
            continue
        clock, position = _time_position(stamp)
        if event.artifact == 'rdp' and event.action == 'rdp_server' and event.time_field == 'key_lastwrite':
            host = details.get('remote_host')
            user, domain = _rdp_account(details.get('username_hint'), details.get('domain'))
            if isinstance(host, str) and user:
                servers[(host.strip().rstrip('.').casefold(), user, domain, clock)].append((position, index))
        elif event.artifact == 'evtx':
            provider = details.get('provider')
            if not isinstance(provider, str) or details.get('event_id') not in providers.get(provider.casefold(), set()):
                continue
            data = details.get('user_data') or details.get('event_data') or {}
            if not isinstance(data, dict):
                continue
            host = details.get('computer')
            user, domain = _rdp_account(data.get('User') or data.get('Param1') or data.get('TargetUserName'),
                                        data.get('Domain') or data.get('Param2') or data.get('TargetDomainName'))
            if isinstance(host, str) and user:
                logs[(host.strip().rstrip('.').casefold(), user, clock)].append((position, index, domain))
    for (host, user, domain, clock), sources in servers.items():
        targets = sorted((position, index) for position, index, log_domain in logs.get((host, user, clock), [])
                         if domain is None or log_domain is None or domain == log_domain)
        positions = [position for position, _ in targets]
        windows = []
        for position, source in sources:
            lower = bisect_left(positions, position - 300000000)
            upper = bisect_right(positions, position + 300000000)
            if lower < upper:
                windows.append((source, position, lower, upper))
        count = sum(upper - lower for _, _, lower, upper in windows)
        if count > PAIR_GROUP_LIMIT:
            indices = {source for source, _, _, _ in windows}
            last_end = 0
            for lower, upper in sorted((lower, upper) for _, _, lower, upper in windows):
                indices.update(targets[index][1] for index in range(max(lower, last_end), upper))
                last_end = max(last_end, upper)
            result.append({'type': 'correlation_group', 'relation_type': 'rdp_session_correlation',
                           'basis': 'rdp_host_user_time', 'confidence': 'candidate', 'execution_confirmed': False,
                           'candidate_count': count, 'event_indices': sorted(indices),
                           'left_event_indices': [source for source, _, _, _ in windows],
                           'remote_host': host, 'username_hint': user, 'window_seconds': 300,
                           'same_clock_required': True, 'pair_expansion_limit': PAIR_GROUP_LIMIT})
            continue
        for source, position, lower, upper in windows:
            for target_position, target in sorted(targets[lower:upper], key=lambda entry: entry[1]):
                result.append({'left': source, 'right': target, 'type': 'rdp_session_correlation',
                               'basis': 'rdp_host_user_time', 'confidence': 'candidate',
                               'execution_confirmed': False, 'delta_seconds': abs(position - target_position) / 1000000,
                               'remote_host': host, 'username_hint': user,
                               'left_time_field': 'key_lastwrite', 'time_is_connection_time': False})
    return result


def _normalize_process_name(name):
    if not name:
        return None
    base = ntpath.basename(name).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base or None


CHAIN_WINDOW = 300  # seconds: records of one run must fall this close together to corroborate each other
EXECUTION_ARTIFACTS = {"prefetch", "bam", "userassist", "amcache"}


def _is_evtx_execution(event):
    details = event.details or {}
    event_id = details.get("event_id")
    if event_id == 4688:  # Security: a new process has been created
        return True
    return event_id == 1 and "sysmon" in str(details.get("provider") or "").lower()


def _chain_confidence(sorted_events, artifacts, parse_ts=_parse_ts):
    """'corroborated_execution' only when an execution log, Prefetch and BAM/UserAssist/Amcache
    for the same program name fall inside CHAIN_WINDOW with no conflicting user SIDs.
    Otherwise the records only share a file name ('multi_source')."""
    sids = {e.sid for _, e in sorted_events if e.sid}
    if len(sids) > 1 or "prefetch" not in artifacts or not artifacts & {"bam", "userassist", "amcache"}             or not any(_is_evtx_execution(e) for _, e in sorted_events):
        return "multi_source"
    stamps = [t for t in (parse_ts(e.timestamp) for _, e in sorted_events) if t]
    if len(stamps) < 3 or len({_time_position(t)[0] for t in stamps}) != 1 or (max(stamps) - min(stamps)).total_seconds() > CHAIN_WINDOW:
        return "multi_source"
    return "corroborated_execution"


def _build_execution_chains(events, parse_ts=_parse_ts):
    proc_map = defaultdict(lambda: {"events": [], "artifacts": set()})
    for index, event in enumerate(events):
        exe = event.process or event.path
        if not exe:
            continue
        norm = _normalize_process_name(exe)
        if not norm:
            continue
        is_evtx_exec = event.artifact == "evtx" and _is_evtx_execution(event)
        if event.artifact in EXECUTION_ARTIFACTS or is_evtx_exec:
            proc_map[norm]["events"].append((index, event))
            proc_map[norm]["artifacts"].add(event.artifact)

    chains = []
    for proc_name, data in proc_map.items():
        if len(data["artifacts"]) < 2:
            continue
        sorted_events = sorted(data["events"], key=lambda x: x[1].timestamp or "")
        timestamps = [parse_ts(e.timestamp) for _, e in sorted_events]
        first_ts = next((t for t in timestamps if t), None)
        last_ts = next((t for t in reversed(timestamps) if t), None)
        confidence = _chain_confidence(sorted_events, data["artifacts"], parse_ts)
        chains.append({
            "type": "execution_chain",
            "process": proc_name,
            "basis": "process_name",
            "confidence": confidence,
            "execution_confirmed": False,
            "sources": sorted(data["artifacts"]),
            "first_seen": first_ts.isoformat() if first_ts else None,
            "last_seen": last_ts.isoformat() if last_ts else None,
            "event_count": len(data["events"]),
            "event_indices": [i for i, _ in sorted_events],
        })
    return chains


def _build_program_groups(events):
    groups = defaultdict(lambda: {"event_indices": [], "artifacts": set()})
    for index, event in enumerate(events):
        exe = event.process or (event.path if event.path and event.path.lower().endswith((".exe", ".dll", ".sys")) else None)
        if not exe:
            continue
        normalized = normalize_executable_path(exe)
        name = ntpath.basename(normalized)
        if not name:
            continue
        groups[name]["event_indices"].append(index)
        groups[name]["artifacts"].add(event.artifact)
    result = []
    for name, data in groups.items():
        if len(data["artifacts"]) >= 2:
            result.append({
                "program": name,
                "event_indices": data["event_indices"],
                "artifact_count": len(data["artifacts"]),
            })
    return result


def summarize_correlations(relations, events):
    type_counts = defaultdict(int)
    programs = defaultdict(int)
    for r in relations:
        type_counts[r.get("type", "unknown")] += 1
        if r.get("type") == "program_group":
            programs[r.get("program", "unknown")] += 1
    exec_chains = [r for r in relations if r.get("type") == "execution_chain"]
    chain_by_confidence = defaultdict(int)
    for c in exec_chains:
        chain_by_confidence[c.get("confidence", "unknown")] += 1
    return {
        "total_relations": len(relations),
        "by_type": dict(type_counts),
        "top_programs": sorted(programs.items(), key=lambda x: -x[1])[:20],
        "temporal_count": sum(1 for r in relations if r.get("temporal_proximity")),
        "url_matches": type_counts.get("url_correlation", 0),
        "usb_file_matches": type_counts.get("usb_file_correlation", 0),
        "mountpoint_usb_matches": type_counts.get("mountpoint_usb_correlation", 0),
        "execution_chains": len(exec_chains),
        "chain_confidence": dict(chain_by_confidence),
        "deletion_matches": type_counts.get("deletion_correlation", 0),
    }
