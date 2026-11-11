"""Attach auditable comparison values and source references to relation candidates."""
from collections import Counter
import ntpath
from .normalization import normalize_executable_path
from .labels import RELATION_REASON_LABELS, relation_label, basis_label


def add_relation_evidence(relations, events, parse_ts=None):
    from .correlation import _normalize_url, _normalize_process_name, _parse_ts, _time_position, _rdp_account, _is_evtx_execution, CHAIN_WINDOW

    parse_ts = parse_ts or _parse_ts

    def target(event):
        field = "path" if event.path else "process"
        return field, getattr(event, field)

    def compare(field, lf, rf, lv, rv, ln, rn, operator="equals"):
        if operator == "contained_in":
            matched = bool(ln) and any(ln in value for value in rn)
        elif operator == "member_of":
            matched = ln is not None and ln in rn
        elif operator == "prefix_in":
            matched = bool(rn) and any(rn.startswith(value) for value in ln)
        else:
            matched = ln is not None and rn is not None and ln == rn
        return {"field": field, "left_field": lf, "right_field": rf,
                "left_value": lv, "right_value": rv, "left_normalized": ln,
                "right_normalized": rn, "operator": operator, "matched": matched}

    def reference(index):
        e = events[index]
        return {"event_index": index, "artifact": e.artifact, "source": e.source,
                "locator": e.locator, "timestamp": e.timestamp, "time_field": e.time_field,
                "sid": e.sid, "path": e.path, "process": e.process, "url": e.url}

    for relation in relations:
        pair = "left" in relation and "right" in relation
        ids = [relation["left"], relation["right"]] if pair else relation.get("event_indices", [])
        ids = list(dict.fromkeys(ids))
        refs = [reference(index) for index in ids]
        counts = Counter((ref["artifact"], ref["source"]) for ref in refs)
        kind = relation.get("relation_type", relation.get("type"))
        basis = relation.get("basis")
        reason = relation.get("confidence") if kind == "execution_chain" else basis
        if relation.get("type") == "correlation_group":
            reason = "candidate_group"
        details = {"rule_name": str(kind) + "." + str(basis),
                   "rule_label": relation_label(kind) + " / " + basis_label(basis),
                   "confidence_reason": reason,
                   "confidence_reason_label": RELATION_REASON_LABELS.get(reason, basis_label(basis)),
                   "comparisons": [], "event_refs": refs,
                   "source_counts": [{"artifact": artifact, "source": source, "count": count}
                                     for (artifact, source), count in sorted(counts.items())]}
        details["grouping"] = {"basis": basis,
            "key": relation.get("process") or relation.get("program") or relation.get("filename") or relation.get("url"),
            "candidate_count": relation.get("candidate_count", 1 if pair else None),
            "pair_expansion_limit": relation.get("pair_expansion_limit"),
            "event_count": len(refs), "artifact_count": len({ref["artifact"] for ref in refs}),
            "source_file_count": len({ref["source"] for ref in refs}),
            "known_sids": sorted({ref["sid"] for ref in refs if ref["sid"]}),
            "candidate_rules": (["different_artifacts", "no_known_sid_conflict"]
                                if kind in ("path_correlation", "url_correlation", "deletion_correlation") else []),
            "criteria": {key: relation[key] for key in ("relation_type", "window_seconds", "same_clock_required",
                         "signed_window_seconds", "signed_delta_basis", "left_event_indices", "remote_host", "username_hint") if key in relation}}
        if pair:
            left, right = events[ids[0]], events[ids[1]]
            lf, lv = target(left)
            rf, rv = target(right)
            if kind == "program_group":
                lf = "process" if left.process else "path"
                rf = "process" if right.process else "path"
                lv, rv = getattr(left, lf), getattr(right, rf)
            if kind in ("path_correlation", "deletion_correlation", "program_group"):
                ln, rn = normalize_executable_path(lv), normalize_executable_path(rv)
                field = "normalized_path" if basis == "normalized_path" else "filename"
                if field == "filename":
                    ln, rn = ntpath.basename(ln), ntpath.basename(rn)
                if kind == "deletion_correlation":
                    ln, rn = ntpath.basename(lv).lower(), ntpath.basename(rv).lower()
                details["comparisons"].append(compare(field, lf, rf, lv, rv, ln, rn))
            elif kind == "task_log_correlation":
                from log_hunter.parser.taskcache import task_path
                data = right.details.get("event_data") or right.details.get("user_data") or {}
                lv = left.details.get("task_path")
                rv = data.get("TaskName") or data.get("TaskPath")
                norm = lambda v: task_path(v).casefold() if task_path(v) else None
                details["comparisons"].append(compare("task_path", "details.task_path",
                    "details.event_data.TaskName/TaskPath", lv, rv, norm(lv), norm(rv)))
            elif kind == "url_correlation":
                details["comparisons"].append(compare("url", "url", "url", left.url, right.url,
                                                     _normalize_url(left.url), _normalize_url(right.url)))
            elif kind == "usb_file_correlation":
                drives = left.details.get("drive_letters", [])
                details["comparisons"].append(compare("drive_prefix", "details.drive_letters", "path", drives,
                    right.path, [str(d).upper() for d in drives], (right.path or "").upper(), "prefix_in"))
            elif kind == "mountpoint_usb_correlation":
                if basis == "volume_guid_match":
                    value = left.details.get("volume_guid", "")
                    values = [item.get("raw_text") or "" for item in right.details.get("mounted_device_matches", [])]
                    details["comparisons"].append(compare("volume_guid", "details.volume_guid",
                        "details.mounted_device_matches[].raw_text", value, values,
                        value.lower(), [v.lower() for v in values], "contained_in"))
                else:
                    value = left.details.get("drive_letter", "")
                    values = right.details.get("drive_letters", [])
                    details["comparisons"].append(compare("drive_letter", "details.drive_letter", "details.drive_letters",
                        value, values, value.upper(), [v.upper() for v in values], "member_of"))
            elif kind == "rdp_session_correlation":
                host = left.details.get("remote_host")
                computer = right.details.get("computer")
                norm = lambda v: v.strip().rstrip(".").casefold() if isinstance(v, str) else None
                details["comparisons"].append(compare("host", "details.remote_host", "details.computer",
                                                      host, computer, norm(host), norm(computer)))
                data = right.details.get("user_data") or right.details.get("event_data") or {}
                user = data.get("User") or data.get("Param1") or data.get("TargetUserName")
                domain = data.get("Domain") or data.get("Param2") or data.get("TargetDomainName")
                ln = _rdp_account(left.details.get("username_hint"), left.details.get("domain"))
                rn = _rdp_account(user, domain)
                account = compare("account", "details.username_hint/domain", "details.event_data/user_data",
                                  left.details.get("username_hint"), {"user": user, "domain": domain}, ln, rn)
                account["operator"] = "compatible_account"
                account["matched"] = ln[0] == rn[0] and (not ln[1] or not rn[1] or ln[1] == rn[1])
                details["comparisons"].append(account)
            a, b = parse_ts(left.timestamp), parse_ts(right.timestamp)
            comparable = a is not None and b is not None and _time_position(a)[0] == _time_position(b)[0]
            delta = (b - a).total_seconds() if comparable else None
            window = 300 if kind in ("usb_file_correlation", "rdp_session_correlation") else 60 if kind == "path_correlation" else 86400 if kind == "deletion_correlation" else None
            details["time_comparison"] = {"left_value": left.timestamp, "right_value": right.timestamp,
                "left_time_field": left.time_field, "right_time_field": right.time_field,
                "comparable": comparable, "signed_delta_seconds": delta,
                "delta_seconds": abs(delta) if delta is not None else None, "window_seconds": window,
                "within_window": abs(delta) <= window if delta is not None and window is not None else None}
        else:
            if kind == "task_log_correlation":
                from log_hunter.parser.taskcache import task_path
                for index in ids:
                    event = events[index]
                    data = event.details.get("event_data") or event.details.get("user_data") or {}
                    raw = (data.get("TaskName") or data.get("TaskPath")) if event.artifact == "evtx" else event.details.get("task_path")
                    normalized = task_path(raw)
                    details["comparisons"].append({"field": "task_path", "event_index": index,
                        "source_field": "details.event_data.TaskName/TaskPath" if event.artifact == "evtx" else "details.task_path",
                        "value": raw, "normalized": normalized.casefold() if normalized else None})
            stamps = [parse_ts(ref["timestamp"]) for ref in refs]
            valid = [stamp for stamp in stamps if stamp is not None]
            comparable = bool(valid) and len({_time_position(stamp)[0] for stamp in valid}) == 1
            span = (max(valid) - min(valid)).total_seconds() if comparable else None
            details["time_comparison"] = {"comparable": comparable, "timestamp_count": len(valid),
                                           "missing_timestamp_count": len(stamps) - len(valid), "span_seconds": span}
            if kind in ("path_correlation", "deletion_correlation", "url_correlation"):
                for index in ids:
                    event = events[index]
                    field, raw = target(event)
                    if kind == "url_correlation":
                        field, raw, normalized = "url", event.url, _normalize_url(event.url)
                    elif kind == "deletion_correlation":
                        normalized = ntpath.basename(raw).lower()
                    else:
                        normalized = ntpath.basename(normalize_executable_path(raw))
                    details["comparisons"].append({"field": "url" if kind == "url_correlation" else "filename",
                        "event_index": index, "source_field": field, "value": raw, "normalized": normalized})
            if kind in ("usb_file_correlation", "rdp_session_correlation"):
                left_indices = set(relation.get("left_event_indices", []))
                details["comparisons"] = [{"field": "timestamp_window", "event_index": index,
                    "value": events[index].timestamp, "time_field": events[index].time_field,
                    "role": "left" if index in left_indices else "right"} for index in ids]
            if kind == "execution_chain":
                details["grouping"]["key"] = relation.get("process")
                details["grouping"]["definition"] = "multi_source"
                artifacts = {ref["artifact"] for ref in refs}
                details["grouping"]["criteria"].update(
                    prefetch_present="prefetch" in artifacts,
                    registry_execution_trace_present=bool(artifacts & {"bam", "userassist", "amcache"}),
                    execution_log_event_indices=[index for index in ids if _is_evtx_execution(events[index])],
                    known_sid_conflict=len(details["grouping"]["known_sids"]) > 1,
                    timestamp_count=len(valid), comparable_clock=comparable,
                    window_seconds=CHAIN_WINDOW, span_seconds=span)
                details["comparisons"] = [{"field": "process_name", "event_index": index,
                    "value": events[index].process or events[index].path,
                    "normalized": _normalize_process_name(events[index].process or events[index].path)} for index in ids]
        relation["evidence_details"] = details
    return relations
