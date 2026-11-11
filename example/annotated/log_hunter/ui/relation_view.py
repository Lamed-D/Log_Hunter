# ▶ 원본: log_hunter/ui/relation_view.py
# ▶ 연관 분석 탭에서 고른 관계의 판단 근거(규칙·비교 값·시각 차이·묶인 수)와 묶인 기록 목록을 쉬운 말로 만듭니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""연관 분석 detail: why two records (or a group) were put together, from the engine's evidence_details, without Tk."""
from log_hunter.core.labels import (RELATION_DETAIL_LABELS as L, artifact_label, confidence_label, time_field_label,
                                    UNKNOWN_VALUE)
from .record_fields import format_time

MEMBER_LIMIT = 2000  # rows shown in the member list; the counts above it stay complete


def _value(value):
    if value is None or value == "" or value == []:
        return UNKNOWN_VALUE
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _seconds(value):
    if value is None:
        return UNKNOWN_VALUE
    value = abs(float(value))
    if value < 120:
        return f"{value:,.0f}초"
    if value < 7200:
        return f"{value / 60:,.1f}분"
    return f"{value / 3600:,.1f}시간"


def _comparison_lines(comparisons, events):
    lines = []
    for c in comparisons:
        field = L["fields"].get(c.get("field"), c.get("field") or UNKNOWN_VALUE)
        if "left_value" in c:  # a pair: both sides and the rule that compared them
            outcome = L["matched"] if c.get("matched") else L["not_matched"]
            lines.append(f"  · {field}: A {_value(c.get('left_value'))}  /  B {_value(c.get('right_value'))}")
            lines.append(f"      {L['normalized']} A {_value(c.get('left_normalized'))}  /  B {_value(c.get('right_normalized'))}"
                         f"  ({L['operators'].get(c.get('operator'), c.get('operator'))}) → {outcome}")
        else:  # one member of a group
            index = c.get("event_index")
            kind = artifact_label(events[index].artifact) if isinstance(index, int) and 0 <= index < len(events) else ""
            role = {"left": " (A쪽)", "right": " (B쪽)"}.get(c.get("role"), "")
            shown = c.get("normalized", c.get("value"))
            lines.append(f"  · {field}{role}: {kind} {_value(shown)}".rstrip())
    return lines


def _time_lines(time):
    if not time:
        return [f"{L['time']}: {UNKNOWN_VALUE}"]
    if "left_value" in time:
        lines = [f"{L['time']}: A {format_time(time.get('left_value'))} ({time_field_label(time.get('left_time_field')) if time.get('left_time_field') else UNKNOWN_VALUE})",
                 f"{' ' * len(L['time'])}  B {format_time(time.get('right_value'))} ({time_field_label(time.get('right_time_field')) if time.get('right_time_field') else UNKNOWN_VALUE})"]
        if not time.get("comparable"):
            lines.append(f"  {L['time_not_comparable']}")
        else:
            line = f"  {L['time_delta']} {_seconds(time.get('delta_seconds'))}"
            if time.get("window_seconds") is not None:
                inside = L["inside"] if time.get("within_window") else L["outside"]
                line += f" ({L['window']} {_seconds(time.get('window_seconds'))} {inside})"
            lines.append(line)
        return lines
    span = _seconds(time.get("span_seconds")) if time.get("comparable") else L["time_not_comparable"]
    return [f"{L['time']}: {L['time_count'].format(count=time.get('timestamp_count', 0))}, {L['span']} {span}"
            + (f", {L['missing'].format(count=time['missing_timestamp_count'])}" if time.get("missing_timestamp_count") else "")]


def detail_lines(relation, events):
    """Plain-language lines: rule, confidence and why, compared fields with both values, time difference, group size."""
    d = relation.get("evidence_details")
    if not isinstance(d, dict):
        return [L["no_details"]]
    g = d.get("grouping") or {}
    lines = [f"{L['rule']}: {d.get('rule_label') or UNKNOWN_VALUE}",
             f"{L['confidence']}: {confidence_label(relation.get('confidence', ''))}",
             f"{L['reason']}: {d.get('confidence_reason_label') or UNKNOWN_VALUE}"]
    if g.get("definition") == "multi_source":
        lines.append(f"  {L['multi_source_note']}")
    comparisons = d.get("comparisons") or []
    lines.append(f"{L['compared']}:" if comparisons else f"{L['compared']}: {UNKNOWN_VALUE}")
    lines.extend(_comparison_lines(comparisons[:50], events))
    if len(comparisons) > 50:
        lines.append(f"  … {L['more'].format(count=len(comparisons) - 50)}")
    lines.extend(_time_lines(d.get("time_comparison")))
    group = [L["group"].format(events=g.get("event_count", 0), artifacts=g.get("artifact_count", 0),
                               sources=g.get("source_file_count", 0))]
    if g.get("candidate_count") is not None:
        group.append(L["candidates"].format(count=g["candidate_count"]))
    if g.get("pair_expansion_limit"):
        group.append(L["pair_limit"].format(count=g["pair_expansion_limit"]))
    if g.get("key"):
        group.append(f"{L['key']} {g['key']}")
    lines.append(" · ".join(group))
    if len(g.get("known_sids") or ()) > 1:
        lines.append(f"  {L['sid_conflict']}: {', '.join(g['known_sids'])}")
    for item in d.get("source_counts") or []:
        lines.append(f"  · {artifact_label(item.get('artifact'))} — {item.get('source')} ({item.get('count', 0):,}건)")
    return lines


def member_rows(relation, events):
    """[(event index, (role, kind, source file, time, time meaning, target))] for the records behind a relation."""
    d = relation.get("evidence_details") if isinstance(relation.get("evidence_details"), dict) else {}
    refs = d.get("event_refs") or []
    if not refs:  # older results: build the list from the indices
        indices = [relation.get("left"), relation.get("right"), *(relation.get("event_indices") or [])]
        refs = [{"event_index": i} for i in dict.fromkeys(i for i in indices if isinstance(i, int))]
    left, right = relation.get("left"), relation.get("right")
    rows = []
    for ref in refs[:MEMBER_LIMIT]:
        index = ref.get("event_index")
        if not isinstance(index, int) or not 0 <= index < len(events):
            continue
        event = events[index]
        role = "A" if index == left else "B" if index == right else ""
        target = event.path or event.process or event.url or ""
        rows.append((index, (role, artifact_label(event.artifact), str(event.source or ""), format_time(event.timestamp),
                             time_field_label(event.time_field) if event.time_field else UNKNOWN_VALUE, target)))
    return rows
