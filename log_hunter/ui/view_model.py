"""What the GUI shows, computed without Tk: filtered records, table rows, counts and summaries."""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from log_hunter.core.labels import (image_verification_lines, action_label, artifact_from_label, artifact_label, basis_label, confidence_label,
                                    evidence_origin, method_label, relation_label, status_label, time_field_label)
from log_hunter.core.sid_resolver import display_name
from log_hunter.core.timeline import parse_filter_date, timeline
from log_hunter.core.tree import matches
from .style import ARTIFACT_COLORS

ALL_LABEL = "전체"
TIMELINE_COLUMNS = ("artifact", "timestamp", "time_field", "sid", "user", "action", "path", "status")


@dataclass
class Filters:
    """The filter bar as typed: labels and text, not internal keys."""
    artifact: str = ALL_LABEL
    start: str = ""
    end: str = ""
    sid: str = ""
    query: str = ""
    status: str = ALL_LABEL


def filter_events(events, filters, node=None, origins=None, names=None):
    """`filters.sid`: a SID (S-1-...) or part of a shown user name (found in the evidence or a well-known account)."""
    art_filter = None if filters.artifact == ALL_LABEL else artifact_from_label(filters.artifact)
    user = filters.sid.strip()
    by_sid = user if user.upper().startswith("S-1-") else None
    filtered = timeline(events, artifact=art_filter, sid=by_sid,
                        start=parse_filter_date(filters.start), end=parse_filter_date(filters.end, end=True),
                        query=filters.query or None)
    if user and not by_sid:
        needle = user.casefold()
        filtered = [e for e in filtered if e.sid and needle in display_name(e.sid, names).casefold()]
    if filters.status != ALL_LABEL:
        filtered = [e for e in filtered if status_label(e.status) == filters.status]
    if node is not None:
        filtered = [e for e in filtered if matches(node, e, origins)]
    return filtered


def display_target(event):
    return event.path or event.process or event.url or (event.details or {}).get("command") or ""


def timeline_row(event, sid_map):
    """(values in TIMELINE_COLUMNS order, color tag or "")."""
    username = display_name(event.sid, sid_map)
    values = (artifact_label(event.artifact), event.timestamp or "알 수 없음",
              time_field_label(event.time_field) if event.time_field else "", event.sid or "", username,
              action_label(event.action), display_target(event), status_label(event.status))
    return values, event.artifact if event.artifact in ARTIFACT_COLORS else ""


def matches_search(event, text, sid_map):
    """Quick search box: raw keys and the shown labels, case-insensitive. `text` is already lowercased."""
    if not text:
        return True
    username = display_name(event.sid, sid_map)
    fields = (event.artifact or "", event.timestamp or "", event.action or "", display_target(event),
              event.sid or "", username, artifact_label(event.artifact), action_label(event.action),
              time_field_label(event.time_field) if event.time_field else "", status_label(event.status))
    return any(text in field.lower() for field in fields)


TIMELINE_PAGE_ROWS = 5000  # rows put into the Tk table at once; millions of rows would freeze it


def page_bounds(count, page, size=TIMELINE_PAGE_ROWS):
    """(page, pages, start, end) for showing `count` rows `size` at a time; page is clamped."""
    pages = max(1, -(-count // size))
    page = min(max(0, page), pages - 1)
    start = page * size
    return page, pages, start, min(count, start + size)


def page_text(page, pages, start, end, count):
    if pages <= 1:
        return ""
    return f"{start + 1:,}–{end:,}번째 / {count:,}건 · 페이지 {page + 1}/{pages}"


def count_text(shown, filtered, total, searching):
    return f"표시: {shown} / 필터: {filtered} / 전체: {total}" if searching else f"표시: {filtered} / 전체: {total}"


def summary_text(result):
    sids = {e.sid for e in result.events if e.sid}
    return " | ".join([f"찾은 기록: {len(result.events)}건", f"기록 종류: {len({e.artifact for e in result.events})}개",
                       f"사용자: {len(sids)}명", f"연관: {len(result.relations)}건", f"오류/경고: {len(result.errors)}건"])


def diagnostic_rows(summaries, errors=()):
    """파일별 결과 rows; the last column says why a file gave no or partial records."""
    by_source = {}
    for error in errors:
        by_source.setdefault(str(error.source), []).append(error)
    return [(s.get("source", ""), artifact_label(s.get("artifact", "")), status_label(s.get("state", "")),
             s.get("events", 0), s.get("errors", 0), s.get("warnings", 0), f"{s.get('elapsed_seconds', 0):.3f}초",
             diagnostic_cause(s, by_source.get(str(s.get("source", "")), [])))
            for s in summaries]


def diagnostic_cause(summary, errors):
    """Plain-language cause: an empty log is normal, a damaged header or partial read is said so, with where."""
    from log_hunter.core.labels import DIAGNOSTIC_TEXT as T
    problems = [e for e in errors if e.severity in ("error", "warning")]
    if not problems:
        if summary.get("state") == "no_data":
            notes = [e.message for e in errors]
            return T["empty_note"].format(message=notes[0]) if notes else T["empty"]
        return T["ok"] if summary.get("state") == "ok" else ""
    locators = [str(e.locator) for e in problems]
    first = lambda key: next(e for e in problems if str(e.locator) == key).message
    parts = []
    if "header" in locators:
        parts.append(T["header"].format(message=first("header")))
    if "flags" in locators:
        parts.append(T["dirty"])
    if "header_crc" in locators:
        parts.append(T["header_crc"])
    damaged = [e for e in problems if str(e.locator).isdigit() or str(e.locator).startswith("chunk:")]
    if damaged:
        parts.append(T["partial"].format(events=summary.get("events", 0), count=len(damaged), first=damaged[0].locator))
    for key, template in (("BinXML", "binxml"), ("checksum", "checksum"), ("chunk_count", "chunks")):
        if key in locators:
            parts.append(T[template].format(message=first(key)))
    known = {"header", "flags", "header_crc", "BinXML", "checksum", "chunk_count"}
    rest = [e for e in problems if str(e.locator) not in known and e not in damaged]
    if rest and not parts:
        parts.append(T["failed" if summary.get("state") == "failed" else "other"].format(message=rest[0].message))
        if len(rest) > 1:
            parts.append(T["more"].format(count=len(rest) - 1))
    return " · ".join(parts)


def error_lines(errors, severity=None):
    return [f"[{status_label(e.severity)}] {artifact_label(e.artifact)} | {e.source} @ {e.locator}: {e.message}\n"
            for e in errors if not severity or e.severity == severity]


def describe_event(events, index):
    if not isinstance(index, int) or not 0 <= index < len(events):
        return ""
    event = events[index]
    target = event.path or event.process or event.url or ""
    return f"{artifact_label(event.artifact)} · {action_label(event.action)} · {target}"


def relation_rows(relations, events, kind=None):
    """Rows for the 연관 분석 table; `relation_events` gives the records behind the same rows."""
    rows = []
    for relation in relations:
        if kind and relation.get("type") != kind:
            continue
        kind_text = relation_label(relation.get("type", ""))
        if relation.get("type") == "execution_chain":
            left = f"프로그램: {relation.get('process', '')}"
            right = ", ".join(artifact_label(s) for s in relation.get("sources", []))
        elif relation.get("type") == "correlation_group":
            kind_text, left, right = _group_texts(relation)
        else:
            left, right = describe_event(events, relation.get("left")), describe_event(events, relation.get("right"))
        rows.append((kind_text, confidence_label(relation.get("confidence", "")),
                     left, right, basis_label(relation.get("basis", ""))))
    return rows


verification_lines = image_verification_lines  # display text lives in core.labels


def _group_texts(relation):
    """A large candidate group is stored as counts and member lists, not as pairs: say so plainly."""
    kind_text = f"{relation_label('correlation_group')}: {relation_label(relation.get('relation_type', ''))}"
    members = relation.get("event_indices") or []
    anchors = relation.get("left_event_indices") or []
    if relation.get("relation_type") == "usb_file_correlation":
        left = f"USB 연결 기록 {len(anchors):,}건 · 파일 기록 {len(members):,}건"
    elif relation.get("relation_type") == "deletion_correlation":
        left = f"삭제 기록 {len(anchors):,}건 · 같은 이름 기록 {len(members):,}건"
    else:
        left = f"기록 {len(members):,}건"
    right = f"후보 {relation.get('candidate_count', 0):,}쌍 (모든 쌍이 관계인 것은 아님)"
    if relation.get("window_seconds"):
        right += f" · 같은 시계 기준 ±{relation['window_seconds']}초"
    return kind_text, left, right


def relation_events(relation, events):
    """Records a relation row points at (pair, chain or group), for showing them in the timeline."""
    indices = [relation.get("left"), relation.get("right"), *(relation.get("event_indices") or []),
               *(relation.get("left_event_indices") or [])]
    seen = []
    for index in indices:
        if isinstance(index, int) and 0 <= index < len(events) and index not in seen:
            seen.append(index)
    return [events[i] for i in seen]


def evidence_rows(evidence):
    return [(evidence_origin(e), e.sha256[:16] + "...", method_label(e.method), e.collected_at or "") for e in evidence]


def stats_lines(result):
    """Summary line for the statistics tab."""
    processes = {e.process for e in result.events if e.process}
    sids = {e.sid for e in result.events if e.sid}
    timestamps = [e.timestamp for e in result.events if e.timestamp]
    time_range = f"{min(timestamps)} ~ {max(timestamps)}" if timestamps else "알 수 없음"
    lines = [f"찾은 기록: {len(result.events)}건", f"기록 종류: {len(Counter(e.artifact for e in result.events))}개",
             f"사용자: {len(sids)}명", f"실행된 프로그램: {len(processes)}개", f"연관 관계: {len(result.relations)}건",
             f"오류/경고: {len(result.errors)}건", f"기간: {time_range}", f"분석한 파일: {len(result.evidence)}개"]
    high_risk = sum(1 for e in result.events
                    if e.details and (e.details.get("risk_level") == "high" or e.details.get("suspicion_flags")))
    if high_risk:
        lines.append(f"위험도 높은 기록: {high_risk}건")
    return lines


# --- automatic input detection (core.auto_detect.detect_inputs) ---------------------------------

UNRECOGNIZED_REASON = "기록 종류를 인식하지 못했습니다."  # engine text for "no artifact matched"


@dataclass
class DetectPlan:
    inputs: list   # (artifact, path, owner sid, reason) to add for analysis
    images: list   # disk image paths to open with image analysis
    unknown: list  # paths no rule recognized: the user may pick a type for these
    notes: list    # (path, reason) for sidecar-only, unsupported or unreadable inputs


def plan_detected(rows):
    """Sort detect_inputs rows into what the GUI adds, opens as an image, asks about, or only reports."""
    plan = DetectPlan([], [], [], [])
    for artifact, path, sid, reason in rows:
        if artifact == "image":
            plan.images.append(path)
        elif artifact:
            plan.inputs.append((artifact, path, sid, reason))
        elif reason == UNRECOGNIZED_REASON:
            plan.unknown.append(path)
        else:
            plan.notes.append((path, reason))
    return plan


def input_line(artifact, path, reason=""):
    """One line of the 분석 대상 파일 list, with why the file was recognized."""
    return f"[{artifact_label(artifact)}] {path}" + (f"  · 인식 근거: {reason}" if reason else "")


def detect_summary(plan, limit=10):
    kinds = {}
    for artifact, _path, _sid, _reason in plan.inputs:
        kinds[artifact_label(artifact)] = kinds.get(artifact_label(artifact), 0) + 1
    lines = [f"분석 대상으로 추가: {len(plan.inputs)}개"]
    lines += [f"  - {name}: {count}개" for name, count in sorted(kinds.items())]
    if plan.images:
        lines.append(f"디스크 이미지: {len(plan.images)}개 (이미지 분석으로 열 수 있습니다)")
    if plan.unknown:
        lines.append(f"기록 종류를 알 수 없는 파일: {len(plan.unknown)}개")
    if plan.notes:
        lines.append(f"추가하지 않은 파일: {len(plan.notes)}개")
        lines += [f"  - {Path(path).name}: {reason}" for path, reason in plan.notes[:limit]]
        if len(plan.notes) > limit:
            lines.append(f"  … 외 {len(plan.notes) - limit}개")
    return "\n".join(lines)
