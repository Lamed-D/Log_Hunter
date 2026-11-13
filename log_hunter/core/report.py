import csv
import html
import json
from dataclasses import asdict
from pathlib import Path
from .correlation import summarize_correlations
from .sid_resolver import display_name
from .task_merge import TASK_ARTIFACTS
from .export import csv_safe
from . import thumbcache_view, wifi_view
from .process_tree import build_process_tree, format_process_tree, detect_suspicious_trees
from .stats import compute_stats, detect_anomalies
from .labels import (image_verification_lines, ACTION_LABELS, ANOMALY_LABELS, ARTIFACT_DESCRIPTIONS, ARTIFACT_LABELS,
                     BASIS_LABELS, CONFIDENCE_LABELS, RELATION_LABELS, STATUS_LABELS, TIME_FIELD_LABELS, anomaly_label,
                     artifact_label, column_label, evidence_origin, method_label, status_label, tag_label, WIFI_TEXT, TASK_TEXT,
                     USB_DEVICE_KINDS, USB_REPORT_TEXT, time_field_label)
from .tree import usb_hidden


def _script_json(value):
    """JSON safe to embed in an inline <script> (evidence strings may contain '</script>')."""
    return json.dumps(value, ensure_ascii=False).replace("</", "<\\/").replace("<!--", "<\\!--")


class _EventRows(list):
    def __init__(self, events):
        self.events = events

    def __len__(self):
        return len(self.events)

    def __iter__(self):
        return (event.to_dict() for event in self.events)


def _payload_json(payload, events):
    return json.JSONEncoder(ensure_ascii=False, indent=2).iterencode({**payload, "events": _EventRows(events)})


def _payload_preview(payload, events, limit=500000):
    chunks = []
    for chunk in _payload_json(payload, events):
        chunks.append(chunk[:limit])
        limit -= len(chunk)
        if limit <= 0:
            break
    return "".join(chunks)


def export_reports(output, evidence, events, errors, relations, summaries, tags=(), image=None, sid_names=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    correlation_summary = summarize_correlations(relations, events)
    payload = {"evidence": [asdict(e) for e in evidence], "events": None,
               "errors": [asdict(e) for e in errors], "relations": relations, "summaries": summaries,
               "correlation_summary": correlation_summary}
    if tags:
        payload["examiner_tags"] = list(tags)  # the examiner's judgement, kept apart from the evidence data
    with (output / "report.json").open("w", encoding="utf-8") as stream:
        for chunk in _payload_json(payload, events):
            stream.write(chunk)
    fields = ["artifact", "source", "locator", "timestamp", "time_field", "sid", "path", "process", "url", "action", "status", "details"]
    with (output / "timeline.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        for event in events:
            row = event.to_dict()
            row["details"] = json.dumps(row["details"], ensure_ascii=False)
            row = {k: csv_safe(v) for k, v in row.items()}
            writer.writerow(row)
    _write_html_report(output / "report.html", payload, evidence, events, errors, relations, summaries, correlation_summary,
                       tags, (image or {}).get("verification"), sid_names)


def _user_text(sid, user_names):
    return f"{user_names[sid]} ({sid})" if sid in user_names else sid


def _write_html_report(path, payload, evidence, events, errors, relations, summaries, correlation_summary=None,
                       tags=(), verification=None, sid_names=None):
    if correlation_summary is None:
        correlation_summary = {}
    artifact_counts = {}
    action_counts = {}
    status_counts = {"ok": 0, "partial": 0, "warning": 0}
    sid_set = set()
    for e in events:
        artifact_counts[e.artifact] = artifact_counts.get(e.artifact, 0) + 1
        action_counts[e.action] = action_counts.get(e.action, 0) + 1
        if e.status in status_counts:
            status_counts[e.status] += 1
        if e.sid:
            sid_set.add(e.sid)

    # Shown user names (found in the evidence > well-known account names); the exported sid values stay as they are.
    user_names = {sid: display_name(sid, sid_names) for sid in sorted(sid_set)}
    user_names = {sid: name for sid, name in user_names.items() if name}
    timestamps = [e.timestamp for e in events if e.timestamp]
    time_range = ""
    if timestamps:
        time_range = f"{min(timestamps)[:19]} ~ {max(timestamps)[:19]} UTC"

    error_count = sum(1 for e in errors if e.severity == "error")
    warn_count = sum(1 for e in errors if e.severity == "warning")

    evtx_events = [e for e in events if e.artifact == "evtx" and e.details.get("event_id")]
    event_id_counts = {}
    for e in evtx_events:
        eid = e.details.get("event_id")
        if eid:
            event_id_counts[eid] = event_id_counts.get(eid, 0) + 1

    artifact_options = "".join(f'<option value="{html.escape(a)}">{html.escape(artifact_label(a))} ({c})</option>'
                               for a, c in sorted(artifact_counts.items(), key=lambda x: artifact_label(x[0])))
    events_json = "__LOG_HUNTER_EVENTS_STREAM__"
    relations_json = _script_json(relations)
    labels_json = _script_json({"artifact": ARTIFACT_LABELS, "action": ACTION_LABELS, "status": STATUS_LABELS,
                                "relation": RELATION_LABELS, "confidence": CONFIDENCE_LABELS, "time": TIME_FIELD_LABELS,
                                "anomaly": ANOMALY_LABELS, "basis": BASIS_LABELS})

    artifact_chart_data = _script_json([{"name": artifact_label(k), "count": v} for k, v in sorted(artifact_counts.items(), key=lambda x: -x[1])])
    top_events_data = _script_json([{"id": k, "count": v} for k, v in sorted(event_id_counts.items(), key=lambda x: -x[1])[:20]])

    stats = compute_stats(events)
    verification_html = "".join(f'<div class="relation-card" style="font-family:var(--mono)">{html.escape(line)}</div>'
                                for line in image_verification_lines(verification))
    anomalies = detect_anomalies(events)

    # Process tree
    proc_roots = build_process_tree(events)
    proc_tree_text = html.escape(format_process_tree(proc_roots)) if proc_roots else ""
    proc_findings = detect_suspicious_trees(proc_roots)

    # Deletion correlation details
    deletion_relations = [r for r in relations if r.get("type") == "deletion_correlation"]
    deleted_files_seen = {}
    for dr in deletion_relations:
        left_ev = events[dr["left"]] if dr["left"] < len(events) else None
        if left_ev:
            fname = left_ev.path or left_ev.process or "unknown"
            deleted_files_seen[fname] = deleted_files_seen.get(fname, 0) + 1
    top_deleted = sorted(deleted_files_seen.items(), key=lambda x: -x[1])[:20]
    hourly_data = _script_json([{"hour": h, "count": c} for h, c in sorted(stats.get("hourly_distribution", {}).items())])
    anomalies_json = _script_json(anomalies)
    risk = stats.get("risk_summary", {})
    high_risk_count = risk.get("high", 0)

    # Examiner tags: an extra tab only when there are tags, so untagged reports stay byte-identical.
    tags_tab = '<div class="tab" data-panel="tags">분석자 태그</div>\n    ' if tags else ''
    tags_panel = _tags_panel(tags) + "\n  " if tags else ''
    # File preview cache: its own tab only when the analysis found such records (other reports stay byte-identical).
    thumbs = [e for e in events if e.artifact == "thumbcache"]
    thumbs_tab = '<div class="tab" data-panel="thumbcache">파일 미리 보기 흔적</div>\n    ' if thumbs else ''
    thumbs_panel = _thumbcache_panel(thumbs) + "\n  " if thumbs else ''
    wifi = [e for e in events if e.artifact == "wlan"]  # own tab only when there are profiles (else bytes unchanged)
    wifi_tab = f'<div class="tab" data-panel="wifi">{html.escape(WIFI_TEXT["tab"])}</div>\n    ' if wifi else ''
    wifi_panel = _wifi_panel(wifi) + "\n  " if wifi else ''
    tasks = [e for e in events if e.artifact in TASK_ARTIFACTS]  # own tab only when there are scheduled tasks
    usb = [e for e in events if e.artifact == "usb"]  # own tab only when there are USB records
    origins = {str(e.source): evidence_origin(e) for e in evidence} if tasks or usb else {}  # image volume paths, not the extracted copies
    tasks_tab = f'<div class="tab" data-panel="tasks">{html.escape(TASK_TEXT["report_tab"])}</div>\n    ' if tasks else ''
    tasks_panel = _tasks_panel(tasks, lambda path: origins.get(str(path), str(path))) + "\n  " if tasks else ''
    usb_tab = f'<div class="tab" data-panel="usb">{html.escape(USB_REPORT_TEXT["tab"])}</div>\n    ' if usb else ''
    usb_panel = _usb_panel(usb, lambda path: origins.get(str(path), str(path))) + "\n  " if usb else ''
    page = f'''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Hunter 분석 보고서</title>
<style>
:root {{
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d; --fg: #e6edf3; --fg2: #8b949e;
  --accent: #58a6ff; --accent2: #388bfd; --green: #3fb950; --yellow: #d29922;
  --red: #f85149; --purple: #bc8cff; --border: #30363d; --mono: 'Cascadia Code', 'Fira Code', monospace;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--fg); line-height: 1.5; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 16px; }}
header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 1px solid var(--border); padding: 24px 16px; }}
header h1 {{ font-size: 1.5rem; font-weight: 600; }}
header .meta {{ color: var(--fg2); font-size: 0.85rem; margin-top: 4px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 16px 0; }}
.stat {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.stat .label {{ font-size: 0.8rem; color: var(--fg2); text-transform: uppercase; letter-spacing: 0.5px; }}
.stat .value {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); margin-top: 4px; }}
.stat .sub {{ font-size: 0.75rem; color: var(--fg2); margin-top: 2px; }}
.stat.warn .value {{ color: var(--yellow); }}
.stat.danger .value {{ color: var(--red); }}
.stat.ok .value {{ color: var(--green); }}
.tabs {{ display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-top: 20px; overflow-x: auto; }}
.tab {{ padding: 10px 20px; cursor: pointer; border-bottom: 2px solid transparent; color: var(--fg2); font-size: 0.9rem; white-space: nowrap; }}
.tab:hover {{ color: var(--fg); }}
.tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.panel {{ display: none; }}
.panel.active {{ display: block; }}
.controls {{ display: flex; gap: 8px; padding: 12px 0; flex-wrap: wrap; align-items: center; }}
.controls input, .controls select {{ background: var(--bg3); border: 1px solid var(--border); color: var(--fg); padding: 6px 12px; border-radius: 6px; font-size: 0.85rem; }}
.controls input {{ flex: 1; min-width: 200px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
th {{ position: sticky; top: 0; background: var(--bg2); text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border); color: var(--fg2); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }}
td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
tr:hover td {{ background: var(--bg3); }}
tr.status-partial td {{ border-left: 3px solid var(--yellow); }}
tr.status-warning td {{ border-left: 3px solid var(--yellow); }}
tr.status-ok td:first-child {{ border-left: 3px solid var(--green); }}
.badge {{ display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.72rem; font-weight: 600; }}
.badge-ok {{ background: #12261e; color: var(--green); }}
.badge-partial {{ background: #2a2013; color: var(--yellow); }}
.badge-error {{ background: #2d1215; color: var(--red); }}
.badge-warning {{ background: #2a2013; color: var(--yellow); }}
.badge-info {{ background: #0d2035; color: var(--accent); }}
.detail-panel {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-top: 12px; display: none; }}
.detail-panel.open {{ display: block; }}
.detail-panel pre {{ font-family: var(--mono); font-size: 0.8rem; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--fg2); max-height: 400px; overflow-y: auto; }}
.chart {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 12px 0; }}
.chart h3 {{ font-size: 0.9rem; color: var(--fg2); margin-bottom: 12px; }}
.bar-chart {{ display: flex; flex-direction: column; gap: 4px; }}
.bar-row {{ display: flex; align-items: center; gap: 8px; }}
.bar-label {{ min-width: 120px; font-size: 0.8rem; text-align: right; color: var(--fg2); }}
.bar {{ height: 22px; border-radius: 4px; background: var(--accent2); min-width: 2px; transition: width 0.3s; }}
.bar-value {{ font-size: 0.75rem; color: var(--fg2); min-width: 40px; }}
.relation-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; margin: 6px 0; font-size: 0.82rem; }}
.relation-card .conf {{ color: var(--yellow); }}
.relation-card .path {{ color: var(--green); }}
.relation-card .temporal {{ color: var(--purple); }}
.table-scroll {{ overflow-x: auto; max-height: 600px; overflow-y: auto; }}
.count {{ background: var(--bg3); color: var(--fg2); padding: 1px 8px; border-radius: 8px; font-size: 0.75rem; margin-left: 4px; }}
footer {{ text-align: center; padding: 20px; color: var(--fg2); font-size: 0.75rem; border-top: 1px solid var(--border); margin-top: 24px; }}
</style>
</head>
<body>
<header>
  <h1>Log Hunter 분석 보고서</h1>
  <div class="meta">생성 시각: {_now()} | 시간 범위: {html.escape(time_range) if time_range else "미상"} | 증거 파일: {len(evidence)}개</div>
</header>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="label">찾은 기록</div><div class="value">{len(events):,}</div><div class="sub">{len(artifact_counts)}개 기록 종류</div></div>
    <div class="stat ok"><div class="label">정상 처리</div><div class="value">{status_counts["ok"]:,}</div><div class="sub">내용을 모두 읽은 기록</div></div>
    <div class="stat warn"><div class="label">일부 손상</div><div class="value">{status_counts["partial"]:,}</div><div class="sub">일부 정보만 읽은 기록</div></div>
    <div class="stat{"" if not error_count else " danger"}"><div class="label">오류 / 경고</div><div class="value">{error_count}</div><div class="sub">{warn_count}건 경고</div></div>
    <div class="stat"><div class="label">연관 관계</div><div class="value">{len(relations):,}</div><div class="sub">여러 기록에서 확인된 실행 {correlation_summary.get("execution_chains", 0)}건</div></div>
    <div class="stat"><div class="label">사용자 (SID)</div><div class="value">{len(sid_set)}</div><div class="sub">{html.escape(", ".join(_user_text(sid, user_names) for sid in sorted(sid_set)[:3]) + ("..." if len(sid_set) > 3 else "")) if sid_set else "알 수 없음"}</div></div>
  </div>

  <div class="tabs" id="tabs">
    <div class="tab active" data-panel="timeline">타임라인</div>
    <div class="tab" data-panel="artifacts">기록 종류별 분포</div>
    <div class="tab" data-panel="relations">연관 분석</div>
    <div class="tab" data-panel="evidence">증거 파일</div>
    <div class="tab" data-panel="errors">오류/경고</div>
    <div class="tab" data-panel="stats">통계/이상탐지</div>
    <div class="tab" data-panel="proctree">프로세스 트리</div>
    {usb_tab}{thumbs_tab}{wifi_tab}{tasks_tab}{tags_tab}<div class="tab" data-panel="raw">원시 JSON</div>
  </div>

  <div class="panel active" id="timeline">
    <div class="controls">
      <input type="text" id="search" placeholder="검색 (파일 경로, 프로그램, 웹 주소, 사용자...)">
      <select id="artifactFilter"><option value="">전체 기록 종류</option>{artifact_options}</select>
      <select id="statusFilter"><option value="">전체 상태</option>{"".join(f'<option value="{s}">{status_label(s)}</option>' for s in ("ok", "partial", "warning"))}</select>
      <input type="text" id="startDate" placeholder="시작 (YYYY-MM-DD)" style="max-width:160px">
      <input type="text" id="endDate" placeholder="종료 (YYYY-MM-DD)" style="max-width:160px">
    </div>
    <div id="filterCount" style="color:var(--fg2);font-size:0.8rem;padding:4px 0;"></div>
    <div class="table-scroll">
      <table id="eventTable">
        <thead><tr><th>시각</th><th>시각의 의미</th><th>기록 종류</th><th>무슨 일</th><th>파일/프로그램/주소</th><th>사용자</th><th>상태</th></tr></thead>
        <tbody id="eventBody"></tbody>
      </table>
    </div>
    <div class="detail-panel" id="detailPanel"><pre id="detailContent"></pre></div>
  </div>

  <div class="panel" id="artifacts">
    <div class="chart"><h3>기록 종류별 건수</h3><div class="bar-chart" id="artifactChart"></div></div>
    <div class="chart"><h3>많이 발생한 윈도우 이벤트 ID (상위 20)</h3><div class="bar-chart" id="eventIdChart"></div></div>
  </div>

  <div class="panel" id="relations">
    <div id="relationsList"></div>
    <div class="chart" style="margin-top:16px"><h3>삭제 연관 분석</h3>
      <div style="padding:8px 0;color:var(--fg2);font-size:0.85rem">삭제 연관 매칭: <strong style="color:var(--yellow)">{correlation_summary.get("deletion_matches", 0)}</strong>건</div>
      {'<div class="table-scroll"><table><thead><tr><th>삭제 파일</th><th>매칭 횟수</th></tr></thead><tbody>' + "".join(f'<tr><td>{html.escape(str(f))}</td><td>{c}</td></tr>' for f, c in top_deleted) + '</tbody></table></div>' if top_deleted else '<div style="color:var(--fg2);padding:8px">삭제 연관 매칭이 없습니다.</div>'}
    </div>
  </div>

  <div class="panel" id="evidence">
    {verification_html}
    <div class="table-scroll">
      <table><thead><tr><th>원본 위치</th><th>수집 방식</th><th>SHA-256 (무결성 확인값)</th></tr></thead>
      <tbody>{"".join(f'<tr><td>{html.escape(evidence_origin(e))}</td><td>{html.escape(method_label(e.method))}</td><td style="font-family:var(--mono);font-size:0.7rem">{html.escape(e.sha256[:16])}...</td></tr>' for e in evidence)}</tbody>
      </table>
    </div>
  </div>

  <div class="panel" id="errors">
    <div class="table-scroll">
      <table><thead><tr><th>심각도</th><th>파일</th><th>기록 종류</th><th>위치</th><th>내용</th></tr></thead>
      <tbody>{"".join(f'<tr><td><span class="badge badge-{html.escape(e.severity)}">{html.escape(status_label(e.severity))}</span></td><td>{html.escape(str(e.source)[:60])}</td><td>{html.escape(artifact_label(e.artifact))}</td><td>{html.escape(str(e.locator)[:40])}</td><td>{html.escape(str(e.message)[:200])}</td></tr>' for e in errors)}</tbody>
      </table>
    </div>
  </div>

  <div class="panel" id="stats">
    <div class="stats" style="margin-bottom:16px">
      <div class="stat"><div class="label">고유 프로세스</div><div class="value">{stats.get("unique_processes", 0)}</div></div>
      <div class="stat"><div class="label">고유 소스</div><div class="value">{stats.get("unique_sources", 0)}</div></div>
      <div class="stat{"" if not high_risk_count else " danger"}"><div class="label">고위험 이벤트</div><div class="value">{high_risk_count}</div></div>
    </div>
    <div class="chart"><h3>시간대별 이벤트 분포 (UTC)</h3><div class="bar-chart" id="hourlyChart"></div></div>
    <div class="chart"><h3>요일×시간 히트맵 (UTC)</h3><canvas id="heatmapCanvas" style="width:100%;max-width:600px;height:200px"></canvas></div>
    <div class="chart"><h3>이상 탐지 결과 ({len(anomalies)}건)</h3><div id="anomalyList"></div></div>
  </div>

  <div class="panel" id="proctree">
    <div class="chart"><h3>프로세스 트리 ({len(proc_roots)}개 루트 프로세스)</h3>
      {'<pre style="font-family:var(--mono);font-size:0.8rem;color:var(--fg);white-space:pre-wrap;overflow-wrap:anywhere;max-height:60vh;overflow-y:auto;padding:12px;background:var(--bg);border-radius:6px">' + proc_tree_text + '</pre>' if proc_tree_text else '<div style="color:var(--fg2);padding:12px">Sysmon Event ID 1 이벤트가 없어 프로세스 트리를 생성할 수 없습니다.</div>'}
    </div>
    <div class="chart"><h3>의심 프로세스 탐지 ({len(proc_findings)}건)</h3>
      {''.join(f'<div class="relation-card"><span class="badge badge-{"error" if f["severity"] == "high" else "warning"}" style="{"background:#2d1215;color:var(--red)" if f["severity"] == "high" else "background:#2a2013;color:var(--yellow)"}">{html.escape(f["severity"])}</span> <strong>[{html.escape(anomaly_label(f["type"]))}]</strong> {html.escape(f["description"])}</div>' for f in proc_findings) if proc_findings else '<div style="color:var(--fg2);padding:8px">의심 프로세스 패턴이 감지되지 않았습니다.</div>'}
    </div>
    <div class="chart"><h3>삭제 연관 요약</h3>
      <div style="padding:8px 0;color:var(--fg2);font-size:0.85rem">삭제 관계 유형 수: <strong style="color:var(--yellow)">{len(deletion_relations)}</strong>건</div>
      {'<div class="table-scroll"><table><thead><tr><th>삭제 파일 경로</th><th>매칭 횟수</th></tr></thead><tbody>' + "".join(f'<tr><td style="font-family:var(--mono);font-size:0.78rem">{html.escape(str(f))}</td><td>{c}</td></tr>' for f, c in top_deleted) + '</tbody></table></div>' if top_deleted else '<div style="color:var(--fg2);padding:8px">삭제 파일 매칭이 없습니다.</div>'}
    </div>
  </div>

  {usb_panel}{thumbs_panel}{wifi_panel}{tasks_panel}{tags_panel}<div class="panel" id="raw">
    <pre style="font-family:var(--mono);font-size:0.75rem;color:var(--fg2);white-space:pre-wrap;overflow-wrap:anywhere;max-height:80vh;overflow-y:auto">{html.escape(_payload_preview(payload, events))}</pre>
  </div>
</div>
<footer>Log Hunter v1.0.0 — Windows 포렌식 아티팩트 분석 도구</footer>

<script>
const ALL_EVENTS = {events_json};
const ALL_RELATIONS = {relations_json};
const ARTIFACT_DATA = {artifact_chart_data};
const TOP_EVENTS = {top_events_data};
const HOURLY_DATA = {hourly_data};
const ANOMALIES = {anomalies_json};
const LABELS = {labels_json};
const USER_NAMES = {_script_json(user_names)};
const lab = (kind, key) => (LABELS[kind] && LABELS[kind][key]) || String(key ?? '').replace(/_/g, ' ');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);

document.querySelectorAll('.tab').forEach(tab => {{
  tab.addEventListener('click', () => {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.panel).classList.add('active');
  }});
}});

const PAGE_SIZE = 500;
let filteredEvents = ALL_EVENTS;
let currentPage = 0;

function renderEvents() {{
  const tbody = document.getElementById('eventBody');
  const slice = filteredEvents.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  tbody.innerHTML = slice.map((e, i) => {{
    const idx = currentPage * PAGE_SIZE + i;
    const target = String(e.path || e.process || e.url || (e.details && e.details.command) || '');
    return `<tr class="status-${{esc(e.status)}}" data-idx="${{idx}}" style="cursor:pointer">` +
      `<td>${{e.timestamp ? esc(e.timestamp.slice(0,19)) : '알 수 없음'}}</td>` +
      `<td>${{e.time_field ? esc(lab('time', e.time_field)) : ''}}</td>` +
      `<td title="${{esc(e.artifact)}}">${{esc(lab('artifact', e.artifact))}}</td>` +
      `<td title="${{esc(e.action)}}">${{esc(lab('action', e.action))}}</td>` +
      `<td title="${{esc(target)}}">${{esc(target.length > 60 ? target.slice(0,60)+'...' : target)}}</td>` +
      `<td title="${{esc(e.sid || '')}}">${{esc(USER_NAMES[e.sid] ? USER_NAMES[e.sid] + ' (' + e.sid + ')' : (e.sid || ''))}}</td>` +
      `<td><span class="badge badge-${{esc(e.status)}}">${{esc(lab('status', e.status))}}</span></td></tr>`;
  }}).join('');
  document.getElementById('filterCount').textContent =
    `${{filteredEvents.length.toLocaleString()}}건 표시 (전체 ${{ALL_EVENTS.length.toLocaleString()}}건)` +
    (filteredEvents.length > PAGE_SIZE ? ` — 페이지 ${{currentPage+1}}/${{Math.ceil(filteredEvents.length/PAGE_SIZE)}}` : '');
}}

function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  const af = document.getElementById('artifactFilter').value;
  const sf = document.getElementById('statusFilter').value;
  const sd = document.getElementById('startDate').value;
  const ed = document.getElementById('endDate').value;
  filteredEvents = ALL_EVENTS.filter(e => {{
    if (af && e.artifact !== af) return false;
    if (sf && e.status !== sf) return false;
    if (sd && (!e.timestamp || e.timestamp < sd)) return false;
    if (ed && (!e.timestamp || e.timestamp > ed + 'T99')) return false;
    if (q) {{
      const text = JSON.stringify(e).toLowerCase();
      if (!text.includes(q)) return false;
    }}
    return true;
  }});
  currentPage = 0;
  renderEvents();
}}

['search','artifactFilter','statusFilter','startDate','endDate'].forEach(id => {{
  document.getElementById(id).addEventListener('input', applyFilters);
}});

document.getElementById('eventBody').addEventListener('click', e => {{
  const row = e.target.closest('tr');
  if (!row) return;
  const idx = parseInt(row.dataset.idx);
  const event = filteredEvents[idx];
  const panel = document.getElementById('detailPanel');
  const content = document.getElementById('detailContent');
  content.textContent = JSON.stringify(event, null, 2);
  panel.classList.toggle('open');
}});

function renderBarChart(container, data, colorFn) {{
  const max = Math.max(...data.map(d => d.count), 1);
  container.innerHTML = data.map(d => {{
    const pct = (d.count / max * 100).toFixed(1);
    const label = d.name != null ? String(d.name) : String(d.id);
    return `<div class="bar-row"><div class="bar-label">${{esc(label)}}</div><div class="bar" style="width:${{pct}}%;background:${{colorFn ? colorFn(d) : 'var(--accent2)'}}"></div><div class="bar-value">${{d.count.toLocaleString()}}</div></div>`;
  }}).join('');
}}

function renderRelations() {{
  const container = document.getElementById('relationsList');
  if (!ALL_RELATIONS.length) {{
    container.innerHTML = '<div style="color:var(--fg2);padding:20px">연관 관계가 없습니다.</div>';
    return;
  }}
  container.innerHTML = ALL_RELATIONS.slice(0, 200).map(r => {{
    const confClass = r.confidence === 'path_match' ? 'path' : r.temporal_proximity ? 'temporal' : 'conf';
    const head = `<span class="${{confClass}}">[${{esc(lab('relation', r.type))}} · ${{esc(lab('confidence', r.confidence))}}]</span> `;
    if (r.type === 'correlation_group') {{
      const anchors = (r.left_event_indices || []).length;
      const members = (r.event_indices || []).length;
      const window = r.window_seconds ? ` · 같은 시계 기준 ±${{esc(r.window_seconds)}}초` : '';
      return `<div class="relation-card"><span class="conf">[${{esc(lab('relation', 'correlation_group'))}}: ` +
        `${{esc(lab('relation', r.relation_type))}}]</span> ` +
        (anchors ? `기준 기록 ${{anchors.toLocaleString()}}건 · ` : '') + `포함 기록 ${{members.toLocaleString()}}건 · ` +
        `후보 ${{Number(r.candidate_count || 0).toLocaleString()}}쌍${{window}} ` +
        `<span style="color:var(--fg2)">(모든 쌍이 관계인 것은 아님)</span></div>`;
    }}
    if (r.type === 'execution_chain') {{
      return `<div class="relation-card">${{head}}<strong>${{esc(r.process)}}</strong>: ` +
        `${{esc((r.sources || []).map(s => lab('artifact', s)).join(', '))}}</div>`;
    }}
    const left = ALL_EVENTS[r.left] || {{}};
    const right = ALL_EVENTS[r.right] || {{}};
    return `<div class="relation-card">` + head +
      `<strong>${{esc(lab('artifact', left.artifact) || '?')}}</strong>: ${{esc(left.path || left.process || '?')}}` +
      ` ↔ <strong>${{esc(lab('artifact', right.artifact) || '?')}}</strong>: ${{esc(right.path || right.process || '?')}}` +
      (r.delta_seconds != null ? ` <span style="color:var(--fg2)">(${{esc(r.delta_seconds)}}초 차이)</span>` : '') +
      `</div>`;
  }}).join('');
  if (ALL_RELATIONS.length > 200) {{
    container.innerHTML += `<div style="color:var(--fg2);padding:10px">... 외 ${{ALL_RELATIONS.length - 200}}건</div>`;
  }}
}}

renderEvents();
renderBarChart(document.getElementById('artifactChart'), ARTIFACT_DATA);
renderBarChart(document.getElementById('eventIdChart'), TOP_EVENTS, d => {{
  const id = d.id;
  if ([4624,4625,4634,4648,4672].includes(id)) return 'var(--yellow)';
  if ([4688,4689,7045,7034].includes(id)) return 'var(--red)';
  if ([1102,4616].includes(id)) return 'var(--purple)';
  return 'var(--accent2)';
}});
renderRelations();

// Hourly chart
renderBarChart(document.getElementById('hourlyChart'),
  HOURLY_DATA.map(d => ({{name: d.hour+'시', count: d.count}})),
  d => {{ const h = parseInt(d.name); return (h >= 0 && h < 5) ? 'var(--red)' : 'var(--accent2)'; }});

// Heatmap day×hour
(function() {{
  const canvas = document.getElementById('heatmapCanvas');
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 600, h = canvas.clientHeight || 200;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const days = ['월','화','수','목','금','토','일'];
  const grid = Array.from({{length:7}}, () => new Array(24).fill(0));
  ALL_EVENTS.forEach(e => {{
    if (!e.timestamp || e.timestamp.length < 13) return;
    try {{
      const d = new Date(e.timestamp);
      const dow = (d.getUTCDay() + 6) % 7;  // UTC, same as the hourly chart
      grid[dow][d.getUTCHours()]++;
    }} catch(ex) {{}}
  }});
  const maxVal = Math.max(...grid.flat(), 1);
  const lx = 30, ty = 15, cw = (w - lx - 5) / 24, ch = (h - ty - 5) / 7;
  ctx.font = '9px sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  for (let hr = 0; hr < 24; hr++) ctx.fillText(hr+'', lx + hr*cw + cw/2, 2);
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let d = 0; d < 7; d++) ctx.fillText(days[d], lx - 3, ty + d*ch + ch/2);
  for (let d = 0; d < 7; d++) for (let hr = 0; hr < 24; hr++) {{
    const v = grid[d][hr] / maxVal;
    const r = hr < 5 ? Math.round(255 - v*150) : Math.round(255 - v*200);
    const g = Math.round(255 - v*255);
    const b = hr < 5 ? Math.round(255 - v*255) : Math.round(255 - v*200);
    ctx.fillStyle = `rgb(${{r}},${{g}},${{b}})`;
    ctx.fillRect(lx + hr*cw, ty + d*ch, cw-1, ch-1);
  }}
}})();

// Anomaly list
const anomalyList = document.getElementById('anomalyList');
if (ANOMALIES.length === 0) {{
  anomalyList.innerHTML = '<div style="color:var(--fg2);padding:8px">이상 패턴이 감지되지 않았습니다.</div>';
}} else {{
  anomalyList.innerHTML = ANOMALIES.map(a => {{
    const cls = a.severity === 'high' ? 'danger' : a.severity === 'warning' ? 'badge-warning' : 'badge-info';
    return `<div class="relation-card"><span class="badge badge-${{esc(a.severity)}}">${{esc(lab('status', a.severity))}}</span> <strong>[${{esc(lab('anomaly', a.type))}}]</strong> ${{esc(a.description)}}</div>`;
  }}).join('');
}}

// Keyboard pagination
document.addEventListener('keydown', e => {{
  if (e.key === 'ArrowRight' && (currentPage + 1) * PAGE_SIZE < filteredEvents.length) {{ currentPage++; renderEvents(); }}
  if (e.key === 'ArrowLeft' && currentPage > 0) {{ currentPage--; renderEvents(); }}
}});
</script>
</body>
</html>'''
    before, after = page.split("const ALL_EVENTS = __LOG_HUNTER_EVENTS_STREAM__;", 1)
    with path.open("w", encoding="utf-8") as stream:
        stream.write(before + "const ALL_EVENTS = [")
        for index, event in enumerate(events):
            if index:
                stream.write(", ")
            stream.write(_script_json(event.to_dict()))
        stream.write("];" + after)


def _tag_target(row):
    ref = row.get("ref") or {}
    if row.get("target") == "file":
        return f"[{ref.get('image_name', '')}] 볼륨 {ref.get('volume')} {ref.get('image_path', '')}", "이미지 안 파일"
    when = f"{ref.get('timestamp') or '시각 없음'} ({time_field_label(ref.get('time_field'))})"
    return f"{when} · {ref.get('path') or ''}", artifact_label(ref.get("artifact"))


def _tags_panel(tags):
    """분석자 태그 tab: what the examiner marked and wrote (not evidence data), escaped."""
    rows = []
    for row in tags:
        target, kind = _tag_target(row)
        names = ", ".join(row.get("tag_labels") or [tag_label(t) for t in row.get("tags", ())])
        rows.append(f'<tr><td>{html.escape(names)}</td><td>{html.escape(kind)}</td><td>{html.escape(target)}</td>'
                    f'<td style="white-space:pre-wrap">{html.escape(row.get("note") or "")}</td>'
                    f'<td>{html.escape(row.get("updated_at") or "")}</td></tr>')
    return ('<div class="panel" id="tags"><div style="color:var(--fg2);padding:8px 0">분석자가 직접 붙인 태그와 메모입니다. '
            '증거에서 나온 내용이 아닙니다.</div><div class="table-scroll"><table><thead><tr><th>태그</th><th>대상 종류</th>'
            '<th>대상</th><th>메모</th><th>수정 시각 (UTC)</th></tr></thead><tbody>' + "".join(rows) +
            '</tbody></table></div></div>')


THUMBCACHE_REPORT_LIMIT = 2000


def _thumbcache_panel(events):
    """파일 미리 보기 흔적 tab: the same columns as the result table, escaped; the images are not included."""
    keys = thumbcache_view.COLUMNS
    shown = events[:THUMBCACHE_REPORT_LIMIT]
    rows = ["<tr>" + "".join(f"<td>{html.escape(thumbcache_view.cell(key, event))}</td>" for key in keys) +
            f"<td>{html.escape(str(event.source or ''))}</td><td>{html.escape(status_label(event.status))}</td></tr>"
            for event in shown]
    more = (f" 표시 상한 {THUMBCACHE_REPORT_LIMIT:,}건 — 전체 {len(events):,}건은 report.json·timeline.csv에 있습니다."
            if len(events) > len(shown) else "")
    head = "".join(f"<th>{html.escape(column_label(key))}</th>" for key in keys) + "<th>출처 파일</th><th>상태</th>"
    return ('<div class="panel" id="thumbcache"><div style="color:var(--fg2);padding:8px 0">'
            + html.escape(ARTIFACT_DESCRIPTIONS["thumbcache"]) + ". 캐시 안의 그림은 해독하거나 보고서에 넣지 않습니다."
            + html.escape(more) + '</div><div class="table-scroll"><table><thead><tr>' + head + "</tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div></div>")


def _tasks_panel(events, origin=None):
    """예약 작업 tab: the basic columns as a table, and per task a collapsible detail (escaped, nothing linked or run)."""
    from log_hunter.ui import task_view
    keys = task_view.COLUMNS
    shown = events[:THUMBCACHE_REPORT_LIMIT]
    rows = ["<tr>" + "".join(f"<td>{html.escape(task_view.cell(key, e))}</td>" for key in keys) + "</tr>" for e in shown]
    details = []
    for e in shown:
        compare = "".join(f"<tr><td>{html.escape(f)}</td><td>{html.escape(a)}</td><td>{html.escape(b)}</td><td>{html.escape(v)}</td></tr>"
                          for f, a, b, v in task_view.compare_rows(e))
        body = html.escape("\n".join(task_view.detail_lines(e, origin)))
        table = (f'<table><thead><tr>' + "".join(f"<th>{html.escape(TASK_TEXT['compare_columns'][k])}</th>"
                                                 for k in ("field", "registry", "xml", "verdict"))
                 + f'</tr></thead><tbody>{compare}</tbody></table>') if compare else ""
        details.append(f'<details><summary>{html.escape(task_view.cell("task_name", e))}</summary>'
                       f'<pre style="white-space:pre-wrap">{body}</pre>{table}</details>')
    head = "".join(f"<th>{html.escape(column_label(key))}</th>" for key in keys)
    return ('<div class="panel" id="tasks"><div style="color:var(--fg2);padding:8px 0">' + html.escape(TASK_TEXT["report_note"])
            + '</div><div class="table-scroll"><table><thead><tr>' + head + "</tr></thead><tbody>" + "".join(rows)
            + "</tbody></table></div><h3>" + html.escape(TASK_TEXT["report_detail"]) + "</h3>" + "".join(details) + "</div>")


def _wifi_panel(events):
    """Wi-Fi 프로필 tab: the result table's Wi-Fi columns, escaped (keys are text, never links)."""
    keys = wifi_view.COLUMNS
    rows = ["<tr><td>" + html.escape(str((event.details or {}).get("profile_name") or "")) + "</td>"
            + "".join(f"<td>{html.escape(wifi_view.cell(key, event))}</td>" for key in keys)
            + f"<td>{html.escape(str(event.source or ''))}</td></tr>" for event in events[:THUMBCACHE_REPORT_LIMIT]]
    head = ("<th>" + html.escape(WIFI_TEXT["fields"]["profile_name"]) + "</th>"
            + "".join(f"<th>{html.escape(column_label(key))}</th>" for key in keys) + "<th>출처 파일</th>")
    return ('<div class="panel" id="wifi"><div style="color:var(--fg2);padding:8px 0">' + html.escape(WIFI_TEXT["note"])
            + '</div><div class="table-scroll"><table><thead><tr>' + head + "</tr></thead><tbody>" + "".join(rows)
            + "</tbody></table></div></div>")


class _Origins:
    """The result table asks origins.text(path); the report maps extracted copies back to image paths."""
    def __init__(self, origin):
        self.text = origin


def _usb_section(event):
    """0 physical device candidates, 1 system devices, 2 auxiliary entries (same split as the tree)."""
    return {None: 0, "system": 1, "auxiliary": 2}[usb_hidden(event.details or {})]


def _usb_panel(events, origin=None):
    """USB·외부 장치 tab: the result table's USB columns (escaped), grouped like the tree; hidden entries are not counted as devices."""
    from log_hunter.ui.columns import CATEGORY_COLUMNS, cell
    keys = [c.key for c in CATEGORY_COLUMNS["usb_devices"] if c.key != "description"]
    origins = _Origins(origin or str)
    kinds = list(USB_DEVICE_KINDS)
    group_kind = {}  # a group sorts by its representative's kind so its records stay together
    for e in events:
        d = e.details or {}
        if d.get("physical_device_id") and (d.get("physical_device_representative")
                                            or d["physical_device_id"] not in group_kind):
            group_kind[d["physical_device_id"]] = d.get("device_kind") or "unknown"

    def order(e):
        d = e.details or {}
        kind = group_kind.get(d.get("physical_device_id")) or d.get("device_kind") or "unknown"
        return (_usb_section(e), kind == "unknown", kinds.index(kind) if kind in kinds else len(kinds),
                str(d.get("physical_device_id") or "~"), not d.get("physical_device_representative"), e.timestamp or "")
    ordered = sorted(events, key=order)
    sections = [_usb_section(e) for e in ordered]
    visible = [e for e, s in zip(ordered, sections) if s == 0]
    devices = {(e.details or {}).get("physical_device_id") for e in visible}
    devices = len(devices - {None, ""}) + sum(1 for e in visible if not (e.details or {}).get("physical_device_id"))
    summary = USB_REPORT_TEXT["summary"].format(devices=devices, records=len(visible),
                                                system=sections.count(1), auxiliary=sections.count(2))
    shown = ordered[:THUMBCACHE_REPORT_LIMIT]
    names = (USB_REPORT_TEXT["candidate"], USB_REPORT_TEXT["system"], USB_REPORT_TEXT["auxiliary"])
    rows = ["<tr><td>" + html.escape(names[s]) + "</td>" + "".join(f"<td>{html.escape(cell(key, e, {}, origins))}</td>"
                                                                   for key in keys) + "</tr>"
            for e, s in zip(shown, sections)]
    more = (USB_REPORT_TEXT["limit"].format(limit=THUMBCACHE_REPORT_LIMIT, total=len(events))
            if len(events) > len(shown) else "")
    head = (f"<th>{html.escape(USB_REPORT_TEXT['section'])}</th>"
            + "".join(f"<th>{html.escape(column_label(key))}</th>" for key in keys))
    return ('<div class="panel" id="usb"><div style="color:var(--fg2);padding:8px 0">' + html.escape(summary)
            + "<br>" + html.escape(USB_REPORT_TEXT["note"] + more) + '</div><div class="table-scroll"><table><thead><tr>'
            + head + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></div>")


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
