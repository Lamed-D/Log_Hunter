import queue
import shutil
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, simpledialog
from log_hunter.core.pipeline import Pipeline, PARSERS, PERMISSION_HINT, apply_image_metadata
from log_hunter.core.tree import OriginIndex, TreeNode, build_tree, event_properties, source_name
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.sid_resolver import display_name, is_service_sid, resolve_sids
from log_hunter.core import tags as tag_book
from log_hunter.core.labels import (ARTIFACT_DESCRIPTIONS, COLUMN_LAYOUT_HINT, COLUMN_LAYOUT_RESET, TAGGED_IMAGE_CHANGED, TAGGED_IMAGE_CHANGED_NOTE, TAG_COLOR_WORDS, TAG_MENU, TASK_TEXT, SNAPSHOT_TEXT, DIAGNOSTIC_TEXT, anomaly_label,
                                    artifact_from_label, artifact_label, status_label)
from log_hunter.image import (extract_artifacts, is_admin, is_live_path, live_device,
                              relaunch_as_admin, system_drive)
from . import charts, content, detail, fs_model, nav, nav_tools, view_model
from .file_list import FileListView
from . import relation_view, recycle_view
from log_hunter.core.labels import CASE_TEXT, NAV_TEXT, RECYCLE_TEXT, SID_TEXT
from . import record_fields
from .properties import PropertiesDialog
from .folder_nav import FolderHistory, crumbs, folder_key, parent_key
from . import columns as table_columns
from .auto_analysis import AutoAnalysis, Superseded
from .jobs import JobRunner
from .settings import Settings
from .style import ARTIFACT_COLORS, TAG_ROW_COLORS
from .view_model import ALL_LABEL, Filters
IMAGE_FILETYPES = [("디스크 이미지", "*.E01 *.e01 *.dd *.raw *.img *.001 *.vhd"), ("모든 파일", "*.*")]



def run(live=None):
    root = tk.Tk()
    root.title("Log Hunter - Windows Forensic Analyzer")
    # Roomy by default: most of the screen (at least the old 1400x850 where it fits), centred.
    screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
    win_w = min(max(1400, int(screen_w * 0.92)), screen_w - 40)
    win_h = min(max(850, int(screen_h * 0.88)), screen_h - 80)
    root.geometry(f"{win_w}x{win_h}+{max((screen_w - win_w) // 2, 0)}+{max((screen_h - win_h) // 3, 0)}")
    prefs = Settings()  # column order/widths, in the user's settings folder (not the case or the repository)
    root.minsize(900, 600)
    inputs, mailbox = [], queue.Queue()
    analysis_state = {"busy": False, "extracting": False}
    loaded_case = {"result": None, "info": None, "path": None}  # an opened saved analysis: new inputs are added to it
    unsaved = {"tags": False}  # tags/notes changed since the analysis was opened or saved
    runner = JobRunner(mailbox)
    background_threads = []
    closing = False
    session = content.ContentSession()  # which file/page the viewer shows (stale results dropped)
    browsers = {}  # image path -> ImageBrowser; created and used only on the worker thread
    opened_images = {}  # image path -> {"name", "volumes"}: shown in the tree before analysis finishes
    folder_cache = {}  # (image, volume, parts) -> listing rows, so a rebuilt tree can reopen folders at once
    scans = {}  # (image, volume) -> MFT scan result for 파일 보기
    scan_state = {"stop": None, "pending": None}
    result = None
    sid_map = {}
    # The examiner's tags/notes; kept across re-analysis (keys are record contents). Colour names and
    # subcategory lists are the examiner's own settings, so they come back next time.
    book = tag_book.TagBook(**prefs.tag_preferences())
    extractions, temp_dirs = [], []
    style = ttk.Style()
    style.configure("Status.TLabel", font=("Segoe UI", 9))
    style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"))
    style.configure("Stats.TLabel", font=("Segoe UI", 9))

    # --- Top controls ---
    top = ttk.Frame(root, padding=(10, 8))
    top.pack(fill="x")
    ttk.Label(top, text="Log Hunter", style="Title.TLabel").pack(side="left")
    image_button = ttk.Button(top, text="디스크 이미지 열기 (E01)", command=lambda: open_image_file())
    image_button.pack(side="left", padx=(15, 3))
    live_button = ttk.Button(top, text="이 PC 직접 분석 (관리자)", command=lambda: analyze_this_pc())
    live_button.pack(side="left", padx=3)
    include_mft = tk.BooleanVar(value=False)
    verify_image = tk.BooleanVar(value=False)
    verify_state = {"stop": None}
    ttk.Checkbutton(top, text="파일 생성·수정 기록 포함(느림)", variable=include_mft).pack(side="left", padx=3)
    ttk.Checkbutton(top, text="이미지 저장 해시 검증(느림)", variable=verify_image).pack(side="left", padx=3)
    verify_cancel = ttk.Button(top, text="검증 취소", state="disabled",
                               command=lambda: verify_state["stop"] and verify_state["stop"].set())
    verify_cancel.pack(side="left", padx=3)
    ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=8)
    ttk.Label(top, text="파일 직접 추가:").pack(side="left", padx=(0, 3))
    artifact = tk.StringVar(value=artifact_label("prefetch"))
    artifact_box = ttk.Combobox(top, textvariable=artifact, values=[artifact_label(k) for k in PARSERS], state="readonly", width=24)
    artifact_box.pack(side="left", padx=3)
    ttk.Button(top, text="파일 추가", command=lambda: add_files()).pack(side="left", padx=3)
    ttk.Button(top, text="폴더 추가", command=lambda: add_folder()).pack(side="left", padx=3)

    actions = ttk.Frame(root, padding=(10, 0, 10, 4))
    actions.pack(fill="x")
    # No "start" button: every change to the inputs starts the analysis by itself (see request_analysis).
    ttk.Button(actions, text=CASE_TEXT["open_button"], command=lambda: open_case_dialog()).pack(side="left", padx=(0, 3))
    ttk.Button(actions, text=CASE_TEXT["save_button"], command=lambda: save_case_dialog()).pack(side="left", padx=3)
    ttk.Button(actions, text=CASE_TEXT["new_button"], command=lambda: new_analysis()).pack(side="left", padx=3)
    relink_button = ttk.Button(actions, text=CASE_TEXT["relink_button"], state="disabled", command=lambda: relink_original())
    relink_button.pack(side="left", padx=3)
    ttk.Button(actions, text="보고서 저장", command=lambda: export()).pack(side="left", padx=3)
    ttk.Button(actions, text=TAG_MENU["load"], command=lambda: load_tags()).pack(side="left", padx=3)
    ttk.Label(actions, text="타임라인 내보내기:").pack(side="left", padx=(12, 3))
    ttk.Button(actions, text="CSV", command=lambda: export_timeline("csv")).pack(side="left", padx=3)
    ttk.Button(actions, text="JSON", command=lambda: export_timeline("json")).pack(side="left", padx=3)
    ttk.Button(actions, text="Bodyfile", command=lambda: export_timeline("bodyfile")).pack(side="left", padx=3)
    sid_var = tk.StringVar()
    sid_entry = ttk.Entry(actions, textvariable=sid_var, width=24)
    sid_entry.pack(side="right")
    ttk.Label(actions, text=SID_TEXT["filter"]).pack(side="right", padx=(10, 2))
    artifact_hint = tk.StringVar()
    ttk.Label(root, textvariable=artifact_hint, style="Status.TLabel", foreground="#555").pack(fill="x", padx=12)

    def _show_hint(*_args):
        key = artifact_from_label(artifact.get())
        artifact_hint.set(ARTIFACT_DESCRIPTIONS.get(key, ""))

    artifact.trace_add("write", _show_hint)
    _show_hint()

    # --- File listing ---
    listing_frame = ttk.LabelFrame(root, text="분석 대상 파일", padding=5)
    listing_frame.pack(fill="x", padx=10, pady=(0, 3))
    listing = tk.Listbox(listing_frame, height=3, selectmode="extended")
    listing.pack(fill="x", side="left", expand=True)
    list_scroll = ttk.Scrollbar(listing_frame, orient="vertical", command=listing.yview)
    list_scroll.pack(side="right", fill="y")
    listing.configure(yscrollcommand=list_scroll.set)

    def remove_selected():
        sel = listing.curselection()
        for i in reversed(sel):
            listing.delete(i)
            inputs.pop(i)
        if sel:
            request_analysis()

    btn_frame = ttk.Frame(listing_frame)
    btn_frame.pack(side="right", padx=5)
    ttk.Button(btn_frame, text="제거", width=6, command=remove_selected).pack()

    # --- Filter bar ---
    filter_bar = ttk.Frame(root, padding=(10, 3))
    filter_bar.pack(fill="x")
    query = tk.StringVar()
    filter_artifact = tk.StringVar(value="all")
    ttk.Label(filter_bar, text="검색:").pack(side="left")
    ttk.Entry(filter_bar, textvariable=query, width=25).pack(side="left", padx=(3, 10))
    filter_artifact.set(ALL_LABEL)
    ttk.Label(filter_bar, text="기록 종류:").pack(side="left")
    ttk.Combobox(filter_bar, textvariable=filter_artifact, values=[ALL_LABEL, *[artifact_label(k) for k in PARSERS]],
                 state="readonly", width=24).pack(side="left", padx=3)

    # Date range filter
    ttk.Label(filter_bar, text="시작:").pack(side="left", padx=(10, 2))
    start_date = tk.StringVar()
    start_entry = ttk.Entry(filter_bar, textvariable=start_date, width=20)
    start_entry.pack(side="left")
    start_entry.insert(0, "")
    ttk.Label(filter_bar, text="종료:").pack(side="left", padx=(5, 2))
    end_date = tk.StringVar()
    end_entry = ttk.Entry(filter_bar, textvariable=end_date, width=20)
    end_entry.pack(side="left")

    # Status filter
    status_filter = tk.StringVar(value=ALL_LABEL)
    ttk.Label(filter_bar, text="상태:").pack(side="left", padx=(10, 2))
    ttk.Combobox(filter_bar, textvariable=status_filter, values=[ALL_LABEL, *[status_label(s) for s in ("ok", "partial", "warning", "error")]],
                 state="readonly", width=10).pack(side="left")

    # --- Stats bar ---
    stats_frame = ttk.Frame(root, padding=(10, 2))
    stats_frame.pack(fill="x")
    stats_var = tk.StringVar(value="분석 대기 중")
    ttk.Label(stats_frame, textvariable=stats_var, style="Stats.TLabel").pack(side="left")
    count_var = tk.StringVar()
    ttk.Label(stats_frame, textvariable=count_var, style="Stats.TLabel").pack(side="right")

    view_var = tk.StringVar(value="보기: 전체")
    ttk.Label(stats_frame, textvariable=view_var, style="Stats.TLabel", foreground="#1a5fb4").pack(side="right", padx=12)

    # --- Body: navigation tree | result tabs ---
    body = ttk.PanedWindow(root, orient="horizontal")
    body.pack(fill="both", expand=True, padx=10, pady=3)
    nav_frame = ttk.Frame(body)
    nav_tools_bar = ttk.Frame(nav_frame)
    nav_tools_bar.pack(side="top", fill="x")
    nav_back = ttk.Button(nav_tools_bar, text=NAV_TEXT["back"], width=3)
    nav_back.pack(side="left")
    nav_forward = ttk.Button(nav_tools_bar, text=NAV_TEXT["forward"], width=3)
    nav_forward.pack(side="left")
    nav_find_var = tk.StringVar()
    nav_find = ttk.Entry(nav_tools_bar, textvariable=nav_find_var)
    nav_find.pack(side="left", fill="x", expand=True, padx=(4, 0))
    nav_path_var = tk.StringVar(value=NAV_TEXT["find_hint"])
    ttk.Label(nav_frame, textvariable=nav_path_var, foreground="#555555", wraplength=260).pack(side="top", fill="x")
    nav_tree = ttk.Treeview(nav_frame, show="tree", selectmode="browse")
    nav_tree.column("#0", width=250, stretch=True)
    nav_tree.tag_configure("service_account", foreground="#777777")  # built-in/service accounts, not people
    nav_scroll = ttk.Scrollbar(nav_frame, orient="vertical", command=nav_tree.yview)
    nav_tree.configure(yscrollcommand=nav_scroll.set)
    nav_scroll.pack(side="right", fill="y")
    nav_tree.pack(fill="both", expand=True)
    nav_tree.insert("", "end", text="분석을 실행하면 여기에 트리가 나타납니다")
    body.add(nav_frame, weight=1)
    right = ttk.PanedWindow(body, orient="vertical")
    body.add(right, weight=4)
    tabs = ttk.Notebook(right)
    right.add(tabs, weight=3)

    # Tab 1: Timeline
    event_frame = ttk.Frame(tabs)
    tabs.add(event_frame, text="타임라인")
    files_state = {"node": None, "view": None}
    files = FileListView(tabs, lambda row: on_file_select(row), lambda row: on_file_open_folder(row),
                         lambda row: on_file_save(row), lambda row: on_file_copy_path(row), lambda: on_show_records(),
                         lambda delta: on_file_turn(delta), lambda: on_scan_cancel(), lambda where: on_folder_nav(where))
    folder_history = FolderHistory()  # visiting the folder back/forward just moved to is a no-op, so history stays intact

    # Global search bar inside timeline tab
    search_bar_frame = ttk.Frame(event_frame)
    search_bar_frame.pack(fill="x", padx=2, pady=(2, 0))
    ttk.Label(search_bar_frame, text="타임라인 검색:").pack(side="left")
    global_search_var = tk.StringVar()
    ttk.Entry(search_bar_frame, textvariable=global_search_var, width=30).pack(side="left", padx=(3, 5))
    ttk.Button(search_bar_frame, text="초기화", command=lambda: global_search_var.set("")).pack(side="left")
    ttk.Button(search_bar_frame, text="표를 CSV로 저장", command=lambda: save_table_csv()).pack(side="right")
    recycle_button = ttk.Button(search_bar_frame, text=RECYCLE_TEXT["save"], state="disabled",
                                command=lambda: save_recycle_original(_selected_event()))
    recycle_button.pack(side="right", padx=4)
    from .tooltip import Tooltip
    Tooltip(recycle_button, lambda: CASE_TEXT["recycle_unavailable"] if _case_without_copies() else "")
    ttk.Button(search_bar_frame, text="◀ 이전", width=8, command=lambda: turn_timeline_page(-1)).pack(side="left", padx=(12, 0))
    ttk.Button(search_bar_frame, text="다음 ▶", width=8, command=lambda: turn_timeline_page(1)).pack(side="left", padx=3)
    timeline_page_var = tk.StringVar(value="")
    ttk.Label(search_bar_frame, textvariable=timeline_page_var, style="Status.TLabel").pack(side="left", padx=6)
    ttk.Label(search_bar_frame, text=COLUMN_LAYOUT_HINT, style="Status.TLabel", foreground="#666").pack(side="right", padx=8)
    timeline_page = {"page": 0, "matched": []}

    tree = ttk.Treeview(event_frame, columns=(), show="headings", selectmode="browse")
    table_state = {"columns": None}

    def _apply_columns(cols):
        """Switch the result table to `cols` (general timeline or one category's set)."""
        if table_state["columns"] == cols:
            return
        table_state["columns"] = cols
        sort_reverse.clear()
        order, widths = prefs.columns(table_columns.set_name(cols))
        table_columns.configure_tree(tree, cols, order, widths, lambda k: sort_column(k))

    def _shown_columns():
        """The current columns in the order the examiner arranged them on screen."""
        shown = tree.cget("displaycolumns")
        order = [] if shown in ("#all", ("#all",)) else list(shown)
        return table_columns.ordered(table_state["columns"], order)

    def _save_column_layout():
        cols = table_state["columns"]
        if not cols:
            return
        widths = {c.key: int(tree.column(c.key, "width")) for c in cols}
        prefs.set_columns(table_columns.set_name(cols), [c.key for c in _shown_columns()], widths)
        prefs.save()

    drag = {"key": None, "resize": False}

    def _heading_key(x):
        index = tree.identify_column(x)  # "#n" counts displayed columns
        shown = [c.key for c in _shown_columns()]
        try:
            return shown[int(index.lstrip("#")) - 1]
        except (ValueError, IndexError):
            return None

    def on_heading_press(event):
        region = tree.identify_region(event.x, event.y)
        drag["resize"] = region == "separator"
        drag["key"] = _heading_key(event.x) if region == "heading" else None

    def on_heading_release(event):
        if drag["resize"]:
            drag["resize"] = False
            _save_column_layout()
            return
        key, drag["key"] = drag["key"], None
        if not key or tree.identify_region(event.x, event.y) != "heading":
            return
        target = _heading_key(event.x)
        if target and target != key:  # dropped on another heading: move the column there (a plain click still sorts)
            tree.configure(displaycolumns=table_columns.moved([c.key for c in _shown_columns()], key, target))
            _save_column_layout()

    def reset_column_layout():
        cols = table_state["columns"]
        if not cols:
            return
        prefs.reset_columns(table_columns.set_name(cols))
        prefs.save()
        table_state["columns"] = None
        _apply_columns(cols)
        _populate_tree(keep_page=True)
    for art_name, color in ARTIFACT_COLORS.items():
        tree.tag_configure(art_name, foreground=color)
    tree.tag_configure("task_signal", foreground="#b35900")  # 예약 작업 with a signal (a lead, not a finding)
    for color, background in TAG_ROW_COLORS.items():  # rows the examiner tagged, by their most urgent colour
        tree.tag_configure(f"tag_{color}", background=background)
    tree_scroll_y = ttk.Scrollbar(event_frame, orient="vertical", command=tree.yview)
    tree_scroll_x = ttk.Scrollbar(event_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
    tree_scroll_y.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)
    tree_scroll_x.pack(fill="x")

    detail_tabs = ttk.Notebook(right)  # shared by the timeline and the file list
    right.add(detail_tabs, weight=1)
    props_frame = ttk.Frame(detail_tabs)
    detail_tabs.add(props_frame, text="기록 정보")
    props = ttk.Treeview(props_frame, columns=("value",), show="tree headings", height=8)
    props.heading("#0", text="항목")
    props.heading("value", text="값")
    props.column("#0", width=220, stretch=False)
    props.column("value", width=700)
    props_scroll = ttk.Scrollbar(props_frame, orient="vertical", command=props.yview)
    props.configure(yscrollcommand=props_scroll.set)
    props_scroll.pack(side="right", fill="y")
    props.pack(fill="both", expand=True)
    viewer = detail.ContentViewer(detail_tabs, lambda delta: change_page(delta))
    # 예약 작업 extra information: task file / registry details, and both sources side by side.
    task_frame = ttk.Frame(detail_tabs)
    detail_tabs.add(task_frame, text=TASK_TEXT["detail_tab"])
    task_text = tk.Text(task_frame, height=8, wrap="word", font=("Segoe UI", 9))
    task_text.pack(fill="both", expand=True)
    compare_frame = ttk.Frame(detail_tabs)
    detail_tabs.add(compare_frame, text=TASK_TEXT["compare_tab"])
    compare_keys = ("field", "registry", "xml", "verdict")
    task_compare = ttk.Treeview(compare_frame, columns=compare_keys, show="headings", height=8)
    for key, width in zip(compare_keys, (200, 360, 360, 120)):
        task_compare.heading(key, text=TASK_TEXT["compare_columns"][key])
        task_compare.column(key, width=width)
    task_compare.tag_configure("different", foreground="#b03030")
    task_compare.pack(fill="both", expand=True)

    def show_task_tabs(event):
        from . import task_view
        task_text.configure(state="normal")
        task_text.delete("1.0", "end")
        task_compare.delete(*task_compare.get_children())
        if not task_view.is_task(event):
            task_text.insert("1.0", TASK_TEXT["pick"])
        else:
            origins = nav_state.get("origins")
            task_text.insert("1.0", "\n".join(task_view.detail_lines(event, origins.text if origins else None)))
            rows = task_view.compare_rows(event)
            for row in rows:
                task_compare.insert("", "end", values=row, tags=("different",) if row[3] != TASK_TEXT["same"] else ())
            if not rows:
                task_compare.insert("", "end", values=(TASK_TEXT["no_compare"], "", "", ""))
        task_text.configure(state="disabled")

    show_task_tabs(None)
    json_frame = ttk.Frame(detail_tabs)
    detail_tabs.add(json_frame, text="원본 JSON")
    json_text = tk.Text(json_frame, height=8, wrap="word", font=("Consolas", 9))
    json_text.pack(fill="both", expand=True)
    detail.configure_json_tags(json_text)

    # Tab 2: Diagnostics
    diag_frame = ttk.Frame(tabs)
    tabs.add(diag_frame, text="처리 결과/오류")
    diag_tree = ttk.Treeview(diag_frame, columns=("source", "artifact", "state", "events", "errors", "warnings", "elapsed",
                                                  "cause"), show="headings")
    diag_headers = {"source": "파일", "artifact": "기록 종류", "state": "결과", "events": "찾은 기록",
                    "errors": "오류", "warnings": "경고", "elapsed": "소요 시간", "cause": DIAGNOSTIC_TEXT["cause_column"]}
    for col, w in [("source", 300), ("artifact", 170), ("state", 80), ("events", 70), ("errors", 60), ("warnings", 70),
                   ("elapsed", 80), ("cause", 460)]:
        diag_tree.heading(col, text=diag_headers[col])
        diag_tree.column(col, width=w)
    diag_tree.pack(fill="both", expand=True)
    error_text = tk.Text(diag_frame, height=6, wrap="word", font=("Consolas", 9))
    error_text.pack(fill="x")

    # Tab 3: Relations
    rel_frame = ttk.Frame(tabs)
    tabs.add(rel_frame, text="연관 분석")
    rel_panes = ttk.PanedWindow(rel_frame, orient="vertical")
    rel_panes.pack(fill="both", expand=True)
    rel_top = ttk.Frame(rel_panes)
    rel_tree = ttk.Treeview(rel_top, columns=("type", "confidence", "left", "right", "basis"), show="headings")
    rel_headers = {"type": "연관 유형", "confidence": "신뢰도", "left": "기록 A", "right": "기록 B", "basis": "근거"}
    for col, w in [("type", 220), ("confidence", 110), ("left", 300), ("right", 300), ("basis", 160)]:
        rel_tree.heading(col, text=rel_headers[col])
        rel_tree.column(col, width=w)
    rel_tree.pack(fill="both", expand=True)
    rel_state = {"shown": [], "members": []}
    ttk.Label(rel_top, text="행을 고르면 아래에 판단 근거, 두 번 누르면 그 관계에 들어 있는 기록만 타임라인에 보여 줍니다.",
              style="Status.TLabel").pack(fill="x")
    rel_panes.add(rel_top, weight=3)
    # Why the selected relation exists: rule, compared values, time difference, group size, and its records.
    rel_bottom = ttk.Frame(rel_panes)
    rel_panes.add(rel_bottom, weight=2)
    RL = relation_view.L
    rel_text = tk.Text(rel_bottom, height=9, wrap="word", font=("Segoe UI", 9))
    rel_text.pack(fill="x", padx=2, pady=(2, 0))
    rel_buttons = ttk.Frame(rel_bottom)
    rel_buttons.pack(fill="x", pady=2)
    ttk.Label(rel_buttons, text=RL["members"], style="Status.TLabel").pack(side="left")
    ttk.Button(rel_buttons, text=RL["show_all"], command=lambda: show_relation_records()).pack(side="right")
    ttk.Button(rel_buttons, text=RL["go_b"], command=lambda: jump_to_member("B")).pack(side="right", padx=3)
    ttk.Button(rel_buttons, text=RL["go_a"], command=lambda: jump_to_member("A")).pack(side="right")
    member_keys = ("role", "artifact", "source", "timestamp", "time_field", "target")
    rel_members = ttk.Treeview(rel_bottom, columns=member_keys, show="headings", height=6)
    for col, w in zip(member_keys, (50, 160, 320, 200, 130, 320)):
        rel_members.heading(col, text=RL["member_columns"][col])
        rel_members.column(col, width=w)
    rel_members.pack(fill="both", expand=True)

    def _show_relation_text(lines):
        rel_text.configure(state="normal")
        rel_text.delete("1.0", "end")
        rel_text.insert("1.0", "\n".join(lines))
        rel_text.configure(state="disabled")  # still selectable and copyable

    _show_relation_text([RL["pick"]])

    # Tab 4: Evidence
    ev_frame = ttk.Frame(tabs)
    tabs.add(ev_frame, text="증거 파일")
    ev_tree = ttk.Treeview(ev_frame, columns=("source", "sha256", "method", "collected_at"), show="headings")
    ev_headers = {"source": "원본 위치", "sha256": "SHA-256 (무결성 확인값)", "method": "수집 방식", "collected_at": "수집 시각"}
    for col, w in [("source", 450), ("sha256", 200), ("method", 100), ("collected_at", 150)]:
        ev_tree.heading(col, text=ev_headers[col])
        ev_tree.column(col, width=w)
    ev_tree.pack(fill="both", expand=True)
    verification_var = tk.StringVar(value="")
    ttk.Label(ev_frame, textvariable=verification_var, justify="left", style="Status.TLabel").pack(fill="x", padx=4, pady=4)

    # Tab 5: Statistics / Visualization
    stat_frame = ttk.Frame(tabs)
    tabs.add(stat_frame, text="통계/시각화")
    stat_plot = ttk.Frame(stat_frame)
    stat_plot.pack(fill="both", expand=True)
    stat_canvas = tk.Canvas(stat_plot, bg="white", highlightthickness=0)
    stat_y = ttk.Scrollbar(stat_plot, orient="vertical", command=stat_canvas.yview)
    stat_x = ttk.Scrollbar(stat_plot, orient="horizontal", command=stat_canvas.xview)
    stat_canvas.configure(yscrollcommand=stat_y.set, xscrollcommand=stat_x.set)
    stat_plot.rowconfigure(0, weight=1)
    stat_plot.columnconfigure(0, weight=1)
    stat_canvas.grid(row=0, column=0, sticky="nsew")
    stat_y.grid(row=0, column=1, sticky="ns")
    stat_x.grid(row=1, column=0, sticky="ew")
    stat_dashboard = charts.Dashboard(stat_canvas)
    stat_text = tk.Text(stat_frame, height=4, wrap="word", font=("Consolas", 9))
    stat_text.pack(fill="x", padx=2, pady=2)

    # --- Progress ---
    progress = ttk.Progressbar(root, mode="determinate")
    progress.pack(fill="x", padx=10, pady=2)
    status = tk.StringVar(value="디스크 이미지(E01)를 열거나 분석할 파일을 추가하세요")
    ttk.Label(root, textvariable=status, style="Status.TLabel").pack(fill="x", padx=10, pady=(0, 5))

    visible = []
    sort_reverse = {}
    _apply_columns(table_columns.DEFAULT)
    nav_nodes = {}
    nav_state = {"node": None, "origins": OriginIndex()}

    def _populate_nav():
        """(Re)build the left tree. Before analysis it holds only the opened images; afterwards
        the full tree. Expanded folders and the selected node are kept across rebuilds."""
        open_keys = {nav_nodes[i].key for i in nav_nodes if nav_tree.exists(i) and nav_tree.item(i, "open")}
        selected = nav_tree.selection()
        selected_key = nav_nodes[selected[0]].key if selected and selected[0] in nav_nodes else None
        nav_tree.delete(*nav_tree.get_children())
        nav_nodes.clear()
        nav_state["node"] = None
        view_var.set("보기: 전체")
        if not result and not opened_images:
            return
        nav_state["origins"] = OriginIndex([*extractions, *loaded_case.get("origins", ())])
        for extraction in extractions:  # images analyzed without the instant "open" step still get their file system
            if extraction.volumes:
                opened_images.setdefault(extraction.image_path, {"name": source_name(extraction),
                                                                 "volumes": extraction.volumes})
        if result:
            roots = build_tree(result.events, result.relations, result.errors, sid_map, nav_state["origins"],
                               [e.source for e in result.evidence])
            nav_state["counts"] = fs_model.prefix_counts(result.events, nav_state["origins"])
        else:
            roots = [TreeNode("src", "데이터 출처", "source")]
            nav_state["counts"] = {}
        for image, info in opened_images.items():
            image_node = next((n for n in roots[0].children if n.label == info["name"]), None)
            if image_node is None:
                image_node = TreeNode("src:" + info["name"], info["name"], "source", (info["name"], ()))
                roots[0].children.insert(0, image_node)
            # Whole file system of the image, read folder by folder when expanded.
            image_node.children = fs_model.volume_nodes(info["name"], image, info["volumes"], nav_state["counts"])
            image_node.children += fs_model.snapshot_nodes(info["name"], image, info.get("snapshots"))
        if result or book.items:
            roots.append(tag_book.tag_tree(book, result.events if result else ()))
        views = [(info["name"], image, v["index"]) for image, info in opened_images.items()
                 for v in info["volumes"] if v.get("browsable", v.get("filesystem") == "ntfs")]
        if views:
            roots.insert(1, fs_model.file_view_root(views))
        nav_nodes.update(nav.fill_nav(nav_tree, roots))
        _restore_tree(open_keys, selected_key)

    def _restore_tree(open_keys, selected_key):
        changed = True
        while changed:
            changed = False
            for iid, node in list(nav_nodes.items()):
                if node.key not in open_keys or not nav_tree.exists(iid):
                    continue
                if fs_model.needs_loading(node):
                    rows = folder_cache.get((node.fs["image"], node.fs["volume"], node.fs["parts"]))
                    if rows is None:
                        continue
                    _show_folder(iid, rows, None)
                    changed = True
                if not nav_tree.item(iid, "open"):
                    nav_tree.item(iid, open=True)
        for iid, node in nav_nodes.items():
            if node.key == selected_key and nav_tree.exists(iid):
                nav_tree.selection_set(iid)
                nav_tree.see(iid)
                break

    def _browser(image):
        if image not in browsers:
            from log_hunter.image.browse import ImageBrowser
            browsers[image] = ImageBrowser(image)
        return browsers[image]

    def on_nav_open(_event):
        iid = nav_tree.focus()
        node = nav_nodes.get(iid)
        if fs_model.needs_loading(node):
            fs = node.fs
            runner.submit(f"fs:{iid}", lambda: _list_folder(fs))

    def _list_folder(fs):
        """Worker thread: a folder listing, cached for tree rebuilds and the file list."""
        key = (fs["image"], fs["volume"], fs["parts"])
        if key not in folder_cache:
            folder_cache[key] = _browser(fs["image"]).list_dir(fs["volume"], fs["parts"])
        return folder_cache[key]

    def _show_folder(iid, rows, error):
        node = nav_nodes.get(iid)
        if node is None or not nav_tree.exists(iid):
            return
        nav_tree.delete(*nav_tree.get_children(iid))
        if error:
            nav_tree.insert(iid, "end", text=f"폴더를 읽지 못했습니다: {error}")
            return
        node.children = fs_model.entry_nodes(node, rows, nav_state.get("counts", {}))
        if not node.children:
            nav_tree.insert(iid, "end", text="(빈 폴더)")
        nav_nodes.update(nav.fill_nav(nav_tree, node.children, iid, 2))

    def on_nav_select(_event):
        selection = nav_tree.selection()
        action = nav.node_action(nav_nodes.get(selection[0]) if selection else None)
        if action is None:
            return
        kind, value = action
        if kind == "relations":
            tabs.select(rel_frame)
            _populate_relations(value)
        elif kind == "errors":
            tabs.select(diag_frame)
            _populate_diagnostics(value)
        elif kind == "snapshot":
            tabs.select(files.frame)
            files.message(SNAPSHOT_TEXT["message"])
            detail_tabs.select(viewer.info_frame)
            viewer.show_info(fs_model.snapshot_info(value))
        elif kind == "fileview":
            _show_file_view(value)
        elif kind == "tagged_files":
            _show_tagged_files()
        else:
            nav_state["node"] = value
            view_var.set(f"보기: {value.label}")
            refresh()
            fs = value.fs
            if fs and not fs.get("directory"):
                tabs.select(event_frame)
                detail_tabs.select(viewer.info_frame)
                open_content(lambda: _browser(fs["image"]).open_file(fs["volume"], fs["parts"]))
            elif fs and fs.get("browsable", True):
                tabs.select(files.frame)
                _show_file_list(value)
            elif value.kind == "source" and not opened_images:
                files.message("디스크 이미지나 이 PC를 열면 파일 탐색을 할 수 있습니다")
                tabs.select(event_frame)
            else:
                tabs.select(event_frame)

    def _where(fs):
        return f"[{opened_images.get(fs['image'], {}).get('name', fs['image'])}] 볼륨 {fs['volume']}\\" + "\\".join(fs["parts"])

    def _show_file_list(node):
        fs = node.fs
        files.busy("폴더를 읽는 중...")
        files_state["node"], files_state["tagged"] = node, False
        key = folder_key(fs)
        folder_history.visit(key)
        _update_path_bar(key)
        runner.submit("files", lambda: (node, _list_folder(fs)))

    def _update_path_bar(key=None):
        if key is None:
            files.set_path(None)
            return
        name = opened_images.get(key[0], {}).get("name", key[0])
        files.set_path(crumbs(key, f"[{name}]"), folder_history.can_back(), folder_history.can_forward(),
                       parent_key(key) is not None)

    def _nav_item_for(key):
        for iid, node in nav_nodes.items():
            if node.fs and node.fs.get("directory") and folder_key(node.fs) == key and nav_tree.exists(iid):
                return iid
        return None

    def go_folder(key):
        """Show folder `key` in the file list; the tree follows, filling in folders already read on the way down."""
        image, volume, parts = key
        for depth in range(len(parts)):  # ancestors listed before (a rebuilt tree drops their children) get them back
            ancestor = (image, volume, tuple(parts[:depth]))
            above = _nav_item_for(ancestor)
            if above is not None and fs_model.needs_loading(nav_nodes[above]) and ancestor in folder_cache:
                _show_folder(above, folder_cache[ancestor], None)
        iid = _nav_item_for(key)
        tabs.select(files.frame)
        if iid is not None:
            parent = nav_tree.parent(iid)
            if parent:
                nav_tree.item(parent, open=True)
            nav_tree.see(iid)
            if nav_tree.selection() == (iid,):
                _show_file_list(nav_nodes[iid])  # selecting the selected item fires no event
            else:
                nav_tree.selection_set(iid)  # on_nav_select lists it
            return
        # not in the tree (beyond its per-folder limit, or a parent not read yet): list it without a tree item
        source = opened_images.get(image, {}).get("name", image)
        node = TreeNode(f"fs:{source}:{volume}/" + "/".join(parts), parts[-1] if parts else f"볼륨 {volume}", "source",
                        (source, (f"볼륨 {volume}", *parts)), fs={"image": image, "volume": volume, "parts": parts,
                                                                  "directory": True})
        nav_state["node"] = node
        _show_file_list(node)

    def on_folder_nav(where):
        current = files_state.get("node")
        if where == "up":
            key = parent_key(folder_key(current.fs)) if current is not None and current.fs else None
        elif where in ("back", "forward"):
            key = folder_history.back() if where == "back" else folder_history.forward()
        else:
            key = where
        if key is not None:
            go_folder(key)

    def _describe_page():
        """Ask the worker for times/state of the rows on the current page that lack them."""
        node = files_state.get("node")
        rows = [r for r in files.model.page_slice() if "in_use" not in r and "error" not in r and r.get("record")]
        if node is not None and node.fs and rows:
            fs = node.fs
            runner.submit("describe", lambda: _browser(fs["image"]).describe(fs["volume"], rows))

    def _show_file_view(view):
        key = (view["image"], view["volume"])
        files_state["node"], files_state["tagged"] = None, False
        files_state["view"] = view
        _update_path_bar()
        tabs.select(files.frame)
        if key in scans:
            _render_file_view(view)
            return
        if scan_state["pending"] == key:
            return
        import threading as _threading
        scan_state["stop"], scan_state["pending"] = _threading.Event(), key
        stop = scan_state["stop"]
        files.message("파일 시스템 전체를 훑는 중입니다(백그라운드). 다른 작업을 계속할 수 있습니다.")
        files.busy("MFT 읽는 중...", cancellable=True)

        def job():
            result_ = _browser(view["image"]).scan_mft(
                view["volume"], fs_model.classify, limit=fs_model.VIEW_LIMIT, cancelled=stop.is_set,
                progress=lambda done, total: mailbox.put(("scan_progress", (done, total))))
            return key, result_

        runner.submit("scan", job)

    def _render_file_view(view):
        scan = scans[(view["image"], view["volume"])]
        bucket = scan["categories"].get(view["category"], {"count": 0, "items": []})
        rows = [{**item, "kind": fs_model.kind_of(item["name"]),
                 "parts": tuple(p for p in item["path"].split("\\") if p)} for item in bucket["items"]]
        note = ""
        if bucket["count"] > len(rows):
            note = f"전체 {bucket['count']:,}개 중 {len(rows):,}개만 표시"
        if scan["cancelled"]:
            note = (note + " · " if note else "") + "중간에 취소되어 일부만 찾았습니다"
        files.show(rows, f"[{opened_images.get(view['image'], {}).get('name', '')}] 볼륨 {view['volume']} · "
                         f"{fs_model.file_view_label_for(view['category'])}", note)
        files.busy(files.model.status() + (f" · {note}" if note else ""))

    def _file_row_source(row):
        node, view = files_state.get("node"), files_state.get("view")
        if "image" in row:  # a row of 태그한 파일: it carries its own image and volume
            fs = {"image": row["image"], "volume": row["volume"]}
            if row.get("record") is None:
                return fs, (lambda: _browser(fs["image"]).open_file(fs["volume"], row["parts"]))
            return fs, (lambda: _browser(fs["image"]).open_record(fs["volume"], row["record"], row["parts"]))
        fs = node.fs if node is not None else {"image": view["image"], "volume": view["volume"]}
        if row.get("in_use") is False or node is None:
            return fs, (lambda: _browser(fs["image"]).open_record(fs["volume"], row["record"], row["parts"]))
        return fs, (lambda: _browser(fs["image"]).open_file(fs["volume"], row["parts"]))

    def on_file_select(row):
        if row.get("directory"):
            return
        _fs, make = _file_row_source(row)
        detail_tabs.select(viewer.info_frame)
        open_content(make)

    def on_file_open_folder(row):
        fs, _make = _file_row_source(row)
        go_folder((fs["image"], fs["volume"], tuple(row["parts"])))

    def on_file_save(row):
        folder = filedialog.askdirectory(title="꺼낸 파일을 저장할 폴더 (원본 이미지는 바뀌지 않습니다)")
        if not folder:
            return
        _fs, make = _file_row_source(row)
        files.busy("파일로 저장하는 중...")

        def job():
            source = make()
            return content.save_copy(source, folder, row["name"], source.info())

        runner.submit("save", job)

    def on_file_copy_path(row):
        root.clipboard_clear()
        root.clipboard_append("\\" + "\\".join(row["parts"]))
        files.busy("이미지 안 경로를 복사했습니다")

    def on_file_turn(delta):
        files.turn(delta)
        _describe_page()

    def on_scan_cancel():
        if scan_state["stop"] is not None:
            scan_state["stop"].set()

    def on_show_records():
        tabs.select(event_frame)

    def _show_properties(event):
        props.delete(*props.get_children())
        username = display_name(event.sid, sid_map)
        detail.fill_properties(props, event_properties(event, nav_state["origins"].text(event.source), username))

    def _populate_tree(*_args, keep_page=False):
        """Fill one page of the table; `visible` (all filtered records) never goes into Tk at once."""
        tree.delete(*tree.get_children())
        search_text = global_search_var.get().strip().lower()
        matched = [i for i, event in enumerate(visible) if view_model.matches_search(event, search_text, sid_map)]
        timeline_page["matched"] = matched
        page, pages, start, end = view_model.page_bounds(len(matched), timeline_page["page"] if keep_page else 0)
        timeline_page["page"] = page
        for i in matched[start:end]:
            event = visible[i]
            values = table_columns.row(event, table_state["columns"], sid_map, nav_state["origins"])
            row_tags = (event.artifact,) if event.artifact in ARTIFACT_COLORS else ()
            if table_columns.task_view.is_task(event) and table_columns.task_view.signals(event):
                row_tags += ("task_signal",)
            color = book.top_color(tag_book.event_key(event))
            if color:
                row_tags += (f"tag_{color}",)
            tree.insert("", "end", iid=str(i), values=values, tags=row_tags)
        timeline_page_var.set(view_model.page_text(page, pages, start, end, len(matched)))
        if result:
            count_var.set(view_model.count_text(len(matched), len(visible), len(result.events), bool(search_text)))

    def turn_timeline_page(delta):
        timeline_page["page"] += delta
        _populate_tree(keep_page=True)

    def sort_column(col):
        """Sort all filtered records (not just the shown page) by the column's shown text."""
        rev = sort_reverse.get(col, False)
        sort_reverse[col] = not rev
        visible.sort(key=lambda event: table_columns.cell(col, event, sid_map, nav_state["origins"]), reverse=rev)
        _populate_tree()
        for column, header in zip(table_state["columns"], table_columns.headers(table_state["columns"])):
            indicator = (" ▲" if not rev else " ▼") if column.key == col else ""
            tree.heading(column.key, text=header + indicator)

    def save_table_csv():
        # Every filtered (and searched) row in the shown order and columns, not only the current page.
        shown = _shown_columns()
        rows = [table_columns.row(visible[i], shown, sid_map, nav_state["origins"])
                for i in timeline_page["matched"]]
        if not rows:
            messagebox.showwarning("저장할 기록 없음", "표에 보이는 기록이 없습니다. 필터를 바꾼 뒤 다시 저장하세요")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            try:
                count = table_columns.save_csv(path, shown, rows)
                messagebox.showinfo("저장 완료", f"필터에 맞는 {count:,}개 행(모든 페이지)을 {path}에 저장했습니다")
            except OSError as exc:
                messagebox.showerror("저장 오류", str(exc))

    def refresh(*_args):
        tree.delete(*tree.get_children())
        visible.clear()
        if not result:
            return
        filters = Filters(filter_artifact.get(), start_date.get(), end_date.get(), sid_var.get(), query.get(),
                          status_filter.get())
        visible.extend(view_model.filter_events(result.events, filters, nav_state["node"], nav_state["origins"], sid_map))
        _apply_columns(table_columns.columns_for(nav_state["node"]))
        _populate_tree()
        _update_stats()

    def _update_stats():
        if result:
            stats_var.set(view_model.summary_text(result))

    def _populate_diagnostics(severity=None):
        diag_tree.delete(*diag_tree.get_children())
        error_text.delete("1.0", "end")
        if not result:
            return
        for row in view_model.diagnostic_rows(result.summaries, result.errors):
            diag_tree.insert("", "end", values=row)
        for line in view_model.error_lines(result.errors, severity):
            error_text.insert("end", line)

    def _populate_relations(kind=None):
        rel_tree.delete(*rel_tree.get_children())
        rel_state["shown"] = [r for r in result.relations if not kind or r.get("type") == kind] if result else []
        if not result:
            return
        for row in view_model.relation_rows(result.relations, result.events, kind):
            rel_tree.insert("", "end", values=row)

    def _populate_evidence():
        ev_tree.delete(*ev_tree.get_children())
        if not result:
            return
        for row in view_model.evidence_rows(result.evidence):
            ev_tree.insert("", "end", values=row)
        verification_var.set("\n".join(view_model.verification_lines((result.image or {}).get("verification"))))

    def _populate_stats():
        stat_canvas.delete("all")
        stat_text.delete("1.0", "end")
        if not result:
            stat_dashboard.set_events([])
            return
        stat_dashboard.set_events(result.events)
        lines = view_model.stats_lines(result)
        stat_text.insert("end", " | ".join(lines))
        try:
            from log_hunter.core.stats import detect_anomalies
            anomalies = detect_anomalies(result.events)
            if anomalies:
                stat_text.insert("end", f"\n\n이상 탐지 ({len(anomalies)}건):\n")
                for a in anomalies[:20]:
                    sev_icon = {"high": "[!]", "warning": "[?]", "info": "[-]"}.get(a["severity"], "[-]")
                    stat_text.insert("end", f"  {sev_icon} [{anomaly_label(a['type'])}] {a['description']}\n")
        except Exception:
            pass

    def _add_input(art, path, owner=None, reason=""):
        inputs.append((art, path, owner))
        listing.insert("end", view_model.input_line(art, path, reason))

    def add_files():
        paths = filedialog.askopenfilenames()
        if paths:
            _detect(list(paths), picked_files=True)

    def add_folder():
        folder = filedialog.askdirectory()
        if folder:
            _detect([folder], picked_files=False)

    def _detect(paths, picked_files):
        """Recognize what each file is (worker thread); results come back as the "detect" job."""
        status.set("파일 종류를 알아보는 중...")
        runner.submit("detect", lambda: (picked_files, view_model.plan_detected(detect_inputs(paths))))

    def _apply_detection(picked_files, plan):
        before = len(inputs)
        for art, path, owner, reason in plan.inputs:
            _add_input(art, path, owner, reason)
        if plan.unknown and picked_files:
            chosen = artifact.get()
            if messagebox.askyesno("기록 종류를 알 수 없는 파일",
                                   f"기록 종류를 알아내지 못한 파일이 {len(plan.unknown)}개 있습니다.\n\n"
                                   f"'파일 직접 추가'에서 고른 종류 '{chosen}'(으)로 추가할까요?"):
                for path in plan.unknown:
                    _add_input(artifact_from_label(chosen), path, None, "사용자가 고른 종류")
        status.set(f"분석 대상 {len(inputs)}개")
        if len(inputs) > before:
            request_analysis()
        messagebox.showinfo("파일 자동 인식", view_model.detect_summary(plan))
        if plan.images and messagebox.askyesno(
                "디스크 이미지", f"디스크 이미지 {Path(plan.images[0]).name}을(를) 열어 분석할까요?"
                + (f"\n(한 번에 하나만 엽니다. 나머지 {len(plan.images) - 1}개는 따로 여세요.)" if len(plan.images) > 1 else "")):
            start_image_extraction(plan.images[0])

    def open_image_file():
        path = filedialog.askopenfilename(title="디스크 이미지 선택 (E01 / dd)", filetypes=IMAGE_FILETYPES)
        if path:
            start_image_extraction(path)

    def analyze_this_pc(drive=None):
        drive = drive or system_drive()
        if not is_admin():
            if not messagebox.askyesno(
                    "관리자 권한 필요",
                    "레지스트리, 이벤트 로그 같은 기록은 Windows가 사용 중이라 잠겨 있습니다.\n"
                    "관리자 권한이 있으면 드라이브에서 직접 읽어 잠금을 우회할 수 있습니다.\n\n"
                    "관리자 권한으로 Log Hunter를 다시 열까요? (Windows 확인 창이 뜹니다)"):
                return
            if relaunch_as_admin(["-m", "log_hunter", "gui", "--live", drive]):
                on_close()
            else:
                messagebox.showerror("관리자 권한", "관리자 권한으로 실행하지 못했습니다 (확인 창에서 '아니요'를 눌렀거나 권한이 없습니다).")
            return
        device = live_device(drive)
        if device is None:
            messagebox.showerror("이 PC 직접 분석", f"드라이브 이름이 올바르지 않습니다: {drive}")
            return
        start_image_extraction(device)

    def _source_name(path):
        return f"이 PC({live_device(path)[4:]})" if is_live_path(path) else "디스크 이미지"

    def start_image_extraction(path):
        analysis_state["extracting"] = True
        workdir = Path(tempfile.mkdtemp(prefix="log-hunter-image-"))
        temp_dirs.append(workdir)
        image_button.configure(state="disabled")
        live_button.configure(state="disabled")
        progress.configure(mode="indeterminate")
        progress.start(15)
        status.set(f"{_source_name(path)}에서 분석할 파일을 찾는 중... {path}")
        with_mft = include_mft.get()  # read Tk variables on the UI thread only
        verify = verify_image.get() and not is_live_path(path)  # a running drive has no stored hash to compare
        stop = threading.Event()
        verify_state["stop"] = stop
        verify_cancel.configure(state="normal" if verify else "disabled")
        # Show the image in the tree right away; extraction and analysis keep running in the background.
        runner.submit("open", lambda: (path, fs_model.image_source_name(path),
                                       _browser(path).volume_info()))

        def worker():
            try:
                extraction = extract_artifacts(path, workdir, include_mft=with_mft, verify=verify,
                                               verification_progress=lambda done, total: mailbox.put(("verify_progress", (done, total))),
                                               verification_cancel=stop.is_set,
                                               progress=lambda count, item: mailbox.put(("extract_progress", (count, item))))
                mailbox.put(("extracted", extraction))
            except Exception as exc:
                mailbox.put(("extract_error", str(exc)))

        thread = threading.Thread(target=worker, daemon=True)
        background_threads.append(thread)
        thread.start()

    def _finish_extraction(extraction):
        analysis_state["extracting"] = False
        verify_cancel.configure(state="disabled")
        if extraction.verification:
            status.set(view_model.verification_lines(extraction.verification)[0])
        progress.stop()
        progress.configure(mode="determinate")
        image_button.configure(state="normal")
        live_button.configure(state="normal")
        extractions.append(extraction)
        for art, path, owner in extraction.inputs:
            _add_input(art, path, owner)
        found = sorted({artifact_label(a) for a, _p, _o in extraction.inputs})
        name = _source_name(extraction.image_path)
        if not extraction.inputs:
            messagebox.showwarning(name, f"{name}에서 분석할 Windows 기록을 찾지 못했습니다.\n\n" + "\n".join(extraction.warnings[:10]))
            return
        notes = ("\n\n주의:\n" + "\n".join(extraction.warnings[:5])) if extraction.warnings else ""
        status.set(f"{name}에서 {len(extraction.files)}개 파일을 꺼냈습니다. 분석을 시작합니다...")
        messagebox.showinfo(name,
                            f"{len(extraction.files)}개 파일을 {name}에서 꺼냈습니다.\n찾은 기록 종류: {', '.join(found)}{notes}")
        auto.run_now()

    def _resolve_sids(batch):
        for art, path, _owner in batch:
            if art in ("network", "amcache") or str(path).lower().endswith("software"):
                try:
                    mapping = resolve_sids(path)
                    if mapping:
                        return mapping
                except Exception:
                    continue
        return {}

    def request_analysis():
        """Inputs changed: analyze again shortly (a burst of changes becomes one run; a running one is replaced)."""
        nonlocal result, sid_map
        if inputs:
            auto.schedule()
            status.set(f"분석 대상 {len(inputs)}개 - 곧 분석을 시작합니다...")
            return
        auto.stop()
        analysis_state["busy"] = False
        if loaded_case["result"] is not None:  # all added inputs removed: back to the opened saved analysis as it was
            result = loaded_case["result"]
            sid_map = dict(getattr(result, "sid_names", None) or {})
            progress["value"] = 0
            _show_result()
            status.set(loaded_case.get("status") or "")
            return
        result, sid_map = None, {}
        progress["value"] = 0
        _show_result()
        status.set("분석 대상이 없습니다. 디스크 이미지를 열거나 파일·폴더를 추가하세요")

    def analyze(generation):
        if not inputs:
            return
        analysis_state["busy"] = True
        batch = list(inputs)
        # The SID box only filters what is shown. It must not become the records' owner SID:
        # that would attribute every input without its own SID to whoever was typed there.
        used = {str(Path(p).resolve()).casefold() for _a, p, _o in batch}
        report = auto.guard(generation, lambda done, total, path: mailbox.put(("progress", (generation, done, total, path))))
        base = loaded_case["result"]

        def worker():
            try:
                mapping = _resolve_sids(batch)
                analysis = Pipeline().analyze(batch, progress=report)
                for extraction in extractions:
                    if used & set(extraction.file_index()):
                        apply_image_metadata(analysis, extraction)
                if base is not None:  # an opened saved analysis: add the new results to it (tags and notes stay)
                    from log_hunter.database.case_db import merge_results
                    analysis = merge_results(base, analysis)
                    mapping = {**(getattr(base, "sid_names", None) or {}), **mapping}
                mailbox.put(("result", (generation, analysis, mapping)))
            except Superseded:
                return  # a newer run took over; its result is the one shown
            except Exception as exc:
                mailbox.put(("error", (generation, str(exc))))

        thread = threading.Thread(target=worker, daemon=True)
        background_threads.append(thread)
        thread.start()
        progress["value"] = 0
        status.set(f"분석 중... (대상 {len(batch)}개)")

    auto = AutoAnalysis(root.after, root.after_cancel, analyze)

    def _show_result():
        _populate_nav()
        refresh()
        _populate_diagnostics()
        _populate_relations()
        _populate_evidence()
        _populate_stats()

    def poll():
        if closing:
            return
        nonlocal result, sid_map
        try:
            while True:
                kind, value = mailbox.get_nowait()
                if kind == "job":
                    on_job(*value)
                elif kind == "verify_progress":
                    done, total = value
                    status.set(f"이미지 저장 해시 검증 중... {done * 100 // max(total, 1)}% ({done:,} / {total:,}바이트)")
                elif kind == "scan_progress":
                    done, total = value
                    files.busy(f"MFT 읽는 중... {done:,} / {total:,}", cancellable=True)
                elif kind == "progress":
                    generation, done, total, path = value
                    if not auto.is_current(generation):
                        continue
                    progress["value"] = done / max(total, 1) * 100
                    status.set(f"분석 중 {done * 100 // max(total, 1)}% [{done}/{total}] {path}")
                elif kind == "extract_progress":
                    count, item = value
                    status.set(f"이미지에서 꺼내는 중 ({count}개): {item}")
                elif kind == "extracted":
                    _finish_extraction(value)
                elif kind == "extract_error":
                    analysis_state["extracting"] = False
                    progress.stop()
                    progress.configure(mode="determinate")
                    image_button.configure(state="normal")
                    live_button.configure(state="normal")
                    status.set("기록 읽기 실패")
                    messagebox.showerror("기록 읽기 실패", value)
                elif kind == "result":
                    generation, analysis, mapping = value
                    if not auto.is_current(generation):
                        continue  # an older run finished after the inputs changed again
                    analysis_state["busy"] = False
                    result, sid_map = analysis, mapping
                    progress["value"] = 100
                    status.set(f"분석 완료: 기록 {len(result.events)}건, 오류/경고 {len(result.errors)}건")
                    _show_result()
                    if any(e.message == PERMISSION_HINT for e in result.errors) and messagebox.askyesno(
                            "파일 접근 권한",
                            "일부 파일이 Windows에 의해 잠겨 있어 읽지 못했습니다.\n\n"
                            "'이 PC 직접 분석'으로 잠긴 파일까지 읽어서 다시 분석할까요? (관리자 권한 필요)"):
                        analyze_this_pc()
                elif kind == "error":
                    generation, message = value
                    if not auto.is_current(generation):
                        continue
                    analysis_state["busy"] = False
                    status.set("분석 오류")
                    messagebox.showerror("분석 오류", message)
        except queue.Empty:
            pass
        root.after(100, poll)

    def select(_event):
        if tree.selection():
            idx = int(tree.selection()[0])
            if idx < len(visible):
                _show_properties(visible[idx])
                detail.show_json(json_text, visible[idx])
                show_task_tabs(visible[idx])
                event = visible[idx]
                if loaded_case["result"] is not None and not Path(event.source).is_file():
                    how = CASE_TEXT["content_how_linked"] if loaded_case.get("linked_image") else CASE_TEXT["content_how_relink"]
                    viewer.clear(CASE_TEXT["content_unavailable"].format(how=how))  # no copy: say why, read nothing
                    return
                extra = content.record_file_extra(event.source, result.evidence if result else (), extractions)
                open_content(lambda: content.LocalFile(event.source), extra)

    def open_content(make_source, extra=None):
        """Show a file in the 파일 정보 / 16진수 / 텍스트 tabs; reading happens on the worker thread."""
        viewer.clear("읽는 중...")
        runner.submit("content", session.open(make_source, extra))

    def change_page(delta):
        job = session.turn(delta)
        if job is not None:
            runner.submit("page", job)

    def on_job(tag, token, value, error):
        if token != runner.latest(tag):
            return  # an older request the user already moved past
        if tag == "analysis_save":
            dialog = saving["dialog"]
            saving["dialog"] = None
            if dialog:
                dialog.grab_release()
                dialog.destroy()
            if error:
                messagebox.showerror("저장 결과", error)
            else:
                report, analysis, rows, original_info = value
                _remember_case(report.folder / "case.sqlite", report.case.name, len(analysis.events))
                if result is analysis and book.rows() == rows and loaded_case["info"] is original_info:
                    unsaved["tags"] = False
                messagebox.showinfo("저장 완료", str(report.folder))
            return
        if tag == "case_relink":
            if error:
                status.set(loaded_case.get("status") or "")
                messagebox.showerror(CASE_TEXT["relink_button"], str(error))
            else:
                _finish_relink(*value)
            return
        if tag == "case_open":
            progress.stop()
            progress.configure(mode="determinate")
            if error:
                status.set(CASE_TEXT["load_error"].format(error=error))
                messagebox.showerror(CASE_TEXT["open_title"], CASE_TEXT["load_error"].format(error=error))
            else:
                _show_loaded_case(*value)
            return
        if tag == "recycle_save":
            if error:
                status.set(RECYCLE_TEXT["failed"].format(error=error))
                messagebox.showerror(RECYCLE_TEXT["title"], RECYCLE_TEXT["failed"].format(error=error))
            else:
                saved, original = value
                status.set(RECYCLE_TEXT["saved"].splitlines()[0].format(target=saved.get("destination", "")))
                messagebox.showinfo(RECYCLE_TEXT["title"], RECYCLE_TEXT["saved"].format(
                    target=saved.get("destination", ""), original=saved.get("original_path") or original or "",
                    sha256=saved.get("sha256", ""), record=saved.get("record", "")))
            return
        if tag == "exe_check":
            if exe_dialog["open"]:
                dialog, label = exe_dialog["open"]
                dialog.set_value(label, record_fields.L["exe_error"] if error else value)
            return
        if tag == "detect":
            if error:
                status.set("파일 종류를 알아보지 못했습니다")
                messagebox.showerror("파일 자동 인식", error)
            else:
                _apply_detection(*value)
        elif tag.startswith("fs:"):
            _show_folder(tag[3:], value, error)
        elif tag == "open":
            if error:
                status.set(f"이미지를 열지 못했습니다: {error}")
            else:
                image, name, volumes = value
                opened_images[image] = {"name": name, "volumes": volumes}
                _populate_nav()
                if not is_live_path(image):  # existing shadow copies: listed from the image on the worker thread
                    from log_hunter.image.vss import list_snapshots
                    runner.submit("vss", lambda: (image, list_snapshots(image)))
        elif tag == "vss":
            if error:
                # the worker lost the image name with the error: mark every offline image still waiting
                for image, info in opened_images.items():
                    if "snapshots" not in info and not is_live_path(image):
                        info["snapshots"] = {"error": error}
            else:
                image, catalogs = value
                if image in opened_images:
                    opened_images[image]["snapshots"] = catalogs
            _populate_nav()
        elif tag == "files":
            if error:
                files.message(f"폴더를 읽지 못했습니다: {error}")
                return
            node, rows = value
            for iid, shown in list(nav_nodes.items()):  # give the tree the folder's children too, so rows can be opened
                if shown is node and fs_model.needs_loading(node) and nav_tree.exists(iid):
                    _show_folder(iid, rows, None)
                    break
            if files_state.get("node") is node:
                files.show(fs_model.folder_rows(node, rows, nav_state.get("counts", {})), _where(node.fs))
                _describe_page()
        elif tag == "describe" and not error:
            files.update_rows(value)
        elif tag == "scan":
            scan_state["pending"] = None
            files.busy("")
            if error:
                files.message(f"파일 시스템을 훑지 못했습니다: {error}")
                return
            key, scan = value
            scans[key] = scan
            view = files_state.get("view")
            if view and (view["image"], view["volume"]) == key:
                _render_file_view(view)
        elif tag == "save":
            if error:
                messagebox.showerror("파일로 저장", error)
                files.busy("저장하지 못했습니다")
            else:
                target, sha256 = value
                files.busy(f"저장함: {target} · SHA-256 {sha256}")
                messagebox.showinfo("파일로 저장", f"{target}\n\nSHA-256: {sha256}\n\n같은 폴더의 .log-hunter.json에 원래 위치를 기록했습니다.")
        elif tag == "content" and not error:
            accepted = session.accept_content(value)
            if accepted is None:
                return  # result for a file the user has already left
            kind, view = accepted
            if kind == "error":
                viewer.clear(f"파일을 읽지 못했습니다: {view}")
            else:
                viewer.show(view)
        elif tag == "page" and not error:
            accepted = session.accept_page(value)
            if accepted is not None:
                viewer.show_page(accepted[0], session.pages, accepted[1])

    def _file_tag_target(row):
        fs, _make = _file_row_source(row)
        name = opened_images.get(fs["image"], {}).get("name", "")
        # a row of 태그한 파일 keeps the identity it was tagged with, so its tags can still be changed
        image_id = row["image_id"] if "image_id" in row else tag_book.image_identity(fs["image"])
        identity = (fs["image"], fs["volume"], row["parts"], row.get("record"))
        return (tag_book.file_key(*identity, row.get("sequence"), image_id), "file",
                tag_book.file_ref(*identity, name, row.get("sequence"), image_id))

    def _event_tag_target(event):
        return tag_book.event_key(event), "event", tag_book.event_ref(event)

    def fill_tag_menu(menu, target):
        """Tag choices, note and clear for one record or file; `target` = (key, kind, ref)."""
        key, kind, ref = target
        current = book.tags_for(key)

        def mark(tag):
            return "✓ " if tag in current else "    "

        for color in tag_book.COLORS:
            menu.add_command(label=f"{mark(color)}● {book.label(color)}", command=lambda t=color: change_tags(
                lambda: book.toggle(key, kind, ref, t)))
            subs = tk.Menu(menu, tearoff=False)
            for sub in book.subcategories[color]:
                tag = f"{color}/{sub}"
                subs.add_command(label=f"{mark(tag)}{sub}", command=lambda t=tag: change_tags(
                    lambda: book.toggle(key, kind, ref, t)))
            if book.subcategories[color]:
                subs.add_separator()
            subs.add_command(label=TAG_MENU["new_subcategory"], command=lambda c=color: new_subcategory(c, target))
            if book.subcategories[color]:
                renames_sub, deletes_sub = tk.Menu(subs, tearoff=False), tk.Menu(subs, tearoff=False)
                for sub in book.subcategories[color]:
                    renames_sub.add_command(label=sub, command=lambda c=color, n=sub: rename_subcategory(c, n))
                    deletes_sub.add_command(label=sub, command=lambda c=color, n=sub: delete_subcategory(c, n))
                subs.add_cascade(label=TAG_MENU["rename_sub"], menu=renames_sub)
                subs.add_cascade(label=TAG_MENU["delete_sub"], menu=deletes_sub)
            menu.add_cascade(label="      " + TAG_MENU["subcategories"].format(color=TAG_COLOR_WORDS[color]), menu=subs)
        renames = tk.Menu(menu, tearoff=False)
        for color in tag_book.COLORS:
            renames.add_command(label=book.label(color), command=lambda c=color: rename_color(c))
        menu.add_cascade(label=TAG_MENU["rename"], menu=renames)
        menu.add_command(label="메모 쓰기..." if not book.note_for(key) else "메모 고치기...",
                         command=lambda: write_note(key, kind, ref))
        if key in book.items:
            menu.add_command(label="태그·메모 지우기", command=lambda: change_tags(lambda: book.clear(key)))

    def new_subcategory(color, target):
        name = simpledialog.askstring(TAG_MENU["new_subcategory"],
                                      TAG_MENU["new_prompt"].format(color=TAG_COLOR_WORDS[color]), parent=root)
        if not (name or "").strip():
            return
        key, kind, ref = target
        tag = book.add_subcategory(color, name)
        _save_tag_preferences()
        if tag not in book.tags_for(key):
            change_tags(lambda: book.toggle(key, kind, ref, tag))
        else:
            change_tags(lambda: None)

    def rename_subcategory(color, old):
        name = simpledialog.askstring(TAG_MENU["rename_sub"], TAG_MENU["rename_sub_prompt"].format(name=old),
                                      initialvalue=old, parent=root)
        if (name or "").strip():
            change_tags(lambda: book.rename_subcategory(color, old, name))
            _save_tag_preferences()

    def delete_subcategory(color, name):
        if messagebox.askyesno(TAG_MENU["delete_sub"], TAG_MENU["delete_sub_confirm"].format(name=name)):
            change_tags(lambda: book.delete_subcategory(color, name))
            _save_tag_preferences()

    def rename_color(color):
        name = simpledialog.askstring(TAG_MENU["rename"], TAG_MENU["rename_prompt"].format(color=TAG_COLOR_WORDS[color]),
                                      initialvalue=book.color_names[color], parent=root)
        if (name or "").strip():
            book.rename_color(color, name)
            _save_tag_preferences()
            change_tags(lambda: None)

    def _save_tag_preferences():
        prefs.set_tag_preferences(book.preferences())
        prefs.save()

    def load_tags():
        """Bring back tags saved with an earlier report (case.sqlite, opened read-only); old tags become colours."""
        path = filedialog.askopenfilename(title=TAG_MENU["load"], filetypes=[("case.sqlite", "*.sqlite"), ("모든 파일", "*.*")])
        if not path:
            return
        try:
            rows = tag_book.load_from_sqlite(path)
        except Exception as exc:  # not a SQLite file, locked, damaged
            messagebox.showerror(TAG_MENU["load"], TAG_MENU["load_error"].format(error=exc))
            return
        if not rows:
            messagebox.showinfo(TAG_MENU["load"], TAG_MENU["load_none"])
            return
        change_tags(lambda: book.load_rows(rows))
        _save_tag_preferences()
        messagebox.showinfo(TAG_MENU["load"], TAG_MENU["load_done"].format(count=len(rows)))

    def write_note(key, kind, ref):
        note = simpledialog.askstring("메모", "이 항목에 남길 메모 (증거와 따로, 보고서와 case.sqlite에 저장됩니다):",
                                      initialvalue=book.note_for(key), parent=root)
        if note is not None:
            change_tags(lambda: book.set_note(key, kind, ref, note))

    def change_tags(change):
        change()
        unsaved["tags"] = True
        _populate_tree(keep_page=True)
        _refresh_tag_root()
        if files_state.get("tagged"):
            _show_tagged_files()

    def _refresh_tag_root():
        """Redraw only the 분석자 태그 branch, so the selected folder/page and open folders stay as they are."""
        selection = nav_tree.selection()
        selected_key = nav_nodes[selection[0]].key if selection and selection[0] in nav_nodes else ""

        def forget(iid):
            for child in nav_tree.get_children(iid):
                forget(child)
            nav_nodes.pop(iid, None)

        for iid in [i for i, node in nav_nodes.items() if node.key == "tags" and nav_tree.exists(i)]:
            forget(iid)
            nav_tree.delete(iid)
        if not result and not book.items:
            return
        added = nav.fill_nav(nav_tree, [tag_book.tag_tree(book, result.events if result else ())])
        nav_nodes.update(added)
        if selected_key.startswith("tags:"):  # the shown tag list changed: show it again
            for iid, node in added.items():
                if node.key == selected_key:
                    nav_tree.selection_set(iid)
                    break
            else:
                nav_state["node"] = None
                refresh()

    def on_timeline_menu(event):
        if tree.identify_region(event.x, event.y) == "heading":
            menu = tk.Menu(tree, tearoff=False)
            menu.add_command(label=COLUMN_LAYOUT_RESET, command=reset_column_layout)
            menu.tk_popup(event.x_root, event.y_root)
            return
        item = tree.identify_row(event.y)
        if not item or not item.isdigit() or int(item) >= len(visible):
            return
        tree.selection_set(item)
        menu = tk.Menu(tree, tearoff=False)
        fill_tag_menu(menu, _event_tag_target(visible[int(item)]))
        if visible[int(item)].artifact == "recyclebin":
            menu.add_separator()
            blocker = recycle_view.save_blocker(visible[int(item)])
            menu.add_command(label=RECYCLE_TEXT["save"] if blocker is None else RECYCLE_TEXT["unavailable"].format(reason=blocker),
                             state="normal" if blocker is None else "disabled",
                             command=lambda e=visible[int(item)]: save_recycle_original(e))
        menu.tk_popup(event.x_root, event.y_root)

    def fill_file_menu():
        files.menu.delete(2, "end")
        row = files.selected_row()
        if row is not None and "parts" in row:
            files.menu.add_separator()
            fill_tag_menu(files.menu, _file_tag_target(row))

    def _show_tagged_files():
        """파일 목록 with every tagged image file (any image), opened through its own image/volume."""
        files_state.update(node=None, view=None, tagged=True)
        _update_path_bar()
        rows = []
        for item in book.rows():
            ref = item["ref"]
            if item["target"] != "file":
                continue
            parts = tuple(ref.get("parts", ()))
            changed = ref.get("image_id") != tag_book.image_identity(ref["image"])
            rows.append({"name": parts[-1] if parts else "", "parts": parts, "record": ref.get("mft_record"),
                         "sequence": ref.get("mft_sequence"), "kind": fs_model.kind_of(parts[-1] if parts else ""),
                         "image": ref["image"], "volume": ref["volume"], "path": ref.get("image_path", ""),
                         "image_id": ref.get("image_id"), "check": TAGGED_IMAGE_CHANGED if changed else ""})
        tabs.select(files.frame)
        note = TAGGED_IMAGE_CHANGED_NOTE if any(row["check"] for row in rows) else "태그는 오른쪽 클릭으로 바꿉니다"
        files.show(rows, "분석자 태그를 붙인 파일", note)

    def on_relation_select(_event=None):
        selection = rel_tree.selection()
        rel_members.delete(*rel_members.get_children())
        rel_state["members"] = []
        if not result or not selection:
            _show_relation_text([RL["pick"]])
            return
        index = rel_tree.index(selection[0])
        if index >= len(rel_state["shown"]):
            return
        relation = rel_state["shown"][index]
        _show_relation_text(relation_view.detail_lines(relation, result.events))
        rel_state["members"] = relation_view.member_rows(relation, result.events)
        for row, (_event_index, values) in enumerate(rel_state["members"]):
            rel_members.insert("", "end", iid=str(row), values=values)

    def jump_to_record(event_index):
        """Show one record of a relation in the timeline and select it."""
        if not result or not 0 <= event_index < len(result.events):
            return
        event = result.events[event_index]
        nav_state["node"] = TreeNode("rel:record", "선택한 연관 관계의 기록", "event_set", frozenset({id(event)}))
        view_var.set("보기: 선택한 연관 관계의 기록 1건")
        tabs.select(event_frame)
        refresh()
        if tree.get_children():
            first = tree.get_children()[0]
            tree.selection_set(first)
            tree.see(first)

    def jump_to_member(role):
        for event_index, values in rel_state["members"]:
            if values[0] == role:
                jump_to_record(event_index)
                return

    def on_member_open(_event=None):
        selection = rel_members.selection()
        if selection and int(selection[0]) < len(rel_state["members"]):
            jump_to_record(rel_state["members"][int(selection[0])][0])

    def show_relation_records():
        selection = rel_tree.selection()
        if not result or not selection:
            return
        index = rel_tree.index(selection[0])
        if index >= len(rel_state["shown"]):
            return
        records = view_model.relation_events(rel_state["shown"][index], result.events)
        nav_state["node"] = TreeNode("rel:selected", "선택한 연관 관계의 기록", "event_set",
                                     frozenset(id(e) for e in records))
        view_var.set(f"보기: 선택한 연관 관계의 기록 {len(records):,}건")
        tabs.select(event_frame)
        refresh()

    def _selected_event():
        selection = tree.selection()
        if selection and selection[0].isdigit() and int(selection[0]) < len(visible):
            return visible[int(selection[0])]
        return None

    def update_recycle_button(_event=None):
        event = _selected_event()
        recycle_button.configure(state="normal" if event is not None and recycle_view.save_blocker(event) is None
                                 and not _case_without_copies() else "disabled")

    def _case_without_copies():
        """An opened saved analysis has no extracted copies of the image's files (until re-analysed)."""
        return loaded_case["result"] is not None and not extractions

    def save_recycle_original(event):
        """Save the original ($R) of a recycle bin record as a NEW file with a provenance record (image only read)."""
        if _case_without_copies():
            messagebox.showwarning(RECYCLE_TEXT["title"], CASE_TEXT["recycle_unavailable"])
            return
        blocker = recycle_view.save_blocker(event)
        if blocker is not None:
            messagebox.showwarning(RECYCLE_TEXT["title"], RECYCLE_TEXT["unavailable"].format(reason=blocker))
            return
        plan = recycle_view.save_plan(event, extractions)
        if plan is None:
            messagebox.showwarning(RECYCLE_TEXT["title"], RECYCLE_TEXT["no_source"])
            return
        folder = filedialog.askdirectory(title=RECYCLE_TEXT["pick"])
        if not folder:
            return
        image, volume, i_path, name = plan
        target = Path(folder) / name
        pair = dict(event.details["recycle_pair"])
        status.set(RECYCLE_TEXT["saving"])
        original = event.details.get("original_path")

        def job():
            from log_hunter.image.recycle import save_recycle_pair
            return save_recycle_pair(image, volume, i_path, target, expected_pair=pair), original

        runner.submit("recycle_save", job)

    def show_event_detail(_event):
        """Double-click: the common properties dialog with this category's fields (자세히… for long lists, raw JSON)."""
        if not tree.selection():
            return
        idx = int(tree.selection()[0])
        if idx >= len(visible):
            return
        evt = visible[idx]
        events = result.events if result else []
        ctx = record_fields.Context(
            siblings=[e for e in events if e is not evt and e.artifact == evt.artifact and e.source == evt.source],
            file_extra=content.record_file_extra(evt.source, result.evidence if result else (), extractions),
            file_size=_file_size(evt.source), sid_map=sid_map,
            source_text=nav_state["origins"].text(evt.source) if nav_state.get("origins") else None,
            origin=nav_state["origins"].text if nav_state.get("origins") else None)
        image, target = _image_of(evt.source), None
        if evt.artifact == "prefetch" and image:
            target = record_fields.prefetch_exe_target(evt)
            ctx.exe_state = record_fields.L["exe_checking" if target else "exe_no_path"]
        props = record_fields.properties(evt, ctx)
        dialog = PropertiesDialog(root, props)
        if target:
            exe_dialog["open"] = (dialog, props.check_label)
            runner.submit("exe_check", lambda: record_fields.check_exe(_browser(image), target))

    exe_dialog = {"open": None}

    def _file_size(source):
        try:
            return Path(source).stat().st_size
        except (OSError, ValueError):
            return None

    def _image_of(source):
        """The disk image (or this PC's drive) a record's file was taken from, or None for files added directly."""
        try:
            key = str(Path(source).resolve()).casefold()
        except (OSError, ValueError):
            return None
        for extraction in extractions:
            if key in extraction.file_index():
                return extraction.image_path
        return None

    saving = {"dialog": None}

    def _start_save(folder, name=None):
        from log_hunter.database.save import save_analysis, OUTPUT_FILES, suggest_save_folder
        if saving["dialog"]:
            return
        if auto.waiting or analysis_state["busy"] or analysis_state["extracting"]:
            messagebox.showwarning("분석 중", "분석이 끝난 뒤 저장하세요")
            return
        if any((Path(folder) / n).exists() for n in OUTPUT_FILES):
            proposed = suggest_save_folder(folder)
            if not messagebox.askyesno("저장 폴더", f"이전 결과가 있습니다. 새 하위 폴더 {proposed.name}에 저장할까요?"):
                return
            folder = proposed
        analysis, rows, owners = result, book.rows(), dict(sid_map)
        original_info = loaded_case["info"]
        selected_inputs = None  # AnalysisResult retains input provenance, including merged/reopened cases.
        stop, updates = threading.Event(), queue.Queue()
        dialog = tk.Toplevel(root)
        saving["dialog"] = dialog
        dialog.title("분석 저장")
        dialog.transient(root)
        dialog.grab_set()
        label = ttk.Label(dialog, text="저장 준비", padding=15)
        label.pack()
        bar = ttk.Progressbar(dialog, length=350, maximum=1)
        bar.pack(padx=15, pady=10)
        ttk.Button(dialog, text="저장 취소", command=stop.set).pack(pady=10)
        dialog.protocol("WM_DELETE_WINDOW", stop.set)

        def poll_save():
            if saving["dialog"] is not dialog:
                return
            while not updates.empty():
                stage, ratio = updates.get_nowait()
                label.configure(text=stage)
                bar.configure(value=ratio)
            root.after(100, poll_save)

        poll_save()
        def job():
            report = save_analysis(folder, analysis, name=name, tags=rows, sid_names=owners,
                                   inputs=selected_inputs, sources=getattr(original_info, "sources", None), cancel=stop.is_set,
                                   progress=lambda stage, ratio: updates.put((stage, ratio)))
            return report, analysis, rows, original_info
        runner.submit("analysis_save", job)

    def export():
        if not result:
            messagebox.showwarning("결과 없음", "분석을 먼저 실행하세요")
            return
        output = filedialog.askdirectory()
        if output:
            _start_save(output)

    def _remember_case(path, name, events, source_state="not_checked"):
        """Put a saved/opened analysis first in the recent list (user settings folder, never the case folder)."""
        from datetime import datetime, timezone
        prefs.add_recent_case(path, name=name, saved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              events=events, source_state=source_state)
        prefs.save()

    def open_saved_case(path):
        """Load a saved analysis on the worker thread without re-analysing (read-only; the case file is not changed).
        Returns True when loading started."""
        try:
            from log_hunter.database.case_db import load_case
        except ImportError:  # the case engine is not in this build yet
            messagebox.showinfo(CASE_TEXT["open_title"], CASE_TEXT["engine_pending"])
            return False
        status.set(CASE_TEXT["loading"])
        progress.configure(mode="indeterminate")
        progress.start(12)
        runner.submit("case_open", lambda: (path, *load_case(path)))
        return True

    def _show_loaded_case(path, analysis, info):
        nonlocal result, sid_map
        from . import case_view
        inputs.clear()
        listing.delete(0, "end")
        auto.stop()
        analysis_state["busy"] = False
        loaded_case.update(result=analysis, info=info, path=path)
        unsaved["tags"] = False
        _forget_opened_sources()
        result, sid_map = analysis, dict(getattr(analysis, "sid_names", None) or {})
        book.items.clear()
        book.load_rows(getattr(analysis, "tags", None) or ())
        _show_result()
        derived = [e.source for e in analysis.evidence if (e.metadata or {}).get("image")]
        loaded_case.update(derived=derived, linked_image=None, origins=case_view.saved_extractions(analysis))
        relink_button.configure(state="normal" if case_view.image_sources(info) else "disabled")
        title, line, warnings = case_view.case_status(info, len(analysis.events), derived)
        loaded_case["status"] = line
        root.title(title)
        status.set(line)
        _remember_case(path, case_view.info_dict(info).get("name") or Path(path).parent.name, len(analysis.events),
                       case_view.source_state(info))
        if warnings:
            messagebox.showwarning(CASE_TEXT["warnings_title"], "\n".join(warnings))

    def save_case_dialog():
        if not result:
            messagebox.showwarning("결과 없음", "분석을 먼저 실행하세요")
            return
        from . import case_view
        default = case_view.info_dict(loaded_case["info"]).get("name") or ""
        name = simpledialog.askstring(CASE_TEXT["save_name"], CASE_TEXT["save_name_prompt"], initialvalue=default, parent=root)
        if not name:
            return
        folder = filedialog.askdirectory(title=CASE_TEXT["save_pick"])
        if folder:
            _start_save(folder, name)

    def _keep_unsaved_ok():
        """Ask before tags/notes changed since opening or saving are dropped. True: go on."""
        if not unsaved["tags"] or not book.items:
            return True
        answer = messagebox.askyesnocancel(CASE_TEXT["unsaved_title"], CASE_TEXT["unsaved"])
        if answer is None:
            return False
        if answer:
            save_case_dialog()
            return not unsaved["tags"]
        return True

    def relink_original():
        """원본 위치 다시 지정: hash the image the examiner picks (read only) and link it only if it matches the saved hash."""
        from . import case_view
        images = case_view.image_sources(loaded_case["info"])
        if not images:
            messagebox.showinfo(CASE_TEXT["relink_button"], CASE_TEXT["relink_no_image"])
            return
        expected = {h.lower() for _p, h, _s in images if h}
        if not expected:
            messagebox.showwarning(CASE_TEXT["relink_button"], CASE_TEXT["relink_unknown"])
            return
        path = filedialog.askopenfilename(title=CASE_TEXT["relink_pick"])
        if not path:
            return
        status.set(CASE_TEXT["relink_checking"])

        def job():
            import hashlib
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                    digest.update(block)
            return path, digest.hexdigest(), sorted(expected)
        runner.submit("case_relink", job)

    def _finish_relink(path, actual, expected):
        status.set(loaded_case.get("status") or "")
        if actual not in expected:
            messagebox.showwarning(CASE_TEXT["relink_button"],
                                   CASE_TEXT["relink_mismatch"].format(expected=", ".join(expected), actual=actual))
            return
        loaded_case["linked_image"] = path
        runner.submit("open", lambda: (path, fs_model.image_source_name(path), _browser(path).volume_info()))
        messagebox.showinfo(CASE_TEXT["relink_button"], CASE_TEXT["relink_done"])

    def _forget_opened_sources():
        """Drop images opened for the previous analysis from the tree (their temp copies are removed on exit)."""
        opened_images.clear()
        extractions.clear()
        folder_cache.clear()

    def new_analysis():
        if not _keep_unsaved_ok():
            return
        if (result or inputs) and not messagebox.askyesno(CASE_TEXT["new_button"], CASE_TEXT["new_confirm"]):
            return
        unsaved["tags"] = False
        loaded_case.update(result=None, info=None, path=None, linked_image=None, origins=())
        relink_button.configure(state="disabled")
        _forget_opened_sources()
        inputs.clear()
        listing.delete(0, "end")
        book.items.clear()
        root.title("Log Hunter - Windows Forensic Analyzer")
        request_analysis()

    def open_case_dialog():
        """Recent analyses (name, saved time, record count, link to the original) and a file picker."""
        from . import case_view
        dialog = tk.Toplevel(root)
        dialog.title(CASE_TEXT["open_title"])
        dialog.transient(root)
        entries = prefs.recent_cases()
        ttk.Label(dialog, text=CASE_TEXT["recent"].format(n=len(entries)) if entries else CASE_TEXT["empty"],
                  wraplength=640).pack(fill="x", padx=10, pady=(10, 4))
        keys = case_view.ROW_KEYS
        listing = ttk.Treeview(dialog, columns=keys, show="headings", height=10, selectmode="browse")
        for key, width in zip(keys, (160, 170, 80, 120, 320)):
            listing.heading(key, text=CASE_TEXT["columns"][key])
            listing.column(key, width=width, stretch=key == "path")
        listing.tag_configure("missing", foreground="#999999")
        listing.pack(fill="both", expand=True, padx=10)
        paths = {}

        def fill():
            listing.delete(*listing.get_children())
            paths.clear()
            for path, values, missing in case_view.recent_rows(prefs.recent_cases()):
                paths[listing.insert("", "end", values=values, tags=("missing",) if missing else ())] = path

        def chosen():
            selection = listing.selection()
            return paths.get(selection[0]) if selection else None

        def open_path(path):
            if not path:
                return
            if not case_view.is_case_file(path):
                messagebox.showwarning(CASE_TEXT["open_title"], CASE_TEXT["not_case_file"], parent=dialog)
                return
            if not Path(path).exists():
                messagebox.showwarning(CASE_TEXT["open_title"], CASE_TEXT["missing"] + f": {path}", parent=dialog)
                return
            if _keep_unsaved_ok() and open_saved_case(path):
                dialog.destroy()

        def browse():
            path = filedialog.askopenfilename(parent=dialog, title=CASE_TEXT["pick_file"],
                                              filetypes=[(CASE_TEXT["file_types"], "case.sqlite"), ("SQLite", "*.sqlite")])
            open_path(path)

        def remove():
            path = chosen()
            if path:
                prefs.remove_recent_case(path)
                prefs.save()
                fill()

        buttons = ttk.Frame(dialog, padding=10)
        buttons.pack(fill="x")
        ttk.Button(buttons, text=CASE_TEXT["browse"], command=browse).pack(side="left")
        ttk.Button(buttons, text=CASE_TEXT["remove"], command=remove).pack(side="left", padx=6)
        ttk.Button(buttons, text=CASE_TEXT["close"], command=dialog.destroy).pack(side="right")
        ttk.Button(buttons, text=CASE_TEXT["open"], command=lambda: open_path(chosen())).pack(side="right", padx=6)
        listing.bind("<Double-1>", lambda _e: open_path(chosen()))
        dialog.bind("<Escape>", lambda _e: dialog.destroy())
        fill()

    def export_timeline(fmt):
        if not result:
            messagebox.showwarning("결과 없음", "분석을 먼저 실행하세요")
            return
        events = list(visible)  # exactly what the filters show; an empty view exports nothing
        if not events:
            messagebox.showwarning("내보낼 기록 없음", "현재 필터에 맞는 기록이 없습니다. 필터를 바꾼 뒤 다시 내보내세요")
            return
        from log_hunter.core.export import export_csv, export_json, export_jsonl, export_bodyfile
        ext = {"csv": ".csv", "json": ".json", "jsonl": ".jsonl", "bodyfile": ".bodyfile"}.get(fmt, ".csv")
        path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(f"{fmt.upper()} files", f"*{ext}")])
        if not path:
            return
        try:
            if fmt == "csv":
                count = export_csv(events, path)
            elif fmt == "json":
                count = export_json(events, path)
            elif fmt == "bodyfile":
                count = export_bodyfile(events, path)
            else:
                count = export_jsonl(events, path)
            messagebox.showinfo("내보내기 완료", f"{count}개 이벤트를 {path}에 저장했습니다")
        except Exception as exc:
            messagebox.showerror("내보내기 오류", str(exc))

    for var in (query, filter_artifact, start_date, end_date, status_filter, sid_var):
        var.trace_add("write", refresh)
    tree.bind("<<TreeviewSelect>>", select)
    tree.bind("<<TreeviewSelect>>", update_recycle_button, add="+")
    nav_tree.bind("<<TreeviewSelect>>", on_nav_select)
    rel_tree.bind("<Double-1>", lambda _e: show_relation_records())
    rel_tree.bind("<<TreeviewSelect>>", on_relation_select)
    rel_members.bind("<Double-1>", on_member_open)
    nav_tree.bind("<<TreeviewOpen>>", on_nav_open)
    tree.bind("<Double-1>", show_event_detail)
    tree.bind("<Button-3>", on_timeline_menu)
    tree.bind("<ButtonPress-1>", on_heading_press, add="+")
    tree.bind("<ButtonRelease-1>", on_heading_release, add="+")
    files.menu.configure(postcommand=fill_file_menu)
    global_search_var.trace_add("write", _populate_tree)

    # Left tree tools: back/forward over selected nodes (by key, so they survive rebuilds), find by name,
    # the selected path and a right-click menu. Folders of an image not read yet are not searched or read.
    nav_history = nav_tools.History()
    nav_moving = {"by_history": False}

    def _nav_label(iid):
        node = nav_nodes.get(iid)
        return node.label if node else nav_tree.item(iid, "text")

    def _nav_path(iid):
        return nav_tools.path_text(iid, nav_tree.parent, _nav_label)

    def _nav_buttons():
        nav_back.state(["!disabled"] if nav_history.back_keys else ["disabled"])
        nav_forward.state(["!disabled"] if nav_history.forward_keys else ["disabled"])

    def _nav_reveal(iid):
        parent = nav_tree.parent(iid)
        while parent:
            nav_tree.item(parent, open=True)
            parent = nav_tree.parent(parent)
        nav_tree.selection_set(iid)
        nav_tree.focus(iid)
        nav_tree.see(iid)

    def on_nav_track(_event):
        selection = nav_tree.selection()
        node = nav_nodes.get(selection[0]) if selection else None
        if node is None:
            return
        nav_path_var.set(_nav_path(selection[0]))
        if not nav_moving["by_history"]:
            nav_history.visit(node.key)
        nav_moving["by_history"] = False
        _nav_buttons()

    def _nav_go(key):
        if key is not None:
            iid = next((i for i, n in nav_nodes.items() if n.key == key and nav_tree.exists(i)), None)
            if iid is not None and iid not in nav_tree.selection():
                nav_moving["by_history"] = True
                _nav_reveal(iid)
        nav_history.drop(lambda k: any(n.key == k for n in nav_nodes.values()))
        _nav_buttons()

    def nav_go_back(*_args):
        _nav_go(nav_history.back())
        return "break"

    def nav_go_forward(*_args):
        _nav_go(nav_history.forward())
        return "break"

    def nav_find_next(*_args):
        text = nav_find_var.get()
        if not text.strip():
            return "break"
        order = [i for i in nav_tools.walk(nav_tree.get_children) if i in nav_nodes]
        selection = nav_tree.selection()
        hit = nav_tools.find_next(order, lambda i: nav_tree.item(i, "text"), text, selection[0] if selection else None)
        if hit:
            _nav_reveal(hit)
            status.set(NAV_TEXT["found"].format(path=_nav_path(hit)))
        else:
            status.set(NAV_TEXT["not_found"].format(text=text.strip()))
        return "break"

    def _nav_open_all(iid, opened):
        for item in [iid, *nav_tools.walk(nav_tree.get_children, iid)]:
            if nav_tree.get_children(item):
                nav_tree.item(item, open=opened)

    def _nav_copy(text):
        root.clipboard_clear()
        root.clipboard_append(text)

    nav_menu = tk.Menu(root, tearoff=0)

    def on_nav_menu(event):
        iid = nav_tree.identify_row(event.y)
        if not iid or iid not in nav_nodes:
            return
        nav_tree.selection_set(iid)
        nav_menu.delete(0, "end")
        nav_menu.add_command(label=NAV_TEXT["expand_all"], command=lambda: _nav_open_all(iid, True))
        nav_menu.add_command(label=NAV_TEXT["collapse_all"], command=lambda: _nav_open_all(iid, False))
        nav_menu.add_separator()
        nav_menu.add_command(label=NAV_TEXT["copy_path"], command=lambda: _nav_copy(_nav_path(iid)))
        nav_menu.add_command(label=NAV_TEXT["copy_name"], command=lambda: _nav_copy(_nav_label(iid)))
        nav_menu.tk_popup(event.x_root, event.y_root)

    nav_back.configure(command=nav_go_back)
    nav_forward.configure(command=nav_go_forward)
    _nav_buttons()
    nav_find.bind("<Return>", nav_find_next)
    nav_tree.bind("<<TreeviewSelect>>", on_nav_track, add="+")
    nav_tree.bind("<Button-3>", on_nav_menu)
    nav_tree.bind("<Alt-Left>", nav_go_back)
    nav_tree.bind("<Alt-Right>", nav_go_forward)

    def on_close():
        nonlocal closing
        if closing:
            return
        if saving["dialog"]:
            return
        if not _keep_unsaved_ok():
            return
        _save_column_layout()
        closing = True
        auto.stop()
        for state in (scan_state, verify_state):
            if state["stop"] is not None:
                state["stop"].set()
        root.withdraw()

        def close_browsers():
            for browser in list(browsers.values()):
                try:
                    browser.close()
                except OSError:
                    pass
            browsers.clear()

        runner.shutdown(close_browsers)

        def finish_close():
            if runner.is_alive() or any(thread.is_alive() for thread in background_threads):
                root.after(50, finish_close)
                return
            for folder in temp_dirs:
                shutil.rmtree(folder, ignore_errors=True)
            root.destroy()

        finish_close()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(100, poll)
    if live is not None:
        root.after(500, lambda: analyze_this_pc(live))
    root.mainloop()
