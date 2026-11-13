"""'파일 목록' tab: the files of the selected folder or file view, like a file explorer.

Data handling (sort, search, pages, cell text) is fs_model.FileTable; this class only builds and fills widgets
and reports what the user did through callbacks."""
import tkinter as tk
from tkinter import ttk

from log_hunter.core.labels import FOLDER_NAV_LABELS, file_table_label
from . import fs_model


class FileListView:
    def __init__(self, notebook, on_select, on_open_folder, on_save, on_copy_path, on_show_records, on_turn_page,
                 on_cancel, on_navigate=lambda _where: None, on_reveal=None):
        self.frame = ttk.Frame(notebook)
        notebook.insert(0, self.frame, text="파일 목록")
        self._navigate = on_navigate
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x", padx=2, pady=(2, 0))
        self.back_button = ttk.Button(bar, text=FOLDER_NAV_LABELS["back"], width=7, command=lambda: on_navigate("back"))
        self.forward_button = ttk.Button(bar, text=FOLDER_NAV_LABELS["forward"], width=7,
                                         command=lambda: on_navigate("forward"))
        self.up_button = ttk.Button(bar, text=FOLDER_NAV_LABELS["up"], width=7, command=lambda: on_navigate("up"))
        for button in (self.back_button, self.forward_button, self.up_button):
            button.pack(side="left", padx=(0, 2))
        self.where = tk.StringVar(value="")
        self.where_label = ttk.Label(bar, textvariable=self.where, foreground="#1a5fb4")
        self.where_label.pack(side="left", padx=(6, 0))
        self.crumb_frame = ttk.Frame(bar)  # clickable path of the shown folder; replaces `where` for folders
        ttk.Button(bar, text="이 폴더의 기록 보기", command=on_show_records).pack(side="right")
        self.cancel_button = ttk.Button(bar, text="찾기 취소", command=on_cancel)
        bar2 = ttk.Frame(self.frame)
        bar2.pack(fill="x", padx=2, pady=2)
        ttk.Label(bar2, text="이름 검색:").pack(side="left")
        self.query = tk.StringVar()
        ttk.Entry(bar2, textvariable=self.query, width=28).pack(side="left", padx=(3, 8))
        ttk.Button(bar2, text="◀ 이전", width=8, command=lambda: on_turn_page(-1)).pack(side="left")
        ttk.Button(bar2, text="다음 ▶", width=8, command=lambda: on_turn_page(1)).pack(side="left", padx=3)
        self.status = tk.StringVar(value="")
        ttk.Label(bar2, textvariable=self.status).pack(side="left", padx=8)
        self.table = ttk.Treeview(self.frame, columns=fs_model.TABLE_COLUMNS, show="headings", selectmode="browse")
        widths = {"name": 260, "kind": 80, "size": 80, "state": 70, "records": 60}
        for key in fs_model.TABLE_COLUMNS:
            self.table.heading(key, text=file_table_label(key), command=lambda k=key: self._on_sort(k))
            self.table.column(key, width=widths.get(key, 150))
        self.table.tag_configure("deleted", foreground="#b03030")
        scroll = ttk.Scrollbar(self.frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.table.pack(fill="both", expand=True)
        self.menu = tk.Menu(self.table, tearoff=False)
        self.menu.add_command(label="파일로 저장 (읽기 전용 복사)", command=lambda: self._with_row(on_save))
        self.menu.add_command(label="이미지 안 경로 복사", command=lambda: self._with_row(on_copy_path))
        self.table.bind("<<TreeviewSelect>>", lambda _e: self._with_row(on_select))
        activate = lambda row: on_open_folder(row) if row.get("directory") else (on_reveal or on_select)(row)
        self.table.bind("<Double-1>", lambda event: self._activate(event, activate))
        self.table.bind("<Return>", lambda _e: self._with_row(activate))
        self.table.bind("<Button-3>", self._popup)
        self.model = fs_model.FileTable()
        self._sort_callback = None
        self.query.trace_add("write", lambda *_a: self._search())
        self.message("디스크 이미지나 이 PC를 열면 파일 탐색을 할 수 있습니다")
        self.set_path(None)

    def set_path(self, items, can_back=False, can_forward=False, can_up=False):
        """Folder path bar: [(label, key)] from the volume down, each part clickable; None shows the plain `where` text."""
        for child in self.crumb_frame.winfo_children():
            child.destroy()
        for button, enabled in ((self.back_button, can_back), (self.forward_button, can_forward), (self.up_button, can_up)):
            button.configure(state="normal" if enabled else "disabled")
        if not items:
            self.crumb_frame.pack_forget()
            self.where_label.pack(side="left", padx=(6, 0))
            return
        self.where_label.pack_forget()
        self.crumb_frame.pack(side="left", padx=(6, 0))
        for index, (label, key) in enumerate(items):
            if index:
                ttk.Label(self.crumb_frame, text="›", foreground="#777").pack(side="left", padx=2)
            last = index == len(items) - 1
            part = ttk.Label(self.crumb_frame, text=label, foreground="#222" if last else "#1a5fb4",
                             cursor="" if last else "hand2")
            part.pack(side="left")
            if not last:
                part.bind("<Button-1>", lambda _e, k=key: self._navigate(k))

    def _with_row(self, callback):
        selection = self.table.selection()
        if selection and selection[0].startswith("r"):
            rows = self.model.page_slice()
            index = int(selection[0][1:])
            if index < len(rows):
                callback(rows[index])

    def _activate(self, event, callback):
        item = self.table.identify_row(event.y)
        if item and item.startswith("r"):
            self.table.selection_set(item)
            self._with_row(callback)
        return "break"

    def select_path(self, parts):
        """Reveal a file even when its name is filtered out or on another page."""
        self.query.set("")
        target = tuple(p.casefold() for p in parts)
        for index, row in enumerate(self.model.rows):
            if tuple(p.casefold() for p in row.get("parts", ())) == target:
                self.model.page = index // self.model.page_rows
                self.render()
                item = f"r{index % self.model.page_rows}"
                self.table.selection_set(item)
                self.table.focus(item)
                self.table.see(item)
                return True
        return False

    def selected_row(self):
        rows = []
        self._with_row(rows.append)
        return rows[0] if rows else None

    def _popup(self, event):
        item = self.table.identify_row(event.y)
        if item and item.startswith("r"):
            self.table.selection_set(item)
            rows = self.model.page_slice()
            if not rows[int(item[1:])].get("directory"):
                self.menu.tk_popup(event.x_root, event.y_root)

    def _on_sort(self, key):
        self.model.sort(key)
        self.render()

    def _search(self):
        self.model.search(self.query.get())
        self.render()

    def message(self, text, where=""):
        """Show a single explanatory line instead of files."""
        self.model = fs_model.FileTable()
        self.where.set(where)
        self.status.set("")
        self.table.delete(*self.table.get_children())
        self.table.insert("", "end", iid="msg", values=(text,) + ("",) * (len(fs_model.TABLE_COLUMNS) - 1))

    def show(self, rows, where, note=""):
        query = self.query.get()
        self.model = fs_model.FileTable(rows)
        if query:
            self.model.search(query)
        self.where.set(where)
        self.render(note)

    def render(self, note=""):
        self.table.delete(*self.table.get_children())
        for index, row in enumerate(self.model.page_slice()):
            deleted = row.get("in_use") is False
            self.table.insert("", "end", iid=f"r{index}", values=fs_model.table_values(row),
                              tags=("deleted",) if deleted else ())
        if not self.model.rows:
            self.table.insert("", "end", iid="msg", values=("(표시할 파일 없음)",) + ("",) * (len(fs_model.TABLE_COLUMNS) - 1))
        self.status.set(self.model.status() + (f" · {note}" if note else ""))

    def turn(self, delta):
        self.model.turn(delta)
        self.render()

    def update_rows(self, described):
        """Merge details (times, state) read on the worker thread into the current rows."""
        selected = self.table.selection()
        by_record = {row["record"]: row for row in described}
        for row in self.model.all:
            extra = by_record.get(row.get("record"))
            if extra is not None:
                row.update({k: v for k, v in extra.items() if k not in ("name", "parts", "records", "kind")})
        self.render()
        if selected and self.table.exists(selected[0]):
            self.table.selection_set(selected[0])
            self.table.focus(selected[0])
            self.table.see(selected[0])

    def busy(self, text, cancellable=False):
        self.status.set(text)
        if cancellable:
            self.cancel_button.pack(side="right", padx=4)
        else:
            self.cancel_button.pack_forget()
