# ▶ 원본: log_hunter/ui/detail.py
# ▶ 선택 기록의 상세 정보를 트리 형태로 표시합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Lower pane: the selected record as an item/value tree and as colored raw JSON."""
import json
import re

JSON_TAGS = {"json_key": "#0066cc", "json_string": "#008800", "json_number": "#cc6600",
             "json_bool": "#9900cc", "json_null": "#999999"}


def configure_json_tags(text):
    for tag, color in JSON_TAGS.items():
        text.tag_configure(tag, foreground=color)


def fill_properties(props, rows, parent=""):
    """Insert core.tree.Property rows (and their children) into a Treeview; top level opens."""
    for row in rows:
        iid = props.insert(parent, "end", text=row.name, values=(row.value,), open=parent == "")
        fill_properties(props, row.children, iid)


def show_json(text, event):
    text.delete("1.0", "end")
    text.insert("end", json.dumps(event.to_dict(), ensure_ascii=False, indent=2))
    colorize_json(text)


def colorize_json(widget):
    content = widget.get("1.0", "end")
    for tag in JSON_TAGS:
        widget.tag_remove(tag, "1.0", "end")
    for m in re.finditer(r'"([^"\\]|\\.)*"\s*:', content):
        widget.tag_add("json_key", f"1.0+{m.start()}c", f"1.0+{m.end() - 1}c")
    for m in re.finditer(r':\s*"([^"\\]|\\.)*"', content):
        colon_end = content.index('"', m.start())
        widget.tag_add("json_string", f"1.0+{colon_end}c", f"1.0+{m.end()}c")
    for m in re.finditer(r'(?<!["\w])-?\d+(?:\.\d+)?(?!["\w])', content):
        widget.tag_add("json_number", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
    for m in re.finditer(r'\b(true|false)\b', content):
        widget.tag_add("json_bool", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
    for m in re.finditer(r'\bnull\b', content):
        widget.tag_add("json_null", f"1.0+{m.start()}c", f"1.0+{m.end()}c")


class ContentViewer:
    """파일 정보 / 16진수 / 텍스트 tabs for the file behind the selected record or tree item.
    Data comes from ui.content (built on the worker thread); this class only fills widgets."""

    def __init__(self, notebook, on_page):
        import tkinter as tk
        from tkinter import ttk
        info_frame = self.info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text="파일 정보")
        self.info = ttk.Treeview(info_frame, columns=("value",), show="tree headings", height=8)
        self.info.heading("#0", text="항목")
        self.info.heading("value", text="값")
        self.info.column("#0", width=220, stretch=False)
        self.info.column("value", width=700)
        self.info.pack(fill="both", expand=True)
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="16진수")
        bar = ttk.Frame(hex_frame)
        bar.pack(fill="x")
        ttk.Button(bar, text="◀ 이전", width=8, command=lambda: on_page(-1)).pack(side="left")
        ttk.Button(bar, text="다음 ▶", width=8, command=lambda: on_page(1)).pack(side="left", padx=3)
        self.page_label = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.page_label).pack(side="left", padx=8)
        self.hex = tk.Text(hex_frame, height=8, wrap="none", font=("Consolas", 9))
        self.hex.pack(fill="both", expand=True)
        text_frame = ttk.Frame(notebook)
        notebook.add(text_frame, text="텍스트")
        self.strings = tk.Text(text_frame, height=8, wrap="none", font=("Consolas", 9))
        self.strings.pack(fill="both", expand=True)
        from log_hunter.core.labels import PREVIEW_TEXT
        self.preview_text = PREVIEW_TEXT
        preview_frame = self.preview_frame = ttk.Frame(notebook)
        notebook.add(preview_frame, text=PREVIEW_TEXT["tab"])
        self.preview_summary = tk.Text(preview_frame, height=4, wrap="word", font=("Segoe UI", 9))
        self.preview_summary.tag_configure("warn", foreground="#b03030")
        self.preview_summary.pack(fill="x")
        self.preview_image = ttk.Label(preview_frame)
        self.preview_image.pack(anchor="w")
        self.preview_body = tk.Text(preview_frame, height=6, wrap="word", font=("Consolas", 9))
        self.preview_body.pack(fill="both", expand=True)
        self._photo = None  # keep a reference or Tk drops the image
        self.clear("기록이나 파일을 고르면 내용을 보여 줍니다")

    def _set(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def clear(self, message):
        self.info.delete(*self.info.get_children())
        self.info.insert("", "end", text=message, values=("",))
        self.page_label.set("")
        self._set(self.hex, message)
        self._set(self.strings, message)
        self.show_preview({"lines": [message], "text": "", "image": None, "format": None, "metadata": []})

    def show(self, view):
        self.info.delete(*self.info.get_children())
        for name, value in view["info"]:
            self.info.insert("", "end", text=name, values=(value,))
        self.show_page(view["page"], view["pages"], view["hex"])
        self._set(self.strings, view["strings"])
        if view.get("preview"):
            self.show_preview(view["preview"])

    def show_preview(self, preview):
        """Summary lines (warnings in red), the image if one was made, then text and metadata. Nothing is run."""
        import tkinter as tk
        self.preview_summary.configure(state="normal")
        self.preview_summary.delete("1.0", "end")
        for line in preview["lines"]:
            self.preview_summary.insert("end", line + "\n", ("warn",) if line.startswith("⚠") else ())
        self.preview_summary.configure(state="disabled")
        self._photo = None
        self.preview_image.configure(image="", text="")
        if preview.get("image"):
            try:
                self._photo = tk.PhotoImage(data=preview["image"], format=(preview.get("format") or "png").lower())
                self.preview_image.configure(image=self._photo)
            except tk.TclError as exc:
                self.preview_image.configure(text=self.preview_text["no_image"].format(error=exc))
        body = preview.get("text") or ""
        if preview.get("metadata"):
            body = (body + "\n\n" if body else "") + f"[{self.preview_text['metadata']}]\n" + "\n".join(preview["metadata"])
        self._set(self.preview_body, body)

    def show_info(self, rows):
        """Only the 파일 정보 list (for things that are not files, like a listed shadow copy)."""
        self.info.delete(*self.info.get_children())
        for name, value in rows:
            self.info.insert("", "end", text=name, values=(value,))

    def show_page(self, page, pages, text):
        self.page_label.set(f"페이지 {page + 1} / {pages}")
        self._set(self.hex, text)
