# ▶ 원본: log_hunter/ui/properties.py
# ▶ 모든 분류가 같이 쓰는 속성 대화상자: 왼쪽 항목 이름, 오른쪽 읽기 전용 값 칸, [확인], [자세히…].
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""The one properties dialog every record category uses: name/value rows, [확인], and 자세히… for the longer lists."""
import tkinter as tk
from tkinter import ttk

from log_hunter.core.labels import PROPERTY_BUTTONS as B
from .style import DIALOG_STYLE as S


class PropertiesDialog:
    def __init__(self, parent, props):
        self.top = tk.Toplevel(parent)
        self.top.title(props.title)
        self.top.transient(parent)
        self.values = {}
        body = ttk.Frame(self.top, padding=(S["pad_x"], S["pad_x"], S["pad_x"], 4))
        body.pack(fill="x")
        body.columnconfigure(1, weight=1)  # widening the window widens the value boxes
        for row, (label, value) in enumerate(props.fields):
            ttk.Label(body, text=label, font=S["label_font"]).grid(row=row, column=0, sticky="w",
                                                                   padx=(0, S["pad_x"]), pady=S["pad_y"])
            var = tk.StringVar(value=value)
            # Read-only but selectable and copyable; a long value scrolls inside its box.
            entry = tk.Entry(body, textvariable=var, state="readonly", font=S["value_font"], fg=S["value_color"],
                             readonlybackground=S["value_background"], width=S["value_chars"], relief="solid", bd=1)
            entry.grid(row=row, column=1, sticky="ew", pady=S["pad_y"])
            self.values[label] = var
        buttons = ttk.Frame(self.top, padding=(S["pad_x"], 6, S["pad_x"], S["pad_x"]))
        buttons.pack(fill="x", side="bottom")
        self.more_button = ttk.Button(buttons, text=B["more"], command=self.toggle)
        if props.tabs:
            self.more_button.pack(side="left")
        ttk.Button(buttons, text=B["ok"], command=self.close, default="active").pack(side="right")
        self.tabs = props.tabs
        self.detail = None
        self.top.bind("<Return>", lambda _e: self.close())
        self.top.bind("<Escape>", lambda _e: self.close())
        self.top.update_idletasks()
        self.top.minsize(S["min_width"], self.top.winfo_reqheight())
        self.top.focus_set()  # Enter / Esc work right away

    def set_value(self, label, value):
        """Fill a field that a background check answers later (for example whether a program file still exists)."""
        if label in self.values and self.top.winfo_exists():
            self.values[label].set(value)

    def toggle(self):
        if self.detail is not None:
            self.detail.destroy()
            self.detail = None
            self.more_button.configure(text=B["more"])
            self.top.geometry("")
            return
        self.more_button.configure(text=B["less"])
        self.detail = ttk.Notebook(self.top)
        self.detail.pack(fill="both", expand=True, padx=S["pad_x"])
        for name, lines, searchable in self.tabs:
            self.detail.add(_list_tab(self.detail, lines, searchable), text=name)
        self.top.geometry("")

    def close(self):
        self.top.destroy()


def _list_tab(notebook, lines, searchable):
    """A read-only list (one line per item) with an optional search box and a copy button."""
    frame = ttk.Frame(notebook, padding=4)
    if searchable:
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Label(bar, text=B["search"]).pack(side="left")
        query = tk.StringVar()
        ttk.Entry(bar, textvariable=query, width=30).pack(side="left", padx=4)
    text = tk.Text(frame, height=12, wrap="none", font=S["value_font"])
    scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    text.pack(fill="both", expand=True)

    def fill(*_args):
        wanted = query.get().casefold() if searchable else ""
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", "\n".join(line for line in lines if wanted in line.casefold()))
        text.configure(state="disabled")  # still selectable; Ctrl+C copies the selection

    if searchable:
        query.trace_add("write", fill)
        ttk.Button(bar, text=B["copy"], command=lambda: _copy(text)).pack(side="right")
    fill()
    return frame


def _copy(text):
    try:
        chosen = text.get("sel.first", "sel.last")
    except tk.TclError:
        chosen = text.get("1.0", "end-1c")
    text.clipboard_clear()
    text.clipboard_append(chosen)
