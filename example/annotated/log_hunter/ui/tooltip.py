"""A small hover note for a widget; the text comes from a function so it can say why something is turned off."""
import tkinter as tk


class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.window = widget, text, None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")

    def current(self):
        return self.text() if callable(self.text) else self.text

    def show(self, _event=None):
        text = self.current()
        if not text or self.window is not None:
            return
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.wm_geometry(f"+{self.widget.winfo_rootx() + 10}+{self.widget.winfo_rooty() + self.widget.winfo_height() + 4}")
        tk.Label(self.window, text=text, background="#ffffe0", relief="solid", borderwidth=1,
                 wraplength=420, justify="left").pack()

    def hide(self, _event=None):
        if self.window is not None:
            self.window.destroy()
            self.window = None
