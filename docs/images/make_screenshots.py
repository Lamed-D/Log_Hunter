"""Make the README screenshots (docs/images/gui-*.png) from a synthetic E01 — fake data only.

Windows only. Run from the repository root:  python docs/images/make_screenshots.py
The synthetic image and the GUI's temporary folders live under C:\\Evidence (a fake path allowed by the
data policy), so no real user path can appear on screen. Only the Log Hunter window is rendered
(PrintWindow), so other windows on the screen can never end up in an image. Pixel output depends on
fonts and display scaling, so images are not byte-identical between PCs.
"""
import ctypes
import os
import shutil
import struct
import sys
import tempfile
import time
import tkinter as tk
import zlib
from ctypes import wintypes
from pathlib import Path
from tkinter import ttk

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from test_image import mbr_disk, windows_volume, write_e01  # noqa: E402  (synthetic NTFS + E01 builders)
from log_hunter.ui import app  # noqa: E402

DEMO = Path(r"C:\Evidence")
OUT = ROOT / "docs" / "images"
CASE, WORK = DEMO / "case", DEMO / "tmp"
log = []


def _fixed_mkdtemp(suffix="", prefix="tmp", dir=None):
    """Same folder names on every run (instead of random ones) so the screenshots are repeatable."""
    path = WORK / f"{prefix}demo{suffix}"
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True)
    return str(path)


def _png(width, height, rows):
    """Minimal PNG writer (RGB, no filtering) so no imaging package is needed."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(bytes([0]) + row for row in rows)
    signature = bytes([0x89]) + b"PNG" + bytes([13, 10, 26, 10])
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return signature + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]


def capture(root, name):
    """Render only the Log Hunter window into docs/images/<name>.png."""
    root.update()
    time.sleep(0.6)
    root.update()
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    hwnd = user32.GetAncestor(root.winfo_id(), 2)  # GA_ROOT: top-level frame including the title bar
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    window_dc = user32.GetWindowDC(hwnd)
    memory_dc = gdi32.CreateCompatibleDC(window_dc)
    bitmap = gdi32.CreateCompatibleBitmap(window_dc, width, height)
    gdi32.SelectObject(memory_dc, bitmap)
    user32.PrintWindow(hwnd, memory_dc, 2)  # PW_RENDERFULLCONTENT
    header = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), width, -height, 1, 32, 0, 0, 0, 0, 0, 0)
    buffer = ctypes.create_string_buffer(width * height * 4)
    gdi32.GetDIBits(memory_dc, bitmap, 0, height, buffer, ctypes.byref(header), 0)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(memory_dc)
    user32.ReleaseDC(hwnd, window_dc)
    data = buffer.raw
    rows = []
    for y in range(height):
        line = data[y * width * 4:(y + 1) * width * 4]
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rows.append(bytes(rgb))
    target = OUT / f"{name}.png"
    target.write_bytes(_png(width, height, rows))
    log.append(f"{name}: {width}x{height} {target.stat().st_size // 1024}KB")


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def script(root):
    root.geometry("1280x900+20+20")
    widgets = list(walk(root))
    nav = next(w for w in widgets if isinstance(w, ttk.Treeview) and "heading" not in str(w["show"]))
    table = next(w for w in widgets if isinstance(w, ttk.Treeview) and "artifact" in w["columns"])
    notebooks = [w for w in widgets if isinstance(w, ttk.Notebook)]
    status = next(w for w in widgets if isinstance(w, ttk.Label) and str(w.cget("textvariable"))
                  and str(w.getvar(str(w.cget("textvariable")))).startswith("디스크 이미지(E01)를"))
    next(w for w in widgets if isinstance(w, ttk.Button) and w.cget("text").startswith("디스크 이미지 열기")).invoke()

    def find(label, item=""):
        for child in nav.get_children(item):
            if nav.item(child, "text").startswith(label):
                return child
            hit = find(label, child)
            if hit:
                return hit

    def select_tab(text):
        notebook = next(n for n in notebooks if any(n.tab(t, "text") == text for t in n.tabs()))
        notebook.select(next(t for t in notebook.tabs() if notebook.tab(t, "text") == text))

    def wait(condition, then, tries=0):
        if condition():
            then()
        elif tries > 150:
            log.append("TIMEOUT")
            root.destroy()
        else:
            root.after(100, lambda: wait(condition, then, tries + 1))

    def expand(label, then):
        iid = find(label)
        nav.item(iid, open=True)
        nav.focus(iid)
        nav.event_generate("<<TreeviewOpen>>")
        root.after(700, then)

    def scene_main():
        # 1) main screen: whole timeline, the recycle bin record selected, 기록 정보 below
        nav.selection_set(find("찾은 기록"))
        root.update()
        select_tab("타임라인")
        first = table.get_children()[0]
        table.selection_set(first)
        table.see(first)
        root.update()
        select_tab("기록 정보")
        capture(root, "gui-main")
        expand("볼륨 0", lambda: expand("Windows", lambda: expand("System32", lambda: expand("config", scene_files))))

    def scene_files():
        # 2) image file explorer: config folder file list, SYSTEM row selected, 16진수 below
        config = find("config")
        nav.selection_set(config)
        nav.see(config)
        root.update()

        def pick_row():
            files = next(w for w in walk(root) if isinstance(w, ttk.Treeview) and "kind" in w["columns"])
            row = next(i for i in files.get_children() if files.item(i, "values")[0] == "SYSTEM")
            files.selection_set(row)
            root.update()
            root.after(1200, show_hex)

        def show_hex():
            select_tab("16진수")
            capture(root, "gui-image-files")
            scene_category()

        root.after(1500, pick_row)

    def scene_category():
        # 3) category result table: 입력한 명령어 with its own columns
        nav.selection_set(find("입력한 명령어"))
        nav.see(find("입력한 명령어"))
        root.update()
        capture(root, "gui-category-table")
        root.destroy()

    wait(lambda: "분석 완료" in status.getvar(str(status.cget("textvariable"))), lambda: root.after(800, scene_main))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for folder in (CASE, WORK):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
    tempfile.mkdtemp = _fixed_mkdtemp
    # Default column order/widths every run, and the examiner's own settings file is never read or written.
    os.environ["LOG_HUNTER_SETTINGS"] = str(WORK / "settings.json")
    volume, _system = windows_volume()
    e01 = write_e01(CASE / "case.E01", mbr_disk(volume))[0]
    app.filedialog.askopenfilename = lambda **_k: str(e01)
    app.messagebox.showinfo = app.messagebox.showwarning = lambda *_a, **_k: None
    app.messagebox.askyesno = lambda *_a, **_k: False
    original = tk.Tk.mainloop

    def scripted(self, n=0):
        self.after(300, lambda: script(self))
        original(self, n)

    tk.Tk.mainloop = scripted
    app.run()
    print("\n".join(log))


if __name__ == "__main__":
    main()
