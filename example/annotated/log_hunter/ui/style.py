# Runtime source with the same executable tokens.
"""Colors and the common dialog look shared by the GUI table, charts and dialogs."""

ARTIFACT_COLORS = {
    'defender': '#c0392b',
    'thumbcache': '#8d6e63',
    'rdp': '#546e7a',
    "evtx": "#e74c3c", "prefetch": "#3498db", "mft": "#2ecc71", "services": "#9b59b6",
    "startup": "#b8860b",
    "userassist": "#e67e22", "bam": "#1abc9c", "run": "#f39c12", "mru": "#8e44ad",
    "usb": "#d35400", "amcache": "#27ae60", "psreadline": "#c0392b", "history": "#2980b9",
    "cache": "#7f8c8d", "shellbag": "#16a085", "srum": "#e91e63", "lnk": "#ff9800",
    "jumplist": "#795548", "network": "#607d8b", "tasks": "#9c27b0", "taskcache": "#9c27b0",
    "wlan": "#00bcd4", "recyclebin": "#ff5722",
}
# Row background of records the examiner tagged, by the most urgent colour on them.
TAG_ROW_COLORS = {"red": "#f9d6d5", "yellow": "#fff3c4", "green": "#d8f0d8"}
BAR_COLORS = ["#e74c3c", "#3498db", "#2ecc71", "#e67e22", "#9b59b6",
              "#1abc9c", "#f39c12", "#d35400", "#27ae60", "#c0392b",
              "#2980b9", "#8e44ad", "#16a085", "#7f8c8d", "#e91e63",
              "#ff9800", "#795548", "#607d8b", "#9c27b0", "#00bcd4"]

# Properties dialog: bold item names on the left, read-only blue values on the right, even spacing.
DIALOG_STYLE = {"label_font": ("Segoe UI", 9, "bold"), "value_font": ("Segoe UI", 9), "value_color": "#1a5fb4",
                "value_background": "#ffffff", "pad_x": 12, "pad_y": 4, "min_width": 560, "value_chars": 60}
