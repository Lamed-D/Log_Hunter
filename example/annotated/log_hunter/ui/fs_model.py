# ▶ 원본: log_hunter/ui/fs_model.py
# ▶ 파일 트리의 볼륨·폴더·파일과 읽기 대상을 연결합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Data source tree items read from an image's file system, built without Tk."""
from collections import Counter

from log_hunter.core.tree import TreeNode

FOLDER_LIMIT = 2000
FILESYSTEM_LABELS = {"ntfs": "NTFS", "fat": "FAT", "exfat": "exFAT", "bitlocker": "BitLocker 암호화",
                     "unknown": "알 수 없는 형식"}


def human_size(value):
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024


def prefix_counts(events, origins):
    """Records under each (data source, path prefix), case-insensitive, for folder counts."""
    counts = Counter()
    for event in events:
        name, parts = origins.origin(event.source)
        folded = tuple(p.casefold() for p in parts)
        for depth in range(1, len(folded) + 1):
            counts[(name, folded[:depth])] += 1
    return counts


def _count(counts, source_name, parts):
    return counts.get((source_name, tuple(p.casefold() for p in parts)), 0)


def volume_label(volume):
    fs = FILESYSTEM_LABELS.get(volume.get("filesystem"), volume.get("filesystem") or "")
    return f"볼륨 {volume['index']} ({fs} · {human_size(volume.get('size'))} · 시작 {human_size(volume.get('offset'))})"


def volume_nodes(source_name, image, volumes, counts):
    nodes = []
    for volume in volumes:
        parts = (f"볼륨 {volume['index']}",)
        nodes.append(TreeNode(f"fs:{source_name}:{volume['index']}", volume_label(volume), "source",
                              (source_name, parts), _count(counts, source_name, parts),
                              fs={"image": image, "volume": volume["index"], "parts": (), "directory": True,
                                  "browsable": volume.get("filesystem") == "ntfs"}))
    return nodes


def entry_nodes(parent, rows, counts, limit=FOLDER_LIMIT):
    """Children of an expanded folder node from ImageBrowser.list_dir rows; at most `limit` shown."""
    source_name, parent_parts = parent.value
    nodes = []
    for row in rows[:limit]:
        parts = (*parent_parts, row["name"])
        fs = {**parent.fs, "parts": (*parent.fs["parts"], row["name"]), "directory": row["directory"],
              "size": row["size"], "record": row["record"]}
        label = row["name"] if row["directory"] else f"{row['name']} · {human_size(row['size'])}"
        nodes.append(TreeNode(f"{parent.key}/{row['name']}", label, "source", (source_name, parts),
                              _count(counts, source_name, parts), fs=fs))
    if len(rows) > limit:
        nodes.append(TreeNode(f"{parent.key}/…", f"… 외 {len(rows) - limit:,}개 (표시 상한 {limit:,}개)"))
    return nodes


def needs_loading(node):
    return bool(node and node.fs and node.fs.get("directory") and node.fs.get("browsable", True)
                and not node.children)


# --- file kinds, file views and the folder file table -------------------------------------------

EXTENSION_KINDS = {
    "image": ("jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "ico", "svg"),
    "video": ("mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg", "3gp"),
    "audio": ("mp3", "wav", "wma", "aac", "flac", "ogg", "m4a", "amr"),
    "document": ("doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "odp", "hwp", "hwpx",
                 "csv", "md"),
    "archive": ("zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso", "alz", "egg"),
    "executable": ("exe", "dll", "sys", "msi", "com", "scr", "cpl", "ocx", "drv"),
    "script": ("ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "py", "sh"),
}
_KIND_BY_EXTENSION = {ext: kind for kind, extensions in EXTENSION_KINDS.items() for ext in extensions}
SIZE_BUCKETS = (("size_50_200", 50 << 20, 200 << 20), ("size_200_1g", 200 << 20, 1 << 30), ("size_1g", 1 << 30, None))
VIEW_LIMIT = 10000
PAGE_ROWS = 2000
TABLE_COLUMNS = ("name", "kind", "size", "modified", "created", "accessed", "mft_modified", "state", "records")


def kind_of(name, directory=False):
    if directory:
        return "folder"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return _KIND_BY_EXTENSION.get(ext, "other")


def classify(item):
    """File view categories for one scanned MFT item: its kind (known kinds only), 'deleted', size bucket."""
    if item["directory"]:
        return []
    if not item["in_use"]:
        return ["deleted"]
    keys = [kind_of(item["name"])] if kind_of(item["name"]) != "other" else []
    size = item.get("size") or 0
    keys += [key for key, low, high in SIZE_BUCKETS if size >= low and (high is None or size < high)]
    return keys


def file_view_root(images):
    """'파일 보기' root: per image volume, 종류별 / 삭제된 파일 / 크기별. `images` = [(source name, image, volume index)]."""
    from log_hunter.core.labels import file_view_label
    root = TreeNode("fv", file_view_label("file_views"))
    for name, image, volume in images:
        parent = root
        if len(images) > 1:
            parent = TreeNode(f"fv:{name}:{volume}", f"{name} 볼륨 {volume}")
            root.children.append(parent)

        def view(key, label_key=None):
            return TreeNode(f"fv:{name}:{volume}:{key}", file_view_label(label_key or key), "fileview",
                            {"image": image, "volume": volume, "category": key})

        kinds = TreeNode(f"fv:{name}:{volume}:kinds", file_view_label("by_kind"),
                         children=[view(kind) for kind in EXTENSION_KINDS])
        sizes = TreeNode(f"fv:{name}:{volume}:sizes", file_view_label("by_size"),
                         children=[view(key) for key, _low, _high in SIZE_BUCKETS])
        parent.children += [kinds, view("deleted"), sizes]
    return root


class FileTable:
    """Rows shown in the file list: sort, name search and pages of PAGE_ROWS, without Tk."""

    def __init__(self, rows=(), page_rows=PAGE_ROWS):
        self.all = list(rows)
        self.page_rows = page_rows
        self.sort_key, self.reverse, self.query, self.page = "name", False, "", 0
        self._apply()

    def _apply(self):
        query = self.query.casefold()
        rows = [r for r in self.all if query in r["name"].casefold()] if query else list(self.all)
        key = self.sort_key

        def sort_value(row):
            value = row.get(key)
            if key in ("size", "records"):
                return (value is None, value or 0)
            return (value is None, str(value or "").casefold())

        rows.sort(key=sort_value, reverse=self.reverse)
        if key == "name":
            rows.sort(key=lambda r: not r.get("directory"))  # folders stay on top (stable sort)
        self.rows = rows
        self.page = min(self.page, self.pages - 1)

    @property
    def pages(self):
        return max(1, -(-len(self.rows) // self.page_rows))

    def sort(self, key):
        self.reverse = not self.reverse if key == self.sort_key else False
        self.sort_key = key
        self._apply()

    def search(self, text):
        self.query, self.page = text.strip(), 0
        self._apply()

    def turn(self, delta):
        self.page = min(max(0, self.page + delta), self.pages - 1)

    def page_slice(self):
        start = self.page * self.page_rows
        return self.rows[start:start + self.page_rows]

    def status(self):
        shown = len(self.rows)
        text = f"{shown:,}개" if shown == len(self.all) else f"{shown:,}개 / 전체 {len(self.all):,}개"
        return text + (f" · 페이지 {self.page + 1}/{self.pages}" if self.pages > 1 else "")


def table_values(row):
    from log_hunter.core.labels import file_kind_label
    if row.get("error"):
        state = "읽기 오류"
    elif row.get("check"):
        state = row["check"]
    elif row.get("in_use") is None:
        state = ""
    else:
        state = "사용 중" if row["in_use"] else "삭제됨"
    return (row["name"], file_kind_label(row.get("kind") or kind_of(row["name"], row.get("directory"))),
            "" if row.get("directory") else human_size(row.get("size")), row.get("modified") or "",
            row.get("created") or "", row.get("accessed") or "", row.get("mft_modified") or "", state,
            row.get("records") or "")


def folder_rows(parent, rows, counts):
    """File table rows for the entries of folder node `parent` (with record counts)."""
    source_name, parent_parts = parent.value
    out = []
    for row in rows:
        parts = (*parent_parts, row["name"])
        out.append({**row, "kind": kind_of(row["name"], row["directory"]), "parts": (*parent.fs["parts"], row["name"]),
                    "records": _count(counts, source_name, parts)})
    return out


def snapshot_nodes(source_name, image, catalogs):
    """Shadow copy list nodes for an opened image (one group per volume that has a catalog). Selecting one only
    describes it: the list is not a readable volume."""
    from log_hunter.core.labels import SNAPSHOT_TEXT as T
    if isinstance(catalogs, dict) and catalogs.get("error"):
        return [TreeNode(f"vss:{source_name}:error", T["failed"].format(error=catalogs["error"]), "snapshot",
                         {"error": catalogs["error"]})]
    nodes = []
    for catalog in catalogs or ():
        volume = (catalog.get("volume") or {}).get("index")
        snapshots, errors = catalog.get("snapshots") or [], catalog.get("errors") or []
        if not catalog.get("present") and not errors:
            continue
        group = TreeNode(f"vss:{source_name}:{volume}", T["group"].format(volume=volume, count=len(snapshots)), "group")
        for snap in snapshots:
            label = (snap.get("created_at") or T["no_time"]) + " · " + T["store"].format(id=snap.get("store_id", ""))
            flags = [T["ambiguous"]] if snap.get("ambiguous") else []
            if not snap.get("catalog_complete"):
                flags.append(T["incomplete"])
            if flags:
                label += " (" + ", ".join(flags) + ")"
            group.children.append(TreeNode(f"vss:{source_name}:{volume}:{snap.get('store_id')}", label, "snapshot",
                                           {"volume": volume, "image": image, "snapshot": snap}))
        if errors:
            group.children.append(TreeNode(f"vss:{source_name}:{volume}:errors", T["errors"].format(count=len(errors)),
                                           "snapshot", {"volume": volume, "image": image, "errors": errors}))
        nodes.append(group)
    return nodes


def snapshot_info(value):
    """(name, value) rows describing a listed shadow copy or the list's problems."""
    from log_hunter.core.labels import SNAPSHOT_TEXT as T
    I = T["info"]
    if "error" in value:
        return [(I["error"], value["error"])]
    if "errors" in value:
        return [(I["volume"], str(value.get("volume")))] + [
            (I["error"], f"{e.get('locator', '')}: {e.get('message', '')}" if isinstance(e, dict) else str(e))
            for e in value["errors"]]
    snap = value["snapshot"]
    yes_no = lambda v: T["yes"] if v else T["no"]
    return [(I["volume"], str(value.get("volume"))),
            (I["created"], snap.get("created_at") or T["no_time"]), (I["time_note"], T["time_note"]),
            (I["raw"], str(snap.get("creation_filetime_raw") or "")),
            (I["store_id"], str(snap.get("store_id") or "")), (I["store_note"], T["store_note"]),
            (I["volume_size"], human_size(snap.get("volume_size"))),
            (I["entry"], str(snap.get("catalog_entry_offset", ""))),
            (I["complete"], T["complete"] if snap.get("catalog_complete") else T["not_complete"]),
            (I["ambiguous"], yes_no(snap.get("ambiguous"))), (I["readable"], T["not_readable"])]


def image_source_name(path):
    """Tree name of an opened image or drive, the same as core.tree.source_name gives after extraction."""
    from pathlib import PureWindowsPath
    from log_hunter.image.live import is_live_path, live_device
    if is_live_path(path):
        return f"이 PC ({live_device(path)[4:]})"
    return PureWindowsPath(str(path)).name


def file_view_label_for(category):
    from log_hunter.core.labels import file_view_label
    return file_view_label(category)
