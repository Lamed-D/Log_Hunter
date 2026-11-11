# Teaching copy: examiner tags remain separate from evidence.
"""Examiner tags and notes on records and files: the examiner's judgement, kept apart from the evidence data."""
import hashlib
import json
import os
from datetime import datetime, timezone

from .labels import TAG_COLOR_DEFAULT_NAMES, TAG_COLOR_WORDS, tag_label
from .tree import TreeNode

# Three colours, each optionally with examiner-made subcategories: a tag is "red" or "red/유출 의심".
COLORS = ("red", "yellow", "green")
TAG_KEYS = COLORS
LEGACY_TAGS = {"notable": "red", "follow_up": "yellow", "benign": "green"}  # tags saved before colours
TAG_FORMAT = 2  # 1: notable / follow_up / benign
KEY_VERSION = 2  # 1: no record content or file sequence in the key (could move a note to other content)
# Filled in by analysis (enrichment), not read from the evidence: a re-run may change them for the same record.
DERIVED_DETAIL_KEYS = frozenset({"activity_class", "risk_score", "session_id"})


def _digest(value):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def event_key(event):
    """Identity of a record: the same evidence content gets the same key in another run, and other
    content at the same source/locator (a changed command, another event payload) gets another key."""
    content = {k: v for k, v in (event.details or {}).items() if k not in DERIVED_DETAIL_KEYS}
    fields = [event.artifact, event.source, event.locator, event.timestamp, event.time_field, event.action,
              event.path, event.process, event.url, event.sid, content]
    return "event:" + _digest(fields)


def image_identity(image):
    """Size and modification time of an image file, so a tag does not move to another image saved at
    the same path. None when it cannot be read (e.g. this PC's live drive)."""
    try:
        stat = os.stat(image)
    except (OSError, ValueError):
        return None
    return [stat.st_size, stat.st_mtime_ns]


def file_key(image, volume, parts, record=None, sequence=None, image_id=None):
    """Identity of an image file: MFT record + sequence number (a reused record gets a new sequence)."""
    return "file:" + json.dumps([str(image), volume, list(parts), record, sequence, image_id], ensure_ascii=False)


def event_ref(event):
    return {"artifact": event.artifact, "timestamp": event.timestamp, "time_field": event.time_field,
            "action": event.action, "path": event.path or event.process or event.url, "sid": event.sid,
            "source": event.source, "locator": event.locator}


def file_ref(image, volume, parts, record=None, image_name="", sequence=None, image_id=None):
    return {"image": str(image), "image_name": image_name, "volume": volume, "parts": list(parts),
            "image_path": "\\" + "\\".join(parts), "mft_record": record, "mft_sequence": sequence,
            "image_id": image_id}


def normalize_tag(tag):
    """'red' or 'red/<subcategory>'; old tag names become their colour. Anything else is refused."""
    tag = LEGACY_TAGS.get(tag, tag)
    color, _, sub = str(tag).partition("/")
    sub = sub.strip()
    if color not in COLORS or (_ and not sub):
        raise ValueError(f"알 수 없는 태그: {tag}")
    return f"{color}/{sub}" if sub else color


def tag_color(tag):
    return str(tag).partition("/")[0]


def migrate_row(row):
    """A saved tag row in the current format (old rows: notable -> red, follow_up -> yellow, benign -> green)."""
    row = dict(row)
    tags = []
    for tag in row.get("tags") or ():
        try:
            tags.append(normalize_tag(tag))
        except ValueError:
            continue
    row["tags"] = sorted(set(tags))
    row["tag_format"] = TAG_FORMAT
    return row


class TagBook:
    def __init__(self, color_names=None, subcategories=None):
        self.items = {}  # key -> {"target", "ref", "tags": set, "note", "updated_at"}
        self.color_names = {c: (color_names or {}).get(c) or TAG_COLOR_DEFAULT_NAMES[c] for c in COLORS}
        self.subcategories = {c: [s for s in (subcategories or {}).get(c) or () if isinstance(s, str) and s.strip()]
                              for c in COLORS}

    def label(self, tag):
        """'빨강 · 중요·확인 필요' for a colour, '빨강 › 유출 의심' for a subcategory, '메모 있음' for notes."""
        color, _, sub = str(tag).partition("/")
        if color not in COLORS:
            return tag_label(tag)
        return f"{TAG_COLOR_WORDS[color]} › {sub}" if sub else f"{TAG_COLOR_WORDS[color]} · {self.color_names[color]}"

    def rename_color(self, color, name):
        if color in COLORS and (name or "").strip():
            self.color_names[color] = name.strip()

    def add_subcategory(self, color, name):
        """Register a subcategory under a colour; returns its tag ('red/<name>')."""
        tag = normalize_tag(f"{color}/{(name or '').strip()}")
        sub = tag.partition("/")[2]
        if sub not in self.subcategories[color]:
            self.subcategories[color].append(sub)
        return tag

    def rename_subcategory(self, color, old, new):
        """Rename a subcategory and every tag that uses it; returns the new tag, or None when nothing changed."""
        new_tag = normalize_tag(f"{color}/{(new or '').strip()}")
        new_sub, old_tag = new_tag.partition("/")[2], f"{color}/{old}"
        if old not in self.subcategories[color] or new_sub == old:
            return None
        names = self.subcategories[color]
        names[names.index(old)] = new_sub
        self.subcategories[color] = list(dict.fromkeys(names))  # renaming onto an existing name merges them
        for item in self.items.values():
            if old_tag in item["tags"]:
                item["tags"].discard(old_tag)
                item["tags"].add(new_tag)
        return new_tag

    def delete_subcategory(self, color, name):
        """Remove a subcategory and take it off every item (their colour and other tags stay)."""
        if name not in self.subcategories[color]:
            return 0
        self.subcategories[color].remove(name)
        tag, changed = f"{color}/{name}", 0
        for key in list(self.items):
            if tag in self.items[key]["tags"]:
                self.items[key]["tags"].discard(tag)
                changed += 1
                self._drop_if_empty(key)
        return changed

    def preferences(self):
        """Colour names and subcategory lists, kept in the user's settings (not the case)."""
        return {"color_names": dict(self.color_names), "subcategories": {c: list(v) for c, v in self.subcategories.items()}}

    def top_color(self, key):
        """The most urgent colour on an item (red, then yellow, then green), for the timeline row colour."""
        colors = {tag_color(t) for t in self.tags_for(key)}
        return next((c for c in COLORS if c in colors), None)

    def load_rows(self, rows):
        """Bring saved rows (any format) back into the book; their subcategories join the lists."""
        for row in rows:
            row = migrate_row(row)
            if not row.get("key") or not (row["tags"] or row.get("note")):
                continue
            self.items[row["key"]] = {"target": row.get("target"), "ref": row.get("ref") or {}, "tags": set(row["tags"]),
                                      "note": row.get("note") or "", "updated_at": row.get("updated_at") or ""}
            for tag in row["tags"]:
                color, _, sub = tag.partition("/")
                if sub and sub not in self.subcategories[color]:
                    self.subcategories[color].append(sub)

    def _item(self, key, target, ref):
        item = self.items.setdefault(key, {"target": target, "ref": ref, "tags": set(), "note": "", "updated_at": ""})
        item["updated_at"] = datetime.now(timezone.utc).isoformat()
        return item

    def _drop_if_empty(self, key):
        item = self.items.get(key)
        if item is not None and not item["tags"] and not item["note"]:
            del self.items[key]

    def toggle(self, key, target, ref, tag):
        tag = normalize_tag(tag)
        tags = self._item(key, target, ref)["tags"]
        tags.symmetric_difference_update({tag})
        self._drop_if_empty(key)

    def set_note(self, key, target, ref, note):
        self._item(key, target, ref)["note"] = (note or "").strip()
        self._drop_if_empty(key)

    def clear(self, key):
        self.items.pop(key, None)

    def tags_for(self, key):
        item = self.items.get(key)
        return set(item["tags"]) if item else set()

    def note_for(self, key):
        item = self.items.get(key)
        return item["note"] if item else ""

    def keys_with(self, tag=None):
        """Keys carrying `tag`; a colour also matches its subcategories; tag=None means anything tagged,
        "note" means anything with a note."""
        if tag == "note":
            return {k for k, v in self.items.items() if v["note"]}
        if tag in COLORS:
            return {k for k, v in self.items.items() if any(tag_color(t) == tag for t in v["tags"])}
        return {k for k, v in self.items.items() if (tag in v["tags"] if tag else v["tags"] or v["note"])}

    def rows(self):
        """Plain dicts for saving: target, ref, sorted tags with their shown names, note, updated_at."""
        return [{"key": key, "key_version": KEY_VERSION, "tag_format": TAG_FORMAT, "target": v["target"], "ref": v["ref"],
                 "tags": sorted(v["tags"]), "tag_labels": [self.label(t) for t in sorted(v["tags"])],
                 "note": v["note"], "updated_at": v["updated_at"]}
                for key, v in sorted(self.items.items(), key=lambda kv: kv[1]["updated_at"])]


def tag_tree(book, events):
    """The "분석자 태그" tree root: colour > subcategory (records as event sets), notes, and the tagged image files."""
    keys = {id(event): event_key(event) for event in events}
    root = TreeNode("tags", "분석자 태그", "group")

    def node(tag):
        wanted = book.keys_with(tag)
        ids = frozenset(i for i, key in keys.items() if key in wanted)
        return TreeNode(f"tags:{tag}", book.label(tag), "event_set", ids, len(ids)) if ids else None

    for color in COLORS:
        top = node(color)
        if top is None:
            continue
        top.children = [n for n in (node(f"{color}/{sub}") for sub in book.subcategories[color]) if n]
        root.children.append(top)
    notes = node("note")
    if notes:
        root.children.append(notes)
    files = [row for row in book.rows() if row["target"] == "file"]
    if files:
        root.children.append(TreeNode("tags:files", "태그한 파일", "tagged_files", None, len(files)))
    if not root.children:
        root.children.append(TreeNode("tags:none", "타임라인·파일 목록에서 오른쪽 클릭으로 태그를 붙입니다", "group"))
    return root


def save_to_sqlite(path, rows):
    """Add the examiner's tags to an existing case.sqlite in their own table (evidence tables untouched)."""
    import sqlite3
    from contextlib import closing
    with closing(sqlite3.connect(path)) as db:
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS examiner_tags(id INTEGER PRIMARY KEY, key TEXT NOT NULL, data TEXT NOT NULL)")
            db.executemany("INSERT INTO examiner_tags(key, data) VALUES(?, ?)",
                           [(row["key"], json.dumps(row, ensure_ascii=False)) for row in rows])
    return len(rows)


def load_from_sqlite(path):
    """Tag rows saved in a case.sqlite (read-only), in the current format; old colourless rows are converted."""
    import sqlite3
    from contextlib import closing
    from pathlib import Path
    uri = Path(path).resolve().as_uri() + "?mode=ro"  # read-only: never changes the saved case
    with closing(sqlite3.connect(uri, uri=True)) as db:
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "examiner_tags" not in names:
            return []
        rows = []
        for key, data in db.execute("SELECT key, data FROM examiner_tags ORDER BY id"):
            try:
                row = json.loads(data)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(migrate_row({**row, "key": row.get("key") or key}))
        return rows
