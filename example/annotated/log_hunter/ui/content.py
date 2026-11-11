# ▶ 원본: log_hunter/ui/content.py
# ▶ 선택 파일의 제한된 페이지를 텍스트·16진수로 표시할 자료를 만듭니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Content viewer data without Tk: hex pages, readable strings and file information rows."""
import hashlib
import os
import re
from datetime import datetime, timezone

from log_hunter.core.labels import file_info_label

PAGE_SIZE = 4096
STRING_SCAN_LIMIT = 1024 * 1024
STRING_LIMIT = 5000
HASH_LIMIT = 256 * 1024 * 1024
_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
FILE_INFO_ORDER = ("path", "image", "drive", "volume", "image_path", "mft_record", "mft_sequence", "in_use", "size",
                   "created", "modified", "accessed", "mft_modified", "sha256", "extracted_copy", "note")


class LocalFile:
    """A file on this computer (evidence added directly, or a copy extracted from an image). Read-only."""

    def __init__(self, path):
        self.path = str(path)
        self.size = os.path.getsize(self.path)

    def read(self, offset, length):
        with open(self.path, "rb") as stream:
            stream.seek(offset)
            return stream.read(max(0, length))

    def sha256(self):
        digest = hashlib.sha256()
        with open(self.path, "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def info(self):
        stat = os.stat(self.path)
        return {"path": self.path, "size": self.size,
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()}


def preview_view(source):
    """미리 보기 tab data from the read-only preview engine: summary lines, text, image bytes and metadata lines.
    Image-inside files are passed as they are; files on this computer by path (added files or extracted copies)."""
    from log_hunter.core.labels import PREVIEW_DATA_STATE_LABELS, PREVIEW_KIND_LABELS, PREVIEW_TEXT as T
    from log_hunter.core.preview import preview
    try:
        result = preview(source.path if isinstance(source, LocalFile) else source)
    except Exception as exc:  # unsupported input, folder, link: say so instead of a traceback
        return {"lines": [T["failed"].format(error=exc)], "text": "", "image": None, "format": None, "metadata": []}
    lines = [f"{T['kind']}: {PREVIEW_KIND_LABELS.get(result.kind, result.kind)}",
             f"{T['state']}: {PREVIEW_DATA_STATE_LABELS.get(result.data_state, result.data_state)}",
             f"{T['name']}: {result.name}  ·  {T['size']}: {result.size:,} 바이트"]
    if result.signature_format:
        lines.append(f"{T['format']}: {result.signature_format}  ·  {T['extension']}: {result.extension or '-'}")
    if result.extension_mismatch:
        lines.append("⚠ " + T["mismatch"].format(extension=(result.extension or "-").lstrip("."), format=result.signature_format or "?"))
    if result.reason:
        lines.append(f"{T['reason']}: {result.reason}")
    if result.truncated:
        lines.append(T["truncated"])
    lines += [f"{T['warning']}: {w}" for w in result.warnings]
    lines += [f"{T['error']}: {getattr(e, 'message', e)}" for e in result.errors]
    metadata = [f"{k}: {v}" for k, v in (result.metadata or {}).items() if k != "preview_format"]
    return {"lines": lines, "text": result.text or "", "image": result.image_bytes or None,
            "format": (result.metadata or {}).get("preview_format"), "metadata": metadata}


def page_count(size):
    return max(1, -(-size // PAGE_SIZE))


def hex_lines(data, base_offset=0):
    """'00001000  4d 5a 90 00 ...  |MZ..|' lines, 16 bytes each."""
    lines = []
    for start in range(0, len(data), 16):
        chunk = data[start:start + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base_offset + start:08x}  {hex_part:<47}  |{text}|")
    return lines


def extract_strings(data, limit=STRING_LIMIT):
    """Readable runs of 4+ characters: [(offset, "ASCII"|"UTF-16", text)] in file order."""
    found = [(m.start(), "ASCII", m.group().decode("ascii")) for m in _ASCII.finditer(data)]
    found += [(m.start(), "UTF-16", m.group().decode("utf-16-le")) for m in _UTF16.finditer(data)]
    found.sort()
    return found[:limit]


def strings_text(strings, truncated):
    lines = [f"{offset:08x}  {kind:<6}  {text}" for offset, kind, text in strings]
    if truncated:
        lines.append(f"… 처음 {STRING_SCAN_LIMIT // 1024 // 1024}MB 또는 {STRING_LIMIT}개까지만 보여 줍니다")
    return "\n".join(lines) if lines else "읽을 수 있는 문자열이 없습니다"


def load(source, extra=None):
    """Everything the viewer shows for a newly selected file. Runs on the worker thread."""
    extra = extra or {}
    info = source.info()
    if extra.get("image_path"):
        # A copy extracted from an image: its own path and mtime are from the extraction, not the
        # evidence. Show the copy's location separately and keep only times recorded in the image.
        info["extracted_copy"] = info.pop("path", None)
        info.pop("modified", None)
    info.update(extra)
    if "sha256" not in info:
        info["sha256"] = source.sha256() if source.size <= HASH_LIMIT else "파일이 커서 계산하지 않았습니다"
    head = source.read(0, STRING_SCAN_LIMIT)
    strings = extract_strings(head)
    return {"info": info_rows(info), "page": 0, "pages": page_count(source.size), "hex": read_page(source, 0),
            "strings": strings_text(strings, source.size > STRING_SCAN_LIMIT or len(strings) >= STRING_LIMIT)}


def read_page(source, page):
    data = source.read(page * PAGE_SIZE, PAGE_SIZE)
    return "\n".join(hex_lines(data, page * PAGE_SIZE)) or "(빈 파일)"


def info_rows(info):
    keys = [k for k in FILE_INFO_ORDER if info.get(k) not in (None, "")]
    keys += sorted(k for k in info if k not in FILE_INFO_ORDER and info[k] not in (None, ""))
    return [(file_info_label(k), _display(k, info[k])) for k in keys]


def _display(key, value):
    if key == "size" and isinstance(value, int):
        return f"{value:,}바이트"
    if key == "in_use":
        return "사용 중" if value else "삭제됨(사용 안 함)"
    return str(value)


def record_file_extra(source, evidence, extractions=()):
    """What is known about a record's source file beyond the file itself: where it sits inside the
    image, its MFT number and times there, and the SHA-256 taken when it was registered."""
    key = os.path.normcase(os.path.abspath(str(source)))
    extra = {}
    for item in evidence:
        if os.path.normcase(os.path.abspath(str(item.source))) == key:
            meta = item.metadata or {}
            extra = {k: meta[k] for k in ("image", "drive", "volume", "image_path", "mft_record") if meta.get(k) is not None}
            extra["sha256"] = item.sha256
            break
    for extraction in extractions:
        origin = extraction.file_index().get(str(os.path.abspath(str(source))).casefold())
        if origin:
            for k in ("created", "modified", "accessed", "mft_modified", "mft_sequence"):
                if origin.get(k):
                    extra[k] = origin[k]
    return extra


class ContentSession:
    """Which file the viewer shows and which page of it, without Tk.

    Every file switch starts a new generation and forgets the old file at once, so a page read
    for the previous file can neither be started while the next one loads nor be shown after it."""

    def __init__(self):
        self.generation = 0
        self.source = None
        self.page = 0
        self.pages = 1

    def open(self, make_source, extra=None):
        """Forget the current file; returns the job to run on the worker thread."""
        self.generation += 1
        self.source, self.page, self.pages = None, 0, 1
        generation = self.generation

        def job():
            try:
                source = make_source()
                view = load(source, extra)
                view["preview"] = preview_view(source)
                return generation, source, view, None
            except Exception as exc:  # shown in the viewer instead of a traceback
                return generation, None, None, str(exc)

        return job

    def accept_content(self, value):
        """('view', view) / ('error', message) for the current file, None for a stale result."""
        generation, source, view, error = value
        if generation != self.generation:
            return None
        if error is not None:
            return "error", error
        self.source, self.page, self.pages = source, 0, view["pages"]
        return "view", view

    def turn(self, delta):
        """Job reading the next/previous page, or None (no file yet, or already at the edge)."""
        if self.source is None:
            return None
        page = min(max(0, self.page + delta), self.pages - 1)
        if page == self.page:
            return None
        self.page = page
        generation, source = self.generation, self.source
        return lambda: (generation, page, read_page(source, page))

    def accept_page(self, value):
        generation, page, text = value
        if generation != self.generation or page != self.page:
            return None
        return page, text


def save_copy(source, folder, name, origin):
    """Write the file's bytes to `folder/name` as a NEW file (never overwrites) and a small JSON record
    `name.log-hunter.json` beside it with where it came from and its SHA-256. The image is only read."""
    import json
    from pathlib import Path
    folder = Path(folder)
    target = folder / name
    record = folder / (name + ".log-hunter.json")
    if target.exists() or record.exists():
        raise FileExistsError(f"같은 이름의 파일이 이미 있습니다: {target.name}. 다른 폴더를 고르세요")
    digest = hashlib.sha256()
    with open(target, "xb") as out:
        for offset in range(0, source.size, 1024 * 1024):
            block = source.read(offset, 1024 * 1024)
            out.write(block)
            digest.update(block)
    sha256 = digest.hexdigest()
    saved = {**{k: v for k, v in origin.items() if v not in (None, "")}, "saved_as": str(target),
             "size": source.size, "sha256": sha256,
             "saved_at": datetime.now(timezone.utc).isoformat()}
    with open(record, "x", encoding="utf-8") as stream:
        json.dump(saved, stream, ensure_ascii=False, indent=2)
    return target, sha256
