"""Web addresses left in the free pages of a browser history database (deleted history rows). Only address text is
recovered: when it was visited, and whether it was a visit at all, is unknown. Addresses still in the live tables are
not reported. The original file is read as bytes; SQLite is only opened read-only to list the live addresses."""
import re
import sqlite3
import struct
from pathlib import Path

from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent

MAX_FILE = 2 * 1024 * 1024 * 1024
MAX_FREE_PAGES = 200_000
MAX_CANDIDATES = 20_000
_URL = re.compile(rb"(?:https?|ftp|file)://[\x21-\x7e]{3,2048}")
_TRAILING = b"\x00\"'<>)]}"


def free_pages(data):
    """Page numbers on the freelist (trunk and leaf pages) of a SQLite database image."""
    if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
        raise ValueError("SQLite 데이터베이스가 아닙니다")
    size = struct.unpack_from(">H", data, 16)[0]
    page_size = 65536 if size == 1 else size
    if page_size < 512 or page_size & (page_size - 1):
        raise ValueError("SQLite 페이지 크기가 올바르지 않습니다")
    trunk, total = struct.unpack_from(">II", data, 32)
    pages, seen = [], set()
    count = len(data) // page_size
    while trunk and trunk not in seen and len(pages) < MAX_FREE_PAGES and 1 <= trunk <= count:
        seen.add(trunk)
        offset = (trunk - 1) * page_size
        next_trunk, leaves = struct.unpack_from(">II", data, offset)
        leaves = min(leaves, (page_size - 8) // 4)
        pages.append(trunk)
        for index in range(leaves):
            leaf, = struct.unpack_from(">I", data, offset + 8 + 4 * index)
            if 1 <= leaf <= count:
                pages.append(leaf)
        trunk = next_trunk
    return page_size, pages[:MAX_FREE_PAGES], total


def carve(blob):
    """Distinct web addresses in a byte range, in first-seen order."""
    found = []
    seen = set()
    for match in _URL.finditer(blob):
        url = match.group(0).rstrip(_TRAILING)
        if url not in seen:
            seen.add(url)
            found.append(url)
    return found


def live_urls(path):
    try:
        connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    except sqlite3.Error:
        return set()
    try:
        return {row[0].encode("utf-8", "replace") for row in connection.execute("SELECT url FROM urls") if row[0]}
    except sqlite3.Error:
        return set()
    finally:
        connection.close()


class BrowserDeletedParser(ArtifactParser):
    artifact = "browser_deleted"

    def parse(self, path):
        path = Path(path)
        if path.stat().st_size > MAX_FILE:
            raise ValueError("데이터베이스가 너무 큽니다")
        data = path.read_bytes()
        page_size, pages, total = free_pages(data)
        if total and len(pages) < total:
            self.error(path, "freelist", f"빈 페이지 목록 일부만 읽었습니다 ({len(pages)}/{total})", "warning")
        live = live_urls(path)
        regions = [(f"free_page:{n}", data[(n - 1) * page_size:n * page_size]) for n in pages]
        wal = Path(str(path) + "-wal")
        if wal.is_file() and wal.stat().st_size <= MAX_FILE:
            regions.append(("wal", wal.read_bytes()))  # older page versions not yet written back
        reported = set()
        for where, blob in regions:
            for url in carve(blob):
                if url in live or url in reported:
                    continue
                if len(reported) >= MAX_CANDIDATES:
                    self.error(path, where, f"후보가 너무 많아 {MAX_CANDIDATES:,}건까지만 보입니다", "warning")
                    return
                reported.add(url)
                text = url.decode("utf-8", "replace")
                details = {"url": text, "found_in": "wal" if where == "wal" else "free_page",
                           "deleted_confidence": "carved_text",
                           "confidence_reason": "빈 페이지에서 주소 문자열만 찾았습니다. 방문 시각과 방문 여부는 알 수 없습니다",
                           "overwrite_note": "빈 페이지는 다시 쓰일 수 있어 일부만 남았을 수 있습니다"}
                yield ForensicEvent(self.artifact, str(path), "deleted_url_candidate", None, None, self.sid, url=text,
                                    locator=where, status="partial", details=details)
