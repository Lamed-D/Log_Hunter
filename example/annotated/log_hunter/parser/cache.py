# ▶ 원본: log_hunter/parser/cache.py
# ▶ 기록 형식에 맞는 필드와 시각을 읽습니다. 범위 검사와 self.error 호출을 함께 확인하세요.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Chromium Blockfile cache parser with raw URL fallback.

Decodes the Chromium disk cache v2 (Blockfile backend):
  - index file: hash table of CacheAddr entries
  - data_N block files: fixed-size block storage
  - f_XXXXXX separate files: large entries

References:
  chromium/src/net/disk_cache/blockfile/disk_format.h
  chromium/src/net/disk_cache/blockfile/addr.h
"""
import re
import struct
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import chromium_timestamp

INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
ENTRY_SIGNATURE = 0xC80A8D6B
ENTRY_SIZE = 256
BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096}
ENTRY_STATE_NAMES = {0: "normal", 1: "evicted", 2: "doomed"}
HEADER_KEYS = frozenset(("content-type", "etag", "last-modified", "cache-control",
                         "date", "expires", "content-length", "content-encoding",
                         "server", "x-content-type-options"))


def _addr_file_type(addr):
    return (addr >> 28) & 0xF


def _addr_file_number(addr):
    return (addr >> 16) & 0xFF


def _addr_block_number(addr):
    return addr & 0xFFFF


def _addr_num_blocks(addr):
    return ((addr >> 24) & 0x3) + 1


class _BlockFileCache:
    def __init__(self, cache_dir):
        self.cache_dir = Path(cache_dir)
        self._block_files = {}

    def _open_block_file(self, file_number):
        if file_number in self._block_files:
            return self._block_files[file_number]
        path = self.cache_dir / f"data_{file_number}"
        if not path.exists():
            return None
        data = path.read_bytes()
        if len(data) < 8192:
            return None
        magic, = struct.unpack_from("<I", data)
        if magic != BLOCK_MAGIC:
            return None
        self._block_files[file_number] = data
        return data

    def read_addr(self, addr, max_size=None):
        if addr == 0:
            return None
        file_type = _addr_file_type(addr)
        if file_type == 0:
            file_num = (addr & 0x0FFFFFFF)
            path = self.cache_dir / f"f_{file_num:06x}"
            if not path.exists():
                return None
            data = path.read_bytes()
            if max_size and len(data) > max_size:
                data = data[:max_size]
            return data
        block_size = BLOCK_SIZES.get(file_type)
        if block_size is None:
            return None
        file_number = _addr_file_number(addr)
        block_number = _addr_block_number(addr)
        num_blocks = _addr_num_blocks(addr)
        data = self._open_block_file(file_number)
        if data is None:
            return None
        offset = 8192 + block_number * block_size
        length = num_blocks * block_size
        if max_size:
            length = min(length, max_size)
        if offset + length > len(data):
            return None
        return data[offset:offset + length]


def _parse_entry(raw):
    if len(raw) < 160:
        return None
    sig, = struct.unpack_from("<I", raw, 0)
    if sig != ENTRY_SIGNATURE:
        return None
    (entry_hash, next_entry, rankings_node,
     reuse_count, refetch_count, state,
     creation_time, key_len, long_key_addr) = struct.unpack_from("<IIIiiIqiI", raw, 4)
    data_addrs = struct.unpack_from("<4I", raw, 40)
    data_sizes = struct.unpack_from("<4i", raw, 56)
    flags, = struct.unpack_from("<I", raw, 72)
    url = None
    if key_len > 0:
        if long_key_addr != 0:
            pass
        else:
            key_start = 160
            key_end = min(key_start + key_len, len(raw))
            try:
                url = raw[key_start:key_end].split(b"\x00", 1)[0].decode("utf-8", "replace")
            except Exception:
                pass
    return {
        "hash": entry_hash,
        "next": next_entry,
        "reuse_count": reuse_count,
        "refetch_count": refetch_count,
        "state": state,
        "state_name": ENTRY_STATE_NAMES.get(state, f"unknown({state})"),
        "creation_time": creation_time,
        "key_len": key_len,
        "long_key_addr": long_key_addr,
        "data_addrs": data_addrs,
        "data_sizes": data_sizes,
        "flags": flags,
        "url": url,
    }


def _parse_http_headers(raw):
    if raw is None or len(raw) < 12:
        return {}
    try:
        flag, = struct.unpack_from("<I", raw, 0)
    except struct.error:
        return {}
    header_start = None
    for offset in range(4, min(len(raw), 512)):
        if raw[offset:offset + 4] == b"HTTP":
            header_start = offset
            break
    if header_start is None:
        for offset in range(0, min(len(raw), 512)):
            if raw[offset:offset + 4] == b"HTTP":
                header_start = offset
                break
    if header_start is None:
        return {}
    try:
        text = raw[header_start:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    except Exception:
        return {}
    headers = {}
    status_line = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        if line.startswith("HTTP/"):
            status_line = line.strip()
            continue
        colon = line.find(":")
        if colon > 0:
            name = line[:colon].strip().lower()
            value = line[colon + 1:].strip()
            if name in HEADER_KEYS:
                headers[name] = value
    if status_line:
        headers["_status_line"] = status_line
    return headers


class CacheParser(ArtifactParser):
    artifact = "cache"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            index_path = source / "index"
            if index_path.exists():
                yield from self._parse_blockfile(source, index_path)
                return
        yield from self._fallback_url_triage(source)

    def _parse_blockfile(self, cache_dir, index_path):
        try:
            index_data = index_path.read_bytes()
        except OSError as exc:
            self.error(index_path, "file", exc)
            return
        if len(index_data) < 368:
            self.error(index_path, "header", "인덱스 파일이 너무 작습니다")
            yield from self._fallback_url_triage(cache_dir)
            return
        magic, version, entry_count, _, table_len = struct.unpack_from("<5I", index_data, 0)
        if magic != INDEX_MAGIC:
            self.error(index_path, "magic", f"인덱스 매직 불일치: {magic:#010x}")
            yield from self._fallback_url_triage(cache_dir)
            return
        self.error(index_path, "header",
                   f"Blockfile cache v{version >> 16}.{version & 0xFFFF}, "
                   f"entries={entry_count}, table_len={table_len}", "warning")
        bfc = _BlockFileCache(cache_dir)
        table_offset = 256
        seen_addrs = set()
        parsed = 0
        for i in range(table_len):
            offset = table_offset + i * 4
            if offset + 4 > len(index_data):
                break
            addr, = struct.unpack_from("<I", index_data, offset)
            if addr == 0:
                continue
            current = addr
            chain_depth = 0
            while current != 0 and chain_depth < 64:
                if current in seen_addrs:
                    break
                seen_addrs.add(current)
                chain_depth += 1
                entry_raw = bfc.read_addr(current, max_size=4096)
                if entry_raw is None:
                    self.error(cache_dir, f"addr:{current:#010x}",
                               "캐시 엔트리 읽기 실패", "warning")
                    break
                entry = _parse_entry(entry_raw)
                if entry is None:
                    break
                url = entry["url"]
                if url is None and entry["long_key_addr"] != 0:
                    key_data = bfc.read_addr(entry["long_key_addr"],
                                             max_size=entry["key_len"] + 1)
                    if key_data:
                        try:
                            url = key_data[:entry["key_len"]].split(b"\x00", 1)[0].decode("utf-8", "replace")
                        except Exception:
                            pass
                ts = chromium_timestamp(entry["creation_time"]) if entry["creation_time"] else None
                headers = {}
                meta_addr = entry["data_addrs"][0]
                meta_size = entry["data_sizes"][0]
                if meta_addr and meta_size > 0:
                    meta_raw = bfc.read_addr(meta_addr, max_size=min(meta_size, 65536))
                    if meta_raw:
                        headers = _parse_http_headers(meta_raw)
                details = {
                    "entry_hash": entry["hash"],
                    "state": entry["state_name"],
                    "reuse_count": entry["reuse_count"],
                    "refetch_count": entry["refetch_count"],
                    "flags": entry["flags"],
                    "data_sizes": list(entry["data_sizes"]),
                    "format_verified": True,
                    "is_visit_evidence": True,
                }
                if headers:
                    for key in ("content-type", "etag", "last-modified",
                                "cache-control", "date", "expires",
                                "content-length", "content-encoding",
                                "server", "x-content-type-options"):
                        if key in headers:
                            details[f"http_{key.replace('-', '_')}"] = headers[key]
                    if "_status_line" in headers:
                        details["http_status_line"] = headers["_status_line"]
                yield ForensicEvent(
                    self.artifact, str(cache_dir), "cache_entry",
                    ts, "creation_time" if ts else None,
                    self.sid, url=url,
                    locator=f"addr:{current:#010x}",
                    status="ok" if url else "partial",
                    details=details,
                )
                parsed += 1
                current = entry["next"]
        if parsed == 0:
            self.error(cache_dir, "index", "인덱스에서 유효한 엔트리를 찾지 못했습니다", "warning")
            yield from self._fallback_url_triage(cache_dir)

    def _fallback_url_triage(self, source):
        source = Path(source)
        files = sorted(source.rglob("*")) if source.is_dir() else [source]
        for entry in files:
            if not entry.is_file():
                continue
            try:
                data = entry.read_bytes()
            except OSError as exc:
                self.error(entry, "file", exc, "warning")
                continue
            if len(data) > 8 * 1024 * 1024:
                data = data[:8 * 1024 * 1024]
            self.error(entry, "cache",
                       "Blockfile 구조 미확인: 원시 URL 후보만 추출", "warning")
            for match in re.finditer(rb"https?://[^\x00-\x20\x7f\"<>]{4,2048}", data):
                yield ForensicEvent(
                    self.artifact, str(entry), "cache_url_candidate",
                    url=match[0].decode("utf-8", "replace"),
                    locator=f"byte:{match.start()}", status="partial",
                    details={"format_verified": False, "is_visit_evidence": False},
                )
