"""Decode Chromium block-file and simple disk caches, with a raw URL fallback."""
import hashlib
import re
import zlib
import struct
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import chromium_timestamp

INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
INDEX_HEADER_SIZE = 368
BLOCK_HEADER_SIZE = 8192
SIMPLE_START = 0xFCFB6D1BA7725C30
SIMPLE_END = 0xF4FA6F45970D41D8
SIMPLE_ENTRY = re.compile(r"[0-9a-f]{16}_0", re.IGNORECASE)
MAX_KEY = 65536
MAX_METADATA = 1024 * 1024
BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096}
ENTRY_STATE_NAMES = {0: "normal", 1: "evicted", 2: "doomed"}
HEADER_KEYS = frozenset(("content-type", "etag", "last-modified", "cache-control",
                         "date", "expires", "content-length", "content-encoding",
                         "server", "x-content-type-options"))


def _addr_file_type(addr):
    return (addr >> 28) & 0x7


def _addr_file_number(addr):
    return (addr >> 16) & 0xFF


def _addr_block_number(addr):
    return addr & 0xFFFF


def _addr_num_blocks(addr):
    return ((addr >> 24) & 0x3) + 1


def _read(stream, offset, size):
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("캐시 파일의 기록 범위를 읽을 수 없습니다")
    return data


def _cache_url(key):
    match = re.search(r"https?://[^\x00-\x20]+$", key)
    return match[0] if match else None


def _block_location(cache_dir, addr):
    if not addr & 0x80000000:
        raise ValueError("미할당 캐시 주소")
    file_type = _addr_file_type(addr)
    if not file_type:
        return cache_dir / f"f_{addr & 0x0fffffff:06x}", 0, None
    block_size = BLOCK_SIZES.get(file_type)
    if block_size is None:
        raise ValueError("지원하지 않는 캐시 블록 유형")
    offset = BLOCK_HEADER_SIZE + _addr_block_number(addr) * block_size
    return cache_dir / f"data_{_addr_file_number(addr)}", offset, _addr_num_blocks(addr) * block_size


def _read_addr(cache_dir, addr, size=None):
    path, offset, capacity = _block_location(cache_dir, addr)
    size = capacity if size is None else size
    if size is None or size < 0 or (capacity is not None and size > capacity):
        raise ValueError("캐시 블록과 기록 길이가 일치하지 않습니다")
    with path.open("rb") as stream:
        if capacity is not None and _read(stream, 0, 4) != struct.pack("<I", BLOCK_MAGIC):
            raise ValueError("캐시 블록 파일 헤더 불일치")
        return _read(stream, offset, size)


def _parse_http_headers(raw):
    start = raw.find(b"HTTP/", 0, 512)
    if start < 0:
        return {}
    text = raw[start:]
    nul = text.find(b"\0")
    newline = text.find(b"\n")
    if nul >= 0 and (newline < 0 or nul < newline):
        text = text.split(b"\0\0", 1)[0].replace(b"\0", b"\n")
    else:
        text = text.split(b"\0", 1)[0].split(b"\r\n\r\n", 1)[0]
    lines = text.decode("utf-8", "replace").splitlines()
    if not lines or not re.fullmatch(r"HTTP/\d(?:\.\d)? \d{3}(?: .*)?", lines[0]):
        return {}
    headers = {"http_status_line": lines[0]}
    for line in lines[1:]:
        key, colon, value = line.partition(":")
        key = key.lower().strip()
        if colon and key in HEADER_KEYS:
            headers[f"http_{key.replace('-', '_')}"] = value.strip()
    return headers


def _simple_entry(path):
    with path.open("rb") as stream:
        magic, version, key_size = struct.unpack("<QII", _read(stream, 0, 24)[:16])
        if magic != SIMPLE_START or version != 5 or not 0 < key_size <= MAX_KEY:
            raise ValueError("지원하지 않는 단일 캐시 항목 헤더")
        key = _read(stream, 24, key_size)
        file_size = stream.seek(0, 2)
        footer = file_size - 24
        magic, flags, crc, size = struct.unpack("<QIII", _read(stream, footer, 24)[:20])
        if magic != SIMPLE_END or flags & ~3 or size > MAX_METADATA:
            raise ValueError("지원하지 않는 캐시 스트림 꼬리표")
        key_hash = 32 if flags & 2 else 0
        offset = footer - key_hash - size
        content = 24 + key_size
        if offset < content + 24:
            raise ValueError("캐시 스트림 범위가 겹칩니다")
        if struct.unpack("<Q", _read(stream, offset - 24, 8))[0] != SIMPLE_END:
            raise ValueError("캐시 본문 스트림 꼬리표가 없습니다")
        payload = _read(stream, offset, size)
        if flags & 1 and zlib.crc32(payload) != crc:
            raise ValueError("캐시 메타데이터 CRC 불일치")
        if key_hash and hashlib.sha256(key).digest() != _read(stream, footer - key_hash, key_hash):
            raise ValueError("캐시 키 해시 불일치")
    return key.decode("utf-8", "replace"), payload, offset, size, content, offset - 24 - content


def cache_directory_format(path, names=None):
    if names is None:
        names = {entry.name.casefold() for entry in path.iterdir()}
    if "index" in names:
        try:
            with (path / "index").open("rb") as stream:
                if stream.read(4) == struct.pack("<I", INDEX_MAGIC):
                    return "blockfile"
        except OSError:
            return None
    if any(SIMPLE_ENTRY.fullmatch(name) for name in names) or (path / "index-dir" / "the-real-index").is_file():
        return "simple"
    return None


class CacheParser(ArtifactParser):
    artifact = "cache"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            try:
                candidates = [source, *(folder for folder in sorted(source.iterdir())
                                        if folder.is_dir() and folder.name.casefold() in ("cache_data", "js", "wasm"))]
            except OSError:
                candidates = [source]
            folders = candidates[1:] if len(candidates) > 1 and not cache_directory_format(source) else candidates
        else:
            folders = [source]
        for folder in folders:
            yield from self._parse_folder(folder)

    def _parse_folder(self, folder):
        before = len(self.errors)
        count = 0
        format_name = None
        reason = None
        missing = not folder.exists()
        try:
            if folder.is_dir():
                children = sorted(folder.iterdir())
                missing = not children
                format_name = cache_directory_format(folder, {path.name.casefold() for path in children})
                if format_name == "blockfile":
                    records = self._parse_blockfile(folder)
                elif format_name == "simple":
                    records = self._parse_simple(p for p in children if p.is_file() and SIMPLE_ENTRY.fullmatch(p.name))
                else:
                    records = self._fallback_url_triage(folder)
            elif folder.is_file() and SIMPLE_ENTRY.fullmatch(folder.name):
                format_name = "simple"
                records = self._parse_simple([folder])
            else:
                records = self._fallback_url_triage(folder)
            for record in records:
                count += 1
                yield record
        except (OSError, ValueError, struct.error) as exc:
            self.error(folder, "cache", exc, "warning")
        if len(self.errors) != before:
            state, reason = "partial", self.errors[before].message
        elif count:
            state = "parsed" if format_name else "partial"
            if not format_name:
                reason = "형식을 확인할 수 없어 주소 후보만 읽었습니다"
        elif missing or format_name == "simple":
            state, reason = "no_files", "읽을 수 있는 캐시 항목 파일이 없습니다"
        elif format_name == "blockfile":
            state, reason = "parsed", "인덱스에 캐시 항목이 없습니다"
        else:
            state, reason = "unsupported", "지원하는 캐시 형식을 확인할 수 없습니다"
        yield ForensicEvent(self.artifact, str(folder), "cache_folder_status", sid=self.sid, path=str(folder),
                            locator="folder" if folder.is_dir() else "file",
                            status="ok" if state == "parsed" else "partial",
                            details={"cache_format": format_name, "cache_status": state,
                                     "cache_reason": reason, "cache_entry_count": count})

    def _parse_simple(self, files):
        for path in files:
            try:
                key, meta, offset, size, body_offset, body_size = _simple_entry(path)
            except (OSError, ValueError, struct.error) as exc:
                self.error(path, "stream:0", exc, "warning")
                continue
            details = {"cache_format": "simple", "cache_key": key, "metadata_offset": offset,
                       "metadata_length": size, "body_offset": body_offset, "body_length": body_size,
                       "format_verified": True, "is_visit_evidence": False, **_parse_http_headers(meta)}
            yield ForensicEvent(self.artifact, str(path), "cache_entry", sid=self.sid, url=_cache_url(key),
                                locator=f"stream:0:byte:{offset}", details=details)

    def _parse_blockfile(self, cache_dir):
        with (cache_dir / "index").open("rb") as stream:
            header = _read(stream, 0, INDEX_HEADER_SIZE)
            version, expected = struct.unpack_from("<Ii", header, 4)
            buckets, = struct.unpack_from("<i", header, 28)
            buckets = buckets or 65536
            if version not in (0x20000, 0x20001, 0x30000) or not 0 < buckets <= 1048576 or expected < 0:
                raise ValueError("지원하지 않는 블록 캐시 인덱스 헤더")
            table = _read(stream, INDEX_HEADER_SIZE, buckets * 4)
        seen = set()
        parsed = 0
        for (address,) in struct.iter_unpack("<I", table):
            while address and address not in seen:
                current = address
                seen.add(current)
                try:
                    raw = _read_addr(cache_dir, current)
                    if len(raw) < 96 or _addr_file_type(current) != 2:
                        raise ValueError("캐시 블록 파일 헤더 불일치")
                    entry_hash, address, _, reuse, refetch, state, created, key_size, long_key = struct.unpack_from(
                        "<IIIiiiQII", raw)
                    sizes = struct.unpack_from("<4i", raw, 40)
                    addresses = struct.unpack_from("<4I", raw, 56)
                    flags, = struct.unpack_from("<I", raw, 72)
                    if not 0 < key_size <= MAX_KEY or (not long_key and key_size > len(raw) - 96):
                        raise ValueError("캐시 키의 길이 또는 위치가 잘못되었습니다")
                    key = (_read_addr(cache_dir, long_key, key_size) if long_key else
                           raw[96:96 + key_size]).decode("utf-8", "replace")
                    path, offset, _ = _block_location(cache_dir, current)
                except (OSError, ValueError, struct.error) as exc:
                    self.error(cache_dir, f"addr:{current:#010x}", exc, "warning")
                    if address == current:
                        break
                    continue
                meta = b""
                if addresses[0] and sizes[0] > 0:
                    try:
                        meta = _read_addr(cache_dir, addresses[0], min(sizes[0], MAX_METADATA))
                    except (OSError, ValueError) as exc:
                        self.error(path, f"addr:{addresses[0]:#010x}", exc, "warning")
                ts = chromium_timestamp(created)
                details = {"cache_format": "blockfile", "cache_key": key, "entry_hash": entry_hash,
                           "state": ENTRY_STATE_NAMES.get(state, str(state)), "reuse_count": reuse, "flags": flags,
                           "refetch_count": refetch, "data_sizes": list(sizes), "entry_offset": offset,
                           "metadata_address": addresses[0], "long_key_address": long_key or None,
                           "format_verified": True, "is_visit_evidence": False, **_parse_http_headers(meta)}
                yield ForensicEvent(self.artifact, str(path), "cache_entry", ts, "creation_time" if ts else None,
                                    self.sid, url=_cache_url(key),
                                    locator=f"addr:{current:#010x}:byte:{offset}", details=details)
                parsed += 1
        if parsed != expected:
            self.error(cache_dir, "index", f"인덱스의 항목 수와 해석된 항목 수가 다릅니다 ({expected} / {parsed})", "warning")

    def _fallback_url_triage(self, source):
        source = Path(source)
        files = sorted(source.rglob("*")) if source.is_dir() else [source]
        for entry in files:
            if not entry.is_file():
                continue
            try:
                with entry.open("rb") as stream:
                    data = stream.read(8 * 1024 * 1024)
            except OSError as exc:
                self.error(entry, "file", exc, "warning")
                continue
            for match in re.finditer(rb"https?://[^\x00-\x20\x7f\"<>]{4,2048}", data):
                yield ForensicEvent(
                    self.artifact, str(entry), "cache_url_candidate",
                    url=match[0].decode("utf-8", "replace"),
                    locator=f"byte:{match.start()}", status="partial",
                    details={"format_verified": False, "is_visit_evidence": False},
                )
