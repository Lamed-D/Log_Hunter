# ▶ 원본: log_hunter/parser/registry.py
# ▶ REGF 셀을 읽고 검증된 로그만 임시 사본에 적용합니다. 원본 하이브는 수정하지 않습니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Bounded, read-only REGF reader with transaction log replay.

Supports allocated nk/vk cells, li/lf/lh/ri subkey lists and bounded big-data
db segments. No operating-system hive mounting occurs.

When recover=True, dirty hives are recovered by replaying LOG1/LOG2 transaction
logs onto an in-memory copy. The original file is never modified.
"""
import struct
from pathlib import Path


LOG_BASE_BLOCK = 512
LOG_ENTRY_HEADER = 40
MARVIN_SEED = 0x82EF4D887A4E55C5
MAX_GROWTH = 64 * 1024 * 1024  # how far a log may grow the hive bins; bounds memory for crafted logs
_M32 = 0xFFFFFFFF


def base_checksum(data):
    checksum = 0
    for offset in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", data, offset)[0]
    return 0xfffffffe if checksum == 0xffffffff else checksum or 1


def _rotl(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & _M32


def _marvin_block(low, high):
    high ^= low
    low = (_rotl(low, 20) + high) & _M32
    high = _rotl(high, 9) ^ low
    low = (_rotl(low, 27) + high) & _M32
    high = _rotl(high, 19)
    return low, high


def marvin32(data, seed=MARVIN_SEED):
    """64-bit Marvin32 hash used by Windows 8.1+ registry transaction log entries."""
    low, high = seed & _M32, seed >> 32
    whole = len(data) - len(data) % 4
    for offset in range(0, whole, 4):
        low = (low + int.from_bytes(data[offset:offset + 4], "little")) & _M32
        low, high = _marvin_block(low, high)
    tail = data[whole:]
    low = (low + (int.from_bytes(tail, "little") | (0x80 << (8 * len(tail))))) & _M32
    low, high = _marvin_block(low, high)
    low, high = _marvin_block(low, high)
    return (high << 32) | low


def _read_log_entries(log_data, bins_limit):
    """Parse a Windows 8.1+ transaction log: a 512-byte base block, then HvLE entries.

    Each entry: signature, size, flags, sequence, hive bins size, dirty page count, hash-1
    (entry body), hash-2 (first 32 bytes), page references (offset, size) and page data.
    Returns (sequence1, sequence2, entries, warnings); entries are verified by both hashes and
    every page must lie inside the entry's hive bins size, which itself is capped at bins_limit.
    """
    warnings = []
    if len(log_data) < LOG_BASE_BLOCK or log_data[:4] != b"regf":
        return None, None, [], ["유효한 regf 로그가 아닙니다"]
    seq1, seq2 = struct.unpack_from("<II", log_data, 4)
    if log_data[LOG_BASE_BLOCK:LOG_BASE_BLOCK + 4] == b"DIRT":
        return seq1, seq2, [], ["Windows 8 이전 형식(DIRT) LOG는 아직 지원하지 않습니다"]
    if (seq1 != seq2 or struct.unpack_from("<I", log_data, 28)[0] != 6
            or base_checksum(log_data) != struct.unpack_from("<I", log_data, 508)[0]):
        return seq1, seq2, [], ["LOG 기본 블록의 형식·시퀀스·체크섬 오류"]
    entries, position = [], LOG_BASE_BLOCK
    while position + LOG_ENTRY_HEADER <= len(log_data) and log_data[position:position + 4] == b"HvLE":
        size, _flags, sequence, bins_size, count = struct.unpack_from("<IIIII", log_data, position + 4)
        if size < LOG_ENTRY_HEADER or size % 512 or position + size > len(log_data):
            warnings.append(f"LOG 항목 {sequence}: 크기 오류")
            break
        entry = log_data[position:position + size]
        hash1, hash2 = struct.unpack_from("<QQ", entry, 24)
        if marvin32(entry[:32]) != hash2 or marvin32(entry[LOG_ENTRY_HEADER:]) != hash1:
            warnings.append(f"LOG 항목 {sequence}: 해시 불일치(쓰다 만 항목), 여기서 중단")
            break
        if not entries and sequence != seq1:
            warnings.append("LOG 첫 항목 시퀀스가 기본 블록과 다릅니다")
            break
        if (not bins_size or bins_size > bins_limit or bins_size % 4096
                or not count or count > (size - LOG_ENTRY_HEADER) // 8):
            warnings.append(f"LOG 항목 {sequence}: 하이브 크기/페이지 수가 범위를 벗어남")
            break
        pages, data_at = [], LOG_ENTRY_HEADER + count * 8
        for index in range(count):
            offset, page_size = struct.unpack_from("<II", entry, LOG_ENTRY_HEADER + index * 8)
            if (not page_size or page_size % 512 or offset % 512
                    or offset + page_size > bins_size or data_at + page_size > size):
                pages = None
                break
            pages.append((offset, entry[data_at:data_at + page_size]))
            data_at += page_size
        if pages is None:
            warnings.append(f"LOG 항목 {sequence}: 페이지가 하이브 범위를 벗어남")
            break
        if entries and sequence != (entries[-1]["sequence"] + 1) & _M32:
            warnings.append("LOG 시퀀스가 연속되지 않아 여기서 중단합니다")
            break
        entries.append({"sequence": sequence, "bins_size": bins_size, "pages": pages, "flags": _flags})
        position += size
    return seq1, seq2, entries, warnings


def replay_logs(hive_path):
    """Read a hive and replay LOG1/LOG2 if the hive is dirty.

    Returns (data: bytes, recovery_info: dict). The data is either the original hive bytes
    (clean, or nothing verifiable to apply) or a recovered in-memory copy. Only hash-verified
    entries with consecutive sequence numbers, starting at the hive's secondary sequence, are
    applied; the original file is never modified.
    """
    hive_path = Path(hive_path)
    data = hive_path.read_bytes()
    info = {"dirty": False, "recovered": False, "log_applied": None, "warnings": []}

    if len(data) < 4096 or data[:4] != b"regf":
        info["warnings"].append("유효한 regf 하이브가 아닙니다")
        return data, info

    hive_seq1, hive_seq2 = struct.unpack_from("<II", data, 4)
    if hive_seq1 == hive_seq2:
        return data, info

    info["dirty"] = True
    if base_checksum(data) != struct.unpack_from("<I", data, 508)[0]:
        info["warnings"].append("하이브 기본 블록 체크섬 오류: 불확실한 헤더 복구는 적용하지 않습니다")
        return data, info
    bins_limit = len(data) - 4096 + MAX_GROWTH
    candidates, conflicts = {}, set()
    for suffix in (".LOG1", ".LOG2"):
        log_path = Path(str(hive_path) + suffix)
        if not log_path.exists():
            continue
        try:
            log_data = log_path.read_bytes()
        except OSError as exc:
            info["warnings"].append(f"{suffix} 읽기 실패: {exc}")
            continue
        _seq1, _seq2, entries, warnings = _read_log_entries(log_data, bins_limit)
        info["warnings"].extend(f"{suffix} {w}" for w in warnings)
        if log_data[12:20] != data[12:20]:
            info["warnings"].append(f"{suffix} 하이브와 LOG의 생성 시각이 다릅니다")
            continue
        for entry in entries:
            sequence = entry["sequence"]
            if (sequence - hive_seq2) & _M32 < 0x80000000:
                if sequence in candidates and candidates[sequence][1] != entry:
                    conflicts.add(sequence)
                    info["warnings"].append(f"시퀀스 {sequence}의 LOG 내용이 충돌합니다")
                candidates.setdefault(sequence, (suffix, entry))

    applied_entries, expected = [], hive_seq2
    while expected in candidates and expected not in conflicts:
        applied_entries.append(candidates[expected])
        expected = (expected + 1) & _M32
    if not applied_entries:
        info["warnings"].append("적용 가능한 트랜잭션 로그 없음")
        return data, info

    recovered = bytearray(data)
    pages = 0
    for _suffix, entry in applied_entries:
        end = 4096 + entry["bins_size"]
        if end > len(recovered):
            recovered.extend(bytes(end - len(recovered)))
        struct.pack_into("<I", recovered, 0x28, entry["bins_size"])
        flags = struct.unpack_from("<I", recovered, 144)[0]
        struct.pack_into("<I", recovered, 144, (flags & ~1) | (entry["flags"] & 1))
        for offset, page in entry["pages"]:
            recovered[4096 + offset:4096 + offset + len(page)] = page
            pages += 1
    last = applied_entries[-1][1]["sequence"]
    sequence = last
    struct.pack_into("<II", recovered, 4, sequence, sequence)
    struct.pack_into("<I", recovered, 508, base_checksum(recovered))

    info["recovered"] = True
    info["log_applied"] = ", ".join(sorted({suffix for suffix, _e in applied_entries}))
    info["entries_applied"] = len(applied_entries)
    info["pages_applied"] = pages
    info["new_sequence"] = sequence
    return bytes(recovered), info


class Hive:
    def __init__(self, path, recover=False, on_error=None):
        self.path = str(path)
        self.on_error = on_error
        self._reported_errors = set()
        self.recovery_info = {"dirty": False, "recovered": False, "log_applied": None, "warnings": []}

        if recover:
            self.data, self.recovery_info = replay_logs(path)
        else:
            self.data = Path(path).read_bytes()

        if len(self.data) < 4096 or self.data[:4] != b"regf":
            raise ValueError("유효한 regf 하이브가 아닙니다")
        self.dirty = self.u32(4) != self.u32(8)
        self.logs = {suffix: Path(str(path) + suffix).exists() for suffix in (".LOG1", ".LOG2")}
        self.root = self.key(self.u32(0x24))

    def u32(self, offset):
        return struct.unpack_from("<I", self.data, offset)[0]

    def cell(self, relative):
        offset = 4096 + relative
        if offset < 4096 or offset + 4 > len(self.data):
            raise ValueError(f"하이브 cell 범위 초과: {relative:#x}")
        size = struct.unpack_from("<i", self.data, offset)[0]
        if size >= 0 or -size < 4 or offset - size > len(self.data):
            raise ValueError(f"할당되지 않았거나 손상된 cell: {relative:#x}")
        return self.data[offset + 4:offset - size]

    def key(self, offset):
        return Key(self, offset)

    def open(self, path):
        key = self.root
        for name in path.strip("\\").split("\\"):
            if name:
                key = next((k for k in key.subkeys(skip_invalid=True) if k.name.casefold() == name.casefold()), None)
                if key is None:
                    raise KeyError(path)
        return key

    def list_offsets(self, offset, seen=None):
        seen = set() if seen is None else seen
        if offset in seen or len(seen) > 128:
            raise ValueError("순환 또는 과도한 하위키 목록")
        seen.add(offset)
        cell = self.cell(offset)
        signature, count = cell[:2], struct.unpack_from("<H", cell, 2)[0]
        stride = 8 if signature in (b"lf", b"lh") else 4
        if signature not in (b"lf", b"lh", b"li", b"ri") or 4 + count * stride > len(cell):
            raise ValueError("손상된 하위키 목록")
        for index in range(count):
            child = struct.unpack_from("<I", cell, 4 + index * stride)[0]
            if signature == b"ri":
                yield from self.list_offsets(child, seen)
            else:
                yield child


class Key:
    def __init__(self, hive, offset):
        self.hive, self.offset = hive, offset
        self.data = hive.cell(offset)
        if len(self.data) < 76 or self.data[:2] != b"nk":
            raise ValueError(f"손상된 nk cell: {offset:#x}")
        length = struct.unpack_from("<H", self.data, 72)[0]
        if 76 + length > len(self.data):
            raise ValueError("키 이름 범위 초과")
        flags = struct.unpack_from("<H", self.data, 2)[0]
        self.name = self.data[76:76 + length].decode("latin1" if flags & 0x20 else "utf-16-le")
        self.lastwrite = struct.unpack_from("<Q", self.data, 4)[0]

    def subkeys(self, skip_invalid=False):
        count, = struct.unpack_from("<I", self.data, 20)
        if count:
            offset, = struct.unpack_from("<I", self.data, 28)
            for child in self.hive.list_offsets(offset):
                try:
                    yield self.hive.key(child)
                except (ValueError, struct.error) as exc:
                    if not skip_invalid:
                        raise
                    callback = getattr(self.hive, "on_error", None)
                    if callback and child not in self.hive._reported_errors:
                        self.hive._reported_errors.add(child)
                        callback(child, exc)

    def values(self):
        count, offset = struct.unpack_from("<II", self.data, 36)
        if not count:
            return
        indexes = self.hive.cell(offset)
        if count * 4 > len(indexes):
            raise ValueError("값 목록 범위 초과")
        for i in range(count):
            index, = struct.unpack_from("<I", indexes, i * 4)
            try:
                yield self._value(index)
            except (ValueError, struct.error, UnicodeError) as exc:
                yield {"name": f"cell:{index:#x}", "error": str(exc), "raw": b"", "type": None, "value": None}

    def _value(self, offset):
        cell = self.hive.cell(offset)
        if len(cell) < 20 or cell[:2] != b"vk":
            raise ValueError("손상된 vk cell")
        name_len, length, data_offset, kind, flags = struct.unpack_from("<HIIIH", cell, 2)
        if 20 + name_len > len(cell):
            raise ValueError("값 이름 범위 초과")
        name = cell[20:20 + name_len].decode("latin1" if flags & 1 else "utf-16-le")
        size = length & 0x7FFFFFFF
        if length & 0x80000000:
            if size > 4:
                raise ValueError("inline 값 크기 초과")
            raw = cell[8:8 + size]
        elif size:
            if size > 16344:
                try:
                    raw = self._read_big_data(data_offset, size)
                except (ValueError, struct.error):
                    raise ValueError(f"big-data 값 읽기 실패 (크기: {size})")
                return {"name": name, "raw": raw, "type": kind, "value": raw.decode("utf-16-le").rstrip("\0") if kind in (1, 2, 6) else raw}
            block = self.hive.cell(data_offset)
            if size > len(block):
                raise ValueError("값 데이터 범위 초과")
            raw = block[:size]
        else:
            raw = b""
        value = raw
        if kind in (1, 2, 6):
            value = raw.decode("utf-16-le").rstrip("\0")
        elif kind == 4 and len(raw) == 4:
            value = struct.unpack("<I", raw)[0]
        elif kind == 11 and len(raw) == 8:
            value = struct.unpack("<Q", raw)[0]
        return {"name": name, "raw": raw, "type": kind, "value": value}

    def _read_big_data(self, offset, size):
        cell = self.hive.cell(offset)
        if len(cell) < 8 or cell[:2] != b"db":
            raise ValueError("db cell 시그니처 불일치")
        count, = struct.unpack_from("<H", cell, 2)
        list_offset, = struct.unpack_from("<I", cell, 4)
        segment_list = self.hive.cell(list_offset)
        if count * 4 > len(segment_list):
            raise ValueError("big-data 세그먼트 목록 범위 초과")
        parts = []
        remaining = size
        for i in range(count):
            seg_offset, = struct.unpack_from("<I", segment_list, i * 4)
            seg_data = self.hive.cell(seg_offset)
            take = min(remaining, len(seg_data))
            parts.append(seg_data[:take])
            remaining -= take
            if remaining <= 0:
                break
        return b"".join(parts)

    def value(self, name):
        value = next((v for v in self.values() if v["name"].casefold() == name.casefold()), None)
        if value is None or "error" in value:
            raise KeyError(name)
        return value["value"]


def current_controlset(hive):
    current = hive.open("Select").value("Current")
    if not isinstance(current, int) or not 1 <= current <= 999:
        raise ValueError("활성 ControlSet 미상")
    return f"ControlSet{current:03d}"


def walk(key, path="", depth=0, seen=None):
    # A crafted hive can list the same nk cell under several parents (or its own ancestor);
    # visiting each cell once keeps the walk linear instead of exponential.
    seen = set() if seen is None else seen
    if key.offset in seen:
        return
    seen.add(key.offset)
    if depth > 128:
        raise ValueError("하이브 깊이 초과")
    yield path, key
    for child in key.subkeys():
        yield from walk(child, path + "\\" + child.name, depth + 1, seen)
