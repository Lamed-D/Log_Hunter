"""Deleted registry keys and values left in a hive's free cells. Every record is a candidate: a free cell can be a
deleted key, an older copy of a key that still exists, or partly overwritten. The confidence says which."""
import struct

from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime

HBIN = 4096
MAX_PATH_DEPTH = 64
MAX_PREVIEW = 256
MAX_NAME_BYTES = 512
FILETIME_MIN, FILETIME_MAX = 119600064000000000, 159725520000000000  # 1980-01-01 .. 2107-01-01
VALUE_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
               6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 11: "REG_QWORD"}


def _cells(data):
    """Yield each cell's relative offset, allocation flag, and payload bounds."""
    offset = HBIN
    while offset + 32 <= len(data) and data[offset:offset + 4] == b"hbin":
        size = struct.unpack_from("<I", data, offset + 8)[0]
        if size < 4096 or size % 4096 or offset + size > len(data):
            size = len(data) - offset
        cell = offset + 32
        while cell + 4 <= offset + size:
            length = struct.unpack_from("<i", data, cell)[0]
            span = abs(length)
            if span < 8 or cell + span > offset + size:
                break
            yield cell - HBIN, length < 0, cell + 4, cell + span
            cell += span
        offset += size


def _name(raw, length, ascii_flag):
    if length == 0 or length > MAX_NAME_BYTES or length > len(raw):
        return None
    try:
        text = raw[:length].decode("latin1" if ascii_flag else "utf-16-le")
    except UnicodeDecodeError:
        return None
    if not text or not text.isprintable():
        return None
    return text


def parse_nk(payload):
    """(name, last write FILETIME, parent offset, complete) of an nk structure, or None when it is not readable."""
    if len(payload) < 76 or payload[:2] != b"nk":
        return None
    flags, lastwrite = struct.unpack_from("<HQ", payload, 2)
    parent, = struct.unpack_from("<I", payload, 16)
    length, = struct.unpack_from("<H", payload, 72)
    name = _name(payload[76:], length, flags & 0x20)
    if name is None or not FILETIME_MIN <= lastwrite <= FILETIME_MAX:
        return None
    return name, lastwrite, parent, 76 + length <= len(payload)


def parse_vk(payload):
    """(name, type, data size, data offset or inline bytes) of a vk structure, or None."""
    if len(payload) < 20 or payload[:2] != b"vk":
        return None
    name_len, size, data_offset, kind, flags = struct.unpack_from("<HIIIH", payload, 2)
    name = _name(payload[20:], name_len, flags & 1) if name_len else "(기본값)"
    if name is None or kind > 0xFFFF:
        return None
    inline = bool(size & 0x80000000)
    size &= 0x7FFFFFFF
    return name, kind, size, (payload[8:8 + min(size, 4)] if inline else data_offset)


def preview(kind, raw):
    if kind in (1, 2, 6, 7):
        text = raw.decode("utf-16-le", "replace").rstrip("\x00").replace("\x00", " | ")
        return text[:MAX_PREVIEW]
    if kind == 4 and len(raw) >= 4:
        return str(struct.unpack_from("<I", raw)[0])
    if kind == 11 and len(raw) >= 8:
        return str(struct.unpack_from("<Q", raw)[0])
    return raw[:64].hex()


class RegistryDeletedParser(ArtifactParser):
    artifact = "registry_deleted"

    def parse(self, path):
        with open(path, "rb") as stream:
            data = stream.read()
        if len(data) < HBIN or data[:4] != b"regf":
            raise ValueError("유효한 regf 하이브가 아닙니다")
        cells = {offset: (allocated, start, end) for offset, allocated, start, end in _cells(data)}
        live_paths = set()
        names = {}
        for offset, (_, start, end) in cells.items():
            if data[start:min(end, start + 2)] == b"nk":
                key = parse_nk(data[start:min(end, start + 76 + MAX_NAME_BYTES)])
                if key:
                    names[offset] = key
        chains = {}

        def chain(offset, depth=0):
            """Names from the hive root down to `offset` (memoized; loops and depth are bounded)."""
            if offset in chains:
                return chains[offset]
            chains[offset] = None  # marks the walk in progress: a loop ends here
            name, _, parent, _ = names[offset]
            above = () if parent == offset or parent not in names or depth > MAX_PATH_DEPTH else chain(parent, depth + 1)
            chains[offset] = (*(above or ()), name)
            return chains[offset]

        def full_path(parent):
            if parent not in names:
                return None
            parts = chain(parent)
            return "\\".join(parts[1:]) if parts else None  # drop the hive's root key name

        for offset, (name, _, parent, _) in names.items():
            if cells[offset][0]:
                base = full_path(parent)
                live_paths.add(((base + "\\") if base else "") + name)
        source = str(path)
        # The hbin walk inserts cell offsets in ascending order.
        for offset, (allocated, start, end) in cells.items():
            if allocated:
                continue
            key = names.get(offset)
            if key:
                name, lastwrite, parent, complete = key
                base = full_path(parent)
                key_path = ((base + "\\") if base else "") + name
                parent_live = parent in names and cells[parent][0]
                if key_path in live_paths:
                    confidence, reason = "old_copy", "같은 경로의 키가 지금도 있습니다(이전 버전의 남은 칸일 수 있음)"
                elif parent_live and complete:
                    confidence, reason = "intact", "구조와 상위 키 연결이 온전합니다"
                else:
                    confidence, reason = "partial", "상위 키를 찾지 못했거나 이름이 잘렸습니다"
                details = {"key_path": key_path if base is not None else None, "key_name": name, "cell_offset": offset,
                           "parent_offset": parent, "deleted_confidence": confidence, "confidence_reason": reason,
                           "overwrite_note": "빈 칸은 다시 쓰일 수 있어 일부가 다른 기록으로 덮였을 수 있습니다"}
                yield ForensicEvent(self.artifact, source, "deleted_registry_key", filetime(lastwrite), "key_lastwrite",
                                    self.sid, path=key_path, locator=f"cell:{offset:#x}", status="partial", details=details)
                continue
            if data[start:min(end, start + 2)] != b"vk":
                continue
            value = parse_vk(data[start:min(end, start + 20 + MAX_NAME_BYTES)])
            if value:
                name, kind, size, where = value
                raw = b""
                if isinstance(where, bytes):
                    raw = where
                elif size and where in cells:
                    _, data_start, data_end = cells[where]
                    raw = data[data_start:min(data_end, data_start + min(size, 4096))]
                details = {"value_name": name, "value_type": VALUE_TYPES.get(kind, str(kind)), "value_size": size,
                           "value_preview": preview(kind, raw) if raw else None, "cell_offset": offset,
                           "deleted_confidence": "partial" if size and not raw else "value_only",
                           "confidence_reason": "값은 어느 키에 속했는지 기록하지 않아 키 경로를 알 수 없습니다",
                           "overwrite_note": "빈 칸은 다시 쓰일 수 있어 데이터가 다른 값으로 덮였을 수 있습니다"}
                yield ForensicEvent(self.artifact, source, "deleted_registry_value", None, None, self.sid, path=name,
                                    locator=f"cell:{offset:#x}", status="partial", details=details)
