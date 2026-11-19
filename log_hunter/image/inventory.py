"""Build a metadata inventory from base NTFS records and bounded content reads."""
import re
import struct
from pathlib import PureWindowsPath

from log_hunter.core.models import ForensicEvent
from log_hunter.core.preview_images import _exif
from .browse import ImageBrowser, SCAN_CHUNK_RECORDS, READ_ERRORS, _scan_record
from .ntfs import ATTR_DATA, FLAG_COMPRESSED, FLAG_ENCRYPTED, ROOT_RECORD, _extents


SIGNATURES = (
    (b"%PDF-", "pdf", (".pdf",)),
    (b"\xff\xd8\xff", "jpeg", (".jpg", ".jpeg", ".jpe", ".jfif")),
    (b"\x89PNG\r\n\x1a\n", "png", (".png",)),
    (b"GIF87a", "gif", (".gif",)),
    (b"GIF89a", "gif", (".gif",)),
    (b"II*\0", "tiff", (".tif", ".tiff")),
    (b"MM\0*", "tiff", (".tif", ".tiff")),
    (b"PK\x03\x04", "zip", (".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
                          ".jar", ".apk", ".appx", ".msix", ".epub", ".odt", ".ods", ".odp")),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "compound",
     (".doc", ".xls", ".ppt", ".hwp", ".msi", ".msg", ".lnk", ".automaticdestinations-ms",
      ".docx", ".xlsx", ".pptx")),
    (b"\x7fELF", "elf", (".elf", ".so", ".out")),
    (b"Rar!\x1a\x07", "rar", (".rar",)),
)
FILE_SUFFIXES = frozenset(ext for _, _, suffixes in SIGNATURES for ext in suffixes)
TEXT_SUFFIXES = frozenset((".txt", ".log", ".csv", ".ini", ".json", ".xml", ".html", ".htm"))
PE_SUFFIXES = (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".mui", ".efi")
UNKNOWN_SUFFIXES = frozenset(("", ".bin", ".dat", ".tmp", ".cache", ".bak", ".old"))
PDF_END = re.compile(rb"startxref\s+(\d{1,20})\s+%%EOF")
PDF_ENCRYPT = re.compile(rb"/Encrypt\s+\d+\s+\d+\s+R\b")


def _signature(prefix):
    for marker, kind, suffixes in SIGNATURES:
        if prefix.startswith(marker):
            return kind, suffixes
    if len(prefix) >= 64 and prefix.startswith(b"MZ"):
        offset, = struct.unpack_from("<I", prefix, 60)
        if prefix[offset:offset + 4] == b"PE\0\0":
            return "pe", PE_SUFFIXES
    return None, ()


def _photo_metadata(data, kind):
    if kind == "tiff":
        return _exif(data)
    at = 2
    while at + 4 <= len(data) and data[at] == 0xff:
        marker = data[at + 1]
        if marker in (0xda, 0xd9):
            break
        if marker == 0xff:
            at += 1
            continue
        if marker in (1, *range(0xd0, 0xd8)):
            at += 2
            continue
        length, = struct.unpack_from(">H", data, at + 2)
        end = at + 2 + length
        if length < 2 or end > len(data):
            break
        if marker == 0xe1 and data[at + 4:at + 10] == b"Exif\0\0":
            return _exif(data[at + 10:end])
        at = end
    return {}


def _pdf_encryption(read, size):
    tail_at = max(0, size - 65536)
    tail = read(tail_at, size - tail_at)
    final = list(PDF_END.finditer(tail))
    if not final:
        return None
    xref = int(final[-1][1])
    if not 0 < xref < tail_at + final[-1].start():
        return None
    head = read(xref, min(65536, size - xref))
    if head.startswith(b"xref"):
        trailer = tail[:final[-1].start()]
        opening = trailer.rfind(b"trailer")
        if opening < 0:
            return None
        prefix = tail_at + opening
        dictionary = trailer[opening + len(b"trailer"):].lstrip()
        prefix += len(trailer[opening:]) - len(dictionary)
    else:
        envelope = re.match(rb"\d+\s+\d+\s+obj\s*(<<[\s\S]*?)\r?\nstream\b", head)
        if envelope is None or not re.search(rb"/Type\s*/XRef\b", envelope[1]):
            return None
        prefix = xref + envelope.start(1)
        dictionary = envelope[1]
    if not dictionary.startswith(b"<<"):
        return None
    match = PDF_ENCRYPT.search(dictionary.partition(b">>")[0])
    return prefix + match.start() if match else None


def _file_stream(volume, record):
    chunks = volume._fragments(record, ATTR_DATA, "")
    if not chunks:
        return None, 0, "no_stream"
    first = chunks[0]
    if first.flags & FLAG_ENCRYPTED:
        return None, 0, "efs"
    if first.flags & FLAG_COMPRESSED:
        return None, 0, "compressed"
    if not first.nonresident:
        return lambda offset, size: first.value[offset:offset + size], len(first.value), "readable"
    extents = _extents(chunks)
    size, initialized = volume._stream_sizes(first, extents)
    def read(offset, length):
        return volume._read_extents(extents, offset, max(0, min(length, initialized - offset)))
    return read, size, "readable"


def _original_path(item, folders):
    parts, seen = [item["name"]], set()
    while item["parent"] != ROOT_RECORD:
        parent = folders.get(item["parent"])
        if (parent is None or parent["sequence"] != item["parent_sequence"]
                or parent["record"] in seen or len(seen) >= 128):
            return None
        seen.add(parent["record"])
        parts.append(parent["name"])
        item = parent
    return "\\" + "\\".join(reversed(parts))


def scan_file_inventory(volume, volume_index, source):
    total = ImageBrowser._mft_records(volume)
    size = volume.record_size
    folders, files = {}, []
    for start in range(0, total, SCAN_CHUNK_RECORDS):
        width = min(SCAN_CHUNK_RECORDS, total - start)
        data = volume._read_extents(volume.mft_extents, start * size, width * size)
        for offset in range(width):
            item = _scan_record(data[offset * size:(offset + 1) * size], start + offset)
            if item:
                if item["directory"]:
                    folders[item["record"]] = item
                else:
                    files.append(item)

    for item in files:
        path = _original_path(item, folders)
        locator = f"volume:{volume_index}:record:{item['record']}:{item['sequence']}"
        suffix = PureWindowsPath(item["name"]).suffix.casefold()
        details = {"source_path": path, "source_locator": locator, "mft_record": item["record"],
                   "mft_sequence": item["sequence"], "volume": volume_index,
                   "file_name": item["name"], "file_size": item["size"], "file_extension": suffix,
                   "in_use": item["in_use"],
                   "file_times": {key: item.get(key) for key in ("created", "modified", "mft_modified", "accessed")}}
        label = "ntfs_file_inventory" if item["in_use"] else "deleted_file_candidate"
        def event(action, **extra):
            return ForensicEvent("mft", source, action, path=path or item["name"], locator=locator,
                                 status="ok" if action in ("ntfs_file_inventory", "photo_metadata") else "partial",
                                 details={**details, **extra})
        if not item["in_use"]:
            yield event(label, file_type=suffix.lstrip(".") or None,
                        file_type_basis="extension" if suffix else "unknown", stream_state="deleted")
            continue
        try:
            record = volume.record(item["record"])
            read, file_size, state = _file_stream(volume, record)
            prefix = read(0, min(file_size, 4096)) if read else b""
        except (OSError, *READ_ERRORS):
            read, file_size, state, prefix = None, 0, "unreadable", b""
        kind, expected = _signature(prefix)
        details.update(stream_state=state, file_type=kind or suffix.lstrip(".") or None,
                       file_type_basis="signature" if kind else "extension" if suffix else "unknown")
        yield event(label)
        if kind and suffix not in UNKNOWN_SUFFIXES and suffix not in expected and (
                suffix in FILE_SUFFIXES or suffix in TEXT_SUFFIXES or suffix in PE_SUFFIXES):
            yield event("extension_mismatch", expected_extensions=expected, signature_offset=0)
        if state == "efs":
            yield event("encrypted_file", encryption_basis="ntfs_efs_stream_flag")
        if not read:
            continue
        try:
            if kind == "pdf":
                offset = _pdf_encryption(read, file_size)
                if offset is not None:
                    yield event("encrypted_file", encryption_basis="pdf_encrypt_reference", encryption_offset=offset)
            if kind in ("jpeg", "tiff"):
                metadata = _photo_metadata(read(0, min(file_size, 512 * 1024)), kind)
                if metadata:
                    raw = metadata.get("date_time_original_raw") or metadata.get("date_time_raw")
                    yield event("photo_metadata", **metadata, timestamp_raw_local=raw,
                                time_basis="시간대 미상" if raw else None)
        except (OSError, *READ_ERRORS):
            continue
