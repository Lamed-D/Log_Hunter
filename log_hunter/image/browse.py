"""Read-only browsing of a disk image or this PC's drive for the GUI: volumes, folders, files and an
MFT-wide scan for file views.

Nothing is copied or written; file content is read page by page straight from the image. Sizes are
clamped to the clusters the data runs really cover, so a crafted size field cannot make a read huge.
"""
import hashlib
import struct
import threading

from log_hunter.core.timestamp import filetime
from .ewf import open_image
from .ntfs import (ATTR_DATA, ATTR_FILE_NAME, ATTR_STANDARD_INFORMATION, FLAG_COMPRESSED, FLAG_ENCRYPTED, ROOT_RECORD,
                   NTFSError, NTFSVolume, _extents, apply_fixup, parse_attributes, parse_file_name)
from .volumes import find_volumes

HASH_BLOCK = 1024 * 1024
SCAN_CHUNK_RECORDS = 1024
DOS_NAMESPACE = 2
TIME_KEYS = ("created", "modified", "mft_modified", "accessed")
READ_ERRORS = (NTFSError, struct.error, ValueError)


class ImageBrowser:
    """One open image (or live drive). Meant to be used from one worker thread; a lock
    serializes access if the GUI ever calls from two threads."""

    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.image = open_image(path)
        try:
            self.volumes = find_volumes(self.image)
        except Exception:
            self.image.close()
            raise
        self._ntfs = {}

    def volume_info(self):
        return [{**volume.to_dict(), "browsable": volume.filesystem in ("ntfs", "fat", "exfat")} for volume in self.volumes]

    def _fat(self, index):
        """The FAT volume at `index`, or None when that volume is not FAT."""
        from .exfat import ExFATVolume
        from .fat import FATVolume
        with self.lock:
            volume = next((v for v in self.volumes if v.index == index), None)
            if volume is None or volume.filesystem not in ("fat", "exfat"):
                return None
            if index not in self._ntfs:
                kind = ExFATVolume if volume.filesystem == "exfat" else FATVolume
                self._ntfs[index] = kind(self.image, volume.offset)
            return self._ntfs[index]

    def _volume(self, index):
        with self.lock:
            if index not in self._ntfs:
                volume = next((v for v in self.volumes if v.index == index), None)
                if volume is None or volume.filesystem != "ntfs":
                    raise NTFSError(f"볼륨 {index}는 NTFS가 아니라서 폴더를 볼 수 없습니다")
                self._ntfs[index] = NTFSVolume(self.image, volume.offset)
            return self._ntfs[index]

    def _entry(self, index, parts):
        volume = self._volume(index)
        if not parts:
            return volume, None
        entry = volume.lookup("\\".join(parts))
        if entry is None:
            raise NTFSError("이미지 안에서 경로를 찾지 못했습니다: \\" + "\\".join(parts))
        return volume, entry

    def list_dir(self, index, parts=()):
        """Entries of a folder: [{name, directory, size, record, sequence}], folders first then by name."""
        fat = self._fat(index)
        if fat is not None:
            with self.lock:
                rows = [{"name": e["name"], "directory": e["directory"], "size": e["size"], "record": None,
                         "sequence": None, "in_use": not e["deleted"], "created": e["created"],
                         "modified": e["modified"], "accessed": e["accessed"]}
                        for e in fat.listdir(tuple(parts))]
            return sorted(rows, key=lambda r: (not r["directory"], not r["in_use"], r["name"].casefold()))
        with self.lock:
            volume, entry = self._entry(index, tuple(parts))
            if entry is not None and not entry.directory:
                raise NTFSError("폴더가 아닙니다")
            listing = volume.listdir(ROOT_RECORD if entry is None else entry.record)
            rows = [{"name": e.name, "directory": e.directory, "size": e.size, "record": e.record,
                     "sequence": e.sequence} for e in listing]
            return sorted(rows, key=lambda r: (not r["directory"], r["name"].casefold()))

    def volume_serial(self, index):
        """The NTFS volume serial number (16 hex digits), as the boot sector records it."""
        fat = self._fat(index)
        with self.lock:
            return fat.serial if fat is not None else self._volume(index).serial

    def exists(self, index, parts):
        """Whether the current file system still has this path (deleted or renamed files do not)."""
        fat = self._fat(index)
        with self.lock:
            if fat is not None:
                entry = fat.lookup(tuple(parts))
                return entry is not None and not entry["deleted"]
            try:
                volume, entry = self._entry(index, tuple(parts))
            except NTFSError:
                return False
            return entry is not None

    def describe(self, index, rows):
        """Add each row's $STANDARD_INFORMATION times and in-use state. One MFT read per row,
        so call it for the page being shown, not for a whole huge folder."""
        if self._fat(index) is not None:
            return [dict(row) for row in rows]  # FAT listings already carry the entry times and state
        with self.lock:
            volume = self._volume(index)
            described = []
            for row in rows:
                row = dict(row)
                try:
                    record = volume.record(row["record"])
                    row.update(in_use=record.in_use, **volume.times(record))
                except READ_ERRORS as exc:
                    row["error"] = str(exc)
                described.append(row)
            return described

    def open_file(self, index, parts):
        fat = self._fat(index)
        if fat is not None:
            with self.lock:
                entry = fat.lookup(tuple(parts))
                if entry is None or entry["directory"]:
                    raise NTFSError("파일이 아닙니다")
                return FATFile(self, fat, index, tuple(parts), entry)
        with self.lock:
            volume, entry = self._entry(index, tuple(parts))
            if entry is None or entry.directory:
                raise NTFSError("파일이 아닙니다")
            return ImageFile(self, volume, index, tuple(parts), entry.record)

    def open_record(self, index, number, parts=()):
        """A file by MFT record number — also for deleted files that no folder lists any more."""
        with self.lock:
            return ImageFile(self, self._volume(index), index, tuple(parts), number)

    def scan_mft(self, index, classify, limit=10000, progress=None, cancelled=None):
        """Walk every MFT record once (deleted ones too) and keep files that `classify(item)` puts
        into categories. Returns {"categories": {key: {"count", "items"}}, "records", "skipped",
        "cancelled"}. At most `limit` items are kept per category, but every match is counted.
        On a FAT volume the directory tree is walked instead (deleted entries included)."""
        fat = self._fat(index)
        if fat is not None:
            return self._scan_fat(fat, classify, limit, progress, cancelled)
        with self.lock:
            volume = self._volume(index)
            total = self._mft_records(volume)
        size, folders, found = volume.record_size, {}, {}
        state = {"records": total, "skipped": 0, "cancelled": False}
        for start in range(0, total, SCAN_CHUNK_RECORDS):
            if cancelled and cancelled():
                state["cancelled"] = True
                break
            count = min(SCAN_CHUNK_RECORDS, total - start)
            with self.lock:
                raw = volume._read_extents(volume.mft_extents, start * size, count * size)
            for offset in range(count):
                piece = raw[offset * size:(offset + 1) * size]
                item = _scan_record(piece, start + offset)
                if item is None:
                    state["skipped"] += piece[:4] == b"FILE"
                    continue
                if item["directory"]:
                    folders[item["record"]] = (item["name"], item["parent"])
                for key in classify(item):
                    bucket = found.setdefault(key, {"count": 0, "items": []})
                    bucket["count"] += 1
                    if len(bucket["items"]) < limit:
                        bucket["items"].append(item)
            if progress:
                progress(min(start + count, total), total)
        for bucket in found.values():
            for item in bucket["items"]:
                item["path"] = _path(item, folders)
        return {"categories": found, **state}

    def _scan_fat(self, fat, classify, limit, progress, cancelled):
        found, state = {}, {"records": 0, "skipped": 0, "cancelled": False}
        with self.lock:
            entries = list(fat.walk())
        for count, entry in enumerate(entries, 1):
            if cancelled and cancelled():
                state["cancelled"] = True
                break
            item = {"record": None, "sequence": None, "name": entry["name"], "path": entry["path"],
                    "in_use": not entry["deleted"], "directory": entry["directory"], "size": entry["size"],
                    "created": entry["created"], "modified": entry["modified"], "accessed": entry["accessed"]}
            state["records"] = count
            for key in classify(item):
                bucket = found.setdefault(key, {"count": 0, "items": []})
                bucket["count"] += 1
                if len(bucket["items"]) < limit:
                    bucket["items"].append(item)
        if progress:
            progress(state["records"], len(entries))
        return {"categories": found, **state}

    @staticmethod
    def _mft_records(volume):
        record0 = volume.record(0)
        fragments = volume._fragments(record0, ATTR_DATA, "")
        allocated = sum(count for _vcn, _lcn, count in volume.mft_extents) * volume.cluster_size
        real = fragments[0].real_size if fragments and fragments[0].nonresident else allocated
        return max(0, min(real, allocated)) // volume.record_size

    def close(self):
        with self.lock:
            self.image.close()


def _scan_record(raw, number):
    """Name, parent, size, times and state of one base MFT record, or None if it is unusable."""
    if raw[:4] != b"FILE":
        return None
    try:
        data = apply_fixup(raw, b"FILE")
        flags, used = struct.unpack_from("<HI", data, 22)
        base, = struct.unpack_from("<Q", data, 32)
        if base & 0xFFFFFFFFFFFF:
            return None  # extension record that belongs to another file
        attributes = parse_attributes(data, min(used, len(data)))
    except READ_ERRORS:
        return None
    names = [n for n in (parse_file_name(a.value) for a in attributes
                         if a.type == ATTR_FILE_NAME and not a.nonresident) if n]
    if not names:
        return None
    name = next((n for n in names if n["namespace"] != DOS_NAMESPACE), names[0])
    data_attribute = next((a for a in attributes if a.type == ATTR_DATA and not a.name), None)
    if data_attribute is None:
        size = name["size"]
    else:
        size = data_attribute.real_size if data_attribute.nonresident else len(data_attribute.value)
    info = next((a for a in attributes if a.type == ATTR_STANDARD_INFORMATION and not a.nonresident), None)
    times = {}
    if info is not None and len(info.value) >= 32:
        times = {key: filetime(value) for key, value in zip(TIME_KEYS, struct.unpack_from("<QQQQ", info.value))}
    return {"record": number, "sequence": struct.unpack_from("<H", data, 16)[0], "name": name["name"],
            "parent": name["parent"], "parent_sequence": name["parent_sequence"],
            "in_use": bool(flags & 1), "directory": bool(flags & 2), "size": size,
            **times}


def _path(item, folders):
    """Folder path from parent references; '?' marks a parent folder that no longer exists."""
    parts, current, seen = [item["name"]], item["parent"], set()
    while current != ROOT_RECORD and len(parts) < 64:
        if current in seen or current not in folders:
            parts.append("?")
            break
        seen.add(current)
        name, current = folders[current]
        parts.append(name)
    return "\\" + "\\".join(reversed(parts))


class FATFile:
    """A file on a FAT volume, with the same reading interface as ImageFile."""

    def __init__(self, browser, fat, index, parts, entry):
        self.browser, self.index, self.parts, self.entry = browser, index, parts, entry
        with browser.lock:
            self._read, self.size = fat.reader(entry["first_cluster"], entry["size"], deleted=entry["deleted"],
                                               contiguous=entry.get("contiguous", False))
        self.mft_record = self.sequence = None
        self.note = ("삭제된 항목입니다. 데이터는 첫 클러스터부터 이어져 있다고 가정했으며 덮어써졌을 수 있습니다"
                     if entry["deleted"] else "")
        if self.size < entry["size"]:
            self.note = (self.note + f" 기록된 크기({entry['size']}바이트) 중 {self.size}바이트만 읽을 수 있습니다").strip()

    def read(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("음수 오프셋/길이")
        with self.browser.lock:
            return self._read(offset, max(0, min(length, self.size - offset)))

    def sha256(self):
        digest = hashlib.sha256()
        for offset in range(0, self.size, HASH_BLOCK):
            digest.update(self.read(offset, HASH_BLOCK))
        return digest.hexdigest()

    def info(self):
        # FAT times are local wall-clock values without a zone: shown as recorded, never converted.
        return {"image": self.browser.path, "volume": self.index, "image_path": "\\" + "\\".join(self.parts),
                "mft_record": None, "mft_sequence": None, "size": self.size, "in_use": not self.entry["deleted"],
                "note": self.note, "created": self.entry["created"], "modified": self.entry["modified"],
                "accessed": self.entry["accessed"], "timezone_known": bool(self.entry.get("times_utc"))}


class ImageFile:
    """The unnamed $DATA stream of one file inside the image."""

    def __init__(self, browser, volume, index, parts, number):
        self.browser, self.volume, self.index, self.parts = browser, volume, index, parts
        self.record = volume.record(number)
        self.mft_record, self.sequence = number, self.record.sequence
        fragments = volume._fragments(self.record, ATTR_DATA, "")
        self.resident = None
        self.extents = []
        self.size = self.initialized = 0
        self.note = ""
        if not fragments:
            self.note = "데이터 스트림 없음"
        elif not fragments[0].nonresident:
            self.resident = fragments[0].value
            self.size = self.initialized = len(self.resident)
        else:
            first = fragments[0]
            self.extents = _extents(fragments)
            allocated = sum(count for _vcn, _lcn, count in self.extents) * volume.cluster_size
            self.size = max(0, min(first.real_size, allocated))
            self.initialized = max(0, min(first.initialized_size, self.size))
            if first.flags & FLAG_ENCRYPTED:
                self.note = "EFS 암호화 파일 — 내용은 암호문입니다"
            elif first.flags & FLAG_COMPRESSED:
                self.note = "NTFS 압축 파일 — 압축된 상태 그대로 보입니다"
            elif self.size < first.real_size:
                self.note = f"기록된 크기({first.real_size}바이트)가 할당 영역보다 커서 {self.size}바이트까지만 읽습니다"
        if not self.record.in_use:
            self.note = ("삭제된 파일입니다. 내용이 다른 파일로 덮어써졌을 수 있습니다. " + self.note).strip()

    def read(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("음수 오프셋/길이")
        end = min(self.size, offset + length)
        if offset >= end:
            return b""
        if self.resident is not None:
            return self.resident[offset:end]
        readable = max(0, min(end, self.initialized) - offset)
        with self.browser.lock:
            data = self.volume._read_extents(self.extents, offset, readable) if readable else b""
        return data + bytes(end - offset - len(data))

    def sha256(self):
        digest = hashlib.sha256()
        for offset in range(0, self.size, HASH_BLOCK):
            digest.update(self.read(offset, HASH_BLOCK))
        return digest.hexdigest()

    def info(self):
        return {"image": self.browser.path, "volume": self.index, "image_path": "\\" + "\\".join(self.parts),
                "mft_record": self.mft_record, "mft_sequence": self.sequence, "size": self.size,
                "in_use": self.record.in_use, "note": self.note, **self.volume.times(self.record)}
