import struct
from .base import ArtifactParser
from .registry import Hive, walk
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.text import decode_text, target_acp


def parse_mru_list_ex(data):
    if len(data) % 4:
        raise ValueError("MRUListEx가 DWORD 경계에 맞지 않습니다")
    result = []
    for (value,) in struct.iter_unpack("<I", data):
        if value == 0xFFFFFFFF:
            return result
        result.append(value)
    raise ValueError("MRUListEx 종료 마커 없음")


def parse_mru_list(data):
    """Parse legacy MRUList (single-char string order, e.g. 'dcba')."""
    if not data:
        return []
    if isinstance(data, bytes):
        data = data.decode("ascii", errors="replace").rstrip("\x00")
    return list(data)


def _decode_utf16le_value(raw):
    end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), None)
    if end is not None:
        return raw[:end].decode("utf-16-le", errors="replace")
    return raw.decode("utf-16-le", errors="replace").rstrip("\0")


def _parse_last_visited_entry(raw, pidl=False, codepage=None):
    """Parse LastVisitedMRU/LastVisitedPidlMRU binary value.

    Format: UTF-16LE executable name, NUL-NUL separator, UTF-16LE directory/shell item.
    """
    end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), None)
    if end is None:
        return None, None
    exe = raw[:end].decode("utf-16-le", errors="replace")
    # A PIDL is binary shell-item data, not a second UTF-16 string.
    if pidl:
        from .shellbag import decode_id_list
        directory, _ = decode_id_list(raw[end+2:], codepage)
    else:
        directory = _decode_utf16le_value(raw[end + 2:]) or None
    return exe, directory


class MRUParser(ArtifactParser):
    artifact = "mru"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        yield from self._parse_recent_docs(hive, path)
        yield from self._parse_open_save_pidl_mru(hive, path)
        yield from self._parse_open_save_mru(hive, path)
        yield from self._parse_last_visited_mru(hive, path)
        yield from self._parse_last_visited_pidl_mru(hive, path)

    def _parse_recent_docs(self, hive, path):
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        try:
            root = hive.open(base)
        except KeyError:
            return
        for suffix, key in walk(root):
            values = {v["name"]: v for v in key.values()}
            if "MRUListEx" not in values:
                continue
            try:
                order = parse_mru_list_ex(values["MRUListEx"]["raw"])
            except ValueError as exc:
                self.error(path, base + suffix, exc)
                continue
            for rank, index in enumerate(order):
                value = values.get(str(index))
                if value is None or "error" in value:
                    self.error(path, base + suffix, f"MRU 값 {index} 없음/손상")
                    continue
                raw = value["raw"]
                filename = None
                end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\0\0"), None)
                if end is not None:
                    filename = raw[:end].decode("utf-16-le", errors="replace")
                yield ForensicEvent(self.artifact, str(path), "recent_document", filetime(key.lastwrite) if rank == 0 else None,
                                    "key_lastwrite" if rank == 0 else None, self.sid, path=filename, locator=base + suffix + "\\" + str(index),
                                    status="ok" if filename else "partial",
                                    details={"rank": rank, "raw": raw.hex(), "pidl_decoded": False,
                                             "time_is_document_open_time": False, "subtype": "RecentDocs"})

    def _parse_open_save_pidl_mru(self, hive, path):
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
        try:
            root = hive.open(base)
        except KeyError:
            return
        for suffix, key in walk(root):
            values = {v["name"]: v for v in key.values()}
            if "MRUListEx" not in values:
                continue
            try:
                order = parse_mru_list_ex(values["MRUListEx"]["raw"])
            except ValueError as exc:
                self.error(path, base + suffix, exc)
                continue
            extension = suffix.lstrip("\\") or "*"
            for rank, index in enumerate(order):
                value = values.get(str(index))
                if value is None or "error" in value:
                    self.error(path, base + suffix, f"MRU 값 {index} 없음/손상")
                    continue
                raw = value["raw"]
                from .shellbag import decode_id_list
                decoded_path, decoded_details = decode_id_list(raw, target_acp(self.environment))
                yield ForensicEvent(self.artifact, str(path), "open_save_dialog", filetime(key.lastwrite) if rank == 0 else None,
                                    "key_lastwrite" if rank == 0 else None, self.sid, path=decoded_path, locator=base + suffix + "\\" + str(index),
                                    status="ok",
                                    details={"rank": rank, "raw": raw.hex(), **decoded_details,
                                             "extension": extension, "subtype": "OpenSavePidlMRU"})

    def _parse_open_save_mru(self, hive, path):
        """Parse legacy OpenSaveMRU (string-based MRUList, pre-Vista)."""
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"
        try:
            root = hive.open(base)
        except KeyError:
            return
        for suffix, key in walk(root):
            values = {v["name"]: v for v in key.values()}
            if "MRUList" not in values:
                continue
            mru_val = values["MRUList"]
            raw_data = mru_val.get("value") or mru_val.get("raw", b"")
            try:
                order = parse_mru_list(raw_data)
            except (ValueError, UnicodeDecodeError) as exc:
                self.error(path, base + suffix, exc)
                continue
            extension = suffix.lstrip("\\") or "*"
            for rank, letter in enumerate(order):
                value = values.get(letter)
                if value is None or "error" in value:
                    continue
                filename = value.get("value")
                decoding = None
                if not filename or isinstance(filename, bytes):
                    raw = value.get("raw", b"")
                    decoding = decode_text(raw, target_acp(self.environment))
                    filename = decoding['text'].rstrip('\0')
                yield ForensicEvent(self.artifact, str(path), "open_save_dialog", filetime(key.lastwrite) if rank == 0 else None,
                                    "key_lastwrite" if rank == 0 else None, self.sid, path=filename,
                                    locator=base + suffix + "\\" + letter, status="ok",
                                    details={"rank": rank, "extension": extension,
                                             "subtype": "OpenSaveMRU",
                                             **({'text_decoding':[{k:v for k,v in decoding.items() if k != 'text'}]}
                                                if decoding else {})})

    def _parse_last_visited_mru(self, hive, path):
        """Parse LastVisitedMRU (legacy, string-based MRUList)."""
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU"
        try:
            key = hive.open(base)
        except KeyError:
            return
        values = {v["name"]: v for v in key.values()}
        if "MRUList" not in values:
            return
        mru_val = values["MRUList"]
        raw_data = mru_val.get("value") or mru_val.get("raw", b"")
        try:
            order = parse_mru_list(raw_data)
        except (ValueError, UnicodeDecodeError) as exc:
            self.error(path, base, exc)
            return
        for rank, letter in enumerate(order):
            value = values.get(letter)
            if value is None or "error" in value:
                continue
            raw = value.get("raw", b"")
            exe, directory = _parse_last_visited_entry(raw)
            yield ForensicEvent(self.artifact, str(path), "last_visited_dialog", filetime(key.lastwrite) if rank == 0 else None,
                                "key_lastwrite" if rank == 0 else None, self.sid, path=directory, process=exe,
                                locator=base + "\\" + letter, status="ok",
                                details={"rank": rank, "executable": exe, "last_directory": directory,
                                         "raw": raw.hex(), "subtype": "LastVisitedMRU"})

    def _parse_last_visited_pidl_mru(self, hive, path):
        """Parse LastVisitedPidlMRU / LastVisitedPidlMRULegacy (MRUListEx-based)."""
        for name in ("LastVisitedPidlMRU", "LastVisitedPidlMRULegacy"):
            base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\\" + name
            try:
                key = hive.open(base)
            except KeyError:
                continue
            values = {v["name"]: v for v in key.values()}
            if "MRUListEx" not in values:
                continue
            try:
                order = parse_mru_list_ex(values["MRUListEx"]["raw"])
            except ValueError as exc:
                self.error(path, base, exc)
                continue
            for rank, index in enumerate(order):
                value = values.get(str(index))
                if value is None or "error" in value:
                    continue
                raw = value["raw"]
                exe, directory = _parse_last_visited_entry(raw, pidl=True, codepage=target_acp(self.environment))
                end = next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'), None)
                from .shellbag import decode_id_list
                _, pidl_details = decode_id_list(raw[end+2:], target_acp(self.environment)) if end is not None else (None,{})
                yield ForensicEvent(self.artifact, str(path), "last_visited_dialog", filetime(key.lastwrite) if rank == 0 else None,
                                    "key_lastwrite" if rank == 0 else None, self.sid, path=directory, process=exe,
                                    locator=base + "\\" + str(index), status="ok",
                                    details={"rank": rank, "executable": exe, "last_directory": directory,
                                             "raw": raw.hex(), "subtype": name, **pidl_details})
