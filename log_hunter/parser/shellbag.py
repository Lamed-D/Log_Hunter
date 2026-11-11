"""ShellBag parser for NTUSER.DAT and UsrClass.dat hives.

Parses BagMRU tree structure to recover folder access history including
deleted folders, network shares, and removable media paths.
"""
import struct
from .base import ArtifactParser
from .registry import Hive, walk
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.text import decode_ansi, target_acp


SHELLBAG_ROOTS = [
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\Shell\Bags",
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Local Settings\Software\Microsoft\Windows\Shell\Bags",
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
]


def _extract_shell_item_name(data, codepage=None):
    if len(data) < 4:
        return None, {}
    size, item_type = struct.unpack_from("<HB", data)
    if size < 3 or size > len(data):
        return None, {}
    data = data[:size]

    details = {"shell_item_type": item_type, "shell_item_size": size}
    if item_type in (0x23, 0x25, 0x29, 0x2F) and size > 3:
        raw = data[3:].split(b'\0', 1)[0]
        decoded = decode_ansi(raw, codepage)
        return decoded['text'], {'type_name':'volume', 'text_decoding':[{k:v for k,v in decoded.items() if k != 'text'}]}

    if item_type == 0x1F:
        if len(data) >= 20:
            details["type_name"] = "root_folder"
            guid_bytes = data[4:20]
            details["guid"] = guid_bytes.hex()
        return None, details

    if item_type in (0x31, 0x32, 0x35, 0xB1):
        details["type_name"] = "file_entry"
        if len(data) > 14:
            name_start = 14
            try:
                if item_type & 4:
                    end = next((i for i in range(name_start, size-1, 2) if data[i:i+2] == b'\0\0'), size)
                    raw = data[name_start:end]
                    failed = False
                    try:
                        short_name = raw.decode('utf-16-le')
                    except UnicodeDecodeError:
                        short_name = raw.decode('utf-16-le', errors='replace')
                        failed = True
                    decoded = {'text':short_name, 'encoding':'utf-16-le', 'inferred':False,
                               'decode_error':failed, 'raw_hex':raw.hex()}
                else:
                    end = data.index(0, name_start)
                    decoded = decode_ansi(data[name_start:end], codepage)
                    short_name = decoded['text']
                if decoded['inferred'] or decoded['decode_error']:
                    details.setdefault('text_decoding', []).append({k:v for k,v in decoded.items() if k != 'text'})
                details["short_name"] = short_name
            except ValueError:
                pass
            ext_offset = _find_extension_block(data, size)
            if ext_offset and ext_offset + 12 < size:
                try:
                    relative_name = struct.unpack_from('<H', data, ext_offset + 16)[0]
                    block_size, version = struct.unpack_from('<HH', data, ext_offset)
                    minimum = {3:20, 7:38, 8:42, 9:46}.get(version)
                    relative_name = relative_name or minimum
                    if minimum is None or relative_name < minimum or relative_name >= block_size - 2:
                        return details.get('short_name'), details
                    long_name_offset = ext_offset + relative_name
                    if long_name_offset < size:
                        end = next((i for i in range(long_name_offset, ext_offset + block_size - 3, 2)
                                    if data[i:i+2] == b'\0\0'), None)
                        if end is not None and end > long_name_offset:
                            raw = data[long_name_offset:end]
                            failed = False
                            try:
                                long_name = raw.decode('utf-16-le')
                            except UnicodeDecodeError:
                                long_name = raw.decode('utf-16-le', errors='replace')
                                failed = True
                            if failed:
                                details.setdefault('text_decoding', []).append({'encoding':'utf-16-le', 'decode_error':True, 'inferred':False, 'raw_hex':raw.hex()})
                            if long_name:
                                return long_name, details
                except (UnicodeDecodeError, struct.error):
                    pass
            return details.get("short_name"), details

    if item_type in (0x41, 0x42, 0x46, 0x47, 0xC3):
        details["type_name"] = "network"
        if len(data) > 5:
            try:
                end = data.index(0, 5)
                decoded = decode_ansi(data[5:end], codepage)
                network_name = decoded['text']
                if decoded['inferred'] or decoded['decode_error']:
                    details.setdefault('text_decoding', []).append({k:v for k,v in decoded.items() if k != 'text'})
                details["network_name"] = network_name
                return network_name, details
            except ValueError:
                pass

    if item_type == 0x61:
        details["type_name"] = "uri"
        if len(data) > 6:
            try:
                end = data.index(0, 6)
                decoded = decode_ansi(data[6:end], codepage)
                uri = decoded['text']
                if decoded['inferred'] or decoded['decode_error']:
                    details.setdefault('text_decoding', []).append({k:v for k,v in decoded.items() if k != 'text'})
                return uri, details
            except ValueError:
                pass

    return None, details


def decode_id_list(data, codepage=None):
    """PIDL에서 실제 해석된 이름만 복원하고 미해석 항목·추정은 별도로 남깁니다."""
    parts, notes = [], []
    offset, unknown = 0, False
    for _ in range(4096):
        if offset + 2 > len(data) or offset > 1024 * 1024:
            unknown = True
            break
        size, = struct.unpack_from('<H',data,offset)
        if size == 0:
            break
        if size < 3 or offset + size > len(data):
            unknown = True
            break
        name, details = _extract_shell_item_name(data[offset:offset+size], codepage)
        if name:
            parts.append(name)
        else:
            unknown = True
        notes.extend(details.get('text_decoding', []))
        offset += size
    else:
        unknown = True
    path = '\\'.join(part.rstrip('\\') for part in parts) if parts else None
    absolute = bool(path and (path.startswith('\\\\') or len(path)>2 and path[0].isascii() and path[0].isalpha() and path[1:3]==':\\'))
    return path, {'pidl_decoded':bool(parts), 'pidl_has_unknown_items':unknown,
                  'full_path_confirmed':absolute and not unknown,
                  **({'text_decoding':notes} if notes else {})}


def _find_extension_block(data, size):
    if size < 24:
        return None
    first, = struct.unpack_from('<H', data, size-2)
    offsets = [first] if 14 <= first < size-18 else []
    offsets += range(14, min(size-18, 65536), 2)
    for offset in offsets:
        block_size, version, signature = struct.unpack_from('<HHI', data, offset)
        if signature == 0xBEEF0004 and version in (3,7,8,9) and block_size >= 20 and offset+block_size <= size:
            return offset
    return None


class ShellBagParser(ArtifactParser):
    artifact = "shellbag"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        for base in SHELLBAG_ROOTS:
            try:
                root = hive.open(base)
            except KeyError:
                continue
            yield from self._walk_bagmru(hive, root, base, path, [], set())

    def _walk_bagmru(self, hive, key, locator, path, path_parts, seen, depth=0):
        # BagMRU keys reached twice (shared or looping subkey lists in a crafted hive) are walked once.
        if key.offset in seen:
            return
        if depth > 128:
            self.error(path, locator, "폴더 기록 키 깊이 상한 초과", "warning")
            return
        seen.add(key.offset)
        values = list(key.values())
        order = []
        from .mru import parse_mru_list_ex
        for value in values:
            if value.get("name") == "MRUListEx" and not value.get("error"):
                try:
                    order = parse_mru_list_ex(value["raw"])
                except (KeyError, ValueError) as exc:
                    self.error(path, locator, exc, "warning")
        for value in values:
            if value.get("error") or value["type"] != 3:
                continue
            name = value["name"]
            if name == "MRUListEx" or name == "NodeSlot" or name == "NodeSlots":
                continue
            try:
                int(name)
            except ValueError:
                continue
            raw = value["raw"]
            item_name, item_details = _extract_shell_item_name(raw, target_acp(self.environment))
            current_path = path_parts + ([item_name] if item_name else [f"[{name}]"])
            full_path = "\\".join(current_path)
            yield ForensicEvent(
                self.artifact, str(path), "folder_access",
                filetime(key.lastwrite) if order and int(name) == order[0] else None,
                "key_lastwrite" if order and int(name) == order[0] else None,
                self.sid, path=full_path, locator=locator + "\\" + name,
                details={
                    **item_details,
                    "registry_key": locator,
                    "value_index": name,
                    "raw_hex": raw[:64].hex() + ("..." if len(raw) > 64 else ""),
                    "full_path_confirmed": item_name is not None and (full_path.startswith('\\\\') or len(full_path)>2 and full_path[1:3]==':\\'),
                    "deleted_folder_evidence": None,
                }
            )
            child_locator = locator + "\\" + name
            try:
                child = hive.open(child_locator)
                yield from self._walk_bagmru(hive, child, child_locator, path, current_path, seen, depth + 1)
            except KeyError:
                pass
