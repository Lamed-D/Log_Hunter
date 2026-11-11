# ▶ 원본: log_hunter/parser/lnk.py
# ▶ 바로가기 헤더·대상·문자열을 읽습니다. 참조 대상 파일을 열거나 명령을 실행하지 않습니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Windows Shell Link (.lnk) parser per MS-SHLLINK specification.

Extracts target path, timestamps, file attributes, string data (description,
relative path, working directory, arguments, icon location), volume info,
and network share paths from LNK shortcut files.
"""
import struct
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.text import decode_ansi, target_acp

LNK_HEADER_SIZE = 0x4C
LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

FLAG_HAS_LINK_TARGET_ID_LIST = 0x01
FLAG_HAS_LINK_INFO = 0x02
FLAG_HAS_NAME = 0x04
FLAG_HAS_RELATIVE_PATH = 0x08
FLAG_HAS_WORKING_DIR = 0x10
FLAG_HAS_ARGUMENTS = 0x20
FLAG_HAS_ICON_LOCATION = 0x40
FLAG_IS_UNICODE = 0x80


def shell_link_span(data, start=0, maximum=16 * 1024 * 1024, budget=None):
    """Return the complete framed Shell Link length, including its terminal block."""
    if start < 0 or maximum < LNK_HEADER_SIZE + 4:
        raise ValueError('바로가기 시작 위치/크기 상한 오류')
    end = min(len(data), start + maximum)
    position = start
    steps = 0

    def take(length):
        nonlocal position, steps
        steps += 1
        if steps > 4096 or budget is not None and budget[0] <= 0:
            raise ValueError('바로가기 구조 해석 횟수 상한 초과')
        if budget is not None:
            budget[0] -= 1
        if length < 0 or position < start or position + length > end:
            raise ValueError('바로가기 레코드 길이/범위 오류')
        previous = position
        position += length
        return previous

    header = take(LNK_HEADER_SIZE)
    if struct.unpack_from('<I', data, header)[0] != LNK_HEADER_SIZE or data[header + 4:header + 20] != LNK_CLSID:
        raise ValueError('바로가기 레코드 헤더 오류')
    flags = struct.unpack_from('<I', data, header + 20)[0]
    if flags & FLAG_HAS_LINK_TARGET_ID_LIST:
        count = struct.unpack_from('<H', data, take(2))[0]
        if count < 2:
            raise ValueError('바로가기 IDList 길이 오류')
        take(count)
    if flags & FLAG_HAS_LINK_INFO:
        size = struct.unpack_from('<I', data, take(4))[0]
        if size < 28:
            raise ValueError('바로가기 LinkInfo 길이 오류')
        take(size - 4)
    for flag in (FLAG_HAS_NAME, FLAG_HAS_RELATIVE_PATH, FLAG_HAS_WORKING_DIR, FLAG_HAS_ARGUMENTS, FLAG_HAS_ICON_LOCATION):
        if flags & flag:
            count = struct.unpack_from('<H', data, take(2))[0]
            take(count * (2 if flags & FLAG_IS_UNICODE else 1))
    while True:
        size = struct.unpack_from('<I', data, take(4))[0]
        if size < 4:
            return position - start
        if size < 8:
            raise ValueError('바로가기 추가 블록 길이 오류')
        take(size - 4)

FILE_ATTR_NAMES = {
    0x01: "READONLY", 0x02: "HIDDEN", 0x04: "SYSTEM", 0x10: "DIRECTORY",
    0x20: "ARCHIVE", 0x80: "NORMAL", 0x100: "TEMPORARY", 0x200: "SPARSE_FILE",
    0x400: "REPARSE_POINT", 0x800: "COMPRESSED", 0x2000: "NOT_CONTENT_INDEXED",
    0x4000: "ENCRYPTED",
}

SHOW_COMMAND_NAMES = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}


def _read_cstring(data, offset, codepage=None, notes=None):
    end = data.find(b"\x00", offset)
    end = len(data) if end < 0 else end
    decoded = decode_ansi(data[offset:end], codepage)
    if notes is not None and (decoded['inferred'] or decoded['decode_error']):
        notes.append({k:v for k,v in decoded.items() if k != 'text'})
    return decoded['text'], min(end + 1, len(data))


def _read_unicode_cstring(data, offset, notes=None):
    end = next((i for i in range(offset, len(data)-1, 2) if data[i:i+2] == b'\0\0'), len(data))
    raw = data[offset:end]
    try:
        text = raw.decode('utf-16-le')
    except UnicodeDecodeError:
        text = raw.decode('utf-16-le', errors='replace')
        if notes is not None:
            notes.append({'encoding':'utf-16-le', 'decode_error':True, 'inferred':False, 'raw_hex':raw.hex()})
    return text, min(end + 2, len(data))


def _decode_file_attributes(flags):
    return [name for bit, name in FILE_ATTR_NAMES.items() if flags & bit]


def parse_lnk(data, codepage=None):
    if len(data) < LNK_HEADER_SIZE:
        raise ValueError("LNK 파일 크기 부족")
    header_size, = struct.unpack_from("<I", data, 0)
    if header_size != LNK_HEADER_SIZE:
        raise ValueError(f"LNK 헤더 크기 불일치: {header_size:#x}")
    clsid = data[4:20]
    if clsid != LNK_CLSID:
        raise ValueError("LNK CLSID 불일치")

    link_flags, = struct.unpack_from("<I", data, 20)
    file_attrs, = struct.unpack_from("<I", data, 24)
    creation_time, access_time, write_time = struct.unpack_from("<QQQ", data, 28)
    file_size, = struct.unpack_from("<I", data, 52)
    icon_index, = struct.unpack_from("<I", data, 56)
    show_command, = struct.unpack_from("<I", data, 60)

    result = {
        "creation_time": filetime(creation_time),
        "access_time": filetime(access_time),
        "write_time": filetime(write_time),
        "file_size": file_size,
        "file_attributes": _decode_file_attributes(file_attrs),
        "file_attributes_raw": file_attrs,
        "icon_index": icon_index,
        "show_command": SHOW_COMMAND_NAMES.get(show_command, show_command),
        "link_flags": link_flags,
    }
    notes = []

    offset = LNK_HEADER_SIZE

    # LinkTargetIDList
    if link_flags & FLAG_HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            raise ValueError("LinkTargetIDList 크기 읽기 오류")
        id_list_size, = struct.unpack_from("<H", data, offset)
        result["id_list_size"] = id_list_size
        if offset + 2 + id_list_size > len(data):
            raise ValueError('LinkTargetIDList 범위 초과')
        from .shellbag import decode_id_list
        result['id_list_path'], result['id_list_decoding'] = decode_id_list(data[offset+2:offset+2+id_list_size], codepage)
        offset += 2 + id_list_size

    # LinkInfo
    target_path = None
    if link_flags & FLAG_HAS_LINK_INFO:
        if offset + 4 > len(data):
            raise ValueError("LinkInfo 크기 읽기 오류")
        link_info_size, = struct.unpack_from("<I", data, offset)
        if link_info_size < 28 or offset + link_info_size > len(data):
            raise ValueError("LinkInfo 크기 범위 초과")
        li = data[offset:offset + link_info_size]
        li_header_size, = struct.unpack_from("<I", li, 4)
        li_flags, = struct.unpack_from("<I", li, 8)
        if li_header_size < 28 or li_header_size > len(li):
            raise ValueError('LinkInfo 헤더 범위 오류')

        if li_flags & 0x01 and li_header_size >= 16:
            volume_id_offset, = struct.unpack_from("<I", li, 12)
            local_base_path_offset, = struct.unpack_from("<I", li, 16)

            # Volume ID
            if volume_id_offset + 16 <= len(li):
                vi_size, = struct.unpack_from("<I", li, volume_id_offset)
                if vi_size >= 16 and volume_id_offset + vi_size <= len(li):
                    drive_type, = struct.unpack_from("<I", li, volume_id_offset + 4)
                    serial, = struct.unpack_from("<I", li, volume_id_offset + 8)
                    label_offset, = struct.unpack_from("<I", li, volume_id_offset + 12)
                    drive_types = {0: "UNKNOWN", 1: "NO_ROOT_DIR", 2: "REMOVABLE",
                                   3: "FIXED", 4: "REMOTE", 5: "CDROM", 6: "RAMDISK"}
                    result["volume_drive_type"] = drive_types.get(drive_type, drive_type)
                    result["volume_serial"] = f"{serial:08X}"
                    if label_offset < vi_size:
                        label, _ = _read_cstring(li[volume_id_offset:volume_id_offset + vi_size], label_offset, codepage, notes)
                        result["volume_label"] = label
                    if label_offset == 20 and vi_size >= 20:
                        unicode_label, = struct.unpack_from('<I', li, volume_id_offset+16)
                        if 20 <= unicode_label < vi_size:
                            result['volume_label'], _ = _read_unicode_cstring(li[volume_id_offset:volume_id_offset+vi_size], unicode_label, notes)

            # Local base path (ASCII)
            if local_base_path_offset < len(li):
                local_path, _ = _read_cstring(li, local_base_path_offset, codepage, notes)
                target_path = local_path

            # Unicode paths (header >= 0x24)
            if li_header_size >= 0x24 and len(li) >= 0x24:
                try:
                    local_base_unicode_offset, = struct.unpack_from("<I", li, 0x1C)
                    common_suffix_unicode_offset, = struct.unpack_from("<I", li, 0x20)
                    if li_header_size <= local_base_unicode_offset < len(li):
                        unicode_path, _ = _read_unicode_cstring(li, local_base_unicode_offset, notes)
                        if unicode_path:
                            target_path = unicode_path
                except (struct.error, ValueError):
                    pass

        if li_flags & 0x02 and li_header_size >= 20:
            cnrl_offset, = struct.unpack_from("<I", li, 20)
            if cnrl_offset + 20 <= len(li):
                cnrl_size, = struct.unpack_from("<I", li, cnrl_offset)
                cnrl_flags, = struct.unpack_from("<I", li, cnrl_offset + 4)
                net_name_offset, = struct.unpack_from("<I", li, cnrl_offset + 8)
                if cnrl_offset + net_name_offset < len(li):
                    net_name, _ = _read_cstring(li, cnrl_offset + net_name_offset, codepage, notes)
                    if net_name_offset > 20 and cnrl_size >= 28 and cnrl_offset + cnrl_size <= len(li):
                        unicode_net_offset, = struct.unpack_from('<I', li, cnrl_offset+20)
                        if 28 <= unicode_net_offset < cnrl_size:
                            net_name, _ = _read_unicode_cstring(li[cnrl_offset:cnrl_offset+cnrl_size], unicode_net_offset, notes)
                    result["network_share_name"] = net_name
                    if not target_path:
                        target_path = net_name

        # Common path suffix (ASCII, after local base path)
        if li_flags & 0x03 and li_header_size >= 28:
            common_path_offset_field = 24
            if common_path_offset_field is not None and common_path_offset_field + 4 <= len(li):
                suffix_offset, = struct.unpack_from('<I', li, common_path_offset_field)
                suffix = ''
                if li_header_size <= suffix_offset < len(li):
                    suffix, _ = _read_cstring(li, suffix_offset, codepage, notes)
                if li_header_size >= 36:
                    unicode_suffix, = struct.unpack_from('<I', li, 32)
                    if li_header_size <= unicode_suffix < len(li):
                        suffix, _ = _read_unicode_cstring(li, unicode_suffix, notes)
                if target_path and suffix and not target_path.casefold().endswith(suffix.casefold()):
                    target_path = target_path.rstrip('\\') + '\\' + suffix.lstrip('\\')

        offset += link_info_size

    result["target_path"] = target_path

    # String Data
    is_unicode = bool(link_flags & FLAG_IS_UNICODE)
    string_fields = []
    if link_flags & FLAG_HAS_NAME:
        string_fields.append("description")
    if link_flags & FLAG_HAS_RELATIVE_PATH:
        string_fields.append("relative_path")
    if link_flags & FLAG_HAS_WORKING_DIR:
        string_fields.append("working_dir")
    if link_flags & FLAG_HAS_ARGUMENTS:
        string_fields.append("arguments")
    if link_flags & FLAG_HAS_ICON_LOCATION:
        string_fields.append("icon_location")

    for field in string_fields:
        if offset + 2 > len(data):
            break
        count, = struct.unpack_from("<H", data, offset)
        offset += 2
        if is_unicode:
            byte_len = count * 2
            if offset + byte_len > len(data):
                break
            raw = data[offset:offset + byte_len]
            try:
                result[field] = raw.decode('utf-16-le')
            except UnicodeDecodeError:
                result[field] = raw.decode('utf-16-le', errors='replace')
                notes.append({'field':field, 'encoding':'utf-16-le', 'inferred':False, 'decode_error':True, 'raw_hex':raw.hex()})
            offset += byte_len
        else:
            if offset + count > len(data):
                break
            decoded = decode_ansi(data[offset:offset + count], codepage)
            result[field] = decoded['text']
            if decoded['inferred'] or decoded['decode_error']:
                notes.append({'field':field, **{k:v for k,v in decoded.items() if k != 'text'}})
            offset += count

    if notes:
        result['text_decoding'] = notes
    if not result.get('target_path') and not result.get('relative_path') and result.get('id_list_path'):
        result['target_path'] = result['id_list_path']
    if result.get('id_list_decoding', {}).get('text_decoding'):
        result.setdefault('text_decoding', []).extend(result['id_list_decoding']['text_decoding'])
    return result


class LNKParser(ArtifactParser):
    artifact = "lnk"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            files = sorted(source.rglob("*.lnk"))
        else:
            files = [source]

        for lnk_file in files:
            if not lnk_file.is_file():
                continue
            try:
                data = lnk_file.read_bytes()
                info = parse_lnk(data, target_acp(self.environment))
            except (ValueError, struct.error, UnicodeError) as exc:
                self.error(lnk_file, "header", exc)
                continue

            target = info.get("target_path") or info.get('relative_path')
            timestamps = [
                ("lnk_target_created", info.get("creation_time")),
                ("lnk_target_accessed", info.get("access_time")),
                ("lnk_target_written", info.get("write_time")),
            ]

            details = {}
            for key in ("file_size", "file_attributes", "icon_index", "show_command",
                        "volume_serial", "volume_label", "volume_drive_type",
                        "network_share_name", "description", "relative_path",
                        "working_dir", "arguments", "icon_location", "id_list_size", "text_decoding", "id_list_decoding"):
                val = info.get(key)
                if val is not None and val != "" and val != [] and val != 0:
                    details[key] = val

            for time_field, timestamp in timestamps:
                if timestamp:
                    yield ForensicEvent(
                        self.artifact, str(lnk_file), "shortcut_target",
                        timestamp, time_field, sid=self.sid,
                        path=target, locator=str(lnk_file.name),
                        details=details,
                    )

            if not any(ts for _, ts in timestamps):
                yield ForensicEvent(
                    self.artifact, str(lnk_file), "shortcut_target",
                    sid=self.sid, path=target, locator=str(lnk_file.name),
                    status="partial", details=details,
                )
