# ▶ 원본: log_hunter/parser/jumplist.py
# ▶ DestList 항목 ID와 16진수 LNK 스트림 이름을 연결합니다. 의미 미확정 필드는 원시 값으로 남깁니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Jump List destination records and compound LNK streams, with partial scan recovery."""
import struct
from pathlib import Path
from .base import ArtifactParser
from .lnk import parse_lnk, LNK_CLSID, shell_link_span
from log_hunter.core.text import target_acp
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime

CFBF_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
LNK_SIGNATURE = b"\x4C\x00\x00\x00" + LNK_CLSID

KNOWN_APP_IDS = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "5d696d521de238c3": "Google Chrome",
    "a7bd71699cd38d1c": "Google Chrome (Alt)",
    "9b9cdc69c1c24e2b": "Notepad",
    "f01b4d95cf55d32a": "Windows Explorer (Alt)",
    "adecfb853d77462a": "Microsoft Word",
    "a4a5324453625195": "Microsoft Word (Alt)",
    "7e4dca80246863e3": "Control Panel",
    "12dc1ea8e34b5a6": "Microsoft Paint",
    "5f7b5f1e01b83767": "Notepad++",
    "b8c29862d9f95832": "Microsoft Edge",
    "1e5bf41c4c3eab9c": "FileZilla",
    "5afe4de1b92fc382": "Firefox",
    "28c8b86deab549a1": "Internet Explorer",
    "9c7cc110ff56d1bd": "PuTTY",
    "776b832c58dc4150": "7-Zip",
    "bc03160ee1a09136": "WinRAR",
    "fb3b0dbfee58fac8": "Windows Media Player",
    "1cf97c38a5881255": "VLC Media Player",
    "e70d383b15687e37": "Notepad (Win10+)",
    "f34ca6a22bd93953": "Microsoft Visual Studio",
    "5c450709f7ae4396": "Firefox (Alt)",
    "560d789a6a42ad5e": "Remote Desktop Connection",
    "5bb3208dc0e2b2d4": "Calculator",
    "b0459de4674aab56": "Windows Terminal",
    "c91d08dcfc247265": "Skype",
    "4cb012e2c43e89fa": "Windows Live Messenger",
    "fe8235e1a578ca32": "TeamViewer",
    "4a7e4f6a20c42b53": "Microsoft PowerPoint",
    "d00655d2aa12ff6d": "Microsoft Excel",
    "cbbf820c2c261a5b": "Microsoft Excel (Alt)",
    "3094cdb43bf5e9c2": "PDF-XChange",
    "590aee7bdd69b59b": "Windows CMD",
    "b91050d8b077a4e8": "Microsoft Outlook",
}

CUSTOM_DEST_SEPARATOR = b"\xAB\xFB\xBF\xBA"
MAX_INPUT = 128 * 1024 * 1024
MAX_CUSTOM_RECORDS = 10000
MAX_CUSTOM_STEPS = 1000000


def _app_id_from_filename(name):
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return stem.lower()


def _find_lnk_offsets(data):
    offsets = []
    pos = 0
    while True:
        idx = data.find(LNK_SIGNATURE, pos)
        if idx < 0:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


def _try_parse_lnk_at(data, offset, codepage=None):
    chunk = data[offset:]
    if len(chunk) < 76:
        return None
    try:
        return parse_lnk(chunk, codepage)
    except (ValueError, struct.error, UnicodeError):
        return None


def _parse_destlist_entry(data, offset, version=1):
    if version not in (1, 3, 4):
        raise ValueError("지원하지 않는 최근 항목 목록 버전")
    fixed = 114 if version == 1 else 130
    if offset < 0 or offset + fixed > len(data):
        raise ValueError("잘린 최근 항목 목록 레코드")
    path_size = struct.unpack_from("<H", data, offset + fixed - 2)[0]
    path_end = offset + fixed + path_size * 2
    end = path_end + (0 if version == 1 else 4)
    if end > len(data):
        raise ValueError("최근 항목 목록 경로 길이 범위 초과")
    stamp = struct.unpack_from("<Q", data, offset + 100)[0]
    raw_count = offset + (96 if version == 1 else 116)
    return {"entry_id": struct.unpack_from("<I", data, offset + 88)[0],
            "netbios_name": data[offset + 72:offset + 88].split(b"\0", 1)[0].decode("ascii", errors="replace") or None,
            "access_count": None, "access_count_raw": data[raw_count:raw_count + 4].hex(),
            "timestamp": filetime(stamp), "timestamp_raw": stamp,
            "pin_status": struct.unpack_from("<i", data, offset + 108)[0],
            "path": data[offset + fixed:path_end].decode("utf-16-le", errors="replace") or None}, end


def _parse_destlist(data, on_error=None):
    def error(locator, message):
        if on_error:
            on_error(locator, message)
        else:
            raise ValueError(message)
    if not data:
        return []
    if len(data) < 32:
        error("DestList", "최근 항목 목록 헤더가 잘렸습니다")
        return []
    version, count = struct.unpack_from("<II", data)
    if not count:
        return []
    if version not in (1, 3, 4):
        error("DestList", f"지원하지 않는 최근 항목 목록 버전: {version}")
        return []
    if count > 10000:
        error("DestList", "최근 항목 목록 레코드 개수 상한 초과")
    entries, offset = [], 32
    for _ in range(min(count, 10000)):
        try:
            entry, offset = _parse_destlist_entry(data, offset, version)
            entries.append(entry)
        except ValueError as exc:
            error(f"DestList:{offset}", str(exc))
            break
    return entries


def _extract_cfbf_streams(data, on_error=None):
    from .cfb import CompoundFile
    import re
    reader = CompoundFile(data, on_error)
    streams, identifiers, conflicts, destlist = {}, {}, set(), None
    destlist_conflict = False
    for name, value in reader.streams():
        if name.casefold() == "destlist":
            if destlist is not None or destlist_conflict:
                destlist, destlist_conflict = None, True
                reader._error(name, ValueError("최근 항목 목록 스트림이 중복됩니다"))
            else:
                destlist = value
        elif re.fullmatch(r"[0-9a-fA-F]+", name):
            identifier = int(name, 16)
            if identifier in conflicts:
                continue
            if identifier in identifiers:
                previous = identifiers.pop(identifier)
                streams.pop(previous)
                conflicts.add(identifier)
                reader._error(name, ValueError("같은 번호의 LNK 스트림이 중복됩니다"))
                continue
            identifiers[identifier] = name
            streams[name] = value
    return streams, destlist


class JumpListParser(ArtifactParser):
    artifact = "jumplist"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            files = sorted(
                list(source.rglob("*.automaticDestinations-ms")) +
                list(source.rglob("*.customDestinations-ms"))
            )
        else:
            files = [source]

        for jl_file in files:
            if not jl_file.is_file():
                continue
            app_id = _app_id_from_filename(jl_file.name)
            app_name = KNOWN_APP_IDS.get(app_id, app_id)
            try:
                with jl_file.open("rb") as stream:
                    data = stream.read(MAX_INPUT + 1)
                if len(data) > MAX_INPUT:
                    self.error(jl_file, "size", "최근 항목 파일의 안전한 읽기 크기 상한(128MiB)을 넘었습니다")
                    continue
            except OSError as exc:
                self.error(jl_file, "file", exc)
                continue

            if jl_file.suffix.lower() == ".automaticdestinations-ms":
                yield from self._parse_automatic(jl_file, data, app_id, app_name)
            elif jl_file.suffix.lower() == ".customdestinations-ms":
                yield from self._parse_custom(jl_file, data, app_id, app_name)
            else:
                if data[:8] == CFBF_MAGIC:
                    yield from self._parse_automatic(jl_file, data, app_id, app_name)
                else:
                    yield from self._parse_custom(jl_file, data, app_id, app_name)

    def _parse_automatic(self, jl_file, data, app_id, app_name):
        if data[:8] != CFBF_MAGIC:
            self.error(jl_file, "magic", "CFBF 매직 불일치: OLE 아님", "warning")
            yield from self._parse_by_lnk_scan(jl_file, data, app_id, app_name, "automatic")
            return

        try:
            streams, destlist_data = _extract_cfbf_streams(data, lambda locator, message: self.error(jl_file, locator, message, "warning"))
        except (struct.error, ValueError, OverflowError) as exc:
            self.error(jl_file, "cfbf", f"CFBF 구조 파싱 오류: {exc}", "warning")
            yield from self._parse_by_lnk_scan(jl_file, data, app_id, app_name, "automatic")
            return

        destlist_entries, conflicts = {}, set()
        if destlist_data:
            for entry in _parse_destlist(destlist_data, lambda locator, message: self.error(jl_file, locator, message, "warning")):
                eid = entry.get("entry_id")
                if eid in conflicts:
                    continue
                if eid in destlist_entries:
                    destlist_entries.pop(eid)
                    conflicts.add(eid)
                    self.error(jl_file, f"DestList:{eid}", "같은 번호의 최근 항목 목록이 중복됩니다", "warning")
                elif eid is not None:
                    destlist_entries[eid] = entry

        parsed_count, parsed_ids = 0, set()
        for stream_name, stream_data in sorted(streams.items(), key=lambda item: int(item[0], 16)):
            try:
                info = parse_lnk(stream_data, target_acp(self.environment))
            except (ValueError, struct.error, UnicodeError):
                info = None

            if info is None:
                lnk_offsets = _find_lnk_offsets(stream_data)
                if lnk_offsets:
                    info = _try_parse_lnk_at(stream_data, lnk_offsets[0], target_acp(self.environment))

            if info is None:
                self.error(jl_file, f"stream:{stream_name}", "LNK 스트림을 해석할 수 없습니다", "warning")
                continue

            parsed_count += 1
            parsed_ids.add(int(stream_name, 16))
            target = info.get("target_path") or info.get("relative_path")
            dest_entry = destlist_entries.get(int(stream_name, 16), {})
            best_time = dest_entry.get("timestamp") or info.get("access_time") or info.get("write_time")

            details = {
                "app_id": app_id,
                "app_name": app_name,
                "jump_list_type": "automatic",
                "stream_index": stream_name,
            }
            if dest_entry:
                details["access_count"] = dest_entry.get("access_count")
                details["access_count_raw"] = dest_entry.get("access_count_raw")
                details["destlist_path"] = dest_entry.get("path")
                details["netbios_name"] = dest_entry.get("netbios_name")
                details["pin_status"] = dest_entry.get("pin_status")
                if not target and dest_entry.get("path"):
                    target = dest_entry["path"]
            for key in ("file_size", "file_attributes", "volume_serial",
                        "volume_label", "volume_drive_type", "network_share_name",
                        "description", "working_dir", "arguments", "text_decoding"):
                val = info.get(key)
                if val is not None and val != "" and val != [] and val != 0:
                    details[key] = val
            details = {k: v for k, v in details.items() if v is not None}

            yield ForensicEvent(
                self.artifact, str(jl_file), "recent_file_access",
                best_time, "destlist_timestamp" if dest_entry.get("timestamp") else "lnk_timestamp",
                sid=self.sid, path=target,
                locator=f"{jl_file.name}:stream:{stream_name}",
                status="ok" if dest_entry else "partial",
                details=details,
            )

        if not parsed_count and not destlist_entries:
            self.error(jl_file, "streams", "LNK 스트림/DestList 없음", "warning")

        for eid, entry in destlist_entries.items():
            if eid not in parsed_ids and entry.get("path"):
                yield ForensicEvent(
                    self.artifact, str(jl_file), "recent_file_access",
                    entry.get("timestamp"), "destlist_timestamp",
                    sid=self.sid, path=entry["path"],
                    locator=f"{jl_file.name}:destlist:{eid}",
                    status="partial",
                    details={
                        "app_id": app_id, "app_name": app_name,
                        "jump_list_type": "automatic", "source": "destlist_only",
                        "access_count": entry.get("access_count"),
                        "netbios_name": entry.get("netbios_name"),
                    },
                )

    def _parse_custom(self, jl_file, data, app_id, app_name):
        position, found, attempts = 0, 0, 0
        budget = [MAX_CUSTOM_STEPS]
        while True:
            offset = data.find(LNK_SIGNATURE, position)
            if offset < 0:
                break
            attempts += 1
            if attempts > MAX_CUSTOM_RECORDS:
                self.error(jl_file, offset, '사용자 지정 바로가기 개수 상한 초과', 'warning')
                break
            position = offset + len(LNK_SIGNATURE)
            try:
                length = shell_link_span(data, offset, budget=budget)
                info = parse_lnk(data[offset:offset + length], target_acp(self.environment))
            except (ValueError, struct.error, UnicodeError) as exc:
                self.error(jl_file, offset, exc, 'warning')
                if budget[0] <= 0:
                    break
                continue
            position = offset + length
            found += 1
            timestamp, time_field = None, None
            for source, field in (('access_time', 'lnk_access_time'), ('write_time', 'lnk_write_time'),
                                  ('creation_time', 'lnk_creation_time')):
                if info.get(source):
                    timestamp, time_field = info[source], field
                    break
            details = {'app_id': app_id, 'app_name': app_name, 'jump_list_type': 'custom',
                       'byte_offset': offset, 'record_size': length,
                       'time_is_recent_access_time': False, 'pinned_status': 'unknown'}
            for key in ('file_size', 'file_attributes', 'volume_serial', 'volume_label', 'volume_drive_type',
                        'network_share_name', 'description', 'working_dir', 'arguments',
                        'creation_time', 'access_time', 'write_time', 'text_decoding'):
                if info.get(key) is not None:
                    details[key] = info[key]
            yield ForensicEvent(self.artifact, str(jl_file), 'recent_file_access', timestamp, time_field,
                                sid=self.sid, path=info.get('target_path') or info.get('relative_path'),
                                locator=f'{jl_file.name}:byte:{offset}',
                                status='ok' if info.get('target_path') or info.get('relative_path') else 'partial',
                                details=details)
        if not found and not attempts:
            self.error(jl_file, 'scan', '사용자 지정 목록에 바로가기 시그니처가 없습니다', 'warning')

    def _parse_by_lnk_scan(self, jl_file, data, app_id, app_name, jl_type):
        offsets = _find_lnk_offsets(data)
        if not offsets:
            self.error(jl_file, "scan", "LNK 시그니처를 찾을 수 없음", "warning")
            return

        for i, offset in enumerate(offsets):
            info = _try_parse_lnk_at(data, offset, target_acp(self.environment))
            if info is None:
                continue
            target = info.get("target_path") or info.get("relative_path")
            best_time = info.get("access_time") or info.get("write_time") or info.get("creation_time")
            details = {
                "app_id": app_id, "app_name": app_name,
                "jump_list_type": jl_type, "scan_index": i,
                "byte_offset": offset,
            }
            for key in ("file_size", "file_attributes", "volume_serial",
                        "volume_label", "volume_drive_type", "text_decoding"):
                val = info.get(key)
                if val is not None and val != "" and val != [] and val != 0:
                    details[key] = val
            details = {k: v for k, v in details.items() if v is not None}

            yield ForensicEvent(
                self.artifact, str(jl_file), "recent_file_access",
                best_time, "lnk_timestamp",
                sid=self.sid, path=target,
                locator=f"{jl_file.name}:scan:{i}:byte:{offset}",
                status="partial",
                details=details,
            )
