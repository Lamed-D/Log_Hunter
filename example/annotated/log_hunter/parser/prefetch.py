# ▶ 원본: log_hunter/parser/prefetch.py
# ▶ 버전별 실행 시각·횟수·참조 파일을 읽고 압축 입력은 순수 Python 해제기로 전달합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
import re
import struct
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime


_PF_NAME_RE = re.compile(r"^(.+)-([0-9A-Fa-f]{8})\.pf$", re.IGNORECASE)

# Absolute offsets: first run time, run count, number of run-time slots.
# v31 uses the 212-byte file-information layout; its count is not at +208.
_LAYOUTS = {17: (120, 144, 1), 23: (128, 152, 1),
            26: (128, 208, 8), 30: (128, 208, 8), 31: (128, 200, 8)}


def _parse_volumes(data, version):
    if version == 17:
        vol_offset_pos, vol_count_pos = 104, 108
        entry_size = 40
    else:
        vol_offset_pos, vol_count_pos = 108, 112
        entry_size = 96 if version >= 30 else 104
    if len(data) < vol_count_pos + 4:
        return []
    vol_info_offset, = struct.unpack_from("<I", data, vol_offset_pos)
    vol_count, = struct.unpack_from("<I", data, vol_count_pos)
    if version == 31:
        vol_size, = struct.unpack_from('<I', data, 116)
        if vol_count > 32 or (vol_count and
                (vol_info_offset < 296 or vol_size < vol_count * entry_size
                 or vol_info_offset + vol_size > len(data))):
            raise ValueError('Prefetch 볼륨 정보 범위 초과')
    if vol_count > 32 or vol_info_offset >= len(data):
        return []
    volumes = []
    for i in range(vol_count):
        base = vol_info_offset + i * entry_size
        if base + 20 > len(data):
            break
        path_offset, = struct.unpack_from("<I", data, base)
        path_length, = struct.unpack_from("<I", data, base + 4)
        creation_raw, = struct.unpack_from("<Q", data, base + 8)
        serial, = struct.unpack_from("<I", data, base + 16)
        abs_path_offset = vol_info_offset + path_offset
        path_end = abs_path_offset + path_length * 2
        if version == 31 and (path_offset < vol_count * entry_size
                              or path_end > vol_info_offset + vol_size):
            raise ValueError('Prefetch 볼륨 이름 범위 초과')
        if path_end <= len(data):
            vol_path = data[abs_path_offset:path_end].decode("utf-16-le", errors="replace").rstrip("\0")
        else:
            vol_path = ""
        volumes.append({
            "path": vol_path,
            "serial": f"{serial:08X}",
            "creation_time": filetime(creation_raw) if creation_raw else None,
        })
    return volumes


class PrefetchParser(ArtifactParser):
    artifact = "prefetch"

    def parse(self, path):
        data = Path(path).read_bytes()
        if data[:3] == b"MAM":
            from .xpress import decompress_prefetch
            data = decompress_prefetch(data)
        if len(data) < 84 or data[4:8] != b"SCCA":
            raise ValueError("유효한 SCCA Prefetch가 아닙니다")
        version, = struct.unpack_from("<I", data)
        if version not in _LAYOUTS:
            raise ValueError(f"미지원 Prefetch 버전: {version} (지원 버전: 17/23/26/30/31)")
        exe = data[16:76].decode("utf-16-le").split("\0", 1)[0]
        hash_value, = struct.unpack_from("<I", data, 76)
        time_offset, count_offset, time_count = _LAYOUTS[version]
        if version == 30 and struct.unpack_from('<I', data, 84)[0] == 296:
            count_offset = 200
        if version == 31:
            declared_size, = struct.unpack_from('<I', data, 12)
            if len(data) < 296 or declared_size < 296 or declared_size > len(data):
                raise ValueError('잘린 Prefetch v31 파일 정보')
            data = data[:declared_size]
        if len(data) < count_offset + 4:
            raise ValueError("잘린 Prefetch 파일 정보")
        count, = struct.unpack_from("<I", data, count_offset)
        times = [struct.unpack_from("<Q", data, time_offset + 8 * i)[0] for i in range(time_count)]
        strings_offset, strings_size = struct.unpack_from("<II", data, 100)
        if strings_offset + strings_size > len(data) or (version == 31 and
                (strings_size % 2 or (strings_size and strings_offset < 296))):
            raise ValueError("참조 파일 목록 범위 초과")
        references = data[strings_offset:strings_offset + strings_size].decode("utf-16-le").strip("\0").split("\0") if strings_size else []

        filename_hash_match = None
        source_name = Path(path).name
        m = _PF_NAME_RE.match(source_name)
        if m:
            filename_hash = int(m.group(2), 16)
            filename_hash_match = filename_hash == hash_value

        full_path_confirmed = False
        exe_lower = exe.lower()
        for ref in references:
            if ref.lower().endswith("\\" + exe_lower):
                full_path_confirmed = True
                break

        volumes = _parse_volumes(data, version)

        detail = {
            "version": version,
            "run_count": count,
            "prefetch_hash": f"{hash_value:08X}",
            "filename_hash_match": filename_hash_match,
            "references": references,
            "reference_count": len(references),
            "volume_count": len(volumes),
            "volumes": volumes if volumes else None,
            "full_executable_path_confirmed": full_path_confirmed,
        }
        for index, raw in enumerate(times):
            if raw:
                yield ForensicEvent(self.artifact, str(path), "execution_trace", filetime(raw), "last_run_time",
                                    process=exe, locator=f"byte:{time_offset + index * 8}",
                                    details={k: v for k, v in {**detail, "raw_filetime": raw}.items() if v is not None})
        if not any(times):
            yield ForensicEvent(self.artifact, str(path), "execution_trace", process=exe,
                                details={k: v for k, v in detail.items() if v is not None}, status="warning")
