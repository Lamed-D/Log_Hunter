# ▶ 원본: log_hunter/parser/mft.py
# ▶ SI·FN 시각과 부모 참조를 읽습니다. 손상된 UTF-16 이름도 원시 바이트와 시각을 보존합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
import struct
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime


def apply_fixup(record, sector_size=512):
    data = bytearray(record)
    if len(data) < 48 or data[:4] != b"FILE":
        raise ValueError("MFT FILE 시그니처 없음")
    offset, count = struct.unpack_from("<HH", data, 4)
    if count != len(data) // sector_size + 1 or offset + count * 2 > len(data):
        raise ValueError("잘못된 USA 범위/개수")
    marker = data[offset:offset + 2]
    for index in range(1, count):
        end = index * sector_size
        if data[end - 2:end] != marker:
            raise ValueError("USA fixup 불일치")
        data[end - 2:end] = data[offset + index * 2:offset + index * 2 + 2]
    return bytes(data)


ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM",
}


def decode_data_runs(data, offset, length):
    runs = []
    pos = offset
    end = offset + length
    prev_lcn = 0
    while pos < end:
        header = data[pos]
        if header == 0:
            break
        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F
        pos += 1
        if pos + len_size + off_size > end or len_size == 0:
            break
        run_length = int.from_bytes(data[pos:pos + len_size], "little", signed=False)
        pos += len_size
        if off_size:
            run_offset = int.from_bytes(data[pos:pos + off_size], "little", signed=True)
            pos += off_size
            prev_lcn += run_offset
            runs.append({"lcn": prev_lcn, "length": run_length, "sparse": False})
        else:
            runs.append({"lcn": 0, "length": run_length, "sparse": True})
    return runs


def parse_record(raw):
    data = apply_fixup(raw)
    sequence, = struct.unpack_from("<H", data, 16)
    offset, flags, used = struct.unpack_from("<HHI", data, 20)
    if not 48 <= offset < used <= len(data):
        raise ValueError("MFT attribute 범위 오류")
    names, times, attributes = [], [], []
    data_size = None
    while offset + 4 <= used:
        kind, = struct.unpack_from("<I", data, offset)
        if kind == 0xFFFFFFFF:
            break
        if offset + 16 > used:
            raise ValueError("잘린 attribute header")
        size, = struct.unpack_from("<I", data, offset + 4)
        if size < 24 or offset + size > used:
            raise ValueError("잘못된 attribute 길이")
        nonresident = data[offset + 8]
        attr_info = {"type": kind, "type_name": ATTR_NAMES.get(kind), "nonresident": bool(nonresident), "offset": offset}
        if nonresident and size >= 64:
            start_vcn, end_vcn = struct.unpack_from("<QQ", data, offset + 16)
            run_offset, = struct.unpack_from("<H", data, offset + 32)
            alloc_size, real_size, init_size = struct.unpack_from("<QQQ", data, offset + 40)
            attr_info.update(start_vcn=start_vcn, end_vcn=end_vcn,
                             allocated_size=alloc_size, real_size=real_size, initialized_size=init_size)
            if kind == 0x80:
                data_size = real_size
            try:
                runs = decode_data_runs(data, offset + run_offset, size - run_offset)
                attr_info["data_runs"] = runs
                attr_info["data_run_count"] = len(runs)
                attr_info["total_clusters"] = sum(r["length"] for r in runs)
            except (IndexError, struct.error):
                attr_info["data_runs_error"] = True
        elif not nonresident:
            length, value_offset = struct.unpack_from("<IH", data, offset + 16)
            if value_offset < 24 or value_offset + length > size:
                raise ValueError("resident value 범위 오류")
            value = data[offset + value_offset:offset + value_offset + length]
            if kind == 0x10 and len(value) >= 32:
                times.extend(("si_" + label, stamp) for label, stamp in zip(("created", "modified", "mft_changed", "accessed"), struct.unpack_from("<QQQQ", value)))
            if kind == 0x30 and len(value) >= 66:
                reference, = struct.unpack_from("<Q", value)
                length, namespace = value[64], value[65]
                if 66 + length * 2 > len(value):
                    raise ValueError("FILE_NAME 이름 범위 오류")
                names.append({"name": value[66:66 + length * 2].decode("utf-16-le", errors="replace"),
                              "name_raw_hex": value[66:66 + length * 2].hex(),
                              "parent": reference & 0xFFFFFFFFFFFF, "parent_sequence": reference >> 48,
                              "namespace": namespace})
                times.extend(("fn_" + label, stamp) for label, stamp in zip(("created", "modified", "mft_changed", "accessed"), struct.unpack_from("<QQQQ", value, 8)))
            if kind == 0x80:
                data_size = length
        attributes.append(attr_info)
        offset += size
    return {"sequence": sequence, "in_use": bool(flags & 1), "directory": bool(flags & 2),
            "names": names, "times": times, "attributes": attributes, "data_size": data_size}


class MFTParser(ArtifactParser):
    artifact = "mft"

    def parse(self, path):
        records = {}
        with Path(path).open("rb") as stream:
            index = 0
            while raw := stream.read(1024):
                if raw[:4] == b"FILE":
                    try:
                        records[index] = parse_record(raw)
                    except (ValueError, struct.error, UnicodeError) as exc:
                        self.error(path, f"record:{index}", exc)
                elif any(raw):
                    self.error(path, f"record:{index}", "미지원 또는 손상된 1024-byte MFT record")
                index += 1

        def resolve(index, seen=None):
            seen = set() if seen is None else seen
            if index == 5:
                return "\\"
            if index in seen or len(seen) > 128 or index not in records:
                return None
            seen.add(index)
            record = records[index]
            name = next((n for n in record["names"] if n["namespace"] != 2), next(iter(record["names"]), None))
            if name is None:
                return None
            parent = records.get(name["parent"])
            if parent is None or parent["sequence"] != name["parent_sequence"]:
                return None
            prefix = resolve(name["parent"], seen)
            return prefix.rstrip("\\") + "\\" + name["name"] if prefix else None

        for index, record in records.items():
            full_path = resolve(index)
            details = {k: v for k, v in record.items() if k not in ("times", "attributes")}
            details["full_path_confirmed"] = full_path is not None
            details["attribute_count"] = len(record["attributes"])
            data_attr = next((a for a in record["attributes"] if a["type"] == 0x80), None)
            if data_attr:
                details["data_nonresident"] = data_attr["nonresident"]
                if data_attr.get("data_runs"):
                    details["data_run_count"] = data_attr["data_run_count"]
                    details["total_clusters"] = data_attr["total_clusters"]
                    details["allocated_size"] = data_attr.get("allocated_size")
                    details["real_size"] = data_attr.get("real_size")
                if data_attr.get("data_runs_error"):
                    details["data_runs_error"] = True
            if record.get("data_size") is not None:
                details["data_size"] = record["data_size"]
            attr_types = [ATTR_NAMES.get(a["type"], f"0x{a['type']:X}") for a in record["attributes"]]
            details["attribute_types"] = attr_types
            for label, timestamp in record["times"] or [("unknown", 0)]:
                yield ForensicEvent(self.artifact, str(path), "file_metadata", filetime(timestamp), label,
                                    path=full_path, locator=f"record:{index}", details=details)
