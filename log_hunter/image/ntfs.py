"""Minimal read-only NTFS reader: MFT records, $I30 directory indexes and file data streams."""
import hashlib
import struct
from dataclasses import dataclass, field
from log_hunter.parser.mft import decode_data_runs
from log_hunter.core.timestamp import filetime

ROOT_RECORD = 5
ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
FLAG_COMPRESSED = 0x0001
FLAG_ENCRYPTED = 0x4000
FN_DIRECTORY = 0x10000000
COPY_BLOCK = 4 * 1024 * 1024
MAX_BUFFERED_STREAM = 64 * 1024 * 1024


class NTFSError(Exception):
    pass


@dataclass
class Attribute:
    type: int
    name: str
    flags: int
    nonresident: bool
    value: bytes = b""
    start_vcn: int = 0
    runs: list = field(default_factory=list)
    real_size: int = 0
    initialized_size: int = 0


@dataclass
class Record:
    number: int
    sequence: int
    in_use: bool
    directory: bool
    base_record: int
    attributes: list


@dataclass
class DirEntry:
    name: str
    record: int
    sequence: int
    directory: bool
    size: int


def apply_fixup(raw, magic):
    data = bytearray(raw)
    if data[:4] != magic:
        raise NTFSError(f"{magic.decode()} 시그니처 없음")
    offset, count = struct.unpack_from("<HH", data, 4)
    if count < 2 or offset + count * 2 > len(data) or (count - 1) * 512 > len(data):
        raise NTFSError("잘못된 update sequence 범위")
    marker = data[offset:offset + 2]
    for index in range(1, count):
        end = index * 512
        if data[end - 2:end] != marker:
            raise NTFSError("update sequence 불일치 (손상된 레코드)")
        data[end - 2:end] = data[offset + index * 2:offset + index * 2 + 2]
    return bytes(data)


def _signed_size(value, cluster_size):
    value = value - 256 if value > 127 else value
    return value * cluster_size if value > 0 else 1 << -value


def parse_attributes(data, used):
    offset, = struct.unpack_from("<H", data, 20)
    attributes = []
    while offset + 16 <= used:
        kind, size = struct.unpack_from("<II", data, offset)
        if kind == 0xFFFFFFFF:
            break
        if size < 24 or offset + size > used:
            raise NTFSError("잘못된 attribute 길이")
        nonresident, name_length, name_offset, flags = struct.unpack_from("<BBHH", data, offset + 8)
        name = data[offset + name_offset:offset + name_offset + name_length * 2].decode("utf-16-le", errors="replace") if name_length else ""
        if nonresident:
            start_vcn, = struct.unpack_from("<Q", data, offset + 16)
            run_offset, = struct.unpack_from("<H", data, offset + 32)
            real_size, initialized = struct.unpack_from("<QQ", data, offset + 48)
            vcn, runs = start_vcn, []
            for run in decode_data_runs(data, offset + run_offset, size - run_offset):
                runs.append((vcn, None if run["sparse"] else run["lcn"], run["length"]))
                vcn += run["length"]
            attributes.append(Attribute(kind, name, flags, True, start_vcn=start_vcn, runs=runs,
                                        real_size=real_size, initialized_size=initialized))
        else:
            length, value_offset = struct.unpack_from("<IH", data, offset + 16)
            if value_offset + length > size:
                raise NTFSError("resident value 범위 오류")
            value = data[offset + value_offset:offset + value_offset + length]
            attributes.append(Attribute(kind, name, flags, False, value=value, real_size=length, initialized_size=length))
        offset += size
    return attributes


def parse_file_name(value):
    if len(value) < 66:
        return None
    parent, = struct.unpack_from("<Q", value, 0)
    real_size, flags = struct.unpack_from("<QI", value, 48)
    length, namespace = value[64], value[65]
    raw = value[66:66 + length * 2]
    damaged = len(raw) != length * 2
    try:
        name = raw.decode('utf-16-le')
    except UnicodeDecodeError:
        name = raw.decode('utf-16-le', errors='replace')
        damaged = True
    return {"parent": parent & 0xFFFFFFFFFFFF, "name": name, "namespace": namespace,
            "size": real_size, "directory": bool(flags & FN_DIRECTORY),
            **({'name_decode_error':True, 'name_raw_hex':raw.hex()} if damaged else {})}


class NTFSVolume:
    def __init__(self, image, offset=0):
        self.image = image
        self.offset = offset
        boot = image.read(offset, 512)
        if boot[3:11] != b"NTFS    ":
            raise NTFSError("NTFS 부트 섹터가 아닙니다")
        bytes_per_sector, sectors_per_cluster = struct.unpack_from("<HB", boot, 0x0B)
        if sectors_per_cluster > 0x80:
            sectors_per_cluster = 1 << (256 - sectors_per_cluster)
        self.cluster_size = bytes_per_sector * sectors_per_cluster
        if not self.cluster_size or self.cluster_size & (self.cluster_size - 1):
            raise NTFSError("잘못된 클러스터 크기")
        mft_lcn, = struct.unpack_from("<Q", boot, 0x30)
        self.record_size = _signed_size(boot[0x40], self.cluster_size)
        self.index_record_size = _signed_size(boot[0x44], self.cluster_size)
        self.serial = f"{struct.unpack_from('<Q', boot, 0x48)[0]:016X}"
        self.mft_extents = [(0, mft_lcn, 1 << 40)]
        record0 = self.record(0)
        own = [a for a in record0.attributes if a.type == ATTR_DATA and not a.name and a.nonresident]
        if not own:
            raise NTFSError("$MFT $DATA 속성이 없습니다")
        self.mft_extents = _extents(own)
        full = self._fragments(record0, ATTR_DATA, "")
        if full and full[0].nonresident:
            self.mft_extents = _extents(full)
        self._listings = {}

    def _read_extents(self, extents, start, length):
        if start < 0 or not 0 <= length <= MAX_BUFFERED_STREAM:
            raise NTFSError("메모리로 읽을 NTFS 스트림 크기 범위 초과")
        out = bytearray()
        end, position = start + length, start
        for vcn, lcn, count in extents:
            extent_start, extent_end = vcn * self.cluster_size, (vcn + count) * self.cluster_size
            if extent_end <= position:
                continue
            if extent_start >= end:
                break
            begin, finish = max(position, extent_start), min(end, extent_end)
            if begin > position:
                out += bytes(begin - position)
            if lcn is None:
                out += bytes(finish - begin)
            else:
                piece = self.image.read(self.offset + lcn * self.cluster_size + (begin - extent_start), finish - begin)
                out += piece + bytes(finish - begin - len(piece))  # run past the image end: keep offsets aligned
            position = finish
        if position < end:
            out += bytes(end - position)
        return bytes(out)

    def record(self, number):
        raw = self._read_extents(self.mft_extents, number * self.record_size, self.record_size)
        data = apply_fixup(raw, b"FILE")
        sequence, = struct.unpack_from("<H", data, 16)
        flags, used = struct.unpack_from("<HI", data, 22)
        base, = struct.unpack_from("<Q", data, 32)
        used = min(used, len(data))
        return Record(number, sequence, bool(flags & 1), bool(flags & 2), base & 0xFFFFFFFFFFFF,
                      parse_attributes(data, used))

    def attributes(self, record):
        attribute_list = next((a for a in record.attributes if a.type == ATTR_ATTRIBUTE_LIST), None)
        if attribute_list is None:
            return record.attributes
        if attribute_list.nonresident:
            extents = _extents([attribute_list])
            raw = self._read_extents(extents, 0, self._stream_sizes(attribute_list, extents)[0])
        else:
            raw = attribute_list.value
        others, position = [], 0
        while position + 26 <= len(raw):
            length, = struct.unpack_from("<H", raw, position + 4)
            if length < 26:
                break
            reference, = struct.unpack_from("<Q", raw, position + 16)
            number = reference & 0xFFFFFFFFFFFF
            if number != record.number and number not in others:
                others.append(number)
            position += length
        combined = list(record.attributes)
        for number in others:
            extension = self.record(number)
            if extension.base_record == record.number:
                combined.extend(extension.attributes)
        return combined

    def _fragments(self, record, kind, name):
        found = [a for a in self.attributes(record) if a.type == kind and a.name == name]
        return sorted(found, key=lambda a: a.start_vcn)

    def read_attribute(self, record, kind, name=""):
        fragments = self._fragments(record, kind, name)
        if not fragments:
            return None
        if not fragments[0].nonresident:
            return fragments[0].value
        extents = _extents(fragments)
        real, initialized = self._stream_sizes(fragments[0], extents)
        if real > MAX_BUFFERED_STREAM:
            raise NTFSError("메모리로 읽을 NTFS 속성 크기 상한 초과")
        return self._read_extents(extents, 0, initialized) + bytes(real - initialized)

    def _stream_sizes(self, first, extents):
        """(real, initialized) sizes clamped to the clusters the runs really cover; a corrupt or crafted
        size field must not make us allocate or write terabytes."""
        allocated = sum(count for _vcn, _lcn, count in extents) * self.cluster_size
        image_capacity = max(0, self.image.size - self.offset)
        real = max(0, min(first.real_size, allocated, image_capacity))
        return real, max(0, min(first.initialized_size, real))

    def listdir(self, number, strict=False):
        cache_key = (number, True) if strict else number
        if cache_key in self._listings:
            return self._listings[cache_key]
        record = self.record(number)
        root = self.read_attribute(record, ATTR_INDEX_ROOT, "$I30")
        if root is None:
            raise NTFSError(f"레코드 {number}는 디렉터리가 아닙니다")
        found = list(_index_entries(root, 16, strict=True) if strict else _index_entries(root, 16))
        allocation = self.read_attribute(record, ATTR_INDEX_ALLOCATION, "$I30")
        if allocation:
            bitmap = self.read_attribute(record, ATTR_BITMAP, "$I30") or b""
            size = self.index_record_size
            if strict and (len(allocation) % size or len(bitmap) * 8 < len(allocation) // size):
                raise NTFSError("???? ??? ?? ???? ??????")
            for block in range(len(allocation) // size):
                if bitmap and not (block // 8 < len(bitmap) and bitmap[block // 8] >> (block % 8) & 1):
                    continue
                try:
                    data = apply_fixup(allocation[block * size:(block + 1) * size], b"INDX")
                except NTFSError:
                    if strict:
                        raise
                    continue
                found.extend(_index_entries(data, 24, strict=True) if strict else _index_entries(data, 24))
        listing = {}
        long_names = {entry.record for entry, namespace in found if namespace != 2}
        for entry, namespace in found:
            if namespace == 2 and entry.record in long_names:
                continue  # Suppress DOS aliases, not distinct long hard-link names.
            key = (entry.record, entry.name)
            listing.setdefault(key, (entry, namespace))
        result = sorted((entry for entry, _ns in listing.values() if entry.name not in (".",)), key=lambda e: e.name.lower())
        self._listings[cache_key] = result
        return result

    def lookup(self, path):
        current = DirEntry("\\", ROOT_RECORD, 0, True, 0)
        for part in [p for p in path.replace("/", "\\").split("\\") if p]:
            entries = self.listdir(current.record)
            candidates = [entry for entry in entries if entry.name == part]
            if not candidates:
                candidates = [entry for entry in entries if entry.name.lower() == part.lower()]
            if len(candidates) > 1:
                raise NTFSError(f"같은 이름으로 해석되는 파일이 여러 개여서 선택할 수 없습니다: {part}")
            if not candidates:
                return None
            current = candidates[0]
        return current

    def copy_file(self, entry, destination):
        record = self.record(entry.record)
        note = None
        if not record.in_use or (entry.sequence and record.sequence != entry.sequence):
            raise NTFSError("인덱스 항목이 가리키는 MFT 레코드가 재사용/삭제되었습니다")
        fragments = self._fragments(record, ATTR_DATA, "")
        digest, written = hashlib.sha256(), 0
        with open(destination, "xb") as out:
            if fragments and not fragments[0].nonresident:
                out.write(fragments[0].value)
                digest.update(fragments[0].value)
                written = len(fragments[0].value)
            elif fragments:
                first = fragments[0]
                if first.flags & FLAG_ENCRYPTED:
                    raise NTFSError("EFS 암호화 파일은 추출할 수 없습니다")
                if first.flags & FLAG_COMPRESSED:
                    raise NTFSError("NTFS 압축 파일은 아직 지원하지 않습니다")
                extents = _extents(fragments)
                real, initialized = self._stream_sizes(first, extents)
                if real < first.real_size:
                    note = f"기록된 파일 크기({first.real_size}바이트)가 실제 할당 영역보다 커서 {real}바이트만 꺼냈습니다"
                while written < real:
                    take = min(COPY_BLOCK, real - written)
                    readable = max(0, min(take, initialized - written))
                    block = self._read_extents(extents, written, readable) + bytes(take - readable)
                    out.write(block)
                    digest.update(block)
                    written += take
        info = {"size": written, "sha256": digest.hexdigest(), "mft_record": entry.record,
                "mft_sequence": record.sequence, **self.times(record)}
        if note:
            info["warning"] = note
        return info

    def times(self, record):
        info = next((a for a in record.attributes if a.type == ATTR_STANDARD_INFORMATION and not a.nonresident), None)
        if info is None or len(info.value) < 32:
            return {}
        labels = ("created", "modified", "mft_modified", "accessed")
        return {label: filetime(value) for label, value in zip(labels, struct.unpack_from("<QQQQ", info.value))}


def _extents(fragments):
    extents = []
    for fragment in sorted(fragments, key=lambda a: a.start_vcn):
        extents.extend(fragment.runs)
    return sorted(extents, key=lambda extent: extent[0])


def _index_entries(data, node_offset, strict=False):
    if node_offset + 16 > len(data):
        if strict:
            raise NTFSError("???? ??? ??? ?????")
        return
    entries_offset, index_length = struct.unpack_from("<II", data, node_offset)
    if strict and (entries_offset < 16 or index_length < entries_offset + 16 or node_offset + index_length > len(data)):
        raise NTFSError("???? ??? ?? ?? ??")
    position, end = node_offset + entries_offset, min(node_offset + index_length, len(data))
    terminal = False
    while position + 16 <= end:
        reference, length, key_length, flags = struct.unpack_from("<QHHI", data, position)
        if strict and (length < 16 or length % 8 or position + length > end
                       or key_length > length - 16 - (8 if flags & 1 else 0)):
            raise NTFSError("???? ??? ?? ?? ?? ?? ??")
        if length < 16 or flags & 2:
            terminal = bool(flags & 2)
            break
        name = parse_file_name(data[position + 16:position + 16 + key_length])
        if strict and (not name or name.get("name_decode_error") or name["namespace"] not in (0,1,2,3)):
            raise NTFSError("???? ?? ??? ???????")
        if name:
            yield DirEntry(name["name"], reference & 0xFFFFFFFFFFFF, reference >> 48,
                           name["directory"], name["size"]), name["namespace"]
        position += length
    if strict and not terminal:
        raise NTFSError("???? ???? ?? ??? ? ????")
