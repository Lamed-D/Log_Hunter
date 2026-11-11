# ▶ 원본: log_hunter/image/ewf.py
# ▶ E01 세그먼트 또는 raw·고정 VHD를 읽기 전용 바이트 스트림으로 제공합니다. 압축 크기와 범위를 제한합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Read-only access to EWF (E01) and raw (dd) disk images, without external libraries."""
import re
import struct
import zlib
from collections import OrderedDict
from pathlib import Path

EVF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
LVF_SIGNATURE = b"LVF\x09\x0d\x0a\xff\x00"
EVF2_SIGNATURE = b"EVF2\x0d\x0a\x81\x00"
SECTION_DESCRIPTOR_SIZE = 76
MAX_METADATA = 1024 * 1024
MAX_TABLE = 16 * 1024 * 1024
MAX_CHUNK = 16 * 1024 * 1024
HEADER_KEYS = {"c": "case_number", "n": "evidence_number", "a": "description", "e": "examiner",
               "t": "notes", "av": "acquisition_software", "ov": "acquisition_os",
               "m": "acquisition_date", "u": "system_date", "md": "model", "sn": "serial_number"}


class ImageError(Exception):
    pass


class _ChunkCache:
    def __init__(self, capacity=64):
        self.capacity = capacity
        self.items = OrderedDict()

    def get(self, key):
        value = self.items.get(key)
        if value is not None:
            self.items.move_to_end(key)
        return value

    def put(self, key, value):
        self.items[key] = value
        if len(self.items) > self.capacity:
            self.items.popitem(last=False)


class DiskImage:
    """Common random-access interface: size, sector_size, read(offset, length)."""
    format = "unknown"
    size = 0
    sector_size = 512

    def read(self, offset, length):
        raise NotImplementedError

    def info(self):
        return {"format": self.format, "size": self.size, "sector_size": self.sector_size}

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class RawImage(DiskImage):
    format = "raw"

    def __init__(self, path):
        self.paths = _raw_segments(Path(path))
        self.handles = [p.open("rb") for p in self.paths]
        self.extents = []
        start = 0
        for handle in self.handles:
            handle.seek(0, 2)
            length = handle.tell()
            self.extents.append((start, length, handle))
            start += length
        self.size = start

    def read(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("음수 오프셋/길이")
        length = max(0, min(length, self.size - offset))
        out = bytearray()
        for start, extent_length, handle in self.extents:
            if length <= 0:
                break
            if offset >= start + extent_length:
                continue
            inner = offset - start
            take = min(length, extent_length - inner)
            handle.seek(inner)
            piece = handle.read(take)
            out += piece
            offset += len(piece)
            length -= len(piece)
            if len(piece) < take:
                break
        return bytes(out)

    def info(self):
        return {**super().info(), "segments": [str(p) for p in self.paths]}

    def close(self):
        for handle in self.handles:
            handle.close()


def _raw_segments(path):
    match = re.fullmatch(r"(.*)\.(\d{3})", path.name)
    if not match:
        return [path]
    width = len(match[2])
    segments, number = [], int(match[2])
    while True:
        candidate = path.with_name(f"{match[1]}.{number:0{width}d}")
        if not candidate.exists():
            break
        segments.append(candidate)
        number += 1
    return segments or [path]


class EWFImage(DiskImage):
    format = "ewf"

    def __init__(self, path):
        self.path = Path(path)
        self.segments = _ewf_segments(self.path)
        self.handles = {}
        self.chunks = []  # (segment_number, offset, compressed, end_bound)
        self.metadata = {}
        self.stored_md5 = None
        self.stored_sha1 = None
        self.integrity_warnings = []
        self.chunk_size = None
        self.size = 0
        self.cache = _ChunkCache()
        try:
            for number, segment in self.segments:
                self.handles[number] = segment.open("rb")
            for number, _segment in self.segments:
                self._read_sections(number)
            if self.chunk_size is None:
                raise ImageError("EWF volume/disk 섹션을 찾을 수 없습니다")
            if not self.chunks:
                raise ImageError("EWF table 섹션(청크 위치 정보)을 찾을 수 없습니다")
        except BaseException:
            self.close()
            raise

    def _read_sections(self, number):
        handle = self.handles[number]
        handle.seek(0, 2)
        file_size = handle.tell()
        offset = 13
        descriptors = []
        seen = set()
        while offset + SECTION_DESCRIPTOR_SIZE <= file_size and offset not in seen:
            if len(seen) >= 65536:
                raise ImageError("EWF 섹션 개수 상한 초과")
            seen.add(offset)
            handle.seek(offset)
            raw = handle.read(SECTION_DESCRIPTOR_SIZE)
            kind = raw[:16].split(b"\0", 1)[0].decode("ascii", errors="replace")
            next_offset, size = struct.unpack_from("<QQ", raw, 16)
            if (size < SECTION_DESCRIPTOR_SIZE and kind not in ("done", "next")
                    or size and size > file_size - offset):
                raise ImageError("EWF 섹션 크기가 세그먼트 범위를 벗어납니다")
            if kind == "table" and size > MAX_TABLE + SECTION_DESCRIPTOR_SIZE:
                raise ImageError("EWF 테이블 크기 상한 초과")
            if struct.unpack_from('<I', raw, 72)[0] != zlib.adler32(raw[:72]) & 0xFFFFFFFF:
                self.integrity_warnings.append(f'EWF 섹션 체크섬 오류: 세그먼트 {number}, 위치 {offset}')
            descriptors.append((kind, offset, size))
            if kind in ("done", "next") or next_offset == offset or next_offset == 0:
                break
            offset = next_offset
        starts = sorted(o for _k, o, _s in descriptors) + [file_size]
        for kind, start, size in descriptors:
            body_offset = start + SECTION_DESCRIPTOR_SIZE
            body_size = max(0, size - SECTION_DESCRIPTOR_SIZE) if size else 0
            if kind in ("volume", "disk") and self.chunk_size is None:
                handle.seek(body_offset)
                self._parse_volume(handle.read(min(body_size or 1052, 1052)))
            elif kind == "table":
                handle.seek(body_offset)
                self._parse_table(number, handle.read(body_size), starts)
            elif kind in ("header2", "header") and not self.metadata:
                try:
                    if body_size > MAX_METADATA:
                        raise ImageError("수집 정보 크기 상한 초과")
                    handle.seek(body_offset)
                    self.metadata = _parse_header(handle.read(body_size), kind == "header2")
                except ImageError as exc:
                    self.integrity_warnings.append(
                        f'EWF {kind} 수집 정보 오류: 세그먼트 {number}, 위치 {start}: {exc}')
            elif kind in ("hash", "digest"):
                handle.seek(body_offset)
                required = 36 if kind == 'hash' else 80
                body = handle.read(min(body_size, required))
                if len(body) != required or body_size != required:
                    self.integrity_warnings.append(f'EWF {kind} 섹션 길이 오류: 세그먼트 {number}, 위치 {start}')
                    continue
                if struct.unpack_from('<I', body, required - 4)[0] != zlib.adler32(body[:-4]) & 0xFFFFFFFF:
                    self.integrity_warnings.append(f'EWF {kind} 섹션 체크섬 오류: 세그먼트 {number}, 위치 {start}')
                    continue
                for name, digest in [('md5', body[:16]), *([('sha1', body[16:36])] if kind == 'digest' else [])]:
                    if not any(digest):
                        continue
                    previous = getattr(self, 'stored_' + name)
                    if previous is not None and previous != digest.hex():
                        self.integrity_warnings.append(f'EWF 저장 {name} 해시 충돌: 세그먼트 {number}, 위치 {start}')
                    setattr(self, 'stored_' + name, digest.hex())

    def _parse_volume(self, body):
        if len(body) < 20:
            raise ImageError("EWF volume 섹션이 너무 짧습니다")
        sectors_per_chunk, bytes_per_sector = struct.unpack_from("<II", body, 8)
        if len(body) >= 24 and len(body) != 94:
            sector_count, = struct.unpack_from("<Q", body, 16)
        else:
            sector_count, = struct.unpack_from("<I", body, 16)
        if (not sectors_per_chunk or bytes_per_sector not in (512, 1024, 2048, 4096)
                or sectors_per_chunk * bytes_per_sector > MAX_CHUNK):
            raise ImageError("EWF volume 섹션 값이 잘못되었습니다")
        self.sector_size = bytes_per_sector
        self.chunk_size = sectors_per_chunk * bytes_per_sector
        self.size = sector_count * bytes_per_sector

    def _parse_table(self, number, body, section_starts):
        if len(body) < 24:
            return
        count, = struct.unpack_from("<I", body, 0)
        base, = struct.unpack_from("<Q", body, 8)
        count = min(count, (len(body) - 24) // 4)
        entries = struct.unpack_from(f"<{count}I", body, 24)
        offsets = [(base + (e & 0x7FFFFFFF), bool(e & 0x80000000)) for e in entries]
        for index, (offset, compressed) in enumerate(offsets):
            end = next((s for s in section_starts if s > offset), None)
            if index + 1 < len(offsets) and offsets[index + 1][0] > offset:
                end = min(end, offsets[index + 1][0]) if end else offsets[index + 1][0]
            self.chunks.append((number, offset, compressed, end))

    def _chunk(self, index):
        cached = self.cache.get(index)
        if cached is not None:
            return cached
        if index >= len(self.chunks):
            raise ImageError(f"EWF 청크 {index} 위치 정보 없음")
        number, offset, compressed, end = self.chunks[index]
        handle = self.handles[number]
        handle.seek(offset)
        if compressed:
            limit = min(end - offset, self.chunk_size + 1024) if end else self.chunk_size + 1024
            raw = handle.read(limit)
            try:
                decoder = zlib.decompressobj()
                data = decoder.decompress(raw, self.chunk_size + 1)
                if len(data) > self.chunk_size or not decoder.eof:
                    raise ImageError(f'EWF 청크 {index} 압축 크기/종료 범위 오류: 세그먼트 {number}, 위치 {offset}')
            except zlib.error as exc:
                raise ImageError(f"EWF 청크 {index} 압축 해제 실패: 세그먼트 {number}, 위치 {offset}: {exc}") from exc
        else:
            data = handle.read(self.chunk_size)
        self.cache.put(index, data)
        return data

    def read(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("음수 오프셋/길이")
        length = max(0, min(length, self.size - offset))
        out = bytearray()
        while length > 0:
            index, inner = divmod(offset, self.chunk_size)
            data = self._chunk(index)
            piece = data[inner:inner + length]
            if not piece:
                raise ImageError(f"EWF 청크 {index} 데이터가 짧습니다")
            out += piece
            offset += len(piece)
            length -= len(piece)
        return bytes(out)

    def info(self):
        return {**super().info(), "segments": [str(p) for _n, p in self.segments],
                "chunk_size": self.chunk_size, "chunk_count": len(self.chunks),
                "stored_md5": self.stored_md5, "stored_sha1": self.stored_sha1,
                "integrity_warnings": self.integrity_warnings,
                "acquisition": self.metadata}

    def close(self):
        for handle in self.handles.values():
            handle.close()


def _ewf_segments(path):
    if not path.exists():
        raise FileNotFoundError(path)
    stem = path.name[:-len(path.suffix)] if path.suffix else path.name
    candidates = [p for p in path.parent.iterdir()
                  if p.is_file() and p.name[:len(stem)] == stem and re.fullmatch(r"\.[A-Za-z][0-9A-Za-z]{2}", p.name[len(stem):])]
    numbered = {}
    for candidate in candidates:
        with candidate.open("rb") as handle:
            header = handle.read(13)
        if header[:8] == EVF_SIGNATURE:
            numbered.setdefault(struct.unpack_from("<H", header, 9)[0], candidate)
    if not numbered:
        raise ImageError("EWF(E01) 시그니처가 없습니다")
    ordered = sorted(numbered.items())
    expected = list(range(1, len(ordered) + 1))
    if [n for n, _p in ordered] != expected:
        missing = sorted(set(range(1, max(numbered) + 1)) - set(numbered))
        raise ImageError(f"EWF 세그먼트 누락: {missing}")
    return ordered


def _parse_header(body, utf16):
    try:
        decoder = zlib.decompressobj()
        text = decoder.decompress(body, MAX_METADATA + 1)
        if len(text) > MAX_METADATA or not decoder.eof:
            raise ImageError("EWF 메타데이터 확장 크기 또는 압축 범위 오류")
    except zlib.error as exc:
        raise ImageError("EWF 수집 정보 압축 오류") from exc
    text = text.decode("utf-16", errors="replace") if utf16 else text.decode("latin-1", errors="replace")
    lines = text.replace("\r", "").split("\n")
    if "main" not in lines:
        return {}
    at = lines.index("main")
    if at + 2 >= len(lines):
        return {}
    keys, values = lines[at + 1].split("\t"), lines[at + 2].split("\t")
    return {HEADER_KEYS.get(k, k): v for k, v in zip(keys, values) if v and k != "p"}


def open_image(path):
    from .live import LiveVolume, is_live_path
    if is_live_path(path):
        return LiveVolume(path)
    path = Path(path)
    with path.open("rb") as handle:
        signature = handle.read(8)
    if signature == EVF_SIGNATURE:
        return EWFImage(path)
    if signature == LVF_SIGNATURE:
        raise ImageError("L01(논리 증거 파일)은 지원하지 않습니다. 디스크 전체 이미지(E01)를 사용하세요")
    if signature[:4] == b"EVF2":
        raise ImageError("Ex01(EWF2) 형식은 아직 지원하지 않습니다. E01로 다시 이미징하세요")
    if signature == b"conectix":
        raise ImageError("동적(가변 크기) VHD는 지원하지 않습니다. 고정 크기 VHD, E01 또는 raw(dd) 이미지를 사용하세요")
    if path.suffix.lower() == ".vhdx" or signature == b"vhdxfile":
        raise ImageError("VHDX는 지원하지 않습니다. E01 또는 raw(dd) 이미지를 사용하세요")
    return RawImage(path)
