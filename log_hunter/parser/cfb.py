"""Bounded read-only compound streams, including DIFAT and MiniFAT (MS-CFB)."""
import struct
from array import array

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
END, FREE = 0xfffffffe, 0xffffffff
MAX_DECODED = 128 * 1024 * 1024


class CompoundFile:
    def __init__(self, data, on_error=None):
        self.data, self.on_error = data, on_error
        self.cache, self.decoded = {}, 0
        if len(data) < 512 or data[:8] != MAGIC:
            raise ValueError("유효한 복합 파일 헤더가 아닙니다")
        self.major, byte_order, shift, mini_shift = struct.unpack_from("<HHHH", data, 26)
        if (byte_order != 0xfffe or (self.major, shift) not in ((3, 9), (4, 12)) or mini_shift != 6):
            raise ValueError("복합 파일 버전·섹터 크기 오류")
        self.sector_size = 1 << shift
        if len(data) % self.sector_size:
            raise ValueError("잘린 복합 파일 섹터")
        self.sectors = len(data) // self.sector_size - 1
        fat_count, directory_start = struct.unpack_from("<II", data, 44)
        cutoff, mini_start, mini_count, difat_start, difat_count = struct.unpack_from("<IIIII", data, 56)
        if cutoff != 4096 or not 0 < fat_count <= self.sectors or max(mini_count, difat_count) > self.sectors:
            raise ValueError("복합 파일 할당 테이블 개수 오류")
        fat_sectors = [value for value in struct.unpack_from("<109I", data, 76) if value != FREE]
        if len(fat_sectors) > fat_count or max(fat_count, mini_count) * self.sector_size > MAX_DECODED:
            raise ValueError("복합 파일 할당 테이블 크기 상한 초과")
        seen, current = set(), difat_start
        for _ in range(difat_count):
            if current in seen:
                raise ValueError("복합 파일 DIFAT 순환")
            seen.add(current)
            values = struct.unpack(f"<{self.sector_size // 4}I", self._sector(current))
            entries = [value for value in values[:-1] if value != FREE]
            if len(entries) + len(fat_sectors) > fat_count:
                raise ValueError("복합 파일 DIFAT 항목 개수 초과")
            fat_sectors.extend(entries)
            current = values[-1]
        if difat_count and current != END:
            raise ValueError("복합 파일 DIFAT 끝 표시 오류")
        if len(fat_sectors) != fat_count or len(set(fat_sectors)) != fat_count:
            raise ValueError("복합 파일 FAT 위치 개수 오류")
        self.fat = array("I")
        for sector in fat_sectors:
            self.fat.extend(struct.unpack(f"<{self.sector_size // 4}I", self._sector(sector)))
        directory = self._regular(directory_start)
        self.entries = [directory[offset:offset + 128] for offset in range(0, len(directory), 128)]
        if not self.entries or self.entries[0][66] != 5:
            raise ValueError("복합 파일 루트 저장소가 없습니다")
        mini_chain = self._chain(mini_start, self.fat, self.sectors) if mini_count else []
        if len(mini_chain) != mini_count:
            raise ValueError("MiniFAT 섹터 개수 불일치")
        self.mini_fat = array("I")
        for sector in mini_chain:
            self.mini_fat.extend(struct.unpack(f"<{self.sector_size // 4}I", self._sector(sector)))
        root = self.entries[0]
        self.mini_stream = self._regular(struct.unpack_from("<I", root, 116)[0], self._size(root)) if self._size(root) else b""

    def _size(self, entry):
        return struct.unpack_from("<Q" if self.major == 4 else "<I", entry, 120)[0]

    def _sector(self, index):
        if not 0 <= index < self.sectors:
            raise ValueError("복합 파일 섹터 범위 초과")
        start = (index + 1) * self.sector_size
        return self.data[start:start + self.sector_size]

    def _chain(self, start, table, limit, unit=None):
        result, seen, current = [], set(), start
        while current != END:
            if (current in seen or not 0 <= current < min(len(table), limit)
                    or len(result) >= MAX_DECODED // (unit or self.sector_size)):
                raise ValueError("복합 파일 스트림 순환 또는 범위 오류")
            seen.add(current)
            result.append(current)
            current = table[current]
        return result

    def _reserve(self, size):
        if size < 0 or self.decoded + size > MAX_DECODED:
            raise ValueError("복합 파일 스트림 확장 크기 상한 초과")
        self.decoded += size

    def _regular(self, start, size=None):
        key = (False, start, size)
        if key in self.cache:
            return self.cache[key]
        if size is not None and size > len(self.data):
            raise ValueError("복합 파일 스트림 크기 범위 초과")
        chain = self._chain(start, self.fat, self.sectors)
        capacity = len(chain) * self.sector_size
        size = capacity if size is None else size
        if size > capacity:
            raise ValueError("잘린 복합 파일 스트림")
        self._reserve(size)
        result = b"".join(self._sector(sector) for sector in chain[:(size + self.sector_size - 1) // self.sector_size])[:size]
        self.cache[key] = result
        return result

    def _small(self, start, size):
        key = (True, start, size)
        if key in self.cache:
            return self.cache[key]
        if size > len(self.mini_stream):
            raise ValueError("작은 스트림 크기 범위 초과")
        chain = self._chain(start, self.mini_fat, len(self.mini_stream) // 64, unit=64)
        if len(chain) * 64 < size:
            raise ValueError("잘린 작은 스트림")
        self._reserve(size)
        result = b"".join(self.mini_stream[sector * 64:(sector + 1) * 64]
                          for sector in chain[:(size + 63) // 64])[:size]
        self.cache[key] = result
        return result

    def _error(self, locator, error):
        if self.on_error is None:
            raise ValueError(str(error)) from error
        self.on_error(locator, str(error))

    def streams(self):
        pending = [struct.unpack_from("<I", self.entries[0], 76)[0]]
        visited = set()
        while pending:
            index = pending.pop()
            if index == FREE:
                continue
            if index in visited or not 0 < index < len(self.entries):
                self._error(index, ValueError("복합 파일 디렉터리 순환 또는 범위 오류"))
                continue
            visited.add(index)
            entry = self.entries[index]
            pending.extend(struct.unpack_from("<II", entry, 68))
            if entry[66] != 2:
                continue
            try:
                name_size = struct.unpack_from("<H", entry, 64)[0]
                if not 2 <= name_size <= 64 or name_size % 2 or entry[name_size - 2:name_size] != b"\0\0":
                    raise ValueError("복합 파일 스트림 이름 길이 오류")
                name = entry[:name_size - 2].decode("utf-16-le", errors="replace")
                size, start = self._size(entry), struct.unpack_from("<I", entry, 116)[0]
                data = b"" if not size else self._small(start, size) if size < 4096 else self._regular(start, size)
                yield name, data
            except (ValueError, struct.error) as error:
                self._error(index, error)
