"""Read-only FAT12/16/32 volume reader (boot sector, allocation table, directories with long names, deleted entries).
FAT keeps local wall-clock dates without a time zone: they are returned as raw text, never as UTC."""
import struct

DELETED, END = 0xE5, 0x00
ATTR_DIRECTORY, ATTR_VOLUME, ATTR_LFN = 0x10, 0x08, 0x0F
MAX_DEPTH, MAX_ENTRIES, MAX_CHAIN = 32, 2_000_000, 4_000_000


class FATError(ValueError):
    pass


def _dos_datetime(date, time=0, centis=0):
    """'YYYY-MM-DDTHH:MM:SS' local wall clock (no zone) from FAT date/time words, or None when unset/invalid."""
    if not date:
        return None
    year, month, day = 1980 + (date >> 9), (date >> 5) & 0x0F, date & 0x1F
    hour, minute, second = time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2 + centis // 100
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 61):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{min(second, 59):02d}"


class FATVolume:
    def __init__(self, image, offset):
        self.image, self.offset = image, offset
        boot = image.read(offset, 512)
        if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
            raise FATError("FAT 부트 섹터 서명이 없습니다")
        self.sector, self.cluster_sectors, reserved, fats, root_entries, total16 = struct.unpack_from("<HBHBHH", boot, 11)
        fat16, = struct.unpack_from("<H", boot, 22)
        total32, = struct.unpack_from("<I", boot, 32)
        fat32, = struct.unpack_from("<I", boot, 36)
        if self.sector not in (512, 1024, 2048, 4096) or self.cluster_sectors not in (1, 2, 4, 8, 16, 32, 64, 128) or not fats:
            raise FATError("FAT 부트 섹터 값이 올바르지 않습니다")
        self.cluster_size = self.sector * self.cluster_sectors
        fat_sectors = fat16 or fat32
        total = total16 or total32
        root_sectors = (root_entries * 32 + self.sector - 1) // self.sector
        self.fat_offset = reserved * self.sector
        self.root_offset = (reserved + fats * fat_sectors) * self.sector
        self.data_offset = self.root_offset + root_sectors * self.sector
        clusters = (total - (reserved + fats * fat_sectors + root_sectors)) // self.cluster_sectors
        if clusters <= 0 or not fat_sectors:
            raise FATError("FAT 크기 값이 올바르지 않습니다")
        self.clusters = clusters
        self.kind = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
        self.root_cluster = struct.unpack_from("<I", boot, 44)[0] if self.kind == 32 else None
        self.root_entries = root_entries
        self._fat = image.read(offset + self.fat_offset, fat_sectors * self.sector)

    def _next(self, cluster):
        if self.kind == 32:
            at = cluster * 4
            return struct.unpack_from("<I", self._fat, at)[0] & 0x0FFFFFFF if at + 4 <= len(self._fat) else None
        if self.kind == 16:
            at = cluster * 2
            return struct.unpack_from("<H", self._fat, at)[0] if at + 2 <= len(self._fat) else None
        at = cluster + cluster // 2
        if at + 2 > len(self._fat):
            return None
        value = struct.unpack_from("<H", self._fat, at)[0]
        return value >> 4 if cluster & 1 else value & 0x0FFF

    def chain(self, first):
        """Cluster numbers of a chain; stops at the end mark, a free/bad/out-of-range cluster or a loop."""
        end = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.kind]
        seen, cluster, result = set(), first, []
        while 2 <= cluster < self.clusters + 2 and cluster not in seen and len(result) < MAX_CHAIN:
            seen.add(cluster)
            result.append(cluster)
            following = self._next(cluster)
            if following is None or following >= end or following < 2:
                break
            cluster = following
        return result

    def _cluster_offset(self, cluster):
        return self.offset + self.data_offset + (cluster - 2) * self.cluster_size

    def reader(self, first, size, deleted=False, contiguous=False):
        """read(offset, length) over a file's data. A deleted file's chain is gone from the table, so its clusters are
        assumed to be contiguous from the first one (a recovery candidate, may be overwritten)."""
        if deleted:
            count = (size + self.cluster_size - 1) // self.cluster_size
            clusters = [first + i for i in range(count) if 2 <= first + i < self.clusters + 2]
        else:
            clusters = self.chain(first) if first else []
        size = min(size, len(clusters) * self.cluster_size)

        def read(offset, length):
            out = bytearray()
            end = min(size, offset + length)
            while offset < end:
                index, inner = divmod(offset, self.cluster_size)
                take = min(self.cluster_size - inner, end - offset)
                out += self.image.read(self._cluster_offset(clusters[index]) + inner, take)
                offset += take
            return bytes(out)
        return read, size

    def _directory_bytes(self, cluster):
        if cluster is None:  # FAT12/16 fixed root directory
            return self.image.read(self.offset + self.root_offset, self.root_entries * 32)
        return b"".join(self.image.read(self._cluster_offset(c), self.cluster_size) for c in self.chain(cluster)[:65536])

    @property
    def serial(self):
        """Volume serial number from the boot sector (8 hex digits)."""
        boot = self.image.read(self.offset, 512)
        at = 67 if self.kind == 32 else 39
        return f"{struct.unpack_from('<I', boot, at)[0]:08X}"

    def _entries(self, cluster, parts=()):
        """Entries of one directory (no recursion), deleted ones included."""
        data = self._directory_bytes(cluster)
        long_name = []
        for at in range(0, len(data) - 31, 32):
            entry = data[at:at + 32]
            if entry[0] == END:
                break
            attr = entry[11]
            if attr == ATTR_LFN:
                chars = entry[1:11] + entry[14:26] + entry[28:32]
                long_name.insert(0, chars.decode("utf-16-le", "replace").split("\x00", 1)[0].replace("￿", ""))
                continue
            if attr & ATTR_VOLUME:
                long_name = []
                continue
            deleted = entry[0] == DELETED
            base, ext = entry[0:8].decode("latin1").rstrip(), entry[8:11].decode("latin1").rstrip()
            short = ("_" + base[1:] if deleted else base) + ("." + ext if ext else "")
            name = "".join(long_name) or short
            long_name = []
            if name in (".", ".."):
                continue
            first = ((struct.unpack_from("<H", entry, 20)[0] << 16) if self.kind == 32 else 0) | struct.unpack_from("<H", entry, 26)[0]
            ctime_centis, ctime, cdate, adate = entry[13], *struct.unpack_from("<HHH", entry, 14)
            mtime, mdate = struct.unpack_from("<HH", entry, 22)
            yield {"path": "\\" + "\\".join((*parts, name)), "name": name, "short_name": short,
                   "size": struct.unpack_from("<I", entry, 28)[0], "first_cluster": first, "deleted": deleted,
                   "directory": bool(attr & ATTR_DIRECTORY),
                   "created": _dos_datetime(cdate, ctime, ctime_centis), "modified": _dos_datetime(mdate, mtime),
                   "accessed": _dos_datetime(adate)}

    def lookup(self, parts):
        """The entry at a path (case-insensitive, live entries first), or None; () is the root folder."""
        cluster, found = self.root_cluster, None
        for depth, name in enumerate(parts):
            matches = [e for e in self._entries(cluster, tuple(parts[:depth])) if e["name"].casefold() == name.casefold()
                       or e["short_name"].casefold() == name.casefold()]
            found = next((e for e in matches if not e["deleted"]), matches[0] if matches else None)
            if found is None:
                return None
            if depth < len(parts) - 1:
                if not found["directory"] or found["deleted"]:
                    return None
                cluster = found["first_cluster"]
        return found

    def listdir(self, parts=()):
        if not parts:
            return list(self._entries(self.root_cluster))
        entry = self.lookup(parts)
        if entry is None or not entry["directory"] or entry["deleted"]:
            raise FATError("폴더가 아닙니다")
        return list(self._entries(entry["first_cluster"], tuple(parts)))

    def walk(self):
        """Every entry of the volume (deleted ones too), depth-first; see _entries for the fields."""
        count = 0
        stack = [((), self.root_cluster, 0)]
        seen = set()
        while stack:
            parts, cluster, depth = stack.pop()
            if cluster in seen or depth > MAX_DEPTH:
                continue
            seen.add(cluster)
            for item in self._entries(cluster, parts):
                count += 1
                if count > MAX_ENTRIES:
                    raise FATError("디렉터리 항목이 너무 많습니다")
                yield item
                if item["directory"] and not item["deleted"] and item["first_cluster"] >= 2:
                    stack.append(((*parts, item["name"]), item["first_cluster"], depth + 1))