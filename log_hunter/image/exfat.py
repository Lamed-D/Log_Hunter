"""Read-only exFAT volume reader with the same interface as FATVolume (walk, listdir, lookup, reader, serial).
exFAT timestamps carry an optional UTC offset: with a valid offset the time is returned in UTC, otherwise as the
local wall-clock text without a zone (never assumed to be UTC)."""
import struct
from datetime import timedelta, timezone

from .fat import FATError, MAX_CHAIN, MAX_DEPTH, MAX_ENTRIES, _fat_wall_clock

FILE, STREAM, NAME = 0x85, 0xC0, 0xC1
IN_USE = 0x80
ATTR_DIRECTORY = 0x10


def exfat_time(stamp, centis=0, offset=0):
    """(text, is_utc): UTC ISO when the offset byte is marked valid, else local 'YYYY-MM-DDTHH:MM:SS'; (None, False)."""
    local = _fat_wall_clock(stamp >> 16, stamp & 0xffff, centis)
    if local is None:
        return None, False
    if offset & 0x80:
        quarters = offset & 0x7F
        quarters = quarters - 0x80 if quarters & 0x40 else quarters
        moment = local.replace(tzinfo=timezone(timedelta(minutes=15 * quarters)))
        return moment.astimezone(timezone.utc).isoformat(), True
    return local.isoformat(), False


class ExFATVolume:
    kind = "exfat"

    def __init__(self, image, offset):
        self.image, self.offset = image, offset
        boot = image.read(offset, 512)
        if len(boot) < 512 or boot[3:11] != b"EXFAT   " or boot[510:512] != b"\x55\xaa":
            raise FATError("exFAT 부트 섹터가 아닙니다")
        fat_offset, fat_length, heap, count, root, self._serial = struct.unpack_from("<IIIIII", boot, 80)
        sector_shift, cluster_shift = boot[108], boot[109]
        if not 9 <= sector_shift <= 12 or sector_shift + cluster_shift > 25 or not count or root < 2:
            raise FATError("exFAT 부트 섹터 값이 올바르지 않습니다")
        self.sector = 1 << sector_shift
        self.cluster_size = self.sector << cluster_shift
        self.heap_offset = heap * self.sector
        self.clusters = count
        self.root_cluster = root
        self._fat = image.read(offset + fat_offset * self.sector, min(fat_length * self.sector, (count + 2) * 4))

    @property
    def serial(self):
        return f"{self._serial:08X}"

    def chain(self, first, contiguous_size=None):
        if contiguous_size is not None:  # NoFatChain: the data is one run of clusters
            count = (contiguous_size + self.cluster_size - 1) // self.cluster_size
            return [first + i for i in range(min(count, MAX_CHAIN)) if 2 <= first + i < self.clusters + 2]
        seen, cluster, result = set(), first, []
        while 2 <= cluster < self.clusters + 2 and cluster not in seen and len(result) < MAX_CHAIN:
            seen.add(cluster)
            result.append(cluster)
            at = cluster * 4
            if at + 4 > len(self._fat):
                break
            following, = struct.unpack_from("<I", self._fat, at)
            if following >= 0xFFFFFFF7 or following < 2:
                break
            cluster = following
        return result

    def _cluster_offset(self, cluster):
        return self.offset + self.heap_offset + (cluster - 2) * self.cluster_size

    def reader(self, first, size, deleted=False, contiguous=False):
        """read(offset, length) over a file's data; deleted files are read as contiguous clusters (a guess)."""
        clusters = self.chain(first, size if (contiguous or deleted) else None) if first else []
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

    def _directory(self, cluster, size=None, contiguous=False):
        clusters = self.chain(cluster, size if contiguous else None)[:65536]
        return b"".join(self.image.read(self._cluster_offset(c), self.cluster_size) for c in clusters)

    def _entries(self, cluster, parts=(), size=None, contiguous=False):
        data = self._directory(cluster, size, contiguous)
        at = 0
        while at + 32 <= len(data):
            kind = data[at]
            if kind == 0x00:
                break
            if kind & 0x7F != FILE & 0x7F:
                at += 32
                continue
            deleted = not kind & IN_USE
            secondary = data[at + 1]
            group = data[at:at + 32 * (secondary + 1)]
            at += 32 * (secondary + 1) if secondary else 32
            if len(group) < 64 or group[32] & 0x7F != STREAM & 0x7F:
                continue
            attributes, = struct.unpack_from("<H", group, 4)
            created, modified, accessed = struct.unpack_from("<III", group, 8)
            c10, m10, c_off, m_off, a_off = group[20], group[21], group[22], group[23], group[24]
            stream = group[32:64]
            flags, name_length = stream[1], stream[3]
            first, = struct.unpack_from("<I", stream, 20)
            length, = struct.unpack_from("<Q", stream, 24)
            name = b"".join(group[64 + 32 * i + 2:64 + 32 * i + 32] for i in range(secondary - 1)
                            if group[64 + 32 * i] & 0x7F == NAME & 0x7F)
            name = name.decode("utf-16-le", "replace")[:name_length]
            if not name:
                continue
            times = {}
            utc = True
            for key, (stamp, centis, offset) in (("created", (created, c10, c_off)), ("modified", (modified, m10, m_off)),
                                                 ("accessed", (accessed, 0, a_off))):
                text, is_utc = exfat_time(stamp, centis, offset)
                times[key] = text
                utc = utc and (is_utc or text is None)
            yield {"path": "\\" + "\\".join((*parts, name)), "name": name, "short_name": name, "size": length,
                   "first_cluster": first, "deleted": deleted, "directory": bool(attributes & ATTR_DIRECTORY),
                   "contiguous": bool(flags & 0x02), "times_utc": utc and any(times.values()), **times}

    def lookup(self, parts):
        cluster, size, contiguous, found = self.root_cluster, None, False, None
        for depth, name in enumerate(parts):
            matches = [e for e in self._entries(cluster, tuple(parts[:depth]), size, contiguous)
                       if e["name"].casefold() == name.casefold()]
            found = next((e for e in matches if not e["deleted"]), matches[0] if matches else None)
            if found is None:
                return None
            if depth < len(parts) - 1:
                if not found["directory"] or found["deleted"]:
                    return None
                cluster, size, contiguous = found["first_cluster"], found["size"], found["contiguous"]
        return found

    def listdir(self, parts=()):
        if not parts:
            return list(self._entries(self.root_cluster))
        entry = self.lookup(parts)
        if entry is None or not entry["directory"] or entry["deleted"]:
            raise FATError("폴더가 아닙니다")
        return list(self._entries(entry["first_cluster"], tuple(parts), entry["size"], entry["contiguous"]))

    def walk(self):
        count = 0
        stack = [((), self.root_cluster, None, False, 0)]
        seen = set()
        while stack:
            parts, cluster, size, contiguous, depth = stack.pop()
            if cluster in seen or depth > MAX_DEPTH:
                continue
            seen.add(cluster)
            for item in self._entries(cluster, parts, size, contiguous):
                count += 1
                if count > MAX_ENTRIES:
                    raise FATError("디렉터리 항목이 너무 많습니다")
                yield item
                if item["directory"] and not item["deleted"] and item["first_cluster"] >= 2:
                    stack.append(((*parts, item["name"]), item["first_cluster"], item["size"], item["contiguous"], depth + 1))
