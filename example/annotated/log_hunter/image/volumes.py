# ▶ 원본: log_hunter/image/volumes.py
# ▶ MBR·GPT 파티션과 볼륨 종류를 판별합니다. 암호화·미지원 종류는 진단으로 남깁니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Partition discovery (MBR, extended MBR, GPT) and filesystem identification."""
import struct
import uuid
from dataclasses import dataclass

GPT_BASIC_DATA = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
GPT_MS_RESERVED = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
GPT_EFI_SYSTEM = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
GPT_MS_RECOVERY = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
EXTENDED_TYPES = (0x05, 0x0F, 0x85)


@dataclass
class Volume:
    index: int
    offset: int
    size: int
    scheme: str
    type_code: str
    filesystem: str = "unknown"
    name: str = ""

    def to_dict(self):
        return {"index": self.index, "offset": self.offset, "size": self.size, "scheme": self.scheme,
                "type": self.type_code, "filesystem": self.filesystem, "name": self.name}


def identify_filesystem(boot):
    if len(boot) < 512:
        return "unknown"
    if boot[3:11] == b"NTFS    ":
        return "ntfs"
    if boot[3:11] == b"-FVE-FS-":
        return "bitlocker"
    if boot[3:11] == b"EXFAT   ":
        return "exfat"
    if boot[82:90] == b"FAT32   " or boot[54:62] in (b"FAT16   ", b"FAT12   ", b"FAT     "):
        return "fat"
    return "unknown"


def find_volumes(image):
    sector = image.sector_size or 512
    first = image.read(0, max(sector, 512))
    whole = identify_filesystem(first)
    if whole != "unknown":
        return _identified(image, [Volume(0, 0, image.size, "none", "volume")])
    if first[510:512] != b"\x55\xaa":
        return []
    entries = [first[446 + i * 16:462 + i * 16] for i in range(4)]
    if any(e[4] == 0xEE for e in entries):
        volumes = _gpt(image, sector)
        if volumes:
            return _identified(image, volumes)
    return _identified(image, _mbr(image, sector, entries))


def _mbr(image, sector, entries):
    volumes = []
    for entry in entries:
        kind = entry[4]
        start, count = struct.unpack_from("<II", entry, 8)
        if not kind or not count:
            continue
        if kind in EXTENDED_TYPES:
            volumes.extend(_extended(image, sector, start, len(volumes)))
            continue
        volumes.append(Volume(len(volumes), start * sector, count * sector, "mbr", f"0x{kind:02X}"))
    for index, volume in enumerate(volumes):
        volume.index = index
    return volumes


def _extended(image, sector, base, first_index):
    volumes, current, seen = [], base, set()
    while current not in seen and len(seen) < 128:
        seen.add(current)
        ebr = image.read(current * sector, 512)
        if ebr[510:512] != b"\x55\xaa":
            break
        logical, link = ebr[446:462], ebr[462:478]
        start, count = struct.unpack_from("<II", logical, 8)
        if logical[4] and count:
            volumes.append(Volume(first_index + len(volumes), (current + start) * sector, count * sector,
                                  "mbr-logical", f"0x{logical[4]:02X}"))
        next_start, = struct.unpack_from("<I", link, 8)
        if not link[4] or not next_start:
            break
        current = base + next_start
    return volumes


def _gpt(image, sector):
    header = image.read(sector, 92)
    if header[:8] != b"EFI PART":
        return []
    table_lba, count, entry_size = struct.unpack_from("<QII", header, 72)
    if not 0 < entry_size <= 4096 or count > 1024:
        return []
    table = image.read(table_lba * sector, count * entry_size)
    volumes = []
    for index in range(count):
        entry = table[index * entry_size:(index + 1) * entry_size]
        if len(entry) < 128 or not any(entry[:16]):
            continue
        type_guid = str(uuid.UUID(bytes_le=entry[:16]))
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        name = entry[56:128].decode("utf-16-le", errors="replace").split("\0", 1)[0]
        volumes.append(Volume(len(volumes), first_lba * sector, (last_lba - first_lba + 1) * sector,
                              "gpt", type_guid, name=name))
    return volumes


def _identified(image, volumes):
    for volume in volumes:
        volume.filesystem = identify_filesystem(image.read(volume.offset, 512))
    return volumes
