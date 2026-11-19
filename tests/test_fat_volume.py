"""FAT volumes (USB sticks, memory cards): file list, long names, deleted entries, content checks, local times kept raw."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.core.pipeline import Pipeline  # noqa: E402
from log_hunter.image.fat import FATError, FATVolume, _dos_datetime  # noqa: E402
from test_image import mbr_disk  # noqa: E402

SECTOR, CLUSTER_SECTORS, RESERVED, FAT_SECTORS, ROOT_ENTRIES, TOTAL = 512, 1, 1, 32, 64, 8192
DATE = ((2020 - 1980) << 9) | (12 << 5) | 30  # 2020-12-30
TIME = (9 << 11) | (30 << 5)                   # 09:30:00


def short_entry(name83, attr, cluster, size, first_byte=None):
    entry = bytearray(32)
    entry[0:11] = name83
    if first_byte is not None:
        entry[0] = first_byte
    entry[11] = attr
    struct.pack_into("<HHH", entry, 14, TIME, DATE, DATE)
    struct.pack_into("<HH", entry, 22, TIME, DATE)
    struct.pack_into("<HI", entry, 26, cluster, size)
    return bytes(entry)


def lfn_entries(name, short83):
    checksum = 0
    for byte in short83:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF
    chars = name.encode("utf-16-le") + b"\x00\x00"
    chars += b"\xff" * ((26 - len(chars) % 26) % 26)
    pieces = [chars[i:i + 26] for i in range(0, len(chars), 26)]
    out = []
    for index, piece in enumerate(pieces, 1):
        entry = bytearray(32)
        entry[0] = index | (0x40 if index == len(pieces) else 0)
        entry[1:11], entry[11], entry[13] = piece[0:10], 0x0F, checksum
        entry[14:26], entry[28:32] = piece[10:22], piece[22:26]
        out.append(bytes(entry))
    return list(reversed(out))


def fat16_volume(files):
    """files: [(long name or None, 8.3 name bytes, data, deleted)] in the root, plus a subfolder with one file."""
    boot = bytearray(SECTOR)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBH", boot, 11, SECTOR, CLUSTER_SECTORS, RESERVED, 2, ROOT_ENTRIES, TOTAL, 0xF8, FAT_SECTORS)
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"
    fat = bytearray(FAT_SECTORS * SECTOR)
    struct.pack_into("<HH", fat, 0, 0xFFF8, 0xFFFF)
    data_start = (RESERVED + 2 * FAT_SECTORS) * SECTOR + ROOT_ENTRIES * 32
    volume = bytearray(TOTAL * SECTOR)
    root = []
    cluster = 2

    def store(data):
        nonlocal cluster
        first = cluster
        count = max(1, (len(data) + SECTOR - 1) // SECTOR)
        for i in range(count):
            struct.pack_into("<H", fat, (cluster + i) * 2, 0xFFFF if i == count - 1 else cluster + i + 1)
        offset = data_start + (first - 2) * SECTOR
        volume[offset:offset + len(data)] = data
        cluster += count
        return first

    for long_name, short83, data, deleted in files:
        first = store(data)
        if long_name:
            root += lfn_entries(long_name, short83)
        root.append(short_entry(short83, 0x20, first, len(data), 0xE5 if deleted else None))
        if deleted:  # the table no longer keeps a deleted file's chain
            struct.pack_into("<H", fat, first * 2, 0)
    sub_file = store(b"plain text")
    sub_dir = bytearray(SECTOR)
    sub_dir[0:32] = short_entry(b".          ", 0x10, 0, 0)
    sub_dir[32:64] = short_entry(b"..         ", 0x10, 0, 0)
    sub_dir[64:96] = short_entry(b"NOTE    TXT", 0x20, sub_file, 10)
    sub = store(bytes(sub_dir))
    root.append(short_entry(b"DOCS       ", 0x10, sub, 0))
    root_bytes = b"".join(root)
    volume[0:SECTOR] = boot
    for copy in range(2):
        offset = (RESERVED + copy * FAT_SECTORS) * SECTOR
        volume[offset:offset + len(fat)] = fat
    root_offset = (RESERVED + 2 * FAT_SECTORS) * SECTOR
    volume[root_offset:root_offset + len(root_bytes)] = root_bytes
    return bytes(volume)


def jpeg_with_exif():
    camera = b"II*\0" + struct.pack("<IHHHI", 8, 1, 0x0110, 2, 4) + b"ABC\0" + bytes(4)
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", 8 + len(camera)) + b"Exif\0\0" + camera + b"\xff\xd9"


class FATVolumeTests(unittest.TestCase):
    def setUp(self):
        files = [("Holiday photo.jpg", b"HOLIDA~1JPG", jpeg_with_exif(), False),
                 (None, b"REPORT  JPG", b"%PDF-1.4\n" + bytes(600), False),  # a PDF named .jpg
                 ("removed.jpg", b"REMOVE~1JPG", jpeg_with_exif(), True)]
        self.volume = fat16_volume(files)

    def test_walk_names_times_and_deleted(self):
        class Image:
            def __init__(self, data):
                self.data = data

            def read(self, offset, size):
                return self.data[offset:offset + size]
        fat = FATVolume(Image(self.volume), 0)
        self.assertEqual(fat.kind, 16)
        items = {i["path"]: i for i in fat.walk()}
        self.assertIn("\\Holiday photo.jpg", items)
        self.assertIn("\\DOCS\\NOTE.TXT", items)
        self.assertTrue(items["\\removed.jpg"]["deleted"])
        self.assertEqual(items["\\Holiday photo.jpg"]["modified"], "2020-12-30T09:30:00")  # local, no zone
        self.assertEqual(_dos_datetime(0), None)

    def test_image_inventory_reports_fat_files(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "usb.dd"
            image.write_bytes(mbr_disk(self.volume))
            result = Pipeline().analyze_image(image, Path(directory) / "work", include_mft=True)
        rows = {}
        for e in result.events:
            rows.setdefault(e.action, []).append(e)
        names = {e.path for e in rows["ntfs_file_inventory"]}
        self.assertIn("\\Holiday photo.jpg", names)
        self.assertEqual(rows["extension_mismatch"][0].path, "\\REPORT.JPG")
        photos = {e.path: e for e in rows["photo_metadata"]}
        self.assertEqual(photos["\\Holiday photo.jpg"].details["camera_model"], "ABC")
        self.assertIn("\\removed.jpg", photos)  # the deleted file's contiguous clusters still hold the photo
        deleted, = rows["deleted_file_candidate"]
        self.assertEqual(deleted.details["stream_state"], "deleted_contiguous_guess")
        self.assertFalse(deleted.details["timezone_known"])
        self.assertTrue(all(e.details.get("filesystem") == "fat16" for e in rows["ntfs_file_inventory"]))

    def test_browser_lists_opens_and_scans_fat(self):
        from log_hunter.image.browse import ImageBrowser
        from log_hunter.ui import fs_model
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "usb.dd"
            image.write_bytes(mbr_disk(self.volume))
            browser = ImageBrowser(image)
            try:
                (info,) = browser.volume_info()
                self.assertTrue(info["browsable"])
                rows = {r["name"]: r for r in browser.list_dir(info["index"])}
                self.assertTrue(rows["DOCS"]["directory"])
                self.assertFalse(rows["removed.jpg"]["in_use"])  # deleted entries are listed, marked
                self.assertEqual(rows["Holiday photo.jpg"]["modified"], "2020-12-30T09:30:00")
                self.assertEqual([r["name"] for r in browser.list_dir(info["index"], ("DOCS",))], ["NOTE.TXT"])
                note = browser.open_file(info["index"], ("DOCS", "NOTE.TXT"))
                self.assertEqual(note.read(0, 100), b"plain text")
                self.assertFalse(note.info()["timezone_known"])
                gone = browser.open_file(info["index"], ("removed.jpg",))
                self.assertTrue(gone.read(0, 3).startswith(b"\xff\xd8\xff"))
                self.assertIn("삭제된 항목", gone.note)
                self.assertTrue(browser.exists(info["index"], ("Holiday photo.jpg",)))
                self.assertFalse(browser.exists(info["index"], ("removed.jpg",)))
                scan = browser.scan_mft(info["index"], fs_model.classify)
                self.assertEqual(scan["categories"]["deleted"]["count"], 1)
                self.assertEqual(len(browser.volume_serial(info["index"])), 8)
            finally:
                browser.close()

    def test_damaged_volumes_end_cleanly(self):
        import random
        from log_hunter.image.inventory import scan_fat_inventory

        class Image:
            def __init__(self, data):
                self.data = data

            def read(self, offset, size):
                return self.data[max(0, offset):max(0, offset) + max(0, size)]
        rng = random.Random(7)
        for _ in range(60):
            blob = bytearray(self.volume)
            for _ in range(rng.randint(1, 20)):
                position = rng.randrange(0, 40 * 1024)  # boot sector, tables, root directory and first data
                blob[position] = rng.randrange(256)
            try:
                list(scan_fat_inventory(FATVolume(Image(bytes(blob)), 0), 0, "x"))
            except ValueError:
                pass  # FATError is a ValueError: a clean "not a usable FAT volume"

    def test_not_fat(self):
        class Image:
            def read(self, offset, size):
                return bytes(size)
        with self.assertRaises(FATError):
            FATVolume(Image(), 0)


if __name__ == "__main__":
    unittest.main()
