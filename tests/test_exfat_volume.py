"""exFAT volumes: file sets, chained and contiguous data, deleted sets, and UTC offsets on timestamps."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.core.pipeline import Pipeline  # noqa: E402
from log_hunter.image.browse import ImageBrowser  # noqa: E402
from log_hunter.image.exfat import ExFATVolume, exfat_time  # noqa: E402
from log_hunter.image.fat import FATError  # noqa: E402
from test_image import mbr_disk  # noqa: E402

SECTOR, CLUSTER = 512, 512
FAT_OFFSET, FAT_LENGTH, HEAP, COUNT = 24, 8, 32, 200
# 2020-12-30 09:30:00 local; offset byte 0x80 | +36 quarters (= +09:00) -> 2020-12-30 00:30:00 UTC
STAMP = ((2020 - 1980) << 25) | (12 << 21) | (30 << 16) | (9 << 11) | (30 << 5)
KST = 0x80 | 36


def file_set(name, first, size, directory=False, contiguous=False, deleted=False, offset=KST):
    names = name.encode("utf-16-le")
    chunks = [names[i:i + 30] for i in range(0, len(names), 30)]
    entry = bytearray(32)
    entry[0], entry[1] = 0x85, 1 + len(chunks)
    struct.pack_into("<H", entry, 4, 0x10 if directory else 0x20)
    struct.pack_into("<III", entry, 8, STAMP, STAMP, STAMP)
    entry[22] = entry[23] = entry[24] = offset
    stream = bytearray(32)
    stream[0], stream[1], stream[3] = 0xC0, 0x01 | (0x02 if contiguous else 0), len(name)
    struct.pack_into("<QIQ", stream, 8, size, 0, 0)
    struct.pack_into("<IQ", stream, 20, first, size)
    out = bytes(entry) + bytes(stream)
    for chunk in chunks:
        part = bytearray(32)
        part[0] = 0xC1
        part[2:2 + len(chunk)] = chunk
        out += bytes(part)
    if deleted:
        out = bytearray(out)
        for i in range(0, len(out), 32):
            out[i] &= 0x7F
        out = bytes(out)
    return out


def exfat_volume():
    volume = bytearray((HEAP + COUNT) * SECTOR)
    boot = bytearray(512)
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<IIIIII", boot, 80, FAT_OFFSET, FAT_LENGTH, HEAP, COUNT, 2, 0x1234ABCD)
    boot[108], boot[109], boot[110] = 9, 0, 1
    boot[510:512] = b"\x55\xaa"
    volume[0:512] = boot
    fat = bytearray(FAT_LENGTH * SECTOR)

    def link(chain):
        for a, b in zip(chain, chain[1:] + [0xFFFFFFFF]):
            struct.pack_into("<I", fat, a * 4, b)

    def put(cluster, data):
        at = (HEAP + cluster - 2) * SECTOR
        volume[at:at + len(data)] = data
    photo = b"\xff\xd8\xff\xe0" + bytes(700)               # spans clusters 4,5 via the FAT
    put(4, photo[:512]); put(5, photo[512:]); link([4, 5])
    put(6, b"%PDF-1.4\n" + bytes(100))                      # contiguous (NoFatChain), named .jpg
    put(8, b"\xff\xd8\xff\xe0" + bytes(50))                 # deleted file's data
    sub = file_set("note.txt", 9, 5, contiguous=True)
    put(3, sub); link([3])
    put(9, b"hello")
    root = (file_set("Folder", 3, CLUSTER, directory=True, contiguous=True) + file_set("Trip photo.jpg", 4, len(photo))
            + file_set("scan.jpg", 6, 109, contiguous=True) + file_set("gone.jpg", 8, 54, contiguous=True, deleted=True)
            + file_set("local.txt", 9, 5, contiguous=True, offset=0))
    put(2, root[:512]); put(10, root[512:]); link([2, 10])
    volume[FAT_OFFSET * SECTOR:(FAT_OFFSET + FAT_LENGTH) * SECTOR] = fat
    return bytes(volume)


class Image:
    def __init__(self, data):
        self.data = data

    def read(self, offset, size):
        return self.data[offset:offset + size]


class ExFATTests(unittest.TestCase):
    def setUp(self):
        self.volume = exfat_volume()

    def test_times(self):
        self.assertEqual(exfat_time(STAMP, 0, KST), ("2020-12-30T00:30:00+00:00", True))
        self.assertEqual(exfat_time(STAMP, 0, 0), ("2020-12-30T09:30:00", False))  # no valid offset: local, not UTC
        self.assertEqual(exfat_time(0), (None, False))

    def test_walk_and_reading(self):
        fat = ExFATVolume(Image(self.volume), 0)
        items = {i["path"]: i for i in fat.walk()}
        self.assertEqual(sorted(items), ["\\Folder", "\\Folder\\note.txt", "\\Trip photo.jpg", "\\gone.jpg",
                                         "\\local.txt", "\\scan.jpg"])
        self.assertTrue(items["\\gone.jpg"]["deleted"])
        self.assertTrue(items["\\Trip photo.jpg"]["times_utc"])
        self.assertFalse(items["\\local.txt"]["times_utc"])
        read, size = fat.reader(4, 704)
        self.assertEqual(size, 704)
        self.assertTrue(read(0, 4).startswith(b"\xff\xd8"))
        self.assertEqual(fat.serial, "1234ABCD")

    def test_image_inventory_and_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "card.dd"
            image.write_bytes(mbr_disk(self.volume))
            result = Pipeline().analyze_image(image, Path(directory) / "work", include_mft=True)
            browser = ImageBrowser(image)
            try:
                (info,) = browser.volume_info()
                self.assertTrue(info["browsable"])
                rows = {r["name"]: r for r in browser.list_dir(info["index"])}
                self.assertFalse(rows["gone.jpg"]["in_use"])
                note = browser.open_file(info["index"], ("Folder", "note.txt"))
                self.assertEqual(note.read(0, 10), b"hello")
            finally:
                browser.close()
        actions = {}
        for e in result.events:
            actions.setdefault(e.action, []).append(e)
        self.assertEqual(actions["extension_mismatch"][0].path, "\\scan.jpg")
        trip = next(e for e in actions["ntfs_file_inventory"] if e.path == "\\Trip photo.jpg")
        self.assertEqual(trip.details["filesystem"], "exfat")
        self.assertTrue(trip.details["timezone_known"])
        self.assertEqual(trip.details["file_times"]["modified"], "2020-12-30T00:30:00+00:00")
        local = next(e for e in actions["ntfs_file_inventory"] if e.path == "\\local.txt")
        self.assertFalse(local.details["timezone_known"])
        self.assertIn("file_times_local", local.details)
        self.assertEqual([e.path for e in actions["deleted_file_candidate"]], ["\\gone.jpg"])

    def test_damaged_volumes_end_cleanly(self):
        import random
        from log_hunter.image.inventory import scan_fat_inventory
        rng = random.Random(11)
        for _ in range(80):
            blob = bytearray(self.volume)
            for _ in range(rng.randint(1, 20)):
                blob[rng.randrange(0, len(blob))] = rng.randrange(256)
            try:
                list(scan_fat_inventory(ExFATVolume(Image(bytes(blob)), 0), 0, "x"))
            except ValueError:
                pass

    def test_not_exfat(self):
        with self.assertRaises(FATError):
            ExFATVolume(Image(bytes(4096)), 0)


if __name__ == "__main__":
    unittest.main()
