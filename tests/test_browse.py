"""Read-only image browsing used by the GUI file tree and content viewer."""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_hunter.image.browse import ImageBrowser
from log_hunter.image.ntfs import NTFSError
from test_image import CLUSTER, MFT_LCN, RECORD, NTFSBuilder, mbr_disk, windows_volume, write_e01


class ImageBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        volume, self.system = windows_volume()
        self.e01 = write_e01(self.root / "case.E01", mbr_disk(volume))[0]
        self.before = hashlib.sha256(self.e01.read_bytes()).hexdigest()
        self.browser = ImageBrowser(self.e01)

    def tearDown(self):
        self.browser.close()
        self.assertEqual(hashlib.sha256(self.e01.read_bytes()).hexdigest(), self.before)  # image untouched
        self.temp.cleanup()

    def test_volumes_and_folders(self):
        volumes = self.browser.volume_info()
        self.assertEqual([(v["index"], v["filesystem"], v["browsable"]) for v in volumes], [(0, "ntfs", True)])
        root = self.browser.list_dir(0)
        names = [r["name"] for r in root]
        self.assertIn("Windows", names)
        self.assertLess(names.index("Windows"), names.index("$MFT"))  # folders first
        prefetch = self.browser.list_dir(0, ("Windows", "Prefetch"))
        self.assertEqual(len([r for r in prefetch if r["name"].endswith(".pf")]), 40)
        with self.assertRaises(NTFSError):
            self.browser.list_dir(0, ("Windows", "Nope"))
        with self.assertRaises(NTFSError):
            self.browser.list_dir(1)

    def test_file_pages_hash_and_info(self):
        system = self.browser.open_file(0, ("Windows", "System32", "config", "SYSTEM"))  # attribute list file
        self.assertEqual(system.size, len(self.system))
        self.assertEqual(system.read(0, 100), self.system[:100])
        self.assertEqual(system.read(len(self.system) - 11, 4096), b"SYSTEM-TAIL")
        self.assertEqual(system.read(len(self.system) + 10, 10), b"")
        self.assertEqual(system.sha256(), hashlib.sha256(self.system).hexdigest())
        info = system.info()
        self.assertEqual(info["image_path"], r"\Windows\System32\config\SYSTEM")
        self.assertEqual(info["created"], "2020-12-30T00:00:00+00:00")
        self.assertTrue(info["in_use"])
        sparse = self.browser.open_file(0, ("Users", "alice", "AppData", "Roaming", "Microsoft", "Windows",
                                            "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
        self.assertEqual(sparse.read(CLUSTER, CLUSTER), bytes(CLUSTER))
        resident = self.browser.open_file(0, ("Windows", "System32", "config", "SYSTEM.LOG1"))
        self.assertEqual(resident.read(0, 8), b"LOG1LOG1")
        with self.assertRaises(NTFSError):
            self.browser.open_file(0, ("Windows",))


class CraftedSizeTests(unittest.TestCase):
    def test_reads_stay_inside_allocated_clusters(self):
        builder = NTFSBuilder()
        folder = builder.makedirs("Data")
        number = builder.add_file(folder, "big.bin", b"A" * 4000)
        image = bytearray(builder.build())
        start = MFT_LCN * CLUSTER + number * RECORD
        position, = struct.unpack_from("<H", image, start + 20)
        while struct.unpack_from("<I", image, start + position)[0] != 0x80:
            position += struct.unpack_from("<I", image, start + position + 4)[0]
        struct.pack_into("<QQ", image, start + position + 48, 1 << 40, 1 << 40)  # real/initialized: 1 TiB
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "disk.dd"
            path.write_bytes(bytes(image))
            browser = ImageBrowser(path)
            try:
                big = browser.open_file(0, ("Data", "big.bin"))
                self.assertEqual(big.size, CLUSTER)
                self.assertIn("할당", big.note)
                self.assertEqual(big.read(0, 4)[:4], b"AAAA")
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
