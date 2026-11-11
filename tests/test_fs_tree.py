"""File system items in the data source tree (Tk-free model)."""
import unittest

from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import OriginIndex, matches
from log_hunter.ui import fs_model


class FakeExtraction:
    image_path = r"C:\cases\case.E01"
    image = {}
    files = [{"volume": 0, "image_path": r"\Windows\System32\config\SYSTEM", "extracted": r"C:\work\SYSTEM"}]


class FsModelTests(unittest.TestCase):
    def setUp(self):
        self.origins = OriginIndex([FakeExtraction()])
        self.events = [ForensicEvent("bam", r"C:\work\SYSTEM", "x"), ForensicEvent("usb", r"C:\work\SYSTEM", "x")]
        self.counts = fs_model.prefix_counts(self.events, self.origins)
        volumes = [{"index": 0, "offset": 1048576, "size": 268435456, "filesystem": "ntfs"},
                   {"index": 1, "offset": 0, "size": 1024, "filesystem": "bitlocker"}]
        self.volumes = fs_model.volume_nodes("case.E01", FakeExtraction.image_path, volumes, self.counts)

    def test_volume_nodes(self):
        first, second = self.volumes
        self.assertEqual(first.label, "볼륨 0 (NTFS · 256.0MB · 시작 1.0MB)")
        self.assertEqual(first.text, "볼륨 0 (NTFS · 256.0MB · 시작 1.0MB) (2)")
        self.assertTrue(fs_model.needs_loading(first))
        self.assertFalse(fs_model.needs_loading(second))
        self.assertEqual(second.text, "볼륨 1 (BitLocker 암호화 · 1.0KB · 시작 0B)")

    def test_folder_children_count_and_filter(self):
        rows = [{"name": "WINDOWS", "directory": True, "size": 0, "record": 30},
                {"name": "pagefile.sys", "directory": False, "size": 1 << 30, "record": 31}]
        windows, pagefile = fs_model.entry_nodes(self.volumes[0], rows, self.counts)
        self.assertEqual(windows.count, 2)  # case-insensitive: records are under \Windows
        self.assertEqual(windows.fs["parts"], ("WINDOWS",))
        self.assertEqual(pagefile.label, "pagefile.sys · 1.0GB")
        self.assertEqual(pagefile.text, "pagefile.sys · 1.0GB")
        self.assertFalse(fs_model.needs_loading(pagefile))
        self.assertTrue(all(matches(self.volumes[0], e, self.origins) for e in self.events))
        self.assertTrue(all(matches(windows, e, self.origins) for e in self.events))
        self.assertFalse(any(matches(pagefile, e, self.origins) for e in self.events))

    def test_folder_limit(self):
        rows = [{"name": f"f{i}", "directory": False, "size": 1, "record": i} for i in range(5)]
        nodes = fs_model.entry_nodes(self.volumes[0], rows, self.counts, limit=3)
        self.assertEqual(len(nodes), 4)
        self.assertEqual(nodes[-1].label, "… 외 2개 (표시 상한 3개)")
        self.assertEqual(nodes[-1].kind, "group")


if __name__ == "__main__":
    unittest.main()
