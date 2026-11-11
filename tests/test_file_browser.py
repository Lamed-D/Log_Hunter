"""File browser: per-page details, MFT-wide file views, deleted files, the folder file table."""
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_hunter.image.browse import ImageBrowser
from log_hunter.ui import fs_model
from test_image import CLUSTER, MFT_LCN, RECORD, NTFSBuilder


def _record_offset(number):
    return MFT_LCN * CLUSTER + number * RECORD


def _data_attribute(image, number):
    start = _record_offset(number)
    position, = struct.unpack_from("<H", image, start + 20)
    while struct.unpack_from("<I", image, start + position)[0] != 0x80:
        position += struct.unpack_from("<I", image, start + position + 4)[0]
    return start + position


def build_volume():
    builder = NTFSBuilder()
    docs = builder.makedirs("Users/alice/Documents")
    builder.add_file(docs, "report.docx", b"PK" + bytes(100), mode="resident")
    builder.add_file(docs, "photo.JPG", b"\xff\xd8" + bytes(100), mode="resident")
    gone = builder.add_file(docs, "secret.txt", b"top secret", mode="resident")
    big = builder.add_file(docs, "backup.bin", b"B" * 4000)
    tools = builder.makedirs("Tools")
    builder.add_file(tools, "run.ps1", b"Write-Host hi", mode="resident")
    image = bytearray(builder.build())
    flags_at = _record_offset(gone) + 22
    struct.pack_into("<H", image, flags_at, struct.unpack_from("<H", image, flags_at)[0] & ~1)  # deleted
    struct.pack_into("<Q", image, _data_attribute(image, big) + 48, 60 << 20)  # claims 60 MB
    return bytes(image), gone


class FileBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        image, self.deleted_record = build_volume()
        path = Path(self.temp.name) / "disk.dd"
        path.write_bytes(image)
        self.browser = ImageBrowser(path)

    def tearDown(self):
        self.browser.close()
        self.temp.cleanup()

    def test_describe_adds_times_and_state(self):
        rows = self.browser.list_dir(0, ("Users", "alice", "Documents"))
        described = {r["name"]: r for r in self.browser.describe(0, rows)}
        self.assertEqual(described["report.docx"]["created"], "2020-12-30T00:00:00+00:00")
        self.assertTrue(described["report.docx"]["in_use"])
        self.assertFalse(described["secret.txt"]["in_use"])  # still in the index, record marked unused

    def test_scan_mft_file_views(self):
        progress = []
        result = self.browser.scan_mft(0, fs_model.classify, progress=lambda done, total: progress.append(done))
        categories = result["categories"]
        names = {key: [i["name"] for i in bucket["items"]] for key, bucket in categories.items()}
        self.assertEqual(names["document"], ["report.docx"])
        self.assertEqual(names["image"], ["photo.JPG"])
        self.assertEqual(names["script"], ["run.ps1"])
        self.assertEqual(names["deleted"], ["secret.txt"])
        self.assertEqual(names["size_50_200"], ["backup.bin"])
        deleted = categories["deleted"]["items"][0]
        self.assertEqual(deleted["path"], "\\Users\\alice\\Documents\\secret.txt")
        self.assertEqual(progress[-1], result["records"])
        self.assertFalse(result["cancelled"])
        opened = self.browser.open_record(0, deleted["record"], ("Users", "alice", "Documents", "secret.txt"))
        self.assertEqual(opened.read(0, 10), b"top secret")
        self.assertIn("삭제된 파일", opened.note)

    def test_scan_limit_and_cancel(self):
        limited = self.browser.scan_mft(0, lambda item: ["all"], limit=3)["categories"]["all"]
        self.assertEqual(len(limited["items"]), 3)
        self.assertGreater(limited["count"], 3)
        stop = threading.Event()
        stop.set()
        cancelled = self.browser.scan_mft(0, fs_model.classify, cancelled=stop.is_set)
        self.assertTrue(cancelled["cancelled"])
        self.assertEqual(cancelled["categories"], {})


class FileTableTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"name": "b.txt", "directory": False, "size": 10, "modified": "2024-01-02"},
                     {"name": "A", "directory": True, "size": 0, "modified": "2024-01-01"},
                     {"name": "c.exe", "directory": False, "size": 5000, "modified": None, "in_use": False}]

    def test_sort_search_pages(self):
        table = fs_model.FileTable(self.rows, page_rows=2)
        self.assertEqual([r["name"] for r in table.rows], ["A", "b.txt", "c.exe"])  # folders first
        self.assertEqual(table.pages, 2)
        self.assertEqual(table.status(), "3개 · 페이지 1/2")
        table.turn(1)
        self.assertEqual([r["name"] for r in table.page_slice()], ["c.exe"])
        table.sort("size")
        self.assertEqual([r["name"] for r in table.rows], ["A", "b.txt", "c.exe"])
        table.sort("size")
        self.assertEqual([r["name"] for r in table.rows], ["c.exe", "b.txt", "A"])
        table.search("B.T")
        self.assertEqual([r["name"] for r in table.rows], ["b.txt"])
        self.assertEqual(table.status(), "1개 / 전체 3개")

    def test_values_and_kinds(self):
        values = fs_model.table_values(self.rows[2])
        self.assertEqual(values[:3], ("c.exe", "실행 파일", "4.9KB"))
        self.assertEqual(values[7], "삭제됨")
        self.assertEqual(fs_model.table_values(self.rows[1])[1:3], ("폴더", ""))
        self.assertEqual(fs_model.kind_of("x.PS1"), "script")
        self.assertEqual(fs_model.kind_of("noext"), "other")

    def test_file_view_tree(self):
        root = fs_model.file_view_root([("case.E01", "C:/case.E01", 0)])
        labels = [n.label for n in root.children]
        self.assertEqual(labels, ["종류별", "삭제된 파일", "크기별"])
        self.assertEqual(root.children[1].value["category"], "deleted")
        self.assertEqual([n.label for n in root.children[2].children], ["50MB ~ 200MB", "200MB ~ 1GB", "1GB 이상"])


if __name__ == "__main__":
    unittest.main()


class SaveCopyTests(unittest.TestCase):
    def test_save_copy_hashes_and_never_overwrites(self):
        import hashlib
        import json
        from log_hunter.ui.content import save_copy
        image, _ = build_volume()
        with tempfile.TemporaryDirectory() as temp:
            disk = Path(temp) / "disk.dd"
            disk.write_bytes(image)
            before = hashlib.sha256(disk.read_bytes()).hexdigest()
            out = Path(temp) / "out"
            out.mkdir()
            browser = ImageBrowser(disk)
            try:
                source = browser.open_file(0, ("Users", "alice", "Documents", "report.docx"))
                target, sha = save_copy(source, out, "report.docx", source.info())
                self.assertEqual(target.read_bytes(), b"PK" + bytes(100))
                self.assertEqual(sha, hashlib.sha256(target.read_bytes()).hexdigest())
                record = json.loads((out / "report.docx.log-hunter.json").read_text(encoding="utf-8"))
                self.assertEqual(record["image_path"], r"\Users\alice\Documents\report.docx")
                self.assertEqual(record["sha256"], sha)
                with self.assertRaises(FileExistsError):
                    save_copy(source, out, "report.docx", source.info())
                self.assertEqual(target.read_bytes(), b"PK" + bytes(100))
            finally:
                browser.close()
            self.assertEqual(hashlib.sha256(disk.read_bytes()).hexdigest(), before)  # image untouched
