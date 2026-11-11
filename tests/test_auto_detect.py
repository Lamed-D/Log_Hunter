"""Synthetic input detection and CLI regression tests."""
import contextlib
import hashlib
import io
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from log_hunter.core.auto_detect import detect_artifact


def hive_bytes(names=(), header_name=""):
    header = bytearray(4096)
    header[:4] = b"regf"
    name = header_name.encode("utf-16-le")[:62]
    header[0x30:0x30 + len(name)] = name
    cells = bytearray(b"hbin" + bytes(28))

    def cell(data):
        offset = len(cells)
        size = (len(data) + 11) & ~7
        cells.extend(struct.pack("<i", -size) + data + bytes(size - 4 - len(data)))
        return offset

    def key(name, children=()):
        data = bytearray(76)
        data[:2] = b"nk"
        struct.pack_into("<H", data, 2, 0x20)
        struct.pack_into("<I", data, 20, len(children))
        if children:
            listing = cell(b"li" + struct.pack("<H", len(children)) + b"".join(struct.pack("<I", n) for n in children))
            struct.pack_into("<I", data, 28, listing)
        struct.pack_into("<H", data, 72, len(name))
        return cell(data + name.encode("ascii"))

    children = [key(name) for name in names]
    struct.pack_into("<I", header, 0x24, key("ROOT", children))
    return bytes(header + cells)


class AutoDetectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self, name, data=b""):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def detect(self, paths):
        from log_hunter.core.auto_detect import detect_inputs
        return detect_inputs(paths)

    def test_multimapping_and_usrclass(self):
        expected = {"NTUSER.DAT": {"userassist", "mru", "run", "shellbag", "rdp"},
                    "SYSTEM": {"bam", "usb", "services"}, "SOFTWARE": {"network", "run", "usb", "taskcache"},
                    "UsrClass.dat": {"shellbag"}}
        for name, kinds in expected.items():
            with self.subTest(name=name):
                path = self.source(name)
                self.assertEqual({row[0] for row in self.detect([path])}, kinds)

    def test_renamed_header_hives(self):
        for name, kind in (("SYSTEM", "bam"), ("SOFTWARE", "network"), ("NTUSER.DAT", "userassist"),
                           ("UsrClass.dat", "shellbag"), ("Amcache.hve", "amcache"), ("SECURITY", None)):
            with self.subTest(name=name):
                path = self.source("renamed", hive_bytes(header_name=name))
                self.assertIn(kind, [r[0] for r in self.detect([path])])

    def test_renamed_root_key_hives(self):
        for names, kind in ((("Select", "ControlSet001"), "bam"), (("Microsoft", "Classes"), "network"),
                            (("Software", "Control Panel"), "userassist"), (("Local Settings",), "shellbag"),
                            (("Root",), None), (("SAM",), None)):
            with self.subTest(names=names):
                path = self.source("copy.hiv", hive_bytes(names))
                self.assertIn(kind, [r[0] for r in self.detect([path])])

    def test_sidecars_are_diagnostic_only(self):
        for name in ("NTUSER.DAT.LOG1", "SYSTEM.LOG2", "History-wal", "History-shm"):
            with self.subTest(name=name):
                path = self.source(name)
                self.assertIsNone(detect_artifact(path))
                rows = self.detect([path])
                self.assertEqual(rows[0][0], None)
                self.assertTrue(rows[0][3])

    def test_collection_rules_dedup_and_input_unchanged(self):
        path = self.source("collection/C/Users/alice/NTUSER.DAT", hive_bytes())
        before = hashlib.sha256(path.read_bytes()).digest()
        rows = self.detect([self.root / "collection", path])
        self.assertEqual(len(rows), 5)
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())
        self.assertTrue(all(row[3] for row in rows))

    def test_startup_path_overrides_lnk(self):
        path = self.source("C/Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/app.lnk")
        self.assertEqual([r[0] for r in self.detect([self.root])], ["startup"])

    def test_e01_segments_grouped(self):
        one = self.source("disk.E01", b"EVF\x09\x0d\x0a\xff\x00" + bytes(8))
        two = self.source("disk.E02", b"EVF\x09\x0d\x0a\xff\x00" + bytes(8))
        rows = self.detect([two, one])
        self.assertEqual([(r[0], r[1]) for r in rows], [("image", str(one))])

    def test_unsupported_images_and_missing_paths(self):
        path = self.source("copy", b"vhdxfile" + bytes(512))
        rows = self.detect([path, self.root / "missing"])
        self.assertEqual([r[0] for r in rows], [None, None])
        self.assertIn("VHDX", rows[0][3])

    def test_cli_auto_reads_synthetic_history(self):
        from log_hunter.main import main
        path = self.source("ConsoleHost_history.txt", b"Get-Date\n")
        output = self.root / "result"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = main(["analyze", "--auto", str(path), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertTrue((output / "report.json").exists())
        self.assertIn(str(path), stdout.getvalue())

    def test_lowercase_e01_and_orphan_segment(self):
        signature = b"EVF\x09\x0d\x0a\xff\x00"
        first = self.source("disk.e01", signature)
        second = self.source("disk.e02", signature)
        rows = self.detect([second, first])
        self.assertEqual([(r[0], r[1]) for r in rows], [("image", str(first))])
        orphan = self.source("other.e02", signature)
        self.assertIsNone(self.detect([orphan])[0][0])

    def test_raw_and_unsupported_image_signatures(self):
        for header, expected in ((b"EVF2", None), (b"LVF", None), (b"conectix", None),
                                  (b"\xeb\x52\x90NTFS    " + bytes(501), "image")):
            path = self.source("image-copy", header)
            self.assertEqual(self.detect([path])[0][0], expected)

    def test_sidecar_with_main_is_not_an_extra_input(self):
        main = self.source("NTUSER.DAT")
        sidecar = self.source("NTUSER.DAT.LOG1")
        self.assertEqual(len(self.detect([main, sidecar])), 5)

    def test_sid_connection_uses_shared_image_logic(self):
        software = self.source("collection/C/Windows/System32/config/SOFTWARE")
        user = self.source("collection/C/Users/alice/NTUSER.DAT")
        sid = "S-1-5-21-1-2-3-1001"
        with patch("log_hunter.image.extract.load_profile_list", return_value={sid: "alice"}):
            rows = self.detect([software, user])
        self.assertTrue(all(row[2] == sid for row in rows if row[1] == str(user)))

    def test_short_regf_does_not_crash(self):
        path = self.source("unknown", b"regf")
        self.assertIsNone(self.detect([path])[0][0])

    def test_cli_rejects_ambiguous_modes_before_analysis(self):
        from log_hunter.main import main
        path = self.source("ConsoleHost_history.txt")
        with patch("log_hunter.main.Pipeline") as pipeline:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["analyze", "--auto", str(path), "--image", str(path), "--output", str(self.root / "out")])
            pipeline.assert_not_called()
