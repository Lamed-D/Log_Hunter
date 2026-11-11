"""NTFS path lookup must never silently select a different file's content."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.image.ewf import RawImage
from log_hunter.image.ntfs import NTFSVolume, NTFSError
from test_image import NTFSBuilder


class NTFSIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        builder = NTFSBuilder()
        folder = builder.makedirs("Data")
        self.upper = builder.add_file(folder, "A.bin", b"UPPER", mode="resident")
        self.lower = builder.add_file(folder, "a.bin", b"lower", mode="resident")
        self.single = builder.add_file(folder, "Single.bin", b"single", mode="resident")
        builder.add_file(folder, "duplicate.bin", b"first", mode="resident")
        builder.add_file(folder, "duplicate.bin", b"second", mode="resident")
        image = self.root / "synthetic.dd"
        image.write_bytes(builder.build())
        self.image = RawImage(image)
        self.addCleanup(self.image.close)
        self.volume = NTFSVolume(self.image)

    def test_exact_case_returns_the_selected_content(self):
        for name, expected_record, expected_content in (("A.bin", self.upper, b"UPPER"), ("a.bin", self.lower, b"lower")):
            with self.subTest(name=name):
                entry = self.volume.lookup("Data/" + name)
                self.assertEqual(entry.record, expected_record)
                target = self.root / (str(expected_record) + ".bin")
                self.volume.copy_file(entry, target)
                self.assertEqual(target.read_bytes(), expected_content)

    def test_unique_case_insensitive_fallback_is_preserved(self):
        self.assertEqual(self.volume.lookup("data/SINGLE.BIN").record, self.single)

    def test_ambiguous_fallback_is_rejected(self):
        with self.assertRaises(NTFSError):
            self.volume.lookup("Data/A.BIN")

    def test_duplicate_exact_name_is_rejected(self):
        with self.assertRaises(NTFSError):
            self.volume.lookup("Data/duplicate.bin")
