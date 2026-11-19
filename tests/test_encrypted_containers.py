"""Password-protected ZIP archives and Office files are marked as encrypted (also when the name hides the format)."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.core.pipeline import Pipeline  # noqa: E402
from log_hunter.image.inventory import _compound_encryption, _zip_encryption  # noqa: E402
from test_image import NTFSBuilder  # noqa: E402


def zip_archive(local_flags=0, central_flags=0, name=b"a.txt", data=b"hello"):
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, local_flags, 0, 0, 0, 0, len(data), len(data), len(name), 0)
    body = local + name + data
    central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, central_flags, 0, 0, 0, 0, len(data), len(data),
                          len(name), 0, 0, 0, 0, 0, 0) + name
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(body), 0)
    return body + central + end


def read_of(data):
    return lambda offset, size: data[offset:offset + size]


class EncryptedContainerTests(unittest.TestCase):
    def test_zip_flags(self):
        plain = zip_archive()
        self.assertIsNone(_zip_encryption(read_of(plain), len(plain)))
        local = zip_archive(local_flags=1, central_flags=1)
        self.assertEqual(_zip_encryption(read_of(local), len(local)), 0)
        central_only = zip_archive(central_flags=1)  # e.g. a later entry; the first header looks plain
        self.assertEqual(_zip_encryption(read_of(central_only), len(central_only)), len(zip_archive()) - 46 - 5 - 22)

    def test_damaged_central_directory_is_not_guessed(self):
        broken = zip_archive(central_flags=1)[:-10]
        self.assertIsNone(_zip_encryption(read_of(broken), len(broken)))

    def test_office_encrypted_package(self):
        office = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(600) + "EncryptedPackage".encode("utf-16-le") + bytes(100)
        self.assertEqual(_compound_encryption(read_of(office), len(office)), 608)
        plain = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(700)
        self.assertIsNone(_compound_encryption(read_of(plain), len(plain)))

    def test_inventory_marks_disguised_encrypted_archive(self):
        ntfs = NTFSBuilder()
        folder = ntfs.makedirs("Evidence")
        ntfs.add_file(folder, "report.pdf", zip_archive(local_flags=1, central_flags=1))
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "synthetic.dd"
            image.write_bytes(ntfs.build())
            result = Pipeline().analyze_image(image, Path(directory) / "work", include_mft=True)
        actions = {e.action: e for e in result.events if e.action in ("extension_mismatch", "encrypted_file")}
        self.assertEqual(actions["encrypted_file"].details["encryption_basis"], "zip_encrypted_entry_flag")
        self.assertEqual(actions["extension_mismatch"].details["file_type"], "zip")


if __name__ == "__main__":
    unittest.main()
