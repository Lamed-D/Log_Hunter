"""Synthetic NTFS inventory observations from original image bytes."""
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.pipeline import Pipeline
from log_hunter.image.inventory import _pdf_encryption
from test_image import NTFSBuilder


def encrypted_pdf():
    content = b"%PDF-1.7\n"
    offset = len(content)
    content += b"xref\n0 1\n0000000000 65535 f\n"
    content += b"trailer\n<< /Size 1 /Root 1 0 R /Encrypt 2 0 R >>\n"
    return content + f"startxref\n{offset}\n%%EOF\n".encode()


class FileInventoryTests(unittest.TestCase):
    def test_inventory_detects_file_types_photo_and_encryption(self):
        camera = b"II*\0" + struct.pack("<IHHHI", 8, 1, 0x0110, 2, 4) + b"ABC\0" + bytes(4)
        jpeg = b"\xff\xd8\xff\xe1" + struct.pack(">H", 8 + len(camera)) + b"Exif\0\0" + camera + b"\xff\xd9"
        ntfs = NTFSBuilder()
        folder = ntfs.makedirs("Evidence")
        ntfs.add_file(folder, "photo.txt", jpeg)
        ntfs.add_file(folder, "document.pdf", encrypted_pdf())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "synthetic.dd"
            image.write_bytes(ntfs.build())
            result = Pipeline().analyze_image(image, root / "work", include_mft=True)
        rows = {action: [e for e in result.events if e.action == action] for action in
                ("extension_mismatch", "photo_metadata", "encrypted_file", "ntfs_file_inventory")}
        photo, = rows["photo_metadata"]
        self.assertEqual(photo.details["camera_model"], "ABC")
        mismatch, = rows["extension_mismatch"]
        self.assertEqual(mismatch.details["file_type"], "jpeg")
        encrypted, = rows["encrypted_file"]
        self.assertEqual(encrypted.details["encryption_basis"], "pdf_encrypt_reference")
        target, = [e for e in rows["ntfs_file_inventory"] if e.details["mft_record"] == encrypted.details["mft_record"]]
        self.assertEqual(target.details["file_size"], len(encrypted_pdf()))
        self.assertEqual(target.details["source_path"], r"\Evidence\document.pdf")

    def test_pdf_encrypt_token_in_body_does_not_establish_encryption(self):
        data = encrypted_pdf().replace(b"/Encrypt 2 0 R", b"/Example 2 0 R")
        self.assertIsNone(_pdf_encryption(lambda offset, length: data[offset:offset + length], len(data)))
