"""Synthetic NTFS inventory observations from original image bytes."""
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.pipeline import Pipeline
from log_hunter.core.preview_images import _exif
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
        ntfs.add_file(folder, "photo.bmp", jpeg)
        ntfs.add_file(folder, "document.pdf", encrypted_pdf())
        ntfs.add_file(folder, "renamed.lnk", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(64))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "synthetic.dd"
            image.write_bytes(ntfs.build())
            result = Pipeline().analyze_image(image, root / "work", include_mft=True)
        rows = {action: [e for e in result.events if e.action == action] for action in
                ("extension_mismatch", "photo_metadata", "encrypted_file", "ntfs_file_inventory")}
        photo, = rows["photo_metadata"]
        self.assertEqual(photo.details["camera_model"], "ABC")
        mismatches = {Path(e.path).suffix: e.details["file_type"] for e in rows["extension_mismatch"]}
        self.assertEqual(mismatches, {".bmp": "jpeg", ".lnk": "compound"})
        encrypted, = rows["encrypted_file"]
        self.assertEqual(encrypted.details["encryption_basis"], "pdf_encrypt_reference")
        target, = [e for e in rows["ntfs_file_inventory"] if e.details["mft_record"] == encrypted.details["mft_record"]]
        self.assertEqual(target.details["file_size"], len(encrypted_pdf()))
        self.assertEqual(target.details["source_path"], r"\Evidence\document.pdf")

    def test_photo_uses_the_offset_paired_with_the_original_timestamp(self):
        raw = b"2024:01:02 01:00:00\0"
        offset = b"+09:00\0"
        fields_offset = 8 + 2 + 2 * 12 + 4
        for tag, expected in ((0x9011, "2024-01-01T16:00:00+00:00"), (0x9010, None)):
            tiff = (b"II*\0" + struct.pack("<IH", 8, 2)
                    + struct.pack("<HHII", 0x9003, 2, len(raw), fields_offset)
                    + struct.pack("<HHII", tag, 2, len(offset), fields_offset + len(raw))
                    + bytes(4) + raw + offset)
            parsed = _exif(tiff)
            self.assertEqual(parsed.get("date_time_original_utc"), expected)
            self.assertEqual(parsed["timezone_known"], expected is not None)

    def test_pdf_encrypt_token_in_body_does_not_establish_encryption(self):
        data = encrypted_pdf().replace(b"/Encrypt 2 0 R", b"/Example 2 0 R")
        self.assertIsNone(_pdf_encryption(lambda offset, length: data[offset:offset + length], len(data)))
