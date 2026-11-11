"""Small synthetic image boundaries must be checked before reads or allocations."""
import io
import struct
import unittest
import tempfile
import zlib
from pathlib import Path
from unittest.mock import Mock, patch

from log_hunter.image.ewf import EWFImage, ImageError, _parse_header, MAX_METADATA
from log_hunter.image.extract import _safe, _copy, ImageExtraction
from log_hunter.image.ntfs import NTFSVolume, Attribute


class ImageGuardTests(unittest.TestCase):
    def test_safe_component_cannot_contain_separators(self):
        name = _safe("..\\..\\escape/file.pf")
        self.assertNotIn("\\", name)
        self.assertNotIn("/", name)

    def test_ewf_rejects_oversized_section_before_read(self):
        descriptor = bytearray(76)
        descriptor[:6] = b"header"
        struct.pack_into("<QQ", descriptor, 16, 13, 1 << 40)
        stream = io.BytesIO(bytes(13) + descriptor + bytes(16))
        image = EWFImage.__new__(EWFImage)
        image.handles, image.metadata, image.chunk_size = {1: stream}, {}, None
        image.stored_md5 = image.stored_sha1 = None
        with patch("log_hunter.image.ewf._parse_header") as parse_header:
            with self.assertRaises(ImageError):
                image._read_sections(1)
            parse_header.assert_not_called()

    def test_metadata_decompression_has_output_limit(self):
        with self.assertRaises(ImageError):
            _parse_header(zlib.compress(b"x" * (MAX_METADATA + 1)), False)

    def test_reserved_device_names_are_sanitized(self):
        for name in ("NUL.pf", "CON", "COM1.evtx", "LPT9.txt"):
            self.assertTrue(_safe(name).startswith("_"))

    def test_copy_race_never_deletes_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "file.pf")
            def collision(entry, destination):
                destination.write_bytes(b"another copy")
                raise FileExistsError(destination)
            volume = Mock()
            volume.copy_file.side_effect = collision
            result = ImageExtraction("", directory)
            self.assertIsNone(_copy(volume, None, target, "source", 0, (), result))
            self.assertEqual(target.read_bytes(), b"another copy")

    def test_forged_sparse_run_is_bounded_by_image_capacity(self):
        volume = NTFSVolume.__new__(NTFSVolume)
        volume.cluster_size, volume.offset, volume.image = 4096, 0, Mock(size=8192)
        attribute = Attribute(0x80, "", 0, True, real_size=1 << 40, initialized_size=1 << 40)
        self.assertEqual(volume._stream_sizes(attribute, [(0, None, 1 << 40)]), (8192, 8192))
