import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from log_hunter.image.ewf import EWFImage, ImageError, MAX_METADATA
from test_image import _section, write_e01


class OptionalHeaderTests(unittest.TestCase):
    def make_image(self, path, body):
        disk = b'synthetic sector'.ljust(512, b'\0')
        write_e01(path, disk, segments=1)
        raw = bytearray(path.read_bytes())
        first_next, first_size = struct.unpack_from('<QQ', raw, 29)
        raw[13:89] = _section('unused', first_next, first_size)
        start = len(raw) - 76
        size = 76 + len(body)
        raw[start:] = _section('header2', start + size, size) + body + _section('done', start + size, 76)
        path.write_bytes(raw)
        return disk

    def test_optional_header_damage_warns_but_disk_is_readable(self):
        compressed = zlib.compress('1\nmain\nc\nCASE-7\n'.encode('utf-16'))
        for body in (b'not compressed', compressed[:-2],
                     zlib.compress(b'x' * (MAX_METADATA + 1)), b'x' * (MAX_METADATA + 1)):
            with self.subTest(length=len(body)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory, 'synthetic.E01')
                disk = self.make_image(path, body)
                before = hashlib.sha256(path.read_bytes()).digest()
                with EWFImage(path) as image:
                    self.assertEqual(image.read(0, len(disk)), disk)
                    self.assertEqual(image.metadata, {})
                    self.assertTrue(any('header2' in warning for warning in image.integrity_warnings))
                self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_volume_damage_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'synthetic.E01')
            self.make_image(path, b'bad optional header')
            raw = bytearray(path.read_bytes())
            volume = struct.unpack_from('<Q', raw, 29)[0]
            raw[volume + 76:volume + 100] = bytes(24)
            path.write_bytes(raw)
            with self.assertRaises(ImageError):
                EWFImage(path)
