"""Bitmap observations never authorize fabricated historical snapshot bytes."""
import hashlib
import itertools
import struct
import unittest

from test_vss_catalog import header
from test_vss_volume import mapped_fixture, prepare
from log_hunter.image.ewf import ImageError
from log_hunter.image.vss import BLOCK_SIZE, read_store_bitmap


class VSSUnmappedPolicyTests(unittest.TestCase):
    def fixture(self, current, previous, forward=False):
        first = [(BLOCK_SIZE * 3, BLOCK_SIZE * 4, 0, 1, 0)] if forward else []
        image, volume, catalog = mapped_fixture(first=first, second=[])
        # The current volume deliberately contains plausible bytes at both targets.
        image.data[BLOCK_SIZE * 4:BLOCK_SIZE * 5] = b'CURRENT' * (BLOCK_SIZE // 7) + b'C' * (BLOCK_SIZE % 7)
        snapshot = catalog.snapshots[0]
        for key, number, state in (("bitmap_offset", 9, current), ("previous_bitmap_offset", 10, previous)):
            snapshot["store"][key] = 0 if state is None else BLOCK_SIZE * number
            if state is not None:
                header(image.data, BLOCK_SIZE * number, 6)
                # Test original block 3 and forwarding destination block 4 together.
                image.data[BLOCK_SIZE * number + 128] = 0x18 if state else 0
        return image, volume, catalog, snapshot

    def test_all_current_previous_bit_combinations_reject_unmapped_bytes(self):
        for current, previous, forward in itertools.product((None, False, True), (None, False, True), (False, True)):
            with self.subTest(current=current, previous=previous, forward=forward):
                image, volume, catalog, snapshot = self.fixture(current, previous, forward)
                before = hashlib.sha256(image.data).digest()
                for prior, expected in ((False, current), (True, previous)):
                    bitmap = read_store_bitmap(image, volume, snapshot, previous=prior)
                    self.assertEqual(bitmap.errors, [])
                    self.assertIs(bitmap.is_set(3), expected)
                    self.assertIs(bitmap.is_set(4), expected)
                result = prepare(image, volume, catalog)
                self.assertEqual(result.errors, [])
                self.assertFalse(result.reader.info()['reconstruction_complete'])
                image.reads.clear()
                with self.assertRaises(ImageError):
                    result.reader.read(BLOCK_SIZE * 3, 512)
                self.assertEqual(image.reads, [])
                self.assertTrue(result.reader.errors)
                self.assertEqual(hashlib.sha256(image.data).digest(), before)

    def test_corrupt_bitmap_cannot_authorize_current_volume_fallback(self):
        image, volume, catalog, snapshot = self.fixture(True, False)
        struct.pack_into('<Q', image.data, BLOCK_SIZE * 9 + 40, BLOCK_SIZE * 9)
        bitmap = read_store_bitmap(image, volume, snapshot)
        self.assertFalse(bitmap.complete)
        self.assertTrue(bitmap.errors)
        # Known prefix bits are observations, not reconstruction permission.
        self.assertTrue(bitmap.is_set(3))
        reader = prepare(image, volume, catalog).reader
        image.reads.clear()
        with self.assertRaises(ImageError):
            reader.read(BLOCK_SIZE * 3, 1)
        self.assertEqual(image.reads, [])

    def test_partly_mapped_request_does_not_read_or_return_prefix(self):
        image, volume, catalog = mapped_fixture(first=[], second=[(BLOCK_SIZE * 3, 0, BLOCK_SIZE * 10, 0, 0)])
        reader = prepare(image, volume, catalog).reader
        image.reads.clear()
        with self.assertRaises(ImageError):
            reader.read(BLOCK_SIZE * 4 - 512, 1024)
        self.assertEqual(image.reads, [])
        self.assertTrue(reader.errors[-1].locator.endswith(str(BLOCK_SIZE * 4)))
