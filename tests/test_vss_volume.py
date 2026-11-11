"""합성 두 스토어에서 확인된 저장 바이트만 읽는 부분 뷰 테스트입니다."""
import hashlib
import struct
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from test_vss_catalog import MemoryImage, header
from test_vss_sequence import sequence_fixture
from test_image import NTFSBuilder
from log_hunter.image.ewf import ImageError
from log_hunter.image.ntfs import NTFSVolume
from log_hunter.image.vss import BLOCK_SIZE, read_catalog
from log_hunter.image.vss_volume import prepare_mapped_volume


def mapped_fixture(prefix=0, first=None, second=None):
    image, volume, _ = sequence_fixture()
    data = image.data
    for offset, entries in ((BLOCK_SIZE*5, first), (BLOCK_SIZE*6, second)):
        header(data, offset, 3)
        if entries is None:
            entries = [(BLOCK_SIZE*3, 0, BLOCK_SIZE*(9 if offset == BLOCK_SIZE*5 else 10), 0, 0)]
        for index, entry in enumerate(entries):
            struct.pack_into('<QQQII', data, offset + 128 + index*32, *entry)
    for number, value in ((3, b'C'), (9, b'A'), (10, b'B'), (11, b'O')):
        data[BLOCK_SIZE*number:BLOCK_SIZE*(number+1)] = value*BLOCK_SIZE
    image = MemoryImage(bytearray(prefix) + data)
    volume.offset = prefix
    catalog = read_catalog(image, volume)
    image.reads.clear()
    return image, volume, catalog


def prepare(image, volume, catalog, number=1):
    return prepare_mapped_volume(image, volume, catalog, str(uuid.UUID(int=number)), 'synthetic-image')


class VSSMappedVolumeTests(unittest.TestCase):
    def test_two_snapshots_read_different_stored_bytes_and_preserve_source(self):
        image, volume, catalog = mapped_fixture(4096)
        before = hashlib.sha256(image.data).digest()
        older = prepare(image, volume, catalog)
        newer = prepare(image, volume, catalog, 2)
        self.assertEqual(older.errors, [])
        self.assertEqual(newer.errors, [])
        self.assertEqual(older.reader.read(BLOCK_SIZE*3 + 7, 1027), b'A'*1027)
        self.assertEqual(newer.reader.read(BLOCK_SIZE*3 + 7, 1027), b'B'*1027)
        self.assertEqual(older.reader.origin['snapshot_id'], str(uuid.UUID(int=101)))
        self.assertEqual(older.reader.origin['store_id'], str(uuid.UUID(int=1)))
        self.assertEqual(older.reader.origin['time_field'], 'snapshot_creation_time')
        self.assertFalse(older.reader.info()['reconstruction_complete'])
        older.reader.close()
        self.assertEqual(newer.reader.read(BLOCK_SIZE*3, 1), b'B')
        self.assertEqual(before, hashlib.sha256(image.data).digest())

    def test_unmapped_is_error_instead_of_current_or_zero(self):
        image, volume, catalog = mapped_fixture(first=[])
        result = prepare(image, volume, catalog)
        # A missing descriptor is looked up only in later validated stores.
        self.assertEqual(result.reader.read(BLOCK_SIZE*3, 1), b'B')
        image.reads.clear()
        with self.assertRaises(ImageError):
            result.reader.read(BLOCK_SIZE*4, 1)
        self.assertEqual(image.reads, [])
        self.assertEqual(len(result.reader.errors), 1)
        self.assertEqual(result.reader.errors[0].artifact, 'vss')

    def test_active_overlay_sector_bits_and_plain_fallback(self):
        first = [(BLOCK_SIZE*3, 0, BLOCK_SIZE*9, 0, 0),
                 (BLOCK_SIZE*3, 0, BLOCK_SIZE*11, 2, 0x80000001)]
        image, volume, catalog = mapped_fixture(first=first)
        reader = prepare(image, volume, catalog).reader
        self.assertEqual(reader.read(BLOCK_SIZE*3 + 500, 24), b'O'*12 + b'A'*12)
        self.assertEqual(reader.read(BLOCK_SIZE*4 - 10, 10), b'O'*10)

    def test_overlay_continuation_reads_only_combined_selected_sectors(self):
        first = [(BLOCK_SIZE*3, 0, BLOCK_SIZE*9, 0, 0),
                 (BLOCK_SIZE*3, 0, BLOCK_SIZE*11, 2, 1),
                 (BLOCK_SIZE*3, 1, BLOCK_SIZE*11, 2, 0x80000002)]
        image, volume, catalog = mapped_fixture(first=first)
        before = hashlib.sha256(image.data).digest()
        result = prepare(image, volume, catalog)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.reader.read(BLOCK_SIZE*3 + 500, 536), b'O'*524 + b'A'*12)
        self.assertEqual(result.reader.read(BLOCK_SIZE*4 - 512, 512), b'O'*512)
        self.assertFalse(result.reader.info()['reconstruction_complete'])
        self.assertEqual(hashlib.sha256(image.data).digest(), before)

    def test_later_overlay_is_not_applied_to_older_snapshot(self):
        second = [(BLOCK_SIZE*3, 0, BLOCK_SIZE*10, 0, 0),
                  (BLOCK_SIZE*3, 0, BLOCK_SIZE*11, 2, 1)]
        image, volume, catalog = mapped_fixture(first=[], second=second)
        self.assertEqual(prepare(image, volume, catalog).reader.read(BLOCK_SIZE*3, 10), b'B'*10)
        self.assertEqual(prepare(image, volume, catalog, 2).reader.read(BLOCK_SIZE*3, 10), b'O'*10)

    def test_forwarder_resolves_in_next_store_and_last_forwarder_is_unknown(self):
        first = [(BLOCK_SIZE*3, BLOCK_SIZE*4, 0, 1, 0)]
        second = [(BLOCK_SIZE*4, 0, BLOCK_SIZE*10, 0, 0)]
        image, volume, catalog = mapped_fixture(first=first, second=second)
        self.assertEqual(prepare(image, volume, catalog).reader.read(BLOCK_SIZE*3 + 17, 42), b'B'*42)
        image, volume, catalog = mapped_fixture(first=[], second=first)
        with self.assertRaises(ImageError):
            prepare(image, volume, catalog, 2).reader.read(BLOCK_SIZE*3, 1)

    def test_partial_overlay_and_cross_block_unmapped_returns_no_partial_bytes(self):
        first = [(BLOCK_SIZE*3, 0, BLOCK_SIZE*11, 2, 1)]
        image, volume, catalog = mapped_fixture(first=first, second=[])
        reader = prepare(image, volume, catalog).reader
        self.assertEqual(reader.read(BLOCK_SIZE*3, 512), b'O'*512)
        with self.assertRaises(ImageError):
            reader.read(BLOCK_SIZE*3, 513)
        with self.assertRaises(ImageError):
            reader.read(BLOCK_SIZE*4 - 1, 2)

    def test_read_bounds_short_io_and_resolution_budget(self):
        image, volume, catalog = mapped_fixture()
        reader = prepare(image, volume, catalog).reader
        for offset, length in ((-1, 1), (0, -1), (reader.size, 1), (True, 1), (0, '1')):
            with self.assertRaises(ImageError):
                reader.read(offset, length)
        self.assertEqual(reader.read(reader.size, 0), b'')
        with patch('log_hunter.image.vss_volume.MAX_READ', 1):
            with self.assertRaises(ImageError):
                reader.read(BLOCK_SIZE*3, 2)
        with patch.object(image, 'read', return_value=b''):
            with self.assertRaises(ImageError):
                reader.read(BLOCK_SIZE*3, 1)
        with patch.object(image, 'read', side_effect=OSError('synthetic I/O error')):
            with self.assertRaises(ImageError):
                reader.read(BLOCK_SIZE*3, 1)
        with patch('log_hunter.image.vss_volume.MAX_RESOLUTION_STEPS', 0):
            with self.assertRaises(ImageError):
                reader.read(BLOCK_SIZE*3, 1)
        image.size = BLOCK_SIZE*9
        with self.assertRaises(ImageError):
            reader.read(BLOCK_SIZE*3, 1)

    def test_corrupt_metadata_missing_store_and_total_cap_disable_reader(self):
        image, volume, catalog = mapped_fixture()
        self.assertIsNone(prepare(image, volume, catalog, 999).reader)
        with patch('log_hunter.image.vss_volume.MAX_BLOCK_DESCRIPTORS', 1):
            result = prepare(image, volume, catalog)
            self.assertIsNone(result.reader)
            self.assertTrue(result.errors)
        struct.pack_into('<I', image.data, BLOCK_SIZE*5 + 20, 6)
        result = prepare(image, volume, catalog)
        self.assertIsNone(result.reader)
        self.assertTrue(result.errors)

    def test_many_read_failures_have_bounded_diagnostics(self):
        image, volume, catalog = mapped_fixture()
        reader = prepare(image, volume, catalog).reader
        for _ in range(300):
            with self.assertRaises(ImageError):
                reader.read(0, 1)
        self.assertEqual(len(reader.errors), 256)

    def test_sequential_forward_rewrite_reads_original_owners_stored_content(self):
        first = [(BLOCK_SIZE*3, BLOCK_SIZE*4, 0, 1, 0),
                 (BLOCK_SIZE*4, 0, BLOCK_SIZE*9, 0, 0)]
        image, volume, catalog = mapped_fixture(first=first, second=[])
        result = prepare(image, volume, catalog)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.reader.read(BLOCK_SIZE*3 + 17, 42), b'A'*42)
        with self.assertRaises(ImageError):
            result.reader.read(BLOCK_SIZE*4, 1)

    def test_existing_ntfs_reader_lists_and_copies_from_fully_mapped_synthetic_volume(self):
        builder = NTFSBuilder()
        parent = builder.makedirs('Users/alice/Documents')
        content = b'synthetic snapshot content\n'
        builder.add_file(parent, 'snapshot.txt', content)
        old = builder.build()
        image, volume, _ = sequence_fixture()
        data = bytearray(len(old)*2)
        data[:len(image.data)] = image.data
        data[len(old):] = old
        for number in (1, 2):
            struct.pack_into('<Q', data, BLOCK_SIZE*2 + number*128 + 8, len(old))
        for offset in (BLOCK_SIZE*5, BLOCK_SIZE*6):
            header(data, offset, 3)
        for index, offset in enumerate(range(0, len(old), BLOCK_SIZE)):
            struct.pack_into('<QQQII', data, BLOCK_SIZE*5 + 128 + index*32,
                             offset, 0, len(old) + offset, 0, 0)
        image = MemoryImage(data)
        volume.size = len(data)
        catalog = read_catalog(image, volume)
        before = hashlib.sha256(data).digest()
        result = prepare(image, volume, catalog)
        self.assertEqual(result.errors, [])
        ntfs = NTFSVolume(result.reader, 0)
        entry = ntfs.lookup('Users/alice/Documents/snapshot.txt')
        self.assertIsNotNone(entry)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'snapshot.txt'
            info = ntfs.copy_file(entry, destination)
            self.assertEqual(destination.read_bytes(), content)
            self.assertEqual(info['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(before, hashlib.sha256(data).digest())
