"""원시 FILETIME과 합성 스토어 식별자로 순서 후보만 검증합니다."""
import copy
import struct
import unittest
import uuid
from unittest.mock import patch

from test_vss_catalog import MemoryImage, catalog, header
from log_hunter.image.volumes import Volume
from log_hunter.image.vss import BLOCK_SIZE, read_catalog, read_store_sequence


def sequence_fixture():
    data = catalog()
    for number in (1, 2):
        offset = BLOCK_SIZE * (number + 6)
        header(data, offset, 4)
        payload = offset + 128
        for relative, value in ((0, 10 + number), (16, 100 + number), (32, 200 + number)):
            data[payload + relative:payload + relative + 16] = uuid.UUID(int=value).bytes_le
        struct.pack_into('<IIII', data, payload + 48, 0x1d, 1, 0x2000d, 0)
        struct.pack_into('<Q', data, offset + 48, 68)
    image = MemoryImage(data)
    volume = Volume(0, 0, len(data), 'test', 'volume', 'ntfs')
    result = read_catalog(image, volume)
    image.reads.clear()
    return image, volume, result


class VSSSequenceTests(unittest.TestCase):
    def test_scattered_catalog_sorted_and_no_input_mutation(self):
        image, volume, catalog_result = sequence_fixture()
        catalog_result.snapshots.reverse()
        before = copy.deepcopy(catalog_result)
        result = read_store_sequence(image, volume, catalog_result)
        self.assertTrue(result.complete)
        self.assertFalse(result.readable)
        self.assertEqual(result.errors, [])
        self.assertEqual([s['snapshot']['store_id'] for s in result.stores],
                         [str(uuid.UUID(int=1)), str(uuid.UUID(int=2))])
        self.assertEqual(catalog_result, before)
        self.assertEqual(image.reads, [(BLOCK_SIZE*7, BLOCK_SIZE), (BLOCK_SIZE*8, BLOCK_SIZE)])
        self.assertFalse(result.to_dict()['readable'])

    def test_raw_submicrosecond_times_override_display_order(self):
        image, volume, catalog_result = sequence_fixture()
        first, second = catalog_result.snapshots
        raw = int(first['creation_filetime_raw'])
        first['creation_filetime_raw'] = str(raw + 2)
        second['creation_filetime_raw'] = str(raw + 1)
        second['created_at'] = first['created_at']
        result = read_store_sequence(image, volume, catalog_result)
        self.assertTrue(result.complete)
        self.assertEqual(result.stores[0]['snapshot']['store_id'], second['store_id'])

    def test_tie_and_duplicate_store_id_fail_before_io(self):
        for key in ('store_id', 'creation_filetime_raw'):
            image, volume, catalog_result = sequence_fixture()
            catalog_result.snapshots[1][key] = catalog_result.snapshots[0][key]
            result = read_store_sequence(image, volume, catalog_result)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(result.stores, [])
            self.assertEqual(image.reads, [])

    def test_invalid_time_and_size_fail_before_io(self):
        updates = [{'creation_filetime_raw': value} for value in
                   (None, '', '0', '-1', '１２３', '1'*1000, str(2**64))]
        updates += [{'volume_size': BLOCK_SIZE}, {'ambiguous': True}, {'catalog_complete': False}]
        for update in updates:
            with self.subTest(update=update):
                image, volume, catalog_result = sequence_fixture()
                catalog_result.snapshots[1].update(update)
                result = read_store_sequence(image, volume, catalog_result)
                self.assertFalse(result.complete)
                self.assertTrue(result.errors)
                self.assertEqual(image.reads, [])

    def test_duplicate_snapshot_id_and_corrupt_header_clear_order(self):
        for corrupt in (False, True):
            image, volume, catalog_result = sequence_fixture()
            if corrupt:
                image.data[BLOCK_SIZE*8] = 0
            else:
                image.data[BLOCK_SIZE*8 + 144:BLOCK_SIZE*8 + 160] = uuid.UUID(int=101).bytes_le
            result = read_store_sequence(image, volume, catalog_result)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(result.stores, [])

    def test_catalog_identity_errors_and_cap(self):
        image, volume, catalog_result = sequence_fixture()
        with patch('log_hunter.image.vss.MAX_CHAIN_STORES', 1):
            self.assertTrue(read_store_sequence(image, volume, catalog_result).errors)
        for update in ({'present': False}, {'volume': {}}, {'errors': ['synthetic error']}):
            candidate = copy.deepcopy(catalog_result)
            for key, value in update.items():
                setattr(candidate, key, value)
            result = read_store_sequence(image, volume, candidate)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
        self.assertEqual(image.reads, [])

    def test_empty_enabled_catalog_has_no_readable_snapshots(self):
        image, volume, catalog_result = sequence_fixture()
        catalog_result.snapshots.clear()
        result = read_store_sequence(image, volume, catalog_result)
        self.assertTrue(result.complete)
        self.assertEqual(result.stores, [])
        self.assertFalse(result.readable)
        self.assertEqual(image.reads, [])
