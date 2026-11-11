"""스토어 헤더를 가짜 바이트로 생성하며 스냅숏 API를 호출하지 않습니다."""
import hashlib
import struct
import unittest
import uuid
from unittest.mock import patch

from test_vss_blocks import fixture
from test_vss_catalog import header
from log_hunter.image.vss import BLOCK_SIZE, read_store_header


def store_fixture(prefix=4096, declared=True):
    image, volume, snapshot = fixture(prefix)
    data = bytearray(image.data)
    offset = snapshot['store']['store_header_offset']
    physical = prefix + offset
    header(data, physical, 4)
    struct.pack_into('<Q', data, physical + 32, offset)
    payload = bytearray(64)
    for position, number in ((0, 100), (16, 101), (32, 102)):
        payload[position:position + 16] = uuid.UUID(int=number).bytes_le
    struct.pack_into('<IIII', payload, 48, 0x1d, 1, 0x2000d, 0)
    for name in ('DESKTOP-TEST01', 'WORKSTATION-01'):
        encoded = name.encode('utf-16-le')
        payload.extend(struct.pack('<H', len(encoded)) + encoded)
    struct.pack_into('<Q', data, physical + 48, len(payload) if declared else 0)
    data[physical + 128:physical + 128 + len(payload)] = payload
    image.data = data
    image.reads.clear()
    return image, volume, snapshot


class VSSStoreHeaderTests(unittest.TestCase):
    def test_identity_is_not_catalog_id_and_no_content_reads(self):
        image, volume, snapshot = store_fixture()
        before = hashlib.sha256(image.data).digest()
        result = read_store_header(image, volume, snapshot)
        self.assertTrue(result.complete)
        self.assertFalse(result.readable)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.store_id, str(uuid.UUID(int=1)))
        self.assertEqual(result.metadata['snapshot_id'], str(uuid.UUID(int=101)))
        self.assertEqual(result.metadata['snapshot_set_id'], str(uuid.UUID(int=102)))
        self.assertEqual(result.metadata['identifier_raw'], str(uuid.UUID(int=100)))
        self.assertEqual(result.metadata['attributes_raw'], 0x2000d)
        self.assertEqual(result.metadata['operating_machine'], 'DESKTOP-TEST01')
        self.assertEqual(result.metadata['service_machine'], 'WORKSTATION-01')
        self.assertEqual(image.reads, [(4096 + BLOCK_SIZE*7, BLOCK_SIZE)])
        self.assertEqual(before, hashlib.sha256(image.data).digest())
        self.assertFalse(result.to_dict()['readable'])

    def test_zero_declaration_and_unknown_values_preserved(self):
        image, volume, snapshot = store_fixture(0, declared=False)
        struct.pack_into('<IIII', image.data, BLOCK_SIZE*7 + 128 + 48,
                         0xffffffff, 0xfffffffe, 0xffffffff, 123)
        result = read_store_header(image, volume, snapshot)
        self.assertTrue(result.complete)
        self.assertEqual(result.metadata['information_size_raw'], 0)
        self.assertEqual(result.metadata['provider_raw'], 0xfffffffe)
        self.assertEqual(result.metadata['reserved_raw'], 123)

    def test_bad_headers_size_and_unsupported_chain(self):
        for position, value in ((0, 0), (16, 2), (20, 3), (32, 0),
                                (40, BLOCK_SIZE*7), (48, 67), (48, BLOCK_SIZE)):
            with self.subTest(position=position, value=value):
                image, volume, snapshot = store_fixture(0)
                struct.pack_into('<Q', image.data, BLOCK_SIZE*7 + position, value)
                result = read_store_header(image, volume, snapshot)
                self.assertFalse(result.complete)
                self.assertTrue(result.errors)
                self.assertEqual(len(image.reads), 1)

    def test_strings_cannot_escape_declared_or_physical_bounds(self):
        for declared, length in ((True, 1), (True, 0xfffe), (False, 0xfffe)):
            image, volume, snapshot = store_fixture(0, declared)
            struct.pack_into('<H', image.data, BLOCK_SIZE*7 + 192, length)
            result = read_store_header(image, volume, snapshot)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
        image, volume, snapshot = store_fixture(0)
        # First name consumes the second length field inside a shorter declaration.
        struct.pack_into('<Q', image.data, BLOCK_SIZE*7 + 48, 68)
        struct.pack_into('<H', image.data, BLOCK_SIZE*7 + 192, 2)
        self.assertTrue(read_store_header(image, volume, snapshot).errors)

    def test_invalid_utf16_and_empty_snapshot_id_are_not_complete(self):
        for position, replacement in ((194, b'\x00\xd8'), (144, bytes(16)), (160, bytes(16))):
            image, volume, snapshot = store_fixture(0)
            image.data[BLOCK_SIZE*7 + position:BLOCK_SIZE*7 + position + len(replacement)] = replacement
            result = read_store_header(image, volume, snapshot)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)

    def test_invalid_catalog_or_offsets_precede_io(self):
        updates = [{'ambiguous': True}, {'catalog_complete': False}, {'store': None}]
        updates.extend({'store': {'store_header_offset': value}}
                       for value in (0, -512, 123, True, '0', BLOCK_SIZE*12))
        for update in updates:
            image, volume, snapshot = store_fixture()
            result = read_store_header(image, volume, {**snapshot, **update})
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(image.reads, [])

    def test_short_read_and_image_error_are_diagnostics(self):
        image, volume, snapshot = store_fixture()
        with patch.object(image, 'read', return_value=b''):
            self.assertTrue(read_store_header(image, volume, snapshot).errors)
        with patch.object(image, 'read', side_effect=OSError('synthetic I/O error')):
            result = read_store_header(image, volume, snapshot)
            self.assertFalse(result.complete)
            self.assertEqual(len(result.errors), 1)
