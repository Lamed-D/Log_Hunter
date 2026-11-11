"""가짜 VSS 카탈로그만 조립하며 운영체제 스냅숏 기능은 호출하지 않습니다."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import uuid

from log_hunter.image.vss import BLOCK_SIZE, HEADER_OFFSET, SIGNATURE, list_snapshots, read_catalog
from log_hunter.image.volumes import Volume
from log_hunter.main import main


class MemoryImage:
    def __init__(self, data):
        self.data = data; self.size = len(data); self.reads = []

    def read(self, offset, length):
        if offset < 0 or offset + length > self.size:
            raise AssertionError('이미지 밖 읽기')
        self.reads.append((offset, length))
        return bytes(self.data[offset:offset + length])


def header(data, offset, kind, next_offset=0):
    data[offset:offset + 16] = SIGNATURE
    struct.pack_into('<IIQQQ', data, offset + 16, 1, kind, 0, offset, next_offset)


def catalog():
    data = bytearray(BLOCK_SIZE * 12)
    data[3:11] = b'NTFS    '
    header(data, HEADER_OFFSET, 1)
    struct.pack_into('<Q', data, HEADER_OFFSET + 24, HEADER_OFFSET)
    struct.pack_into('<Q', data, HEADER_OFFSET + 48, BLOCK_SIZE)
    header(data, BLOCK_SIZE, 2, BLOCK_SIZE * 2)
    header(data, BLOCK_SIZE * 2, 2)
    # 두 스냅숏의 위치 항목을 기본 항목보다 먼저 배치합니다.
    for number in (1, 2):
        identifier = uuid.UUID(int=number).bytes_le
        position = BLOCK_SIZE + number * 128
        struct.pack_into('<QQ', data, position, 3, BLOCK_SIZE * (number + 4))
        data[position + 16:position + 32] = identifier
        struct.pack_into('<Q', data, position + 32, BLOCK_SIZE * (number + 6))
        position = BLOCK_SIZE * 2 + number * 128
        struct.pack_into('<QQ', data, position, 2, len(data))
        data[position + 16:position + 32] = identifier
        struct.pack_into('<Q', data, position + 48, 132537600000000000 + number * 10000000)
    return data


def parse(data, prefix=0):
    image = MemoryImage(b'\0' * prefix + data)
    result = read_catalog(image, Volume(3, prefix, len(data), 'test', 'volume', 'ntfs'))
    return result, image


class VSSCatalogTests(unittest.TestCase):
    def test_two_snapshots_scattered_entries_and_partition_offset(self):
        data = catalog(); before = hashlib.sha256(data).digest()
        result, image = parse(data, 4096)
        self.assertTrue(result.present)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.snapshots), 2)
        first = result.snapshots[0]
        self.assertEqual(first['store_id'], str(uuid.UUID(int=1)))
        self.assertEqual(first['created_at'], '2020-12-30T00:00:01+00:00')
        self.assertEqual(first['time_field'], 'snapshot_creation_time')
        self.assertEqual(first['store']['store_header_offset'], BLOCK_SIZE * 7)
        self.assertTrue(first['catalog_complete'])
        self.assertFalse(first['readable'])
        self.assertTrue(all(offset >= 4096 for offset, _ in image.reads))
        self.assertEqual(hashlib.sha256(data).digest(), before)

    def test_absent_and_enabled_empty_catalog(self):
        result, _ = parse(bytearray(BLOCK_SIZE * 2))
        self.assertFalse(result.present)
        data = catalog(); struct.pack_into('<Q', data, HEADER_OFFSET + 48, 0)
        result, _ = parse(data)
        self.assertTrue(result.present)
        self.assertEqual(result.snapshots, [])
        self.assertEqual(result.errors, [])

    def test_cycle_and_bad_next_preserve_partial_entries(self):
        for next_offset in (BLOCK_SIZE, len(catalog()) + BLOCK_SIZE, 123):
            with self.subTest(next_offset=next_offset):
                data = catalog(); struct.pack_into('<Q', data, BLOCK_SIZE * 2 + 40, next_offset)
                result, _ = parse(data)
                self.assertEqual(len(result.snapshots), 2)
                self.assertTrue(result.errors)
                self.assertTrue(all(not item['catalog_complete'] for item in result.snapshots))

    def test_header_version_and_current_offsets(self):
        for position, value in ((HEADER_OFFSET + 16, 99), (HEADER_OFFSET + 24, 0),
                                (BLOCK_SIZE + 20, 99), (BLOCK_SIZE + 32, 0)):
            with self.subTest(position=position):
                data = catalog(); struct.pack_into('<I', data, position, value)
                result, _ = parse(data)
                self.assertTrue(result.errors)
                self.assertEqual(result.snapshots, [])

    def test_duplicates_missing_pair_unknown_and_invalid_time(self):
        data = catalog()
        data[BLOCK_SIZE + 3 * 128:BLOCK_SIZE + 4 * 128] = data[BLOCK_SIZE + 128:BLOCK_SIZE + 256]
        data[BLOCK_SIZE + 256:BLOCK_SIZE + 384] = b'\0' * 128
        struct.pack_into('<Q', data, BLOCK_SIZE * 2 + 256 + 48, 0)
        struct.pack_into('<Q', data, BLOCK_SIZE + 4 * 128, 99)
        result, _ = parse(data)
        self.assertEqual(len(result.snapshots), 2)
        first = next(item for item in result.snapshots if item['store_id'] == str(uuid.UUID(int=1)))
        second = next(item for item in result.snapshots if item['store_id'] == str(uuid.UUID(int=2)))
        self.assertTrue(first['ambiguous'])
        self.assertIsNone(second['store'])
        self.assertIsNone(second['created_at'])
        self.assertIsNone(second['time_field'])
        self.assertGreaterEqual(len(result.errors), 4)

    def test_out_of_bounds_store_and_warning_limit(self):
        data = catalog()
        struct.pack_into('<Q', data, BLOCK_SIZE + 128 + 32, len(data))
        result, _ = parse(data)
        self.assertTrue(result.snapshots[0]['ambiguous'])
        for block in (BLOCK_SIZE, BLOCK_SIZE * 2):
            for offset in range(128, BLOCK_SIZE, 128):
                struct.pack_into('<Q', data, block + offset, 99)
        # 추가 블록으로 진단 상한을 확인합니다.
        struct.pack_into('<Q', data, BLOCK_SIZE * 2 + 40, BLOCK_SIZE * 3)
        header(data, BLOCK_SIZE * 3, 2)
        for offset in range(128, BLOCK_SIZE, 128): struct.pack_into('<Q', data, BLOCK_SIZE * 3 + offset, 99)
        result, _ = parse(data)
        self.assertEqual(len(result.errors), 257)

    def test_cli_and_api_no_writes_or_live_access(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'synthetic.raw'; path.write_bytes(catalog())
            digest = hashlib.sha256(path.read_bytes()).digest()
            self.assertEqual(len(list_snapshots(path)[0]['snapshots']), 2)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['snapshots', str(path)]), 0)
            self.assertEqual(len(json.loads(output.getvalue())[0]['snapshots']), 2)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), digest)
            self.assertEqual(len(list(Path(folder).iterdir())), 1)
        with self.assertRaises(ValueError): list_snapshots(r'\\.\C:')
