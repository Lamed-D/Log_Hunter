"""논리 범위를 먼저 검증한 뒤 인접 저장 범위를 한 번에 읽는지 확인합니다."""
import unittest

from test_vss_catalog import MemoryImage
from test_vss_extract import snapshot_image, STORE_ID
from test_vss_volume import mapped_fixture, prepare
from log_hunter.image.ewf import ImageError
from log_hunter.image.volumes import Volume
from log_hunter.image.vss import BLOCK_SIZE, read_catalog
from log_hunter.image.vss_volume import prepare_mapped_volume


class VSSCoalescedTests(unittest.TestCase):
    def test_contiguous_stored_blocks_use_one_physical_read(self):
        data = snapshot_image()
        image = MemoryImage(data)
        volume = Volume(0, 0, len(data), 'test', 'volume', 'ntfs')
        catalog = read_catalog(image, volume)
        result = prepare_mapped_volume(image, volume, catalog, STORE_ID)
        self.assertEqual(result.errors, [])
        image.reads.clear()
        length = BLOCK_SIZE*4
        self.assertEqual(result.reader.read(0, length), data[len(data)//2:len(data)//2 + length])
        self.assertEqual(image.reads, [(len(data)//2, length)])

    def test_unknown_tail_rejects_request_before_any_stored_read(self):
        image, volume, catalog = mapped_fixture()
        reader = prepare(image, volume, catalog).reader
        image.reads.clear()
        with self.assertRaises(ImageError):
            reader.read(BLOCK_SIZE*3, BLOCK_SIZE + 1)
        self.assertEqual(image.reads, [])

    def test_noncontiguous_overlay_ranges_stay_separate(self):
        first = [(BLOCK_SIZE*3, 0, BLOCK_SIZE*9, 0, 0),
                 (BLOCK_SIZE*3, 0, BLOCK_SIZE*11, 2, 1)]
        image, volume, catalog = mapped_fixture(first=first)
        reader = prepare(image, volume, catalog).reader
        image.reads.clear()
        self.assertEqual(reader.read(BLOCK_SIZE*3, 1024), b'O'*512 + b'A'*512)
        self.assertEqual(image.reads, [(BLOCK_SIZE*11, 512), (BLOCK_SIZE*9 + 512, 512)])
