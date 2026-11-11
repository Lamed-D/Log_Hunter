"""합성 비트맵의 원시 비트를 읽으며 누락을 0으로 추정하지 않습니다."""
import struct
import unittest
from unittest.mock import patch
from test_vss_blocks import fixture
from test_vss_catalog import header
from log_hunter.image.vss import BLOCK_SIZE, read_store_bitmap


def bitmap_fixture():
    image,volume,snapshot=fixture(0)
    data=bytearray(image.data)
    for offset in (BLOCK_SIZE*6, BLOCK_SIZE*7):
        header(data,offset,6)
    data[BLOCK_SIZE*6+128]=0x81
    data[BLOCK_SIZE*7+128]=0x02
    image.data=data
    snapshot['store']['bitmap_offset']=BLOCK_SIZE*6
    snapshot['store']['previous_bitmap_offset']=BLOCK_SIZE*7
    return image,volume,snapshot


class VSSBitmapTests(unittest.TestCase):
    def test_current_previous_lsb_order_and_bounds(self):
        image,volume,snapshot=bitmap_fixture()
        current=read_store_bitmap(image,volume,snapshot)
        previous=read_store_bitmap(image,volume,snapshot,previous=True)
        self.assertTrue(current.complete)
        self.assertTrue(current.present)
        self.assertFalse(current.errors)
        self.assertTrue(current.is_set(0))
        self.assertTrue(current.is_set(7))
        self.assertFalse(current.is_set(1))
        self.assertTrue(previous.is_set(1))
        self.assertFalse(previous.is_set(0))
        for index in (-1,12,True,'0'):
            self.assertIsNone(current.is_set(index))
        self.assertEqual(image.reads,[(BLOCK_SIZE*6,BLOCK_SIZE),(BLOCK_SIZE*7,BLOCK_SIZE)])

    def test_absent_is_unknown_not_clear(self):
        image,volume,snapshot=bitmap_fixture()
        snapshot['store']['bitmap_offset']=0
        result=read_store_bitmap(image,volume,snapshot)
        self.assertFalse(result.complete)
        self.assertFalse(result.present)
        self.assertEqual(result.errors,[])
        self.assertIsNone(result.is_set(0))
        self.assertEqual(image.reads,[])

    def test_cycles_range_headers_and_short_reads(self):
        for position,value in ((40,BLOCK_SIZE*6),(40,123),(40,BLOCK_SIZE*12),
                               (16,99),(20,3),(32,0),(0,0)):
            with self.subTest(position=position,value=value):
                image,volume,snapshot=bitmap_fixture()
                struct.pack_into('<Q',image.data,BLOCK_SIZE*6+position,value)
                result=read_store_bitmap(image,volume,snapshot)
                self.assertFalse(result.complete)
                self.assertTrue(result.errors)
        image,volume,snapshot=bitmap_fixture()
        with patch.object(image,'read',return_value=b''):
            self.assertTrue(read_store_bitmap(image,volume,snapshot).errors)
        with patch('log_hunter.image.vss.MAX_BLOCKS',0):
            self.assertTrue(read_store_bitmap(image,volume,snapshot).errors)

    def test_chain_and_missing_coverage_preserve_known_bits(self):
        image,volume,snapshot=bitmap_fixture()
        volume.size=((BLOCK_SIZE-128)*8+1)*BLOCK_SIZE
        image.size=volume.size
        snapshot['volume_size']=volume.size
        result=read_store_bitmap(image,volume,snapshot)
        self.assertFalse(result.complete)
        self.assertTrue(result.is_set(0))
        self.assertIsNone(result.is_set((BLOCK_SIZE-128)*8))
        struct.pack_into('<Q',image.data,BLOCK_SIZE*6+40,BLOCK_SIZE*7)
        result=read_store_bitmap(image,volume,snapshot)
        self.assertTrue(result.complete)
        self.assertFalse(result.is_set((BLOCK_SIZE-128)*8))
        self.assertEqual(len(result.data),BLOCK_SIZE-128+1)

    def test_invalid_snapshot_and_memory_limit_precede_reads(self):
        for update in ({'ambiguous':True},{'catalog_complete':False},{'store':None},{'volume_size':0}):
            image,volume,snapshot=bitmap_fixture()
            result=read_store_bitmap(image,volume,{**snapshot,**update})
            self.assertTrue(result.errors)
            self.assertFalse(result.complete)
            self.assertEqual(image.reads,[])
        image,volume,snapshot=bitmap_fixture()
        volume.size=image.size=(32*1024*1024*8+1)*BLOCK_SIZE
        snapshot['volume_size']=volume.size
        result=read_store_bitmap(image,volume,snapshot)
        self.assertTrue(result.errors)
        self.assertEqual(image.reads,[])
