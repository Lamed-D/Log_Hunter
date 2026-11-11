"""합성 스토어 블록 기술자만 읽으며 저장 데이터 내용은 열지 않습니다."""
import hashlib
import struct
import unittest
from unittest.mock import patch
from test_vss_catalog import MemoryImage, catalog, header
from log_hunter.image.volumes import Volume
from log_hunter.image.vss import BLOCK_SIZE, read_catalog, read_block_list


def fixture(prefix=4096):
    data = catalog()
    offset = BLOCK_SIZE * 5
    header(data, offset, 3)
    entries = [(0, 0, BLOCK_SIZE*9, 0, 0),
               (BLOCK_SIZE, 0, BLOCK_SIZE*10, 2, 0x80000001),
               (BLOCK_SIZE*2, BLOCK_SIZE*3, 0, 1, 0),
               (0xffffffffffffffff, 0, 0, 4, 0)]
    for i, entry in enumerate(entries):
        struct.pack_into('<QQQII', data, offset + 128 + i*32, *entry)
    image = MemoryImage(bytes(prefix) + data)
    volume = Volume(3, prefix, len(data), 'test', 'volume', 'ntfs')
    snapshot = read_catalog(image, volume).snapshots[0]
    image.reads.clear()
    return image, volume, snapshot


class VSSBlockListTests(unittest.TestCase):
    def test_order_raw_flags_and_only_metadata_reads(self):
        image, volume, snapshot = fixture()
        before = hashlib.sha256(image.data).digest()
        result = read_block_list(image, volume, snapshot)
        self.assertTrue(result.complete)
        self.assertFalse(result.readable)
        self.assertFalse(result.errors)
        self.assertEqual([d['kind'] for d in result.descriptors], ['plain', 'overlay', 'forwarder', 'unused'])
        self.assertEqual(result.descriptors[1]['allocation_bitmap'], 0x80000001)
        self.assertEqual(image.reads, [(4096 + BLOCK_SIZE*5, BLOCK_SIZE)])
        self.assertEqual(hashlib.sha256(image.data).digest(), before)
        self.assertFalse(result.to_dict()['readable'])

    def test_cycle_and_bad_next_preserve_descriptors(self):
        for next_offset in (BLOCK_SIZE*5, 123, BLOCK_SIZE*12):
            image, volume, snapshot = fixture(0)
            data=bytearray(image.data)
            struct.pack_into('<Q', data, BLOCK_SIZE*5+40, next_offset)
            image.data=data
            result=read_block_list(image,volume,snapshot)
            self.assertFalse(result.complete)
            self.assertEqual(len(result.descriptors),4)
            self.assertTrue(result.errors)
            self.assertTrue(all(o+n<=image.size for o,n in image.reads))

    def test_bad_descriptors_and_unknown_flags_are_not_applied(self):
        cases = [(1,0,BLOCK_SIZE*9,0,0), (BLOCK_SIZE*12,0,BLOCK_SIZE*9,0,0),
                 (0,0,BLOCK_SIZE*12,0,0), (0,0,123,0,0),
                 (0,0,BLOCK_SIZE*9,8,0), (0,0,BLOCK_SIZE*9,3,1),
                 (0,0,BLOCK_SIZE*9,0,1), (0,1,0,1,0), (0,0,512,1,0)]
        for entry in cases:
            with self.subTest(entry=entry):
                image,volume,snapshot=fixture(0)
                data=bytearray(image.data)
                struct.pack_into('<QQQII',data,BLOCK_SIZE*5+128,*entry)
                image.data=data
                result=read_block_list(image,volume,snapshot)
                self.assertFalse(result.descriptors[0]['valid'])
                self.assertFalse(result.complete)
                self.assertFalse(result.readable)
                self.assertTrue(result.errors)

    def test_incomplete_catalog_and_invalid_volume_do_not_read(self):
        for update in ({'catalog_complete':False},{'ambiguous':True},{'store':None},
                       {'volume_size':0},{'store':{'block_list_offset':-512}}):
            image,volume,snapshot=fixture()
            result=read_block_list(image,volume,{**snapshot,**update})
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(image.reads,[])
        image,volume,snapshot=fixture()
        volume.size+=1
        self.assertTrue(read_block_list(image,volume,snapshot).errors)
        self.assertEqual(image.reads,[])

    def test_bad_headers_and_short_read(self):
        for position,value in ((0,0),(16,99),(20,2),(32,0)):
            image,volume,snapshot=fixture(0)
            data=bytearray(image.data)
            struct.pack_into('<I',data,BLOCK_SIZE*5+position,value)
            image.data=data
            result=read_block_list(image,volume,snapshot)
            self.assertFalse(result.complete)
            self.assertEqual(result.descriptors,[])
            self.assertTrue(result.errors)
        image,volume,snapshot=fixture()
        with patch.object(image,'read',return_value=b''):
            self.assertTrue(read_block_list(image,volume,snapshot).errors)

    def test_chain_and_descriptor_limits(self):
        image,volume,snapshot=fixture(0)
        with patch('log_hunter.image.vss.MAX_BLOCK_DESCRIPTORS',2):
            result=read_block_list(image,volume,snapshot)
        self.assertEqual(len(result.descriptors),2)
        self.assertFalse(result.complete)
        with patch('log_hunter.image.vss.MAX_BLOCKS',0):
            self.assertTrue(read_block_list(image,volume,snapshot).errors)

    def test_empty_list_is_metadata_only(self):
        image,volume,snapshot=fixture()
        snapshot['store']['block_list_offset']=0
        result=read_block_list(image,volume,snapshot)
        self.assertTrue(result.complete)
        self.assertFalse(result.readable)
        self.assertEqual(result.descriptors,[])
        self.assertEqual(image.reads,[])

    def test_linked_blocks_and_diagnostic_cap(self):
        image,volume,snapshot=fixture(0)
        data=bytearray(image.data)
        struct.pack_into('<Q',data,BLOCK_SIZE*5+40,BLOCK_SIZE*6)
        header(data,BLOCK_SIZE*6,3)
        struct.pack_into('<QQQII',data,BLOCK_SIZE*6+128,BLOCK_SIZE*4,0,BLOCK_SIZE*11,0,0)
        image.data=data
        result=read_block_list(image,volume,snapshot)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.descriptors),5)
        self.assertEqual(image.reads,[(BLOCK_SIZE*5,BLOCK_SIZE),(BLOCK_SIZE*6,BLOCK_SIZE)])
        for pos in range(128,BLOCK_SIZE,32):
            struct.pack_into('<QQQII',data,BLOCK_SIZE*5+pos,1,0,0,0,0)
        result=read_block_list(image,volume,snapshot)
        self.assertFalse(result.complete)
        self.assertEqual(len(result.errors),257)
        self.assertEqual(len(result.descriptors),509)
