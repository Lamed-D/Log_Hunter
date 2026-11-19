"""Synthetic block and single-file cache layouts."""
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.pipeline import Pipeline
from log_hunter.parser.cache import BLOCK_MAGIC, INDEX_MAGIC, SIMPLE_END, SIMPLE_START, CacheParser
from test_image import NTFSBuilder


def simple_record(key, metadata, body=b''):
    header = struct.pack('<QIIII', SIMPLE_START, 5, len(key), 0, 0)
    data_end = struct.pack('<QIIII', SIMPLE_END, 0, 0, 0, 0)
    meta_end = struct.pack('<QIIII', SIMPLE_END, 3, zlib.crc32(metadata), len(metadata), 0)
    return header + key + body + data_end + metadata + hashlib.sha256(key).digest() + meta_end


class BrowserCacheTests(unittest.TestCase):
    def test_simple_cache_auto_detection_and_http_stream_offsets(self):
        key = b'https://example.com/synthetic'
        metadata = b'\x00' * 12 + b'HTTP/1.1 200 OK\0Content-Type: text/plain\0Set-Cookie: marker\0\0'
        body = b'example body'
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            entry = cache / '0123456789abcdef_0'
            entry.write_bytes(simple_record(key, metadata, body))
            (cache / 'fedcba9876543210_0').write_bytes(b'broken')
            self.assertEqual([(row[0], row[1]) for row in detect_inputs([cache, entry])],
                             [('cache', str(cache))])
            record, status = list(CacheParser().parse(cache))
        self.assertEqual(record.url, key.decode())
        self.assertEqual(record.details['http_content_type'], 'text/plain')
        self.assertNotIn('http_set_cookie', record.details)
        self.assertEqual(record.details['metadata_offset'], 48 + len(key) + len(body))
        self.assertEqual(record.details['body_length'], len(body))
        self.assertEqual(status.details['cache_status'], 'partial')
        self.assertEqual(status.details['cache_entry_count'], 1)

    def test_blockfile_reads_external_long_key_and_tracks_entry_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            key = b'https://example.com/' + b'a' * 1100
            index = bytearray(372)
            struct.pack_into('<III', index, 0, INDEX_MAGIC, 0x30000, 1)
            struct.pack_into('<I', index, 28, 1)
            struct.pack_into('<I', index, 368, 0xa0010000)
            (cache / 'index').write_bytes(index)
            data = bytearray(8192 + 256)
            struct.pack_into('<I', data, 0, BLOCK_MAGIC)
            struct.pack_into('<IIIiiiQII', data, 8192, 42, 0, 0, 1, 0, 0, 0, len(key), 0x80000001)
            (cache / 'data_1').write_bytes(data)
            (cache / 'f_000001').write_bytes(key + b'\0')
            record, status = list(CacheParser().parse(cache))
        self.assertEqual(record.url, key.decode())
        self.assertEqual(record.details['entry_offset'], 8192)
        self.assertEqual(record.details['long_key_address'], 0x80000001)
        self.assertEqual(status.details['cache_status'], 'parsed')

    def test_image_analyzes_cache_folders_and_empty_profile_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ntfs = NTFSBuilder()
            chrome = 'Users/alice/AppData/Local/Google/Chrome/User Data/Default'
            edge = 'Users/alice/AppData/Local/Microsoft/Edge/User Data/Default'
            js = ntfs.makedirs(chrome + '/Code Cache/js')
            ntfs.add_file(js, '0123456789abcdef_0', simple_record(b'https://example.com/js', b''))
            ntfs.makedirs(edge + '/Cache')
            image = root / 'synthetic.dd'
            image.write_bytes(ntfs.build())
            result = Pipeline().analyze_image(image, root / 'work')
        entries = [row for row in result.events if row.action == 'cache_entry']
        statuses = [row for row in result.events if row.action == 'cache_folder_status']
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].details['source_path'].endswith('Code Cache\\js\\0123456789abcdef_0'))
        self.assertEqual({row.details['cache_status'] for row in statuses}, {'parsed', 'no_files'})
        self.assertTrue(all(row.details.get('source_path') for row in statuses))
