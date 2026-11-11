import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from log_hunter.parser.thumbcache import LAYOUTS, ThumbcacheParser


def synthetic_png():
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\0\xff\0\0')) + chunk(b'IEND', b''))


def synthetic_bmp():
    return struct.pack('<2sIHHI', b'BM', 58, 0, 0, 54) + struct.pack(
        '<IiiHHIIiiII', 40, 1, 1, 1, 24, 0, 4, 0, 0, 0, 0) + b'\0\0\xff\0'


def cache_entry(version, data, cache_id=1, identifier='synthetic', padding=4):
    header_size = LAYOUTS[version][2]
    identifier = identifier.encode('utf-16-le')
    raw = bytearray(header_size)
    struct.pack_into('<4sIQIII', raw, 0, b'CMMM', header_size + len(identifier) + padding + len(data),
                     cache_id, len(identifier), padding, len(data))
    struct.pack_into('<QQ', raw, header_size - 16, 0x1234, 0x5678)
    return bytes(raw) + identifier + bytes(padding) + data


def cache_file(version=32, entries=None):
    entries = [cache_entry(version, synthetic_png())] if entries is None else entries
    header_size, pointer, _ = LAYOUTS[version]
    raw = bytearray(header_size)
    struct.pack_into('<4sII', raw, 0, b'CMMM', version, 4)
    struct.pack_into('<II', raw, pointer, header_size, header_size + sum(map(len, entries)))
    return bytes(raw) + b''.join(entries)


class ThumbcacheTests(unittest.TestCase):
    def parse(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'thumbcache_256.db')
            path.write_bytes(data)
            before = hashlib.sha256(data).hexdigest()
            parser = ThumbcacheParser(sid='S-1-5-21-1000-2000-3000-1001')
            events = list(parser.parse(path))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
            self.assertEqual(list(Path(directory).iterdir()), [path])
            return events, parser.errors

    def test_supported_versions_png_metadata_and_unknown_path_time(self):
        for version in LAYOUTS:
            with self.subTest(version=version):
                events, errors = self.parse(cache_file(version))
                self.assertFalse(errors)
                event, = events
                self.assertIsNone(event.path)
                self.assertIsNone(event.timestamp)
                self.assertIsNone(event.time_field)
                self.assertEqual(event.details['cache_id'], '0000000000000001')
                self.assertEqual(event.details['image_sha256'], hashlib.sha256(synthetic_png()).hexdigest())
                self.assertEqual(event.details['image_format'], 'png')
                self.assertEqual(event.details['data_size'], len(synthetic_png()))
                self.assertFalse(event.details['checksum_verified'])
                self.assertFalse(event.details['view_confirmed'])

    def test_bmp_jpeg_signature_unknown_and_empty(self):
        payloads = [synthetic_bmp(), b'\xff\xd8\xffsynthetic\xff\xd9', b'unknown', b'']
        events, errors = self.parse(cache_file(entries=[cache_entry(32, data, i + 1) for i, data in enumerate(payloads)]))
        self.assertFalse(errors)
        self.assertEqual([e.details['image_format'] for e in events], ['bmp', 'jpeg', 'unknown', 'empty'])
        self.assertIsNone(events[-1].details['image_sha256'])

    def test_bad_identifier_length_skips_framed_record_and_continues(self):
        bad = bytearray(cache_entry(32, b'bad'))
        struct.pack_into('<I', bad, 16, 3)
        events, errors = self.parse(cache_file(entries=[bytes(bad), cache_entry(32, synthetic_png(), 2)]))
        self.assertEqual(len(errors), 1)
        self.assertEqual([e.details['cache_id'] for e in events], ['0000000000000002'])

    def test_truncated_entries_unknown_version_and_index_warn(self):
        for data in (b'', b'CMMM', b'IMMM' + bytes(24), b'\0' * 4 + b'IMMM' + bytes(24),
                     cache_file()[:-5], b'CMMM' + struct.pack('<II', 99, 0)):
            with self.subTest(length=len(data)):
                events, errors = self.parse(data)
                self.assertFalse(events)
                self.assertTrue(errors)

    def test_free_tail_is_not_reported_and_pointers_are_bounded(self):
        data = cache_file()
        events, errors = self.parse(data + cache_entry(32, synthetic_png(), 2))
        self.assertEqual(len(events), 1)
        self.assertEqual([error.severity for error in errors], ['info'])
        for first, available in ((1, len(data)), (len(data) + 1, len(data)), (24, 1), (24, len(data) + 1)):
            bad = bytearray(data)
            struct.pack_into('<II', bad, 16, first, available)
            self.assertTrue(self.parse(bad)[1])

    def test_zero_huge_sizes_and_payload_overflow_are_bounded(self):
        for field, value in ((4, 0), (4, 0xffffffff), (16, 0xfffffffe),
                             (20, 0xffffffff), (24, 0xffffffff)):
            bad = bytearray(cache_entry(32, synthetic_png()))
            struct.pack_into('<I', bad, field, value)
            events, errors = self.parse(cache_file(entries=[bytes(bad)]))
            self.assertFalse(events)
            self.assertTrue(errors)

    def test_directory_batch_continues_after_bad_file_and_caps_file_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'thumbcache_bad.db').write_bytes(b'bad')
            (root / 'thumbcache_256.db').write_bytes(cache_file())
            parser = ThumbcacheParser()
            self.assertEqual(len(list(parser.parse(root))), 1)
            self.assertTrue(parser.errors)
            with patch('log_hunter.parser.thumbcache.MAX_FILES', 1):
                parser = ThumbcacheParser()
                list(parser.parse(root))
                self.assertTrue(any(error.locator == 'files' for error in parser.errors))

    def test_hash_and_record_limits_never_return_partial_hash_as_complete(self):
        data = cache_file(entries=[cache_entry(32, synthetic_png(), i + 1) for i in range(3)])
        with patch('log_hunter.parser.thumbcache.MAX_DATA_HASH', 1):
            events, errors = self.parse(data)
        self.assertEqual(len(events), 3)
        self.assertTrue(errors)
        self.assertTrue(all(e.details['image_sha256'] is None and e.status == 'partial' for e in events))
        with patch('log_hunter.parser.thumbcache.MAX_ENTRIES', 1):
            events, errors = self.parse(data)
        self.assertEqual(len(events), 1)
        self.assertTrue(errors)

    def test_identifier_error_and_hash_limit_both_survive(self):
        raw = bytearray(cache_entry(32, synthetic_png(), identifier='x'))
        raw[56:58] = b'\x00\xd8'
        struct.pack_into('<II', raw, 28, 1, 2)
        with patch('log_hunter.parser.thumbcache.MAX_DATA_HASH', 1):
            events, errors = self.parse(cache_file(entries=[bytes(raw)]))
        event, = events
        self.assertEqual(event.status, 'partial')
        self.assertTrue(event.details['identifier_decode_error'])
        self.assertEqual(event.details['image_hash_status'], 'limit')
        self.assertEqual((event.details['entry_aux_28'], event.details['entry_aux_32']), (1, 2))
        self.assertEqual(len(errors), 2)

    def test_large_payload_hash_is_streamed(self):
        payload = b'BM' + bytes(200000)
        data = cache_file(entries=[cache_entry(32, payload)])
        original = Path.open
        reads = []
        class Stream:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def seek(self, *args): return self.stream.seek(*args)
            def read(self, length):
                reads.append(length)
                if length < 0 or length > 65536:
                    raise AssertionError('unbounded read')
                return self.stream.read(length)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'thumbcache_256.db')
            path.write_bytes(data)
            with patch.object(Path, 'open', lambda p, mode='r', **kwargs: Stream(original(p, mode, **kwargs))):
                event, = ThumbcacheParser().parse(path)
            self.assertEqual(event.details['image_sha256'], hashlib.sha256(payload).hexdigest())
            self.assertGreater(len(reads), 6)

    def test_auto_detection_image_extraction_and_pipeline(self):
        from log_hunter.core.auto_detect import detect_inputs
        from log_hunter.core.pipeline import Pipeline
        from log_hunter.image.extract import extract_artifacts
        from test_image import NTFSBuilder
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'thumbcache_256.db'
            raw = cache_file()
            path.write_bytes(raw)
            detected = detect_inputs([path])
            self.assertEqual([item[0] for item in detected], ['thumbcache'])
            result = Pipeline().analyze([('thumbcache', path)])
            self.assertEqual(len(result.events), 1)
            self.assertFalse(result.errors)
            self.assertEqual(result.evidence[0].sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(path.read_bytes(), raw)
            builder = NTFSBuilder()
            folder = builder.makedirs('Users/alice/AppData/Local/Microsoft/Windows/Explorer')
            builder.add_file(folder, path.name, raw, mode='resident')
            image = root / 'synthetic.dd'
            image.write_bytes(builder.build())
            extracted = extract_artifacts(image, root / 'extracted')
            self.assertEqual([item[0] for item in extracted.inputs], ['thumbcache'])
            self.assertEqual(extracted.files[0]['sha256'], hashlib.sha256(raw).hexdigest())
            analyzed = Pipeline().analyze(extracted.inputs)
            self.assertEqual(len(analyzed.events), 1)
            self.assertFalse(analyzed.errors)
            self.assertFalse(list((root / 'extracted').rglob('*.png')))
