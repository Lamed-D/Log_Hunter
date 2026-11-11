import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from log_hunter.parser.prefetch import PrefetchParser
from log_hunter.core.pipeline import Pipeline
from test_xpress import encode_literals


def fixture(version=31):
    data = bytearray(672)
    struct.pack_into('<I4s', data, 0, version, b'SCCA')
    struct.pack_into('<I', data, 12, len(data))
    name = 'TESTAPP.EXE'.encode('utf-16-le')
    data[16:16 + len(name)] = name
    struct.pack_into('<I', data, 84, 296)
    refs = 'C:\\Evidence\\TESTAPP.EXE\0'.encode('utf-16-le')
    struct.pack_into('<II', data, 100, 296, len(refs))
    data[296:296 + len(refs)] = refs
    struct.pack_into('<III', data, 108, 360, 2, 312)
    for index in range(8):
        struct.pack_into('<Q', data, 128 + index * 8, 133485408000000000 - index * 10000000)
    struct.pack_into('<I', data, 200, 19)
    struct.pack_into('<I', data, 208, 777)  # Wrong v26-style count must be ignored.
    for index in range(2):
        base = 360 + 96 * index
        path = ('\\DEVICE\\HARDDISKVOLUME' + str(index + 1)).encode('utf-16-le')
        relative = 192 + index * 56
        struct.pack_into('<IIQI', data, base, relative, len(path) // 2,
                         133485408000000000, index + 1)
        data[360 + relative:360 + relative + len(path)] = path
    return bytes(data)


class Prefetch31Tests(unittest.TestCase):
    def parse(self, payload):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'TESTAPP-00000000.pf'
            source.write_bytes(payload)
            before = hashlib.sha256(source.read_bytes()).digest()
            events = list(PrefetchParser().parse(source))
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), before)
            return events

    def test_version31_distinct_count_eight_times_references_and_two_volumes(self):
        events = self.parse(fixture())
        self.assertEqual(len(events), 8)
        self.assertEqual(events[0].process, 'TESTAPP.EXE')
        detail = events[0].details
        self.assertEqual(detail['run_count'], 19)
        self.assertEqual(detail['references'], ['C:\\Evidence\\TESTAPP.EXE'])
        self.assertEqual([v['serial'] for v in detail['volumes']], ['00000001', '00000002'])
        self.assertTrue(detail['volumes'][1]['path'].endswith('2'))
        self.assertEqual(len({e.timestamp for e in events}), 8)

    def test_mam_decompression_before_version_selection(self):
        raw = fixture()
        self.assertEqual(self.parse(b'MAM\x04' + struct.pack('<I', len(raw)) + encode_literals(raw))[0].details['run_count'], 19)

    def test_version30_compact_layout_and_no_execution_times(self):
        self.assertEqual(self.parse(fixture(30))[0].details['run_count'], 19)
        raw = bytearray(fixture())
        raw[128:192] = bytes(64)
        events = self.parse(raw)
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].timestamp)
        self.assertEqual(events[0].status, 'warning')

    def test_truncated_and_corrupt_ranges(self):
        raw = fixture()
        for size in (0, 83, 199, 295, 639):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.parse(raw[:size])
        for offset, value in ((100, 0xffffffff), (104, 3), (108, 0xffffffff), (112, 33)):
            damaged = bytearray(raw)
            struct.pack_into('<I', damaged, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.parse(damaged)

    def test_unknown_version_lists_supported_versions(self):
        with self.assertRaisesRegex(ValueError, '17/23/26/30/31'):
            self.parse(fixture(99))

    def test_pipeline_continues_after_corrupt_prefetch(self):
        with tempfile.TemporaryDirectory() as folder:
            bad, good = [Path(folder) / name for name in ('bad.pf', 'good.pf')]
            bad.write_bytes(fixture()[:200])
            good.write_bytes(fixture())
            result = Pipeline().analyze([('prefetch', bad), ('prefetch', good)])
            self.assertEqual(len(result.events), 8)
            self.assertTrue(result.errors)
