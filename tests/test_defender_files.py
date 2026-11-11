"""가짜 백신 기록으로 읽기 경계와 해석의 한계를 확인합니다."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import uuid
from unittest.mock import patch

from log_hunter.parser.defender import DefenderParser
from log_hunter.parser.defender_history import MAGIC, read_history
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.pipeline import Pipeline


def value(kind, data):
    raw = struct.pack('<II', len(data), kind) + data
    return raw + b'\0' * (-len(raw) % 8)


def text(data):
    return value(0x15, data.encode('utf-16-le'))


def history(location=r'C:\Evidence\가짜.exe'):
    return (value(8, struct.pack('<Q', 1001)) + value(0x1e, uuid.UUID(int=1).bytes_le)
            + text(MAGIC) + text('Test:Win32/Synthetic')
            + value(0, b'\0' * 4) * 2 + value(0, struct.pack('<I', 7))
            + text(MAGIC) + text('file') + text(location)
            + value(0x28, b'synthetic') + value(0x0a, struct.pack('<Q', 132537600000000000)))


class DefenderFileTests(unittest.TestCase):
    def test_image_extracts_only_metadata_sources(self):
        from test_image import NTFSBuilder
        from log_hunter.image import extract_artifacts
        builder = NTFSBuilder()
        base = 'ProgramData/Microsoft/Windows Defender/'
        for folder, name, content in (
            ('Support', 'MPLog-fake.log', b'Threat Name: Test:Win32/Synthetic'),
            ('Scans/History/Service/DetectionHistory/00', 'fake', history()),
            ('Quarantine/Entries', str(uuid.UUID(int=1)), b'fake metadata'),
            ('Quarantine/Resources', 'fake', b'never extracted'),
            ('Quarantine/ResourceData/00', 'fake', b'never extracted'),
        ):
            builder.add_file(builder.makedirs(base + folder), name, content)
        with tempfile.TemporaryDirectory() as folder:
            image = Path(folder) / 'synthetic.raw'; image.write_bytes(builder.build())
            digest = hashlib.sha256(image.read_bytes()).digest()
            result = extract_artifacts(image, Path(folder) / 'out')
            self.assertEqual(len(result.inputs), 3)
            self.assertEqual({row[0] for row in result.inputs}, {'defender'})
            self.assertFalse(any('ResourceData' in row['image_path'] or '\\Resources\\' in row['image_path']
                                 for row in result.files))
            self.assertEqual(hashlib.sha256(image.read_bytes()).digest(), digest)

    def test_history_values_without_unverified_event_time(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'record'; path.write_bytes(history())
            parser = DefenderParser(); event, = parser.parse(path)
            self.assertEqual(event.path, r'C:\Evidence\가짜.exe')
            self.assertEqual(event.details['threat_id'], '1001')
            self.assertEqual(event.details['threat_category_raw'], 7)
            self.assertIsNone(event.timestamp)
            self.assertFalse(event.details['remediation_confirmed'])
            self.assertFalse(event.details['threat_execution_confirmed'])
            raw_time = event.details['history_values'][-1]
            self.assertIsNotNone(raw_time['filetime_decoded'])
            self.assertFalse(raw_time['time_meaning_verified'])
            self.assertEqual(detect_inputs([path])[0][0], 'defender')

    def test_log_time_and_text_references(self):
        lines = ('2026-01-02T03:04:05+09:00 DETECTIONEVENT MPSOURCE_REALTIME Test:Win32/Synthetic file:C:\\Evidence\\fake.exe;\n'
                 '2026-01-02 03:04:05 Exclusion C:\\Evidence\\fake.exe\n'
                 '2026-01-02T03:04:05Z Begin Resource Scan\n'
                 'ProcessImageName: cmd.exe /c echo fake\n')
        for encoding in ('utf-8', 'utf-16', 'utf-16-be'):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'MPLog-fake.log'; path.write_bytes(lines.encode(encoding))
                digest = hashlib.sha256(path.read_bytes()).digest()
                result = Pipeline().analyze([('defender', path)])
                self.assertEqual(len(result.events), 4)
                detected = next(e for e in result.events if e.action == 'defender_detection')
                self.assertEqual(detected.timestamp, '2026-01-01T18:04:05+00:00')
                self.assertEqual(detected.path, r'C:\Evidence\fake.exe')
                excluded = next(e for e in result.events if e.action == 'defender_exclusion_reference')
                self.assertIsNone(excluded.timestamp)
                self.assertFalse(excluded.details['timezone_known'])
                self.assertTrue(all(not e.details['threat_execution_confirmed'] for e in result.events))
                self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), digest)

    def test_compound_and_relative_locations_are_not_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'MPLog-fake.log'
            for resource in ('file:C:\\Evidence\\a.exe;file:C:\\Evidence\\b.exe;', 'file:\\relative.exe'):
                path.write_text('DETECTIONEVENT MPSOURCE_REALTIME Test:Win32/Synthetic ' + resource, encoding='utf-8')
                event, = DefenderParser().parse(path)
                self.assertIsNone(event.path)

    def test_unknown_quarantine_metadata_and_payload_never_opened(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'Quarantine'; entries = root / 'Entries'; entries.mkdir(parents=True)
            entry = entries / str(uuid.UUID(int=1)); entry.write_bytes(b'fake encrypted metadata')
            payload = root / 'ResourceData' / 'fake'; payload.parent.mkdir(); payload.write_bytes(b'never read')
            original = Path.open
            def guarded(path, *args, **kwargs):
                self.assertNotEqual(path, payload)
                return original(path, *args, **kwargs)
            with patch.object(Path, 'open', guarded):
                parser = DefenderParser(); event, = parser.parse(root)
                self.assertFalse(event.details['metadata_format_supported'])
                self.assertFalse(event.details['quarantine_payload_recovered'])
                self.assertEqual(event.status, 'partial')
                self.assertEqual(list(parser.parse(payload)), [])
                self.assertTrue(parser.errors)

    def test_malformed_history_and_later_file_continue(self):
        raw = history()
        for bad in (raw[:-10], raw[:40] + struct.pack('<II', 0xffffffff, 0x15), b'', b'random'):
            with self.subTest(size=len(bad)):
                with self.assertRaises(ValueError): read_history(bad)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'DetectionHistory'; root.mkdir()
            (root / 'a').write_bytes(raw[:-10]); (root / 'b').write_bytes(raw)
            parser = DefenderParser()
            self.assertEqual(len(list(parser.parse(root))), 1)
            self.assertTrue(parser.errors)

    def test_long_line_and_invalid_time_mark_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'MPLog-fake.log'
            path.write_text('2026-99-99T99:99:99Z Threat Name: Test:Win32/Synthetic\n'
                            + 'Exclusion ' + 'x' * 20000, encoding='utf-8')
            events = list(DefenderParser().parse(path))
            self.assertEqual(len(events), 2)
            self.assertTrue(all(e.status == 'partial' for e in events))
            self.assertLess(len(events[1].details['log_line']), 9000)
