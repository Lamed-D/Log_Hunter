"""Synthetic file recognition, allocation and partial-read regressions."""
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from test_evtx_chunks import ChunkWriter
from log_hunter.parser.evtx import EVTXParser
from log_hunter.core.auto_detect import detect_artifact, detect_inputs


class EVTXRecognitionTests(unittest.TestCase):
    def parse(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'synthetic.evtx')
            path.write_bytes(payload)
            parser = EVTXParser()
            events = list(parser.parse(path))
            return events, parser.errors

    def test_empty_log_and_unused_chunks(self):
        writer = ChunkWriter()
        payload = bytearray(writer.file()[:4096])
        struct.pack_into('<H', payload, 42, 0)
        struct.pack_into('<I', payload, 124, zlib.crc32(payload[:120]))
        events, errors = self.parse(bytes(payload) + bytes(65536))
        self.assertEqual((events, errors), ([], []))
        writer.direct()
        events, errors = self.parse(writer.file() + bytes(65536 * 2))
        self.assertEqual(len(events), 1)
        self.assertFalse(errors)

    def test_truncated_chunk_retains_complete_records(self):
        writer = ChunkWriter()
        writer.direct()
        end = len(writer.data)
        writer.direct(4625)
        events, errors = self.parse(writer.file()[:4096 + end + 40])
        self.assertEqual([e.details['event_id'] for e in events], [4624])
        self.assertTrue(errors)
        self.assertEqual(events[0].status, 'partial')

    def test_dirty_and_count_mismatch_preserve_events(self):
        writer = ChunkWriter()
        writer.direct()
        payload = bytearray(writer.file())
        struct.pack_into('<I', payload, 120, 1)
        struct.pack_into('<H', payload, 42, 65535)
        struct.pack_into('<I', payload, 124, zlib.crc32(payload[:120]))
        events, errors = self.parse(payload)
        self.assertEqual(len(events), 1)
        self.assertTrue(any(e.locator == 'flags' for e in errors))
        self.assertTrue(any(e.locator == 'chunk_count' for e in errors))

    def test_signature_detection_and_legacy_diagnostic(self):
        writer = ChunkWriter()
        writer.direct()
        with tempfile.TemporaryDirectory() as directory:
            for name in ('renamed', 'Microsoft-Windows-TaskScheduler%4Operational.evtx', 'UPPER.EVTX', 'misleading.pf'):
                path = Path(directory, name)
                path.write_bytes(writer.file())
                self.assertEqual(detect_artifact(path), 'evtx')
                self.assertEqual(detect_inputs([path])[0][0], 'evtx')
            path = Path(directory, 'old.evt')
            path.write_bytes(struct.pack('<I', 48) + b'LfLe' + bytes(40))
            row = detect_inputs([path])[0]
            self.assertIsNone(row[0])
            self.assertIn('구형', row[3])

    def test_invalid_files_report_errors_without_raising(self):
        for payload in (b'', b'bad', struct.pack('<I', 48) + b'LfLe' + bytes(40)):
            events, errors = self.parse(payload)
            self.assertFalse(events)
            self.assertTrue(errors)

    def test_unknown_event_has_explicit_description(self):
        writer = ChunkWriter()
        writer.direct(65000)
        events, errors = self.parse(writer.file())
        self.assertFalse(errors)
        event = events[0]
        self.assertEqual(event.action, 'event_record')
        self.assertIn('기타 이벤트', event.details['known_event'])
        self.assertIn('65000', event.details['known_event'])
        self.assertIn('Microsoft-Windows-Security-Auditing', event.details['known_event'])

    def test_unknown_value_preserves_other_fields_and_warns(self):
        writer = ChunkWriter()
        def body(w):
            w.element('Event', children=[
                dict(name='System', children=[dict(name='EventID', text='65000')]),
                dict(name='EventData', children=[dict(name='Data', attrs=[('Name', 'Unknown')], text=(0, 0x7f))])])
        writer.custom_template(body, [(0x7f, b'\xab\xcd')])
        events, errors = self.parse(writer.file())
        self.assertEqual(events[0].details['event_id'], 65000)
        self.assertEqual(events[0].details['event_data']['Unknown'], 'abcd')
        self.assertEqual(events[0].status, 'partial')
        self.assertTrue(events[0].details['binxml_value_warnings'])
        self.assertTrue(errors)

    def test_template_in_other_chunk_is_not_read_as_current_chunk(self):
        first = ChunkWriter()
        reference = first.templated(4624)
        second = ChunkWriter()
        second.templated(4625, reference)
        # Offsets are relative to each chunk: an absent definition must not
        # resolve to arbitrary bytes from another chunk or hide later records.
        second.direct(4625)
        payload = bytearray(first.file())
        struct.pack_into('<H', payload, 42, 2)
        struct.pack_into('<I', payload, 124, zlib.crc32(payload[:120]))
        events, errors = self.parse(bytes(payload) + second.file()[4096:])
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].details['event_id'], 4624)
        self.assertEqual(events[1].status, 'partial')
        self.assertEqual(events[2].details['event_id'], 4625)
        self.assertTrue(errors)

    def test_header_crc_warning_preserves_readable_record(self):
        writer = ChunkWriter()
        writer.direct()
        payload = bytearray(writer.file())
        payload[124] ^= 1
        events, errors = self.parse(payload)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, 'partial')
        self.assertTrue(any(e.locator == 'header_crc' for e in errors))

    def test_unrelated_provider_cannot_reuse_security_meaning(self):
        writer = ChunkWriter()
        start = writer.begin()
        writer.element('Event', children=[dict(name='System', children=[
            dict(name='Provider', attrs=[('Name', 'Example-Provider')]),
            dict(name='EventID', text='4624'), dict(name='Channel', text='Example')])])
        writer.finish(start)
        events, errors = self.parse(writer.file())
        self.assertFalse(errors)
        self.assertEqual(events[0].action, 'event_record')
        self.assertEqual(events[0].details['categories'], ['OTHER'])
        self.assertIn('Example-Provider', events[0].details['known_event'])
