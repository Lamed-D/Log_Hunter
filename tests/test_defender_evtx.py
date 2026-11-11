import hashlib
from pathlib import Path
import tempfile
import unittest

from log_hunter.parser.evtx import EVTXParser, defender_details, defender_path
from test_evtx_chunks import ChunkWriter


PROVIDER = 'Microsoft-Windows-Windows Defender'


def defender_record(writer, event_id, data, provider=PROVIDER):
    start = writer.begin()
    writer.element('Event', children=[
        dict(name='System', children=[dict(name='Provider', attrs=[('Name', provider)]),
                                     dict(name='EventID', text=event_id),
                                     dict(name='Channel', text='Microsoft-Windows-Windows Defender/Operational'),
                                     dict(name='Security', attrs=[('UserID', 'S-1-5-18')])]),
        dict(name='EventData', children=[dict(name='Data', attrs=[('Name', name)], text=value)
                                         for name, value in data.items()])])
    writer.finish(start)


class DefenderEVTXTests(unittest.TestCase):
    def parse(self, writer):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'synthetic.evtx')
            path.write_bytes(writer.file())
            before = hashlib.sha256(path.read_bytes()).digest()
            parser = EVTXParser()
            result = list(parser.parse(path))
            self.assertFalse(parser.errors)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
            return result

    def test_detection_and_allow_action_are_not_execution_or_remediation_proof(self):
        writer = ChunkWriter()
        values = {'Threat Name': 'Synthetic:Test/Example', 'Threat ID': '1001', 'Detection ID': 'TEST-1',
                  'Detection User': r'WORKSTATION-01\alice', 'Severity Name': 'Low',
                  'Category Name': 'Synthetic test', 'Path': r'C:\Users\alice\Downloads\test.bin',
                  'Process Name': r'C:\Evidence\scanner.exe', 'Detection Time': '2024-01-01T10:00:00'}
        defender_record(writer, 1116, values)
        defender_record(writer, 1117, {**values, 'Action Name': 'Allow', 'Error Code': '0x00000000'})
        detected, action = self.parse(writer)
        self.assertEqual(detected.action, 'defender_detection')
        self.assertEqual(action.action, 'defender_action')
        self.assertEqual(action.details['defender_action_name'], 'Allow')
        self.assertEqual(detected.sid, 'S-1-5-18')
        self.assertEqual(detected.path, values['Path'])
        self.assertEqual(detected.process, values['Process Name'])
        self.assertEqual(detected.time_field, 'record_filetime')
        self.assertEqual(detected.details['detection_user'], values['Detection User'])
        self.assertEqual(detected.details['defender_detection_time_raw'], values['Detection Time'])
        for event in (detected, action):
            self.assertFalse(event.details['remediation_confirmed'])
            self.assertFalse(event.details['threat_execution_confirmed'])
            self.assertIn('ANTIVIRUS', event.details['categories'])

    def test_wrong_provider_and_compound_resources_do_not_claim_a_file(self):
        writer = ChunkWriter()
        defender_record(writer, 1116, {'Path': r'C:\Evidence\test.bin'}, 'Synthetic-Defender')
        defender_record(writer, 1116, {'Path': r'file:_C:\Evidence\a;containerfile:_C:\Evidence\b',
                                     'Process Name': 'Unknown'})
        generic, compound = self.parse(writer)
        self.assertEqual(generic.action, 'event_record')
        self.assertNotIn('remediation_confirmed', generic.details)
        self.assertIsNone(compound.path)
        self.assertIsNone(compound.process)
        self.assertIn('containerfile:', compound.details['threat_resource'])

    def test_unknown_payload_types_are_not_invented_and_values_are_bounded(self):
        self.assertEqual(defender_details(1116, PROVIDER, {'Threat Name': ['ambiguous']})['remediation_confirmed'], False)
        details = defender_details(1116, PROVIDER, {'Threat Name': 'x' * 10000})
        self.assertEqual(len(details['threat_name']), 4096)
        self.assertNotIn('threat_id', details)
        self.assertIsNone(defender_details(1116, 'other', {}))

    def test_single_file_resource_is_supported_but_composites_remain_unknown(self):
        path = r'C:\Users\alice\Downloads\test.bin'
        self.assertEqual(defender_path('file:_' + path), path)
        for prefix in ('containerfile:_', 'webfile:_'):
            self.assertIsNone(defender_path(prefix + path))
        for tail in (';file:_other', '->member', '|file:_other'):
            self.assertIsNone(defender_path('file:_' + path + tail))
        writer = ChunkWriter()
        defender_record(writer, 1116, {'Path': 'file:_' + path})
        event, = self.parse(writer)
        self.assertEqual(event.path, path)
        self.assertEqual(event.details['categories'], ['ANTIVIRUS'])
        self.assertEqual(event.details['known_event'], '백신 탐지 기록')

    def test_numeric_ids_do_not_accept_booleans_or_ambiguous_types(self):
        self.assertEqual(defender_details(1116, PROVIDER, {'Threat ID': 1001})['threat_id'], '1001')
        for value in (True, -1, 1 << 80, ['1001']):
            self.assertNotIn('threat_id', defender_details(1116, PROVIDER, {'Threat ID': value}))
