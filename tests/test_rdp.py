"""Generated Terminal Server Client hive and connection-setting files."""
from pathlib import Path
import tempfile
import unittest
import struct

from log_hunter.parser.rdp import RDPParser
from test_example_samples import load_demo
from test_evtx_chunks import ChunkWriter
from log_hunter.parser.evtx import EVTXParser
from log_hunter.core.correlation import correlate
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.image import extract_artifacts
from test_image import NTFSBuilder
from log_hunter.core.models import ForensicEvent


def rdp_hive(include_bad=True):
    demo = load_demo()
    builder = demo.HiveBuilder()
    stamp = demo.to_filetime(demo.utc(10, 0))
    default = builder.key('Default', stamp, values=[
        ('MRU2', 1, '198.51.100.10\0'.encode('utf-16-le')),
        ('MRU0', 1, 'WORKSTATION-01\0'.encode('utf-16-le')),
        *([('MRU1', 3, b'broken')] if include_bad else [])])
    host = builder.key('WORKSTATION-01', stamp, values=[
        ('UsernameHint', 1, 'alice\0'.encode('utf-16-le'))])
    servers = builder.key('Servers', stamp, children=[host])
    client = builder.key('Terminal Server Client', stamp, children=[default, servers])
    microsoft = builder.key('Microsoft', stamp, children=[client])
    software = builder.key('Software', stamp, children=[microsoft])
    root = builder.key('ROOT', stamp, children=[software])
    return builder.build(root)


class RDPTests(unittest.TestCase):
    def test_dense_rdp_candidates_are_grouped_without_confirming_sessions(self):
        timestamp = '2024-01-01T12:00:00+00:00'
        events = [ForensicEvent('rdp', 'generated', 'rdp_server', timestamp, 'key_lastwrite',
                               details={'remote_host': 'WORKSTATION-01', 'username_hint': 'alice'})]
        events += [ForensicEvent('evtx', 'generated', 'event_record', timestamp, 'record_filetime',
                                details={'provider': 'Microsoft-Windows-TerminalServices-LocalSessionManager',
                                         'event_id': 21, 'computer': 'WORKSTATION-01',
                                         'user_data': {'User': 'alice'}}) for _ in range(10001)]
        relations = correlate(events)
        group, = [item for item in relations if item.get('relation_type') == 'rdp_session_correlation']
        self.assertEqual(group['candidate_count'], 10001)
        self.assertEqual(len(group['event_indices']), 10002)
        self.assertFalse(group['execution_confirmed'])

    def test_auto_detection_and_image_extraction_include_rdp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = root / 'Default.rdp'
            data = b'full address:s:198.51.100.10\r\nusername:s:alice\r\n'
            settings.write_bytes(data)
            self.assertEqual([row[0] for row in detect_inputs([settings])], ['rdp'])
            builder = NTFSBuilder()
            user = builder.makedirs('Users/alice')
            builder.add_file(user, 'NTUSER.DAT', rdp_hive())
            documents = builder.makedirs('Users/alice/Documents')
            builder.add_file(documents, 'Default.rdp', data, mode='resident')
            image = root / 'synthetic.dd'
            image.write_bytes(builder.build())
            extraction = extract_artifacts(image, root / 'out')
            self.assertEqual(len([row for row in extraction.inputs if row[0] == 'rdp']), 2)

    def test_text_damage_duplicate_target_and_size_cap(self):
        for data in (b'full address:s:first\nfull address:s:second\n', b'\xff\xfe\x00',
                     b'x' * (1024 * 1024 + 1), b'full address:s:WORKSTATION-01:65536\n'):
            with self.subTest(size=len(data)), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'Default.rdp'
                path.write_bytes(data)
                parser = RDPParser()
                self.assertEqual(list(parser.parse(path)), [])
                self.assertTrue(parser.errors)

    def test_userdata_names_do_not_override_system_fields(self):
        from log_hunter.parser.binxml import extract_event_fields
        fields = extract_event_fields([
            {'name': 'System', 'children': [{'name': 'EventID', 'text': '1149'}]},
            {'name': 'UserData', 'children': [{'name': 'EventID', 'text': '999'},
                                             {'name': 'User', 'text': 'alice'},
                                             {'name': 'User', 'text': 'bob'}]}])
        self.assertEqual(fields['event_id'], 1149)
        self.assertEqual(fields['user_data']['EventID'], '999')
        self.assertEqual(fields['user_data']['User'], ['alice', 'bob'])

    def test_real_userdata_evtx_correlates_only_matching_remote_host_user_and_time(self):
        writer = ChunkWriter()
        start = writer.begin()
        writer.element('Event', children=[dict(name='System', children=[
            dict(name='Provider', attrs=[('Name', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager')]),
            dict(name='EventID', text=1149), dict(name='Computer', text='WORKSTATION-01')]),
            dict(name='UserData', children=[dict(name='EventXML', children=[
                dict(name='Param1', text='alice'), dict(name='Param2', text='WORKSTATION-01'),
                dict(name='Param3', text='198.51.100.10')])])])
        writer.finish(start)
        demo = load_demo()
        struct.pack_into('<Q', writer.data, start + 16, demo.to_filetime(demo.utc(10, 0)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hive, evtx = root / 'NTUSER.DAT', root / 'synthetic.evtx'
            hive.write_bytes(rdp_hive())
            evtx.write_bytes(writer.file())
            events = list(RDPParser().parse(hive)) + list(EVTXParser().parse(evtx))
        self.assertEqual(events[-1].details['user_data']['Param1'], 'alice')
        relations = [r for r in correlate(events) if r['type'] == 'rdp_session_correlation']
        self.assertEqual(len(relations), 1)
        self.assertFalse(relations[0]['execution_confirmed'])
        self.assertEqual(relations[0]['delta_seconds'], 0)
        events[-1].details['computer'] = 'DESKTOP-TEST01'
        self.assertFalse([r for r in correlate(events) if r['type'] == 'rdp_session_correlation'])
        events[-1].details['computer'] = 'WORKSTATION-01'
        events[-1].details['user_data']['Param1'] = 'bob'
        self.assertFalse([r for r in correlate(events) if r['type'] == 'rdp_session_correlation'])
        events[-1].details['user_data']['Param1'] = 'alice'
        events[-1].timestamp = '2024-01-01T00:00:00+00:00'
        self.assertFalse([r for r in correlate(events) if r['type'] == 'rdp_session_correlation'])

    def test_registry_mru_order_bad_value_and_server_key_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'NTUSER.DAT'
            path.write_bytes(rdp_hive())
            parser = RDPParser(sid='S-1-5-21-1000-2000-3000-1001')
            events = list(parser.parse(path))
        mru = [event for event in events if event.action == 'rdp_mru']
        self.assertEqual([event.details['rank'] for event in mru], [0, 2])
        self.assertEqual([event.details['remote_host'] for event in mru], ['WORKSTATION-01', '198.51.100.10'])
        self.assertTrue(all(event.timestamp is None and event.time_field is None for event in mru))
        server, = [event for event in events if event.action == 'rdp_server']
        self.assertEqual(server.time_field, 'key_lastwrite')
        self.assertEqual(server.details['username_hint'], 'alice')
        self.assertFalse(server.details['time_is_connection_time'])
        self.assertTrue(parser.errors)

    def test_utf16_settings_preserve_target_not_host_mtime_or_password(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'Default.rdp'
            path.write_bytes(('full address:s:WORKSTATION-01:3389\r\nusername:s:alice\r\n'
                              'password 51:b:01234567\r\n').encode('utf-16'))
            event, = RDPParser().parse(path)
        self.assertEqual(event.details['remote_host'], 'WORKSTATION-01')
        self.assertEqual(event.details['remote_port'], 3389)
        self.assertIsNone(event.timestamp)
        self.assertIsNone(event.time_field)
        self.assertNotIn('password', str(event.details))
