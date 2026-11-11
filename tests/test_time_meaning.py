"""Synthetic checks for declared and locally observed timestamps."""
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from log_hunter.parser.network import NetworkProfileParser, _parse_network_time
from log_hunter.parser.tasks import TaskSchedulerParser
from log_hunter.parser.startup import StartupParser
from log_hunter.parser.mru import MRUParser, _parse_last_visited_entry
from log_hunter.parser.shellbag import ShellBagParser
from log_hunter.parser.recyclebin import RecycleBinParser
from log_hunter.parser.mft import parse_record
from log_hunter.parser.userassist import resolve_guid_path
from test_image import _record, _resident


class TimeMeaningTests(unittest.TestCase):
    def test_network_profile_keeps_local_value_out_of_utc_timeline(self):
        raw = struct.pack('<8H', 2024, 2, 4, 29, 12, 34, 56, 123)
        profile = SimpleNamespace(name='synthetic', values=lambda: [
            {'name': 'DateLastConnected', 'type': 3, 'raw': raw}])
        root = SimpleNamespace(subkeys=lambda: [profile])
        event, = NetworkProfileParser()._parse_profiles(SimpleNamespace(open=lambda path: root), 'synthetic')
        self.assertIsNone(event.timestamp)
        self.assertIsNone(event.time_field)
        self.assertEqual(event.details['date_last_connected'], '2024-02-29T12:34:56.123')

    def test_startup_reads_lnk_working_directory_and_arguments(self):
        data = bytearray(76)
        struct.pack_into('<I', data, 0, 76)
        data[4:20] = bytes.fromhex('0114020000000000c000000000000046')
        struct.pack_into('<I', data, 20, 0x80 | 0x10 | 0x20)
        for text in ('C:\\synthetic', '--example'):
            data += struct.pack('<H', len(text)) + text.encode('utf-16-le')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'start.lnk'
            path.write_bytes(data)
            parser = StartupParser()
            event, = parser.parse(path)
            self.assertEqual(event.details['working_dir'], 'C:\\synthetic')
            self.assertEqual(event.details['arguments'], '--example')
            self.assertFalse(parser.errors)
            path.write_bytes(b'broken')
            self.assertEqual(len(list(parser.parse(path))), 1)
            self.assertTrue(parser.errors)

    def test_knownfolder_programs_and_architecture_unknown(self):
        self.assertEqual(resolve_guid_path('{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\\app.lnk'),
                         '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\app.lnk')
        self.assertEqual(resolve_guid_path('{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}'),
                         '%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs')
        guid = '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}'
        self.assertEqual(resolve_guid_path(guid + '\\app.exe'), guid + '\\app.exe')

    def test_knownfolder_table_follows_documented_ids_only(self):
        # The Videos library id must resolve to the library, not to a public folder.
        self.assertEqual(resolve_guid_path('{491E922F-5643-4AF4-A7EB-4E7A138D8174}'),
                         '%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms')
        self.assertEqual(resolve_guid_path('{374DE290-123F-4565-9164-39C4925E467B}\\setup.exe'),
                         '%USERPROFILE%\\Downloads\\setup.exe')
        # Architecture-dependent ids and shell class ids outside KNOWNFOLDERID stay as GUIDs.
        for guid in ('{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}', '{DE974D24-D9C6-4D3E-BF91-F4455120B917}',
                     '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'):
            self.assertEqual(resolve_guid_path(guid + '\\app.exe'), guid + '\\app.exe')

    def test_recycle_metadata_alone_does_not_prove_content_absent(self):
        name = 'C:\\folder\\example.txt\0'.encode('utf-16-le')
        data = struct.pack('<QQQI', 2, 12, 133000000000000000, len(name) // 2) + name
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / '$iexample'
            metadata.write_bytes(data)
            event, = RecycleBinParser().parse(metadata)
            self.assertIsNone(event.details.get('r_file_exists'))
            self.assertEqual(event.details['original_name'], 'example.txt')
            (metadata.parent / '$Rexample').write_bytes(b'synthetic')
            event, = RecycleBinParser().parse(metadata)
            self.assertTrue(event.details['r_file_exists'])

    def test_mft_unpaired_surrogate_preserves_record_times(self):
        value = bytearray(68)
        struct.pack_into('<4Q', value, 8, *([133000000000000000] * 4))
        value[64:66] = bytes([1, 1])
        value[66:] = b'\x00\xd8'
        record = parse_record(_record(1, [_resident(0x30, value)]))
        self.assertEqual(record['names'][0]['name'], '\ufffd')
        self.assertEqual(len(record['times']), 4)

    def test_mru_lastwrite_only_links_first_rank(self):
        values = [{'name': 'MRUListEx', 'raw': struct.pack('<3I', 1, 0, 0xffffffff)},
                  {'name': '0', 'raw': 'old\0'.encode('utf-16-le')},
                  {'name': '1', 'raw': 'new\0'.encode('utf-16-le')}]
        key = SimpleNamespace(offset=1, lastwrite=133000000000000000,
                              values=lambda: values, subkeys=lambda: [])
        hive = SimpleNamespace(open=lambda path: key)
        events = list(MRUParser()._parse_recent_docs(hive, 'synthetic'))
        self.assertEqual([e.path for e in events], ['new', 'old'])
        self.assertIsNotNone(events[0].timestamp)
        self.assertIsNone(events[1].timestamp)
        self.assertIsNone(events[1].time_field)

    def test_shellbag_does_not_prove_deletion_or_time_every_entry(self):
        values = [{'name': 'MRUListEx', 'type': 3, 'raw': struct.pack('<3I', 1, 0, 0xffffffff)},
                  {'name': '0', 'type': 3, 'raw': b'\x00\x00'},
                  {'name': '1', 'type': 3, 'raw': b'\x00\x00'}]
        key = SimpleNamespace(offset=1, lastwrite=133000000000000000, values=lambda: values)
        def missing(path):
            raise KeyError(path)
        hive = SimpleNamespace(open=missing)
        events = list(ShellBagParser()._walk_bagmru(hive, key, 'BagMRU', 'synthetic', [], set()))
        self.assertFalse(any(e.details.get('deleted_folder_evidence') for e in events))
        self.assertIsNone(events[0].timestamp)
        self.assertIsNotNone(events[1].timestamp)

    def test_last_visited_utf16_boundary_and_binary_pidl(self):
        executable = 'example.exe\0'.encode('utf-16-le')
        directory = 'C:\\資料\0'.encode('utf-16-le')
        self.assertEqual(_parse_last_visited_entry(executable + directory),
                         ('example.exe', 'C:\\資料'))
        self.assertEqual(_parse_last_visited_entry(executable + b'\x04\x00\x31\x00\x00\x00', pidl=True),
                         ('example.exe', None))
        self.assertEqual(_parse_last_visited_entry(b'\x61\x00'), (None, None))

    def test_network_time_has_no_invented_offset(self):
        raw = struct.pack('<8H', 2024, 2, 4, 29, 12, 34, 56, 123)
        self.assertEqual(_parse_network_time(raw), '2024-02-29T12:34:56.123')
        invalid = struct.pack('<8H', 2023, 2, 3, 29, 12, 34, 56, 0)
        self.assertIsNone(_parse_network_time(invalid))

    def test_task_utf16_and_declared_date(self):
        xml = ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
               '<RegistrationInfo><Date>2024-02-29T12:34:56</Date></RegistrationInfo>'
               '<Actions><Exec><Command>example.exe</Command></Exec></Actions></Task>')
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory) / 'task'
            task.write_bytes(xml.encode('utf-16'))
            events = list(TaskSchedulerParser().parse(task))
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].timestamp)
        self.assertIsNone(events[0].time_field)
        self.assertEqual(events[0].details['registration_date'], '2024-02-29T12:34:56')

    def test_startup_input_mtime_is_not_target_history(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'start.cmd'
            script.write_bytes(b'echo synthetic')
            event, = StartupParser().parse(script)
        self.assertIsNone(event.timestamp)
        self.assertIsNone(event.time_field)


if __name__ == '__main__':
    unittest.main()
