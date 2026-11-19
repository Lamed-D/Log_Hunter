"""Generated adjacent Shell Links must retain independent record boundaries."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from log_hunter.parser.jumplist import JumpListParser, LNK_SIGNATURE, deleted_jump_list_records
from log_hunter.parser.lnk import shell_link_span
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import build_tree, matches
from log_hunter.image import extract_artifacts
from log_hunter.image.ntfs import DirEntry, NTFSVolume
from test_image import NTFSBuilder


def link(path, extra=b''):
    header = bytearray(76)
    header[:20] = LNK_SIGNATURE
    struct.pack_into('<I', header, 20, 0x88)  # Unicode relative path.
    struct.pack_into('<3Q', header, 28, *([133485408000000000] * 3))
    text = path.encode('utf-16-le')
    return bytes(header) + struct.pack('<H', len(text) // 2) + text + extra + bytes(4)


class CustomJumpListTests(unittest.TestCase):
    def test_pipeline_keeps_empty_file_and_links_entries_to_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            filled = root / '1b4dd67f29cb1962.customDestinations-ms'
            empty = root / '0.customDestinations-ms'
            filled.write_bytes(link(r'C:\Evidence\first.txt'))
            empty.write_bytes(b'')
            stamp = '2024-01-01T09:00:00+00:00'
            result = Pipeline({str(filled.resolve()).casefold(): {
                'modified': stamp, 'mft_modified': stamp, 'size': filled.stat().st_size,
            }}).analyze([('jumplist', empty), ('jumplist', filled)])
        files = {row.source: row for row in result.events if row.action == 'jump_list_file'}
        self.assertEqual(len(files), 2)
        self.assertEqual(files[str(empty)].details['item_count'], 0)
        self.assertEqual(files[str(empty)].details['file_parse_state'], 'no_entries')
        self.assertEqual(files[str(filled)].details['file_times']['mft_modified'], stamp)
        item, = [row for row in result.events if row.action == 'recent_file_access']
        self.assertEqual(item.details['jump_list_file_id'], files[str(filled)].details['jump_list_file_id'])
        recent = next(node for node in build_tree(result.events)[1].children if node.key == 'art:recent_documents')
        jump = next(node for node in recent.children if node.value == ('jumplist',))
        self.assertEqual([node.count for node in jump.children], [2, 1])
        self.assertTrue(matches(jump.children[0], files[str(empty)], None))
        self.assertFalse(matches(jump.children[0], item, None))

    def test_deleted_list_is_one_candidate_and_short_alias_is_filtered(self):
        long_name = '1b4dd67f29cb1962.customDestinations-ms'
        details = {'in_use': False, 'names': [{'name': long_name}, {'name': '1B4DD6~1.CUS'}], 'sequence': 2}
        rows = [ForensicEvent('mft', 'synthetic', 'file_metadata', '2024-01-01T00:00:00+00:00', field,
                              locator='record:7', details=details) for field in ('si_created', 'si_modified')]
        candidate, = deleted_jump_list_records(rows)
        self.assertEqual(candidate.details['file_parse_state'], 'deleted')
        self.assertEqual(len(candidate.details['file_times']), 2)
        self.assertIsNone(candidate.details['item_count'])
        volume = NTFSVolume.__new__(NTFSVolume)
        volume._listings = {}
        long_entry = DirEntry(long_name, 7, 2, False, 8)
        alias = DirEntry('1B4DD6~1.CUS', 7, 2, False, 8)
        with patch.object(volume, 'record', return_value=None), \
                patch.object(volume, 'read_attribute', side_effect=[b'index', None]), \
                patch('log_hunter.image.ntfs._index_entries', return_value=iter([(long_entry, 1), (alias, 2)])):
            self.assertEqual(volume.listdir(5), [long_entry])

    def test_automatic_detection_and_image_rule(self):
        data = link(r'C:\Evidence\first.txt') + link(r'C:\Evidence\second.txt')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = '1b4dd67f29cb1962.customDestinations-ms'
            path = root / name
            path.write_bytes(data)
            self.assertEqual([row[0] for row in detect_inputs([path])], ['jumplist'])
            builder = NTFSBuilder()
            folder = builder.makedirs('Users/alice/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations')
            builder.add_file(folder, name, data)
            image = root / 'synthetic.dd'
            image.write_bytes(builder.build())
            extraction = extract_artifacts(image, root / 'out')
            self.assertEqual([row[0] for row in extraction.inputs], ['jumplist'])

    def test_terminal_range_and_decode_budget(self):
        data = link(r'C:\Evidence\first.txt')
        self.assertEqual(shell_link_span(data[:-4] + struct.pack('<I', 3)), len(data))
        with self.assertRaises(ValueError):
            shell_link_span(data, -1)
        with patch('log_hunter.parser.jumplist.MAX_CUSTOM_RECORDS', 1):
            parser, events = self.parse(data + data)
        self.assertEqual(len(events), 1)
        self.assertTrue(parser.errors)
        with patch('log_hunter.parser.jumplist.MAX_CUSTOM_STEPS', 1):
            parser, events = self.parse(data)
        self.assertEqual(events, [])
        self.assertTrue(parser.errors)

    def parse(self, data):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / '1b4dd67f29cb1962.customDestinations-ms'
            path.write_bytes(data)
            parser = JumpListParser()
            events = list(parser.parse(path))
        return parser, events

    def test_adjacent_links_with_damaged_middle_record(self):
        first, second = link(r'C:\Evidence\first.txt'), link(r'C:\Evidence\second.txt')
        broken = bytearray(78)
        broken[:20] = LNK_SIGNATURE
        struct.pack_into('<I', broken, 20, 0x88)
        struct.pack_into('<H', broken, 76, 65535)
        parser, events = self.parse(struct.pack('<3I', 2, 0, 3) + first + broken + second)
        self.assertEqual([event.path for event in events], [r'C:\Evidence\first.txt', r'C:\Evidence\second.txt'])
        self.assertTrue(parser.errors)
        self.assertEqual(events[0].time_field, 'lnk_access_time')
        self.assertFalse(events[0].details['time_is_recent_access_time'])
        self.assertEqual(events[0].details['app_name'], 'Windows Explorer')

    def test_link_signature_inside_extra_data_does_not_become_a_record(self):
        embedded = link(r'C:\Evidence\embedded.txt')
        block = struct.pack('<II', len(embedded) + 8, 0xa000ffff) + embedded
        parser, events = self.parse(link(r'C:\Evidence\outer.txt', block) + link(r'C:\Evidence\last.txt'))
        self.assertEqual([event.path for event in events], [r'C:\Evidence\outer.txt', r'C:\Evidence\last.txt'])
        self.assertFalse(parser.errors)
