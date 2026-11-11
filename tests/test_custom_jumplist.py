"""Generated adjacent Shell Links must retain independent record boundaries."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from log_hunter.parser.jumplist import JumpListParser, LNK_SIGNATURE
from log_hunter.parser.lnk import shell_link_span
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.image import extract_artifacts
from test_image import NTFSBuilder


def link(path, extra=b''):
    header = bytearray(76)
    header[:20] = LNK_SIGNATURE
    struct.pack_into('<I', header, 20, 0x88)  # Unicode relative path.
    struct.pack_into('<3Q', header, 28, *([133485408000000000] * 3))
    text = path.encode('utf-16-le')
    return bytes(header) + struct.pack('<H', len(text) // 2) + text + extra + bytes(4)


class CustomJumpListTests(unittest.TestCase):
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
