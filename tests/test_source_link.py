"""Verify that an explicit source selection matches a complete saved segment set."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from log_hunter.database.source_link import verify_image_attachment
from test_image import write_e01


class SourceLinkTests(unittest.TestCase):
    def test_segment_group_must_match_all_hashes_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            segments = write_e01(root / 'synthetic.E01', bytes(512 * 256), segments=2)
            source_rows = [{'kind': 'image', 'path': str(path),
                            'expected_sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in segments]
            image = {'image_path': str(segments[0]), 'image': {'segments': [str(p) for p in segments]}}
            selected, actual, expected, matched = verify_image_attachment(segments[0], image, source_rows)
            self.assertTrue(matched)
            self.assertEqual(actual, expected[0])
            self.assertEqual(selected, str(segments[0]))
            source_rows[1]['expected_sha256'] = '0' * 64
            self.assertFalse(verify_image_attachment(segments[0], image, source_rows)[-1])
            self.assertEqual(verify_image_attachment(root / 'absent.E01', image, source_rows[:1])[1:],
                             ((), (), False))
