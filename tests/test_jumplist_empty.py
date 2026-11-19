"""Empty Jump Lists are reported as empty (information), not as damaged files."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.parser.jumplist import JumpListParser  # noqa: E402
from test_jumplist_streams import compound  # noqa: E402


def severities(path):
    parser = JumpListParser()
    events = list(parser.parse(path))
    return [(e.severity, e.message) for e in parser.errors], events


class EmptyJumpListTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_custom_list_with_only_header_and_end_marker(self):
        path = self.root / "1b4dd67f29cb1962.customDestinations-ms"
        path.write_bytes(struct.pack("<IIIII", 2, 1, 0, 1, 2) + b"\xab\xfb\xbf\xba")
        errors, _events = severities(path)
        self.assertEqual([s for s, _ in errors], ["info"])
        self.assertIn("항목이 없는", errors[0][1])

    def test_custom_list_without_end_marker_still_warns(self):
        path = self.root / "1b4dd67f29cb1962.customDestinations-ms"
        path.write_bytes(b"\x02\x00\x00\x00" + b"\x11" * 40)
        errors, _events = severities(path)
        self.assertIn("warning", [s for s, _ in errors])

    def test_automatic_list_without_streams(self):
        path = self.root / "1b4dd67f29cb1962.automaticDestinations-ms"
        path.write_bytes(compound({}))
        errors, _events = severities(path)
        self.assertEqual([s for s, _ in errors], ["info"])


if __name__ == "__main__":
    unittest.main()
