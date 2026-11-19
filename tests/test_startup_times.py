"""Startup folder entries take their time from the image's file system record, never from the analysed copy."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import DETAIL_LABELS


class StartupTimeTests(unittest.TestCase):
    def test_image_times_used_and_copy_time_labelled(self):
        with tempfile.TemporaryDirectory() as folder:
            entry = Path(folder) / "Startup" / "tool.exe"
            entry.parent.mkdir()
            entry.write_bytes(b"MZ")
            times = {str(entry.resolve()).casefold(): {"created": "2020-12-30T00:00:00+00:00",
                                                         "modified": "2020-12-31T00:00:00+00:00"}}
            (event,) = Pipeline(times).analyze([("startup", entry.parent)]).events
            self.assertEqual((event.timestamp, event.time_field), ("2020-12-30T00:00:00+00:00", "startup_file_created"))
            self.assertEqual(event.details["file_modified"], "2020-12-31T00:00:00+00:00")
            (plain,) = Pipeline().analyze([("startup", entry.parent)]).events
            self.assertIsNone(plain.timestamp)  # a file given directly: its copy time is not the evidence time
            self.assertIn("input_file_mtime", plain.details)
        self.assertIn("원본의 시각 아님", DETAIL_LABELS["input_file_mtime"])


if __name__ == "__main__":
    unittest.main()
