"""Screen CSV and per-category CSVs: shown columns plus the shared timeline columns with the same values, UTC times,
one encoding, formula-safe, never overwriting."""
import csv
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.export import CSV_ENCODING, export_csv
from log_hunter.core.models import ForensicEvent
from log_hunter.ui import columns


def events():
    return [
        ForensicEvent("bam", r"C:\Evidence\SYSTEM", "activity_update", "2024-01-01T09:00:00+09:00", "last_execution",
                      "S-1-5-21-1000-2000-3000-1001", path="=cmd|' /C calc'!A0"),
        ForensicEvent("history", r"C:\Evidence\History", "download", "2024-01-02T00:00:00+00:00", "start_time",
                      path=r"C:\Users\alice\Downloads\a.exe", url="https://example.org/a.exe",
                      details={"download_save_path": r"C:\Users\alice\Downloads\a.exe", "final_url": "https://example.org/a.exe"}),
        ForensicEvent("mru", r"C:\Evidence\NTUSER.DAT", "recent_document", None, None, path="a.txt",
                      details={"timestamp_raw_local": "2024-01-03T10:00:00", "timezone_known": False}),
    ]


def read(path):
    with open(path, encoding=CSV_ENCODING, newline="") as stream:
        return list(csv.reader(stream))


class ScreenCSVTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.events = events()
        self.names = {"S-1-5-21-1000-2000-3000-1001": "alice"}

    def tearDown(self):
        self.temp.cleanup()

    def test_shown_columns_then_shared_columns_with_timeline_values(self):
        cols = columns.DEFAULT
        rows = [columns.row(e, cols, self.names, None) for e in self.events]
        path = self.root / "table.csv"
        columns.save_csv(path, cols, rows, self.events, self.names)
        table = read(path)
        header = table[0]
        self.assertEqual(header[:len(cols)], columns.headers(cols))
        self.assertIn("timestamp_utc", header[len(cols):])
        first = dict(zip(header, table[1]))
        self.assertEqual(first["시각"], "2024-01-01 00:00:00 UTC")  # shown text is UTC
        self.assertTrue(first["파일/프로그램/주소"].startswith("'="))  # formula-safe
        export_csv(self.events, self.root / "timeline.csv", sid_names=self.names)
        with open(self.root / "timeline.csv", encoding=CSV_ENCODING, newline="") as stream:
            timeline = list(csv.DictReader(stream))
        for screen_row, timeline_row in zip(table[1:], timeline):
            shared = dict(zip(header[len(cols):], screen_row[len(cols):]))
            for key in ("timestamp_utc", "time_basis", "timestamp_raw_local", "user", "target", "download_save_path"):
                self.assertEqual(shared[key], timeline_row[key], key)
        third = dict(zip(header, table[3]))
        self.assertEqual((third["timestamp_utc"], third["timestamp_raw_local"]), ("", "2024-01-03T10:00:00"))
        self.assertEqual(third["시각"], "2024-01-03 10:00:00 (시간대 미상)")

    def test_never_overwrites_and_uses_one_encoding(self):
        path = self.root / "table.csv"
        path.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            columns.save_csv(path, columns.DEFAULT, [], [], {})
        self.assertEqual(path.read_text(encoding="utf-8"), "keep")
        columns.save_csv(self.root / "new.csv", columns.DEFAULT, [], [], {})
        self.assertTrue((self.root / "new.csv").read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_category_bundle_has_one_file_per_category_and_a_guide(self):
        folder = self.root / "bundle"
        written = columns.save_category_csvs(folder, self.events, self.names)
        self.assertEqual(written, {"run_programs.csv": 1, "web_history.csv": 1, "recent_documents.csv": 1})
        web = read(folder / "web_history.csv")
        cols = columns.CATEGORY_COLUMNS["web_history"]
        self.assertEqual(web[0][:len(cols)], columns.headers(cols))
        guide = read(folder / columns.CATEGORY_CSV_GUIDE)
        self.assertEqual(guide[0], ["파일", "분류", "열", "뜻"])
        self.assertIn(["web_history.csv", "웹 기록", "timestamp_utc", "시각 (UTC, ISO 8601). 시간대를 모르는 값은 비움"], guide)
        with self.assertRaises(FileExistsError):  # an existing folder is never reused
            columns.save_category_csvs(folder, self.events)


if __name__ == "__main__":
    unittest.main()
