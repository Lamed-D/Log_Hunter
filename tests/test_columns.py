"""Result table columns per record category and the table CSV."""
import csv
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import TreeNode
from log_hunter.ui import columns, view_model


class ColumnTests(unittest.TestCase):
    def setUp(self):
        self.bam = ForensicEvent("bam", "SYSTEM", "execution_trace", "2024-01-01T00:00:00+00:00",
                                 time_field="last_execution", sid="S-1", path="C:/evil.exe")
        self.recycled = ForensicEvent("recyclebin", "$IABC", "deleted_file", "2024-01-02T00:00:00+00:00",
                                      details={"original_path": "C:/Users/a/secret.txt", "file_size": 4096})

    def test_default_columns_match_the_timeline_rows(self):
        self.assertEqual(columns.columns_for(None), columns.DEFAULT)
        self.assertEqual([c.key for c in columns.DEFAULT][:2], ["timestamp", "artifact"])  # time first, then kind
        shown = dict(zip([c.key for c in columns.DEFAULT], columns.row(self.bam, columns.DEFAULT, {"S-1": "alice"}, None)))
        legacy = dict(zip(("artifact", "timestamp", "time_field", "sid", "user", "action", "path", "status"),
                          view_model.timeline_row(self.bam, {"S-1": "alice"})[0]))
        self.assertEqual(shown, legacy)

    def test_category_columns(self):
        run = columns.columns_for(TreeNode("art:run_programs", "실행한 프로그램", "artifacts", ("prefetch", "bam")))
        self.assertEqual(columns.headers(run)[:4], ["시각", "기록 종류", "프로그램", "사용자"])
        values = dict(zip([c.key for c in run], columns.row(self.bam, run, {"S-1": "alice"}, None)))
        self.assertEqual(values["program"], "C:/evil.exe")
        self.assertIn("BAM", values["description"])
        recycle = columns.columns_for(TreeNode("x", "휴지통", "artifacts", ("recyclebin",)))
        values = dict(zip([c.key for c in recycle], columns.row(self.recycled, recycle, {}, None)))
        self.assertEqual((values["original_path"], values["file_size"]), ("C:/Users/a/secret.txt", "4096"))
        mixed = TreeNode("art", "찾은 기록", "artifacts", ("bam", "recyclebin"))
        self.assertEqual(columns.columns_for(mixed), columns.DEFAULT)

    def test_table_csv_is_what_is_shown_and_formula_safe(self):
        rows = [("=cmd|' /C calc'!A0", "alice"), ("C:/a.exe", "")]
        cols = (columns.Column("program", 10), columns.Column("user", 10))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "table.csv"
            self.assertEqual(columns.save_csv(path, cols, rows), 2)
            with path.open(encoding="utf-8-sig", newline="") as stream:
                lines = list(csv.reader(stream))
        self.assertEqual(lines[0], ["프로그램", "사용자"])
        self.assertEqual(lines[1][0], "'=cmd|' /C calc'!A0")


if __name__ == "__main__":
    unittest.main()


class RemoteDesktopColumnTests(unittest.TestCase):
    def test_remote_desktop_columns(self):
        node = TreeNode("art:remote_desktop", "원격 데스크톱 접속 기록", "artifacts", ("rdp",))
        cols = columns.columns_for(node)
        self.assertEqual(columns.headers(cols)[2:5], ["원격 접속 대상", "사용자 이름 힌트", "목록 순위"])
        mru = ForensicEvent("rdp", "NTUSER.DAT", "rdp_mru", details={"rank": 0, "remote_host": "192.0.2.10",
                                                                     "connection_confirmed": False})
        server = ForensicEvent("rdp", "NTUSER.DAT", "rdp_server", "2024-01-01T00:00:00+00:00", "key_lastwrite",
                               details={"remote_host": "198.51.100.5", "username_hint": "EXAMPLE\\alice"})
        rows = [dict(zip([c.key for c in cols], columns.row(e, cols, {}, None))) for e in (mru, server)]
        self.assertEqual((rows[0]["remote_host"], rows[0]["rank"], rows[0]["username_hint"]), ("192.0.2.10", "0", ""))
        self.assertEqual(rows[1]["time_field"], "레지스트리 마지막 변경")  # key change time, not a connection time
        self.assertIn("접속 성공을 확정하지 않음", rows[1]["description"])
