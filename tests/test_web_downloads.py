"""Web history: visits and downloads are told apart, and each download URL keeps its role."""
import csv
import sqlite3
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.export import DOWNLOAD_FIELDS, export_csv
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import OriginIndex, build_tree, matches
from log_hunter.parser.history import browser_profile
from log_hunter.ui import columns
from log_hunter.ui.record_fields import properties

START = 13253760000000000  # 2020-12-30 00:00:00 UTC in Chromium microseconds


def make_history(folder):
    """Synthetic Chromium History: one visit reached from another, and one download that was redirected once."""
    path = Path(folder) / "Google" / "Chrome" / "User Data" / "Default" / "History"
    path.parent.mkdir(parents=True)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER, from_visit INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT, start_time INTEGER,
            received_bytes INTEGER, total_bytes INTEGER, state INTEGER, end_time INTEGER, referrer TEXT, site_url TEXT,
            tab_url TEXT, tab_referrer_url TEXT, mime_type TEXT);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
    """)
    db.execute("INSERT INTO urls VALUES(1,'https://example.com/','Example',?)", (START,))
    db.execute("INSERT INTO urls VALUES(2,'https://example.com/get','Get',?)", (START,))
    db.execute("INSERT INTO visits VALUES(1,1,?,0,0)", (START,))
    db.execute("INSERT INTO visits VALUES(2,2,?,0,1)", (START + 1_000_000,))
    db.execute("INSERT INTO downloads VALUES(1,'g',?,?,?,10,10,1,?,'https://example.com/get','','https://example.com/get',"
               "'https://example.com/','application/octet-stream')",
               (r"C:\Users\alice\Downloads\tool.exe", r"C:\Users\alice\Downloads\tool.exe", START + 2_000_000, START + 3_000_000))
    db.execute("INSERT INTO downloads_url_chains VALUES(1,0,'https://example.com/dl?id=1')")
    db.execute("INSERT INTO downloads_url_chains VALUES(1,1,'https://cdn.example.org/tool.exe')")
    db.commit()
    db.close()
    return path


class WebDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = make_history(self.temp.name)
        self.events = Pipeline().analyze([("history", self.path)]).events

    def tearDown(self):
        self.temp.cleanup()

    def by_action(self, action):
        return [e for e in self.events if e.action == action]

    def test_download_roles_and_save_path(self):
        (download,) = self.by_action("download")
        d = download.details
        self.assertEqual(d["download_save_path"], r"C:\Users\alice\Downloads\tool.exe")
        self.assertEqual(d["download_url"], "https://example.com/dl?id=1")
        self.assertEqual(d["final_url"], "https://cdn.example.org/tool.exe")
        self.assertEqual(download.url, d["final_url"])
        self.assertEqual(d["referrer_url"], "https://example.com/get")
        self.assertEqual(d["tab_url"], "https://example.com/get")
        self.assertIsNone(d["site_url"])  # empty text is not a URL
        self.assertEqual(d["download_state"], "complete")
        self.assertEqual(d["download_start"], "2020-12-30T00:00:02+00:00")
        self.assertEqual(d["download_end"], "2020-12-30T00:00:03+00:00")
        self.assertEqual((d["browser"], d["profile"]), ("Google Chrome", "Default"))

    def test_visit_referrer_comes_from_the_previous_visit(self):
        visits = sorted(self.by_action("url_visit"), key=lambda e: e.locator)
        self.assertNotIn("referrer_url", visits[0].details)
        self.assertEqual(visits[1].details["referrer_url"], "https://example.com/")

    def test_tree_splits_visits_and_downloads(self):
        roots = build_tree(self.events)
        nodes = {n.key: n for r in roots for n in r.walk()}
        visits, downloads = nodes["art:web_history:history:visits"], nodes["art:web_history:history:downloads"]
        self.assertEqual((visits.label, visits.count), ("방문", 2))
        self.assertEqual((downloads.label, downloads.count), ("다운로드", 1))
        self.assertEqual(nodes["art:web_history"].label, "웹 기록")
        self.assertEqual([e.action for e in self.events if matches(downloads, e, OriginIndex())], ["download"])
        self.assertEqual(columns.columns_for(downloads), columns.CATEGORY_COLUMNS["web_downloads"])
        self.assertEqual(columns.columns_for(visits), columns.CATEGORY_COLUMNS["web_visits"])

    def test_download_table_cells(self):
        (download,) = self.by_action("download")
        cols = columns.CATEGORY_COLUMNS["web_downloads"]
        row = dict(zip([c.key for c in cols], columns.row(download, cols, {}, None)))
        self.assertEqual(row["download_file"], "tool.exe")
        self.assertEqual(row["download_url"], "https://example.com/dl?id=1")
        self.assertEqual(row["final_url"], "https://cdn.example.org/tool.exe")
        self.assertEqual(row["download_state"], "완료")
        visit = self.by_action("url_visit")[0]
        self.assertEqual(columns.cell("download_url", visit, {}, None), "")  # visits have no download columns

    def test_properties_name_each_url_role(self):
        (download,) = self.by_action("download")
        props = properties(download)
        fields = dict(props.fields)
        self.assertEqual(fields["최종 주소 (파일을 내려 준 곳)"], "https://cdn.example.org/tool.exe")
        self.assertEqual(fields["참조 페이지"], "https://example.com/get")
        self.assertEqual(fields["저장 경로"], r"C:\Users\alice\Downloads\tool.exe")
        chain = dict((name, lines) for name, lines, _ in props.tabs)["주소 이동 순서 (요청 → 최종)"]
        self.assertEqual(chain, ["1. https://example.com/dl?id=1", "2. https://cdn.example.org/tool.exe"])

    def test_timeline_csv_has_download_columns_and_leaves_visits_empty(self):
        out = Path(self.temp.name) / "timeline.csv"
        export_csv(self.events, out)
        with out.open(encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        header = list(rows[0])
        start = header.index("details_json") + 1
        self.assertEqual(header[start:start + len(DOWNLOAD_FIELDS)], list(DOWNLOAD_FIELDS))
        download = next(r for r in rows if r["action"] == "download")
        self.assertEqual(download["download_save_path"], r"C:\Users\alice\Downloads\tool.exe")
        self.assertEqual(download["final_url"], "https://cdn.example.org/tool.exe")
        visit = next(r for r in rows if r["action"] == "url_visit" and r["referrer_url"])
        self.assertEqual(visit["download_url"], "")
        self.assertEqual(visit["referrer_url"], "https://example.com/")

    def test_browser_profile_from_path(self):
        self.assertEqual(browser_profile(r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Profile 1\History"),
                         ("Microsoft Edge", "Profile 1"))
        self.assertEqual(browser_profile(r"C:\Evidence\History"), (None, None))


if __name__ == "__main__":
    unittest.main()
