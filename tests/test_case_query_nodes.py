"""Saved-case queries know the view nodes (방문/다운로드·점프 목록 파일/항목, 같은 대상, 바로가기별) and give the same
records and counts as the loaded tree, with and without the query index."""
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.recent_targets import attach_target_keys
from log_hunter.core.tree import OriginIndex, build_tree, matches
from log_hunter.database.case_db import save_case
from log_hunter.database.case_query import open_case_query

T = "2024-01-01T00:00:0{}+00:00"


def events():
    rows = [
        ForensicEvent("history", r"C:\Evidence\History", "url_visit", T.format(1), "visit_time", url="https://example.com/"),
        ForensicEvent("history", r"C:\Evidence\History", "download", T.format(2), "start_time", path=r"C:\Users\alice\a.exe"),
        ForensicEvent("history", r"C:\Evidence\History", "web_search", T.format(3), "search_last_visit"),
        ForensicEvent("lnk", r"C:\Evidence\a.lnk", "shortcut_target", T.format(4), "lnk_target_accessed",
                      path=r"C:\Users\alice\report.docx", locator="a.lnk", details={"lnk_representative": True}),
        ForensicEvent("lnk", r"C:\Evidence\a.lnk", "shortcut_file", T.format(5), "lnk_file_created",
                      path=r"C:\Users\alice\report.docx", locator="a.lnk", details={"lnk_representative": False}),
        ForensicEvent("mru", r"C:\Evidence\NTUSER.DAT", "recent_document", T.format(6), "key_lastwrite", path="report.docx",
                      locator="RecentDocs\\0"),
        ForensicEvent("jumplist", r"C:\Evidence\x.automaticDestinations-ms", "jump_list_file", T.format(7), "file_modified"),
        ForensicEvent("jumplist", r"C:\Evidence\x.automaticDestinations-ms", "recent_file_access", T.format(8),
                      "destlist_timestamp", path=r"C:\Users\alice\other.txt", locator="x:stream:1"),
    ]
    return attach_target_keys(rows)


class CaseQueryNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.events = events()
        cls.path = Path(cls.temp.name) / "case.sqlite"
        save_case(cls.path, AnalysisResult(events=cls.events))
        cls.legacy = Path(cls.temp.name) / "legacy.sqlite"
        save_case(cls.legacy, AnalysisResult(events=cls.events))
        with closing(sqlite3.connect(cls.legacy)) as db:  # an index from an older version: answered from the raw events
            db.execute("UPDATE case_query_meta SET version=1")
            db.commit()
        cls.nodes = {n.key: n for r in build_tree(cls.events) for n in r.walk()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def expected(self, node):
        return sorted(e.locator or e.action for e in self.events if matches(node, e, OriginIndex()))

    def queried(self, path, node):
        with open_case_query(path) as query:
            page = query.query_events({"node": {"kind": node.kind, "value": node.value}}, limit=500)
            return sorted(e.locator or e.action for e in page.events), query.indexed

    def test_view_nodes_match_the_tree_in_both_paths(self):
        keys = ["art:web_history:history:visits", "art:web_history:history:downloads", "art:web_history:history:searches",
                "art:recent_documents:lnk:shortcuts", "art:recent_documents:targets",
                r"art:recent_documents:target:path:c:\users\alice\report.docx", "art:recent_documents:target:single"]
        jump = [k for k in self.nodes if k.startswith("art:recent_documents:jumplist:")]
        self.assertEqual(len(jump), 2)
        for key in keys + jump:
            node = self.nodes[key]
            for path, indexed in ((self.path, True), (self.legacy, False)):
                got, was_indexed = self.queried(path, node)
                self.assertEqual(was_indexed, indexed)
                self.assertEqual(got, self.expected(node), (key, path.name))

    def test_tree_counts_include_views(self):
        with open_case_query(self.path) as query:
            counts = query.tree_counts()
        actions = {(r["artifact"], r["action"]): r["records"] for r in counts["actions"]}
        self.assertEqual(actions[("history", "download")], 1)
        self.assertEqual(actions[("jumplist", "jump_list_file")], 1)
        self.assertEqual(counts["shortcuts"], 1)
        targets = {r["group"]: (r["kinds"], r["records"]) for r in counts["targets"]}
        self.assertEqual(targets[r"path:c:\users\alice\report.docx"], (2, 3))  # shortcut + recent list (name match)

    def test_quick_page_reads_first_records_only_from_an_indexed_case(self):
        from log_hunter.core.timeline import timeline
        from log_hunter.ui.case_view import quick_page
        events, total, counts = quick_page(self.path, 3)
        self.assertEqual(counts["records"], len(self.events))
        self.assertEqual(total, len(self.events))
        self.assertEqual([e.locator or e.action for e in events], [e.locator or e.action for e in timeline(self.events)[:3]])
        self.assertIsNone(quick_page(self.legacy, 3))  # no current index: the normal full load shows it
        self.assertIsNone(quick_page(Path(self.temp.name) / "missing.sqlite", 3))

    def test_db_tree_matches_loaded_tree_and_pages(self):
        from log_hunter.ui.case_view import db_page, db_tree, node_filter, quick_page
        _events, _total, counts = quick_page(self.path, 5)
        db_nodes = {n.key: n for r in db_tree(counts) for n in r.walk()}
        for key, node in self.nodes.items():
            if not key.startswith("art:") or key not in db_nodes:
                continue
            self.assertEqual((db_nodes[key].kind, db_nodes[key].count), (node.kind, node.count), key)
            if node_filter(node):
                got, total, _warnings = db_page(self.path, {"artifact": "전체", "status": "전체"}, db_nodes[key], 500)
                self.assertEqual(total, node.count, key)
                self.assertEqual(sorted(e.locator or e.action for e in got), self.expected(node), key)
        for key in ("art:web_history:history:visits", "art:recent_documents:lnk:shortcuts", "art:recent_documents:targets"):
            self.assertIn(key, db_nodes)
        self.assertFalse(node_filter(type("N", (), {"kind": "event_set", "value": frozenset()})()))

    def test_db_page_offset_and_sort(self):
        from log_hunter.ui.case_view import db_page, db_sort
        every = {"artifact": "전체", "status": "전체"}
        first, total, _ = db_page(self.path, every, None, 3)
        second, _, _ = db_page(self.path, every, None, 3, offset=3)
        self.assertEqual(total, 8)
        self.assertEqual([e.timestamp for e in first + second], [T.format(i) for i in range(1, 7)])
        newest, _, _ = db_page(self.path, every, None, 2, sort=db_sort("timestamp", True))
        self.assertEqual([e.timestamp for e in newest], [T.format(8), T.format(7)])
        self.assertEqual(db_sort("timestamp", False), "timeline")
        self.assertIsNone(db_sort("path", False))  # only the loaded view sorts by shown text

    def test_bad_view_node_values_are_rejected(self):
        from log_hunter.database.query_common import QueryInputError
        with open_case_query(self.path) as query:
            for node in ({"kind": "action_set", "value": "history"}, {"kind": "target_group", "value": 3}):
                with self.assertRaises(QueryInputError):
                    query.query_events({"node": node})


if __name__ == "__main__":
    unittest.main()
