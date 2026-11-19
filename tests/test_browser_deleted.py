"""Deleted history addresses carved from free pages: only addresses no longer in the live table, marked as candidates."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import build_tree
from log_hunter.parser.browser_deleted import BrowserDeletedParser, carve, free_pages


def history_with_deleted(path, deleted=200):
    db = sqlite3.connect(path)
    db.execute("PRAGMA secure_delete=OFF")
    db.execute("PRAGMA page_size=4096")
    db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)")
    db.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)")
    db.execute("INSERT INTO urls VALUES(1,'https://example.com/kept','kept',13253760000000000)")
    db.executemany("INSERT INTO urls(url,title,last_visit_time) VALUES(?,?,0)",
                   [(f"https://example.org/removed/{i}/" + "x" * 300, "t") for i in range(deleted)])
    db.commit()
    db.execute("DELETE FROM urls WHERE id > 1")
    db.commit()
    db.close()


class BrowserDeletedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        folder = Path(self.temp.name) / "Google" / "Chrome" / "User Data" / "Default"
        folder.mkdir(parents=True)
        self.path = folder / "History"
        history_with_deleted(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_free_pages_and_carving(self):
        _size, pages, total = free_pages(self.path.read_bytes())
        self.assertTrue(pages)
        self.assertEqual(len(pages), total)
        self.assertEqual(carve(b"\x00https://example.com/a\x00junk http://example.org/b'"),
                         [b"https://example.com/a", b"http://example.org/b"])

    def test_only_deleted_addresses_are_candidates(self):
        events = list(BrowserDeletedParser().parse(self.path))
        urls = {e.url for e in events}
        self.assertTrue(any(u.startswith("https://example.org/removed/") for u in urls))
        self.assertNotIn("https://example.com/kept", urls)  # still in the live table
        first = events[0]
        self.assertIsNone(first.timestamp)
        self.assertEqual((first.status, first.details["deleted_confidence"]), ("partial", "carved_text"))

    def test_pipeline_detection_and_tree(self):
        kinds = sorted(row[0] for row in detect_inputs([str(self.path)]))
        self.assertEqual(kinds, ["browser_deleted", "history"])
        result = Pipeline().analyze([("history", self.path), ("browser_deleted", self.path)])
        nodes = {n.key: n for r in build_tree(result.events) for n in r.walk()}
        self.assertGreater(nodes["art:deleted_records:browser_deleted"].count, 0)
        self.assertEqual(nodes["art:web_history:history:visits"].count, 0)

    def test_not_sqlite(self):
        other = Path(self.temp.name) / "other"
        other.write_bytes(b"not a database" * 100)
        self.assertEqual(Pipeline().analyze([("browser_deleted", other)]).summaries[0]["state"], "failed")


if __name__ == "__main__":
    unittest.main()
