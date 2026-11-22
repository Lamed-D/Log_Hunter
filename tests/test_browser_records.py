"""Browser profile records besides visits: search terms, cookies, site icons and autofill (values never read)."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.auto_detect import detect_artifact
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import OriginIndex, build_tree, matches
from log_hunter.image.extract import ARTIFACT_SPECS
from log_hunter.ui import columns

T = 13253760000000000  # 2020-12-30 00:00:00 UTC (Chromium microseconds)
UNIX = 1609286400      # 2020-12-30 00:00:00 UTC
SECRET = "secret-value-should-not-appear"


def profile(root):
    folder = Path(root) / "Microsoft" / "Edge" / "User Data" / "Default"
    (folder / "Network").mkdir(parents=True)
    return folder


def make_cookies(folder):
    path = folder / "Network" / "Cookies"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT,"
               " expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, is_persistent INTEGER)")
    db.execute("INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (T, ".example.com", "session", SECRET, SECRET.encode(), "/", T + 86_400_000_000, 1, 1, T + 1_000_000, 1))
    db.execute("INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?,?)", (T, "example.org", "pref", SECRET, b"", "/", 0, 0, 0, 0, 0))
    db.commit()
    db.close()
    return path


def make_favicons(folder):
    path = folder / "Favicons"
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE favicons(id INTEGER PRIMARY KEY, url TEXT, icon_type INTEGER);"
                     "CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY, icon_id INTEGER, last_updated INTEGER, image_data BLOB,"
                     " width INTEGER, height INTEGER, last_requested INTEGER);"
                     "CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY, page_url TEXT, icon_id INTEGER);")
    db.execute("INSERT INTO favicons VALUES(1,'https://example.com/favicon.ico',1)")
    db.execute("INSERT INTO favicon_bitmaps VALUES(1,1,?,x'00',16,16,0)", (T,))
    db.execute("INSERT INTO icon_mapping VALUES(1,'https://example.com/page',1)")
    db.commit()
    db.close()
    return path


def make_web_data(folder):
    path = folder / "Web Data"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE autofill(name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER)")
    db.execute("INSERT INTO autofill VALUES('email',?,?,?,?,3)", (SECRET, SECRET, UNIX, UNIX + 60))
    db.commit()
    db.close()
    return path


def make_history(folder):
    path = folder / "History"
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER);"
                     "CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);")
    db.execute("INSERT INTO urls VALUES(1,'https://search.example.com/?q=report','report',?)", (T,))
    db.execute("INSERT INTO keyword_search_terms VALUES(2,1,'Report','report')")
    db.commit()
    db.close()
    return path


class BrowserRecordTests(unittest.TestCase):
    def test_repeated_visits_keep_both_clocks(self):
        from log_hunter.parser.history import HistoryParser

        with tempfile.TemporaryDirectory() as tmp:
            path = make_history(Path(tmp))
            db = sqlite3.connect(path)
            db.executescript("CREATE TABLE visits(id INTEGER, url INTEGER, visit_time INTEGER, transition INTEGER);")
            db.executemany("INSERT INTO visits VALUES(?,1,?,0)", [(1, T - 500_000), (2, T)])
            db.commit()
            db.close()
            visits = sorted((e for e in HistoryParser().parse(path) if e.action == "url_visit"),
                            key=lambda e: e.locator)
            self.assertEqual([e.timestamp for e in visits],
                             ["2020-12-29T23:59:59.500000+00:00", "2020-12-30T00:00:00+00:00"])
            self.assertEqual([e.details["url_last_visit_utc"] for e in visits],
                             ["2020-12-30T00:00:00+00:00"] * 2)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        folder = profile(self.temp.name)
        self.paths = {"cookies": make_cookies(folder), "favicons": make_favicons(folder),
                      "autofill": make_web_data(folder), "history": make_history(folder)}
        self.result = Pipeline().analyze([(a, p) for a, p in self.paths.items()])
        self.events = self.result.events

    def tearDown(self):
        self.temp.cleanup()

    def of(self, artifact):
        return [e for e in self.events if e.artifact == artifact]

    def test_values_are_never_stored(self):
        text = json.dumps([e.to_dict() for e in self.events], ensure_ascii=False, default=str)
        self.assertNotIn(SECRET, text)

    def test_cookies_keep_site_name_and_times(self):
        cookies = {e.details["cookie_name"]: e for e in self.of("cookies")}
        session = cookies["session"]
        self.assertEqual((session.url, session.time_field), (".example.com", "cookie_last_access"))
        self.assertEqual(session.timestamp, "2020-12-30T00:00:01+00:00")
        self.assertEqual(session.details["cookie_expires"], "2020-12-31T00:00:00+00:00")
        self.assertTrue(session.details["cookie_secure"])
        self.assertEqual(session.details["browser"], "Microsoft Edge")
        pref = cookies["pref"]  # never used: falls back to its creation time
        self.assertEqual(pref.time_field, "cookie_created")
        self.assertIsNone(pref.details["cookie_expires"])

    def test_site_icon_and_autofill(self):
        (icon,) = self.of("favicons")
        self.assertEqual((icon.url, icon.details["icon_url"]), ("https://example.com/page", "https://example.com/favicon.ico"))
        self.assertEqual(icon.timestamp, "2020-12-30T00:00:00+00:00")
        (entry,) = self.of("autofill")
        self.assertEqual((entry.details["field_name"], entry.details["use_count"]), ("email", 3))
        self.assertEqual(entry.timestamp, "2020-12-30T00:01:00+00:00")
        self.assertEqual(entry.details["first_used"], "2020-12-30T00:00:00+00:00")

    def test_search_terms_come_from_the_history_database(self):
        (search,) = [e for e in self.of("history") if e.action == "web_search"]
        self.assertEqual(search.details["search_term"], "Report")
        self.assertEqual((search.time_field, search.timestamp), ("search_last_visit", "2020-12-30T00:00:00+00:00"))
        roots = build_tree(self.events)
        nodes = {n.key: n for r in roots for n in r.walk()}
        node = nodes["art:web_history:history:searches"]
        self.assertEqual(node.count, 1)
        self.assertFalse(matches(nodes["art:web_history:history:visits"], search, OriginIndex()))
        self.assertEqual(columns.columns_for(node), columns.CATEGORY_COLUMNS["web_searches"])
        self.assertEqual(columns.columns_for(nodes["art:web_history:cookies"]), columns.CATEGORY_COLUMNS["web_cookies"])

    def test_evidence_files_are_unchanged_and_sidecars_registered(self):
        self.assertTrue(all(s["state"] == "ok" for s in self.result.summaries), self.result.summaries)
        self.assertEqual(self.result.errors, [])

    def test_detection_and_image_patterns(self):
        for artifact, path in self.paths.items():
            self.assertEqual(detect_artifact(str(path)), artifact)
        self.assertIsNone(detect_artifact(str(Path(self.temp.name) / "Cookies")))  # not in a browser profile
        patterns = {p for p, artifacts, _ in ARTIFACT_SPECS if artifacts[0] in ("cookies", "favicons", "autofill")}
        self.assertIn("Users/*/AppData/Local/Google/Chrome/User Data/*/Network/Cookies", patterns)
        self.assertIn("Users/*/AppData/Local/Microsoft/Edge/User Data/*/Web Data", patterns)

    def test_damaged_database_is_an_error_not_a_crash(self):
        bad = Path(self.temp.name) / "bad" / "Favicons"
        bad.parent.mkdir()
        sqlite3.connect(bad).close()
        result = Pipeline().analyze([("favicons", bad)])
        self.assertEqual(result.events, [])
        self.assertEqual(result.summaries[0]["state"], "failed")


if __name__ == "__main__":
    unittest.main()
