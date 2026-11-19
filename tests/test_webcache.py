"""Legacy browser web cache database (ESE): catalog, records, long values, 7-bit text and the visit/cookie records."""
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.auto_detect import detect_artifact
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import build_tree
from log_hunter.parser.ese import ESEDatabase, ESEError, decompress
from log_hunter.parser.webcache import cookie_domain, split_url
from log_hunter.ui import columns

spec = importlib.util.spec_from_file_location("ese_builder", Path(__file__).parent / "fixtures/ese_builder.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
B = builder
FT = 132537600000000000  # 2020-12-30 00:00:00 UTC
HOUR = 36_000_000_000
SECRET = b"cookie-value-should-not-appear"
CONTAINER = {1: ("EntryId", B.I64, 0), 10: ("SyncTime", B.I64, 0), 11: ("CreationTime", B.I64, 0),
             13: ("ModifiedTime", B.I64, 0), 14: ("AccessedTime", B.I64, 0), 9: ("AccessCount", B.U32, 0),
             2: ("ContainerId", B.I64, 0), 3: ("CacheId", B.I64, 0), 4: ("UrlHash", B.I64, 0), 5: ("SecureDirectory", B.U32, 0),
             6: ("FileSize", B.I64, 0), 7: ("Type", B.U32, 0), 8: ("Flags", B.U32, 0), 12: ("ExpiryTime", B.I64, 0),
             256: ("Url", B.LONG_TEXT, 1200), 260: ("ResponseHeaders", B.LONG_BINARY, 0)}


def pack7(text):
    """7-bit ASCII packing with the scheme header (for the decompression test)."""
    bits, count = 0, 0
    for i, ch in enumerate(text.encode("ascii")):
        bits |= ch << (7 * i)
        count += 7
    data = bits.to_bytes((count + 7) // 8, "little")
    used = count - (len(data) - 1) * 8
    return bytes([(1 << 3) | (used - 1)]) + data


def make(path, state=3):
    containers = ("Containers", {1: ("ContainerId", B.I64, 0), 128: ("Name", B.TEXT, 0)},
                  [{1: 1, 128: "MSHist012020123020201231"}, {1: 2, 128: "History"}, {1: 3, 128: "Content"}])
    daily = ("Container_1", CONTAINER, [
        {1: 1, 14: FT, 13: FT + 9 * HOUR, 9: 2, 256: ":2020123020201231: alice@https://example.com/page"},
        {1: 2, 14: FT + 60 * 10_000_000, 256: (0x05, b"\x05\x00\x00\x00"),  # Url kept as a separate long value
         260: (0x02 | 0x01, pack7("HTTP/1.1 200"))}])
    master = ("Container_2", CONTAINER, [{1: 7, 14: FT, 256: "Visited: alice@https://example.org/"}])
    content = ("Container_3", CONTAINER, [{1: 1, 14: FT, 256: "https://example.com/cached.css"}])
    cookies = ("CookieEntryEx_4", {1: ("EntryId", B.I64, 0), 2: ("Expires", B.I64, 0), 3: ("LastModified", B.I64, 0),
                                   257: ("RDomain", B.LONG_TEXT, 0), 258: ("Path", B.LONG_TEXT, 0),
                                   259: ("Name", B.LONG_BINARY, 0), 260: ("Value", B.LONG_BINARY, 0)},
               [{1: 1, 2: FT + 24 * HOUR, 3: FT, 257: (0x01, b"com.example"), 258: (0x01, b"/"),
                 259: (0x01, b"session\x00"), 260: (0x01, SECRET)}])
    url = "Visited: alice@https://example.net/long".encode("utf-16-le")
    B.build(path, [containers, daily, master, content, cookies], state=state,
            long_values={"Container_1": {b"\x05\x00\x00\x00": url}})


class WebCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "WebCacheV01.dat"
        make(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_reader_catalog_values_long_values_and_7bit_text(self):
        db = ESEDatabase(self.path)
        self.assertIn("Container_1", db.tables)
        rows = list(db.rows("Container_1"))
        self.assertEqual(rows[0]["Url"], ":2020123020201231: alice@https://example.com/page")
        self.assertEqual(rows[1]["Url"], "Visited: alice@https://example.net/long")  # from the long value tree
        self.assertEqual(rows[1]["ResponseHeaders"], b"HTTP/1.1 200")  # 7-bit packed
        self.assertEqual(rows[0]["AccessCount"], 2)
        self.assertEqual(db.warnings, [])
        self.assertEqual(decompress(pack7("abc")), b"abc")
        with self.assertRaises(ValueError):
            decompress(bytes([3 << 3, 1, 2]))  # Xpress is not supported: reported, not guessed

    def test_visits_summaries_and_cookies_without_values(self):
        result = Pipeline().analyze([("webcache", self.path)])
        events = {(e.action, e.locator): e for e in result.events}
        self.assertEqual(sorted(a for a, _ in events), ["cookie_stored", "url_summary", "url_visit", "url_visit"])
        visit = events[("url_visit", "Container_1:1")]
        self.assertEqual((visit.url, visit.details["user_hint"]), ("https://example.com/page", "alice"))
        self.assertEqual((visit.timestamp, visit.time_field), ("2020-12-30T00:00:00+00:00", "webcache_accessed"))
        # The daily container's modified time follows the local clock: kept raw, never converted or shown as UTC.
        self.assertEqual(visit.details["modified_time_raw_local"], FT + 9 * HOUR)
        self.assertNotIn("modified", visit.details)
        cookie = events[("cookie_stored", "CookieEntryEx_4:1")]
        self.assertEqual((cookie.details["cookie_site"], cookie.details["cookie_name"]), ("example.com", "session"))
        self.assertEqual(cookie.details["cookie_expires"], "2020-12-31T00:00:00+00:00")
        self.assertNotIn(SECRET.decode(), json.dumps([e.to_dict() for e in result.events], default=str))
        self.assertFalse(any("cached.css" in (e.url or "") for e in result.events))  # page contents are not history

    def test_tree_columns_detection(self):
        events = Pipeline().analyze([("webcache", self.path)]).events
        nodes = {n.key: n for r in build_tree(events) for n in r.walk()}
        self.assertEqual(nodes["art:web_history:webcache:visits"].count, 2)
        self.assertEqual(nodes["art:web_history:webcache:cookies"].count, 1)
        self.assertEqual(columns.columns_for(nodes["art:web_history:webcache:cookies"]), columns.CATEGORY_COLUMNS["web_cookies"])
        self.assertEqual(detect_artifact(str(self.path)), "webcache")

    def test_dirty_or_broken_databases(self):
        dirty = Path(self.temp.name) / "dirty" / "WebCacheV01.dat"
        dirty.parent.mkdir()
        make(dirty, state=2)
        result = Pipeline().analyze([("webcache", dirty)])
        self.assertTrue(result.events)
        self.assertTrue(any("정상 종료되지 않은" in e.message for e in result.errors))
        bad = Path(self.temp.name) / "bad.dat"
        bad.write_bytes(b"\x00" * 8192)
        with self.assertRaises(ESEError):
            ESEDatabase(bad)
        self.assertEqual(Pipeline().analyze([("webcache", bad)]).summaries[0]["state"], "failed")
        broken = bytearray(self.path.read_bytes())
        struct.pack_into("<H", broken, (6 + 1) * B.PAGE + 34, 60000)  # a table page with an impossible tag count
        corrupt = Path(self.temp.name) / "corrupt.dat"
        corrupt.write_bytes(bytes(broken))
        db = ESEDatabase(corrupt)
        list(db.rows("Container_1"))
        self.assertTrue(db.warnings)

    def test_helpers(self):
        self.assertEqual(split_url("Visited: bob@file:///C:/a.txt"), ("bob", "file:///C:/a.txt"))
        self.assertEqual(split_url("https://example.com/"), (None, "https://example.com/"))
        self.assertEqual(cookie_domain("com.example.www"), "www.example.com")


if __name__ == "__main__":
    unittest.main()
