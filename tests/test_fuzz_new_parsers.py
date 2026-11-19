"""Corrupted inputs for the newer parsers: seeded byte mutations and truncations of valid synthetic files must end in
records, recorded errors or a ValueError/OSError (a clean "bad input"), never another exception type."""
import importlib.util
import random
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.parser.browser_deleted import BrowserDeletedParser  # noqa: E402
from log_hunter.parser.chromium_prefs import BookmarksParser, BrowserExtensionsParser  # noqa: E402
from log_hunter.parser.email_message import EmailParser  # noqa: E402
from log_hunter.parser.registry_deleted import RegistryDeletedParser  # noqa: E402
from log_hunter.parser.srum import SRUMParser  # noqa: E402
from log_hunter.parser.webcache import WebCacheParser  # noqa: E402

ROUNDS = 40
ALLOWED = (ValueError, OSError)


def mutations(data, seed):
    rng = random.Random(seed)
    yield data[: len(data) // 2]
    yield data[:100]
    for _ in range(ROUNDS):
        blob = bytearray(data)
        for _ in range(rng.randint(1, 12)):
            position = rng.randrange(len(blob))
            blob[position] = rng.randrange(256)
        if rng.random() < 0.3:  # also break a length-like field with an extreme value
            position = rng.randrange(max(1, len(blob) - 4))
            struct.pack_into("<I", blob, position, rng.choice((0, 0x7FFFFFFF, 0xFFFFFFFF, len(blob) * 2)))
        yield bytes(blob)


class FuzzTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_parser(self, factory, name, data, seed):
        for index, blob in enumerate(mutations(data, seed)):
            path = self.root / f"{seed}-{index}" / name
            path.parent.mkdir()
            path.write_bytes(blob)
            parser = factory()
            started = time.monotonic()
            try:
                list(parser.parse(path))
            except ALLOWED:
                pass
            except Exception as exc:  # pragma: no cover - the failure message names the input
                self.fail(f"{factory.__name__} round {index}: {type(exc).__name__}: {exc}")
            self.assertLess(time.monotonic() - started, 10, f"{factory.__name__} round {index} too slow")

    def test_web_cache_and_srum_databases(self):
        import test_webcache
        import test_srum_ese
        cache = self.root / "seed" / "WebCacheV01.dat"
        cache.parent.mkdir()
        test_webcache.make(cache)
        self.run_parser(WebCacheParser, "WebCacheV01.dat", cache.read_bytes(), 1)
        srum = self.root / "seed" / "SRUDB.dat"
        test_srum_ese.make(srum)
        self.run_parser(SRUMParser, "SRUDB.dat", srum.read_bytes(), 2)

    def test_tagged_area_cannot_overwrite_fixed_columns(self):
        """A damaged tagged area that names column 1 must not replace the fixed value (it used to crash the catalog)."""
        import test_webcache
        from log_hunter.parser.ese import ESEDatabase
        path = self.root / "seed" / "WebCacheV01.dat"
        path.parent.mkdir()
        test_webcache.make(path)
        db = ESEDatabase(path)
        tagged = struct.pack("<HH", 1, 8) + struct.pack("<HH", 300, 9) + b"\x01A" + b"\x01B"
        self.assertEqual(sorted(db._tagged(tagged)), [300])

    def test_registry_free_cells(self):
        import test_registry_deleted
        case = test_registry_deleted.RegistryDeletedTests("test_garbage_and_live_cells_are_not_reported")
        case.setUp()
        try:
            self.run_parser(RegistryDeletedParser, "NTUSER.DAT", case.path.read_bytes(), 3)
        finally:
            case.tearDown()

    def test_history_free_pages(self):
        import test_browser_deleted
        seed = self.root / "seed" / "History"
        seed.parent.mkdir()
        test_browser_deleted.history_with_deleted(seed, deleted=40)
        self.run_parser(BrowserDeletedParser, "History", seed.read_bytes(), 4)

    def test_mail_and_settings_files(self):
        import test_email_messages
        self.run_parser(EmailParser, "m.eml", test_email_messages.MESSAGE.encode("utf-8"), 5)
        prefs = b'{"extensions":{"settings":{"a":{"manifest":{"name":"x","permissions":["tabs"]},"install_time":"13253760000000000"}}}}'
        self.run_parser(BrowserExtensionsParser, "Secure Preferences", prefs, 6)
        marks = b'{"roots":{"bookmark_bar":{"name":"b","children":[{"type":"url","name":"n","url":"https://example.com/","date_added":"1"}]}}}'
        self.run_parser(BookmarksParser, "Bookmarks", marks, 7)


if __name__ == "__main__":
    unittest.main()
