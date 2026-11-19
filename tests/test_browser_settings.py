"""Browser settings files: extensions, profiles and bookmarks (Chromium JSON and .url favorites)."""
import json
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.auto_detect import detect_artifact
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import build_tree
from log_hunter.ui import columns

T = "13253760000000000"  # 2020-12-30 00:00:00 UTC as Chromium keeps it in settings (text)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class BrowserSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "Google" / "Chrome" / "User Data"
        default = root / "Default"
        ext = {"id1": {"manifest": {"name": "Example Tool", "version": "1.2", "permissions": ["tabs", "storage"]},
                       "first_install_time": T, "state": 1, "from_webstore": True},
               "id2": {"manifest": {"name": "__MSG_appName__"}, "install_time": T, "state": 0}}
        self.secure = write_json(default / "Secure Preferences", {"extensions": {"settings": ext}})
        self.prefs = write_json(default / "Preferences", {"extensions": {"settings": {
            "id1": {"manifest": {"name": "Example Tool"}}, "id3": {"manifest": {"name": "Only Here"}}}}})
        self.state = write_json(root / "Local State", {"profile": {"info_cache": {
            "Default": {"name": "Person 1", "user_name": "alice@example.com", "active_time": 1609286400.5}}}})
        self.bookmarks = write_json(default / "Bookmarks", {"roots": {"bookmark_bar": {"name": "Bar", "children": [
            {"type": "folder", "name": "Work", "children": [
                {"type": "url", "id": "7", "name": "Example", "url": "https://example.com/", "date_added": T}]}]}}})
        self.url = Path(self.temp.name) / "Users" / "alice" / "Favorites" / "Example.url"
        self.url.parent.mkdir(parents=True)
        self.url.write_text("[InternetShortcut]\r\nURL=https://example.org/\r\n", encoding="utf-8")
        times = {str(self.url.resolve()).casefold(): {"created": "2024-01-01T00:00:00+00:00"}}
        inputs = [("browser_extensions", self.secure), ("browser_extensions", self.prefs),
                  ("browser_profiles", self.state), ("bookmarks", self.bookmarks), ("bookmarks", self.url)]
        self.result = Pipeline(times).analyze(inputs)
        self.events = self.result.events

    def tearDown(self):
        self.temp.cleanup()

    def of(self, artifact):
        return [e for e in self.events if e.artifact == artifact]

    def test_extensions_once_each_with_permissions_and_install_time(self):
        by_id = {e.details["extension_id"]: e for e in self.of("browser_extensions")}
        self.assertEqual(sorted(by_id), ["id1", "id2", "id3"])  # id1 in both files is one record
        tool = by_id["id1"]
        self.assertEqual((tool.details["extension_name"], tool.details["extension_version"]), ("Example Tool", "1.2"))
        self.assertEqual(tool.details["extension_permissions"], ["tabs", "storage"])
        self.assertTrue(tool.details["extension_enabled"])
        self.assertEqual(tool.timestamp, "2020-12-30T00:00:00+00:00")
        self.assertEqual(by_id["id2"].details["name_localized_key"], "__MSG_appName__")
        self.assertFalse(by_id["id2"].details["extension_enabled"])
        self.assertEqual(columns.cell("extension_permissions", tool, {}, None), "tabs, storage")

    def test_profiles_and_bookmarks(self):
        (profile,) = self.of("browser_profiles")
        self.assertEqual((profile.details["account_name"], profile.details["browser"]), ("alice@example.com", "Google Chrome"))
        self.assertEqual(profile.timestamp, "2020-12-30T00:00:00.500000+00:00")
        marks = {e.url: e for e in self.of("bookmarks")}
        chromium = marks["https://example.com/"]
        self.assertEqual(chromium.details["bookmark_folder"], "Bar/Work")
        self.assertEqual(chromium.time_field, "bookmark_added")
        favorite = marks["https://example.org/"]
        self.assertEqual((favorite.time_field, favorite.timestamp), ("bookmark_file_created", "2024-01-01T00:00:00+00:00"))

    def test_tree_columns_and_detection(self):
        nodes = {n.key: n for r in build_tree(self.events) for n in r.walk()}
        self.assertEqual(nodes["art:web_history:browser_extensions"].count, 3)
        self.assertEqual(columns.columns_for(nodes["art:web_history:bookmarks"]), columns.CATEGORY_COLUMNS["web_bookmarks"])
        self.assertEqual(detect_artifact(str(self.secure)), "browser_extensions")
        self.assertEqual(detect_artifact(str(self.state)), "browser_profiles")
        self.assertEqual(detect_artifact(str(self.bookmarks)), "bookmarks")
        self.assertEqual(detect_artifact(str(self.url)), "bookmarks")

    def test_broken_settings_file_is_an_error_not_a_crash(self):
        bad = Path(self.temp.name) / "bad" / "Preferences"
        bad.parent.mkdir()
        bad.write_text("{not json", encoding="utf-8")
        result = Pipeline().analyze([("browser_extensions", bad)])
        self.assertEqual((result.events, result.summaries[0]["state"]), ([], "failed"))


if __name__ == "__main__":
    unittest.main()
