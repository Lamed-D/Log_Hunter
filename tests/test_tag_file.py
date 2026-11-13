"""Standalone examiner tag files use only synthetic records."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from log_hunter.core.tags import TagBook, load_tag_file, save_tag_file


class TagFileTest(unittest.TestCase):
    def test_round_trip_includes_unused_categories_and_notes(self):
        book = TagBook()
        book.rename_color("red", "중요 기록")
        book.add_subcategory("yellow", "재검토")
        book.toggle("event:synthetic", "event", {}, "red")
        book.set_note("file:synthetic", "file", {}, "확인할 항목")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tags.json"
            save_tag_file(path, book)
            loaded = load_tag_file(path)
        self.assertEqual(loaded.rows(), book.rows())
        self.assertEqual(loaded.preferences(), book.preferences())

    def test_empty_book_preserves_preferences(self):
        book = TagBook()
        book.add_subcategory("green", "확인 완료 항목")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tags.json"
            save_tag_file(path, book)
            self.assertEqual(load_tag_file(path).preferences(), book.preferences())

    def test_malformed_and_future_formats_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tags.json"
            book = TagBook()
            book.toggle("event:synthetic", "event", {}, "red")
            save_tag_file(path, book)
            valid = json.loads(path.read_text(encoding="utf-8"))
            for field, value in [("version", 99), ("rows", {}), ("preferences", [])]:
                with self.subTest(field=field):
                    path.write_text(json.dumps({**valid, field: value}), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_tag_file(path)
            for field, value in [("tags", [None]), ("key_version", 999), ("note", []), ("ref", [])]:
                with self.subTest(field=field):
                    data = {**valid, "rows": [{**valid["rows"][0], field: value}]}
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_tag_file(path)

    def test_failed_replace_preserves_existing_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tags.json"
            path.write_text("previous", encoding="utf-8")
            with patch("log_hunter.core.tags.os.replace", side_effect=OSError("write failed")):
                with self.assertRaises(OSError):
                    save_tag_file(path, TagBook())
            self.assertEqual(path.read_text(encoding="utf-8"), "previous")
            self.assertEqual(list(Path(folder).iterdir()), [path])
