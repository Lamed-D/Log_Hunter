"""Result table layout: saved column order and widths per column set, kept in the user's settings file."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from log_hunter.ui import columns, settings


class OrderTests(unittest.TestCase):
    def test_every_set_starts_with_time_then_kind(self):
        for name, cols in columns.CATEGORY_COLUMNS.items():
            if name == "thumbnail_cache":  # cache metadata has no time at all
                continue
            keys = [c.key for c in cols]
            # 예약 작업: the registration time is its time column, then the task itself.
            self.assertEqual(keys[0], "registration_time" if name == "scheduled_tasks" else "timestamp", name)
            second = {"usb_devices": "device_kind_name", "security_detections": "action",
                      "scheduled_tasks": "task_name"}.get(name, "artifact")
            self.assertEqual(keys[1], second, name)  # one artifact only: what kind of record it is
            self.assertEqual(len(keys), len(set(keys)), name)
            self.assertEqual(columns.set_name(cols), name)
        self.assertEqual(columns.set_name(columns.DEFAULT), "default")

    def test_ordered_ignores_unknown_and_keeps_missing(self):
        cols = (columns.Column("a", 1), columns.Column("b", 1), columns.Column("c", 1))
        self.assertEqual([c.key for c in columns.ordered(cols, ["c", "gone", "a"])], ["c", "a", "b"])
        self.assertEqual(columns.ordered(cols, None), cols)

    def test_moved(self):
        self.assertEqual(columns.moved(["a", "b", "c", "d"], "a", "c"), ["b", "c", "a", "d"])  # to a later one: after it
        self.assertEqual(columns.moved(["a", "b", "c", "d"], "d", "b"), ["a", "d", "b", "c"])  # to an earlier one: before
        self.assertEqual(columns.moved(["a", "b"], "a", "zz"), ["a", "b"])


class SettingsTests(unittest.TestCase):
    def test_round_trip_and_damaged_values(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sub" / "settings.json"
            prefs = settings.Settings(path)
            self.assertEqual(prefs.columns("default"), ([], {}))
            prefs.set_columns("default", ["path", "timestamp"], {"path": 500, "timestamp": 160})
            self.assertTrue(prefs.save())
            again = settings.Settings(path)
            self.assertEqual(again.columns("default"), (["path", "timestamp"], {"path": 500, "timestamp": 160}))
            again.reset_columns("default")
            self.assertEqual(again.columns("default"), ([], {}))
            path.write_text(json.dumps({"columns": {"default": {"order": ["a", 3], "widths": {"a": 5, "b": "x", "c": 200}}}}),
                            encoding="utf-8")
            self.assertEqual(settings.Settings(path).columns("default"), (["a"], {"c": 200}))
            path.write_text("{broken", encoding="utf-8")
            self.assertEqual(settings.Settings(path).data, {})

    def test_damaged_field_types_fall_back_to_defaults(self):
        damaged = [{"columns": ["synthetic"]}, {"columns": {"default": ["x"]}}, {"columns": {"default": {"widths": [1]}}},
                   {"columns": {"default": {"order": "path", "widths": {"path": True}}}}, {"columns": None}]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.json"
            for data in damaged:
                with self.subTest(data=data):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    prefs = settings.Settings(path)
                    self.assertEqual(prefs.columns("default"), ([], {}))
                    prefs.reset_columns("default")
                    prefs.set_columns("default", ["path"], {"path": 300})
                    self.assertEqual(prefs.columns("default"), (["path"], {"path": 300}))

    def test_tag_preferences_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.json"
            prefs = settings.Settings(path)
            self.assertEqual(prefs.tag_preferences(), {})
            prefs.set_tag_preferences({"color_names": {"red": "꼭 볼 것"}, "subcategories": {"red": ["유출 의심"]}})
            prefs.save()
            self.assertEqual(settings.Settings(path).tag_preferences(),
                             {"color_names": {"red": "꼭 볼 것"}, "subcategories": {"red": ["유출 의심"]}})
            path.write_text(json.dumps({"tags": {"color_names": {"red": 3}, "subcategories": {"red": "x"}}}), encoding="utf-8")
            self.assertEqual(settings.Settings(path).tag_preferences(), {"color_names": {}, "subcategories": {}})

    def test_location_is_the_user_folder_unless_overridden(self):
        with mock.patch.dict(os.environ, {"APPDATA": r"C:\Users\alice\AppData\Roaming"}, clear=False):
            os.environ.pop(settings.ENV, None)
            self.assertEqual(settings.settings_path(), Path(r"C:\Users\alice\AppData\Roaming") / "LogHunter" / "settings.json")
        with mock.patch.dict(os.environ, {settings.ENV: "x.json"}):
            self.assertEqual(settings.settings_path(), Path("x.json"))


if __name__ == "__main__":
    unittest.main()


class TreeSwitchTests(unittest.TestCase):
    def test_switching_sets_after_a_custom_order(self):
        import tkinter as tk
        from tkinter import ttk
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"no display: {exc}")
        try:
            tree = ttk.Treeview(root, show="headings")
            usb = columns.CATEGORY_COLUMNS["usb_devices"]
            columns.configure_tree(tree, columns.DEFAULT, ["path", "timestamp"], {"path": 500}, lambda k: None)
            self.assertEqual(list(tree["displaycolumns"])[:2], ["path", "timestamp"])
            self.assertEqual(int(tree.column("path", "width")), 500)
            columns.configure_tree(tree, usb, [], {}, lambda k: None)  # failed with "Invalid column index"
            self.assertEqual(list(tree["displaycolumns"]), [c.key for c in usb])
            columns.configure_tree(tree, columns.DEFAULT, ["status"], {}, lambda k: None)
            self.assertEqual(list(tree["displaycolumns"])[0], "status")
        finally:
            root.destroy()
