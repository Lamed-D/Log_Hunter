"""Damaged inputs found by fuzzing: a hive without a readable Select key and a truncated SQLite database."""
import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures.synthetic_windows_case import put, registry_bytes  # noqa: E402
from log_hunter.core.pipeline import Pipeline  # noqa: E402
from log_hunter.parser.registry import Hive, current_controlset  # noqa: E402


def dword(name, value):
    return name, 4, struct.pack("<i", value)


class DamagedInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def hive(self, tree):
        path = self.root / "SYSTEM"
        path.write_bytes(registry_bytes(tree, "SYSTEM"))
        return Hive(path)

    def test_missing_select_uses_the_only_control_set(self):
        tree = {}
        put(tree, r"ControlSet002\Control", [dword("X", 1)])
        self.assertEqual(current_controlset(self.hive(tree)), "ControlSet002")

    def test_missing_select_with_several_sets_is_unknown_not_guessed(self):
        tree = {}
        put(tree, r"ControlSet001\Control", [dword("X", 1)])
        put(tree, r"ControlSet002\Control", [dword("X", 1)])
        with self.assertRaisesRegex(ValueError, "활성 ControlSet 미상"):
            current_controlset(self.hive(tree))

    def test_readable_select_wins(self):
        tree = {}
        put(tree, "Select", [dword("Current", 1)])
        put(tree, r"ControlSet001\Control", [dword("X", 1)])
        put(tree, r"ControlSet002\Control", [dword("X", 1)])
        self.assertEqual(current_controlset(self.hive(tree)), "ControlSet001")

    def test_truncated_sqlite_gets_a_plain_message(self):
        profile = self.root / "Default"
        profile.mkdir()
        path = profile / "Cookies"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, creation_utc INTEGER)")
            db.executemany("INSERT INTO cookies VALUES (?, ?, ?)", [("example.com", f"n{i}", 0) for i in range(500)])
        db.close()
        data = path.read_bytes()
        path.write_bytes(data[:len(data) // 3])
        result = Pipeline().analyze([("cookies", path)])
        messages = [e.message for e in result.errors]
        self.assertEqual(result.summaries[0]["state"], "failed")
        self.assertTrue(any("SQLite 데이터베이스가 손상" in m for m in messages), messages)


if __name__ == "__main__":
    unittest.main()
