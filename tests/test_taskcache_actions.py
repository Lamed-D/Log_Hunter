"""Registered task actions: an Exec action may be followed by a 2-byte field that is not the next action's marker."""
import struct
import unittest

from log_hunter.parser.taskcache import actions_info


def text(value):
    raw = value.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def exec_action(command, arguments="", flags=None):
    data = struct.pack("<H", 0x6666) + text("") + text(command) + text(arguments) + text("")
    return data + (struct.pack("<H", flags) if flags is not None else b"")


class TaskCacheActionTests(unittest.TestCase):
    def test_trailing_flags_after_exec(self):
        blob = struct.pack("<H", 3) + text("Author") + exec_action(r"C:\Tools\a.exe", "/c", flags=0)
        result = actions_info(blob)
        self.assertEqual(result["parse_state"], "decoded")
        self.assertEqual(result["actions"][0]["command"], r"C:\Tools\a.exe")
        self.assertEqual(result["actions"][0]["flags"], 0)

    def test_two_actions_with_and_without_flags(self):
        blob = (struct.pack("<H", 3) + text("Author") + exec_action(r"C:\Tools\a.exe", flags=1)
                + exec_action(r"C:\Tools\b.exe"))
        result = actions_info(blob)
        self.assertEqual(result["parse_state"], "decoded")
        self.assertEqual([a["command"] for a in result["actions"]], [r"C:\Tools\a.exe", r"C:\Tools\b.exe"])
        self.assertNotIn("flags", result["actions"][1])

    def test_truncation_is_still_reported(self):
        blob = struct.pack("<H", 3) + text("Author") + exec_action(r"C:\Tools\a.exe")[:-3]
        self.assertEqual(actions_info(blob)["parse_state"], "damaged")


if __name__ == "__main__":
    unittest.main()
