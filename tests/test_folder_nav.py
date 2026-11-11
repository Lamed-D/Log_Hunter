"""File list folder moves: history, parent and the path bar."""
import unittest

from log_hunter.ui.folder_nav import FolderHistory, crumbs, folder_key, parent_key


class FolderNavTests(unittest.TestCase):
    def test_history_back_forward_and_new_visit_drops_forward(self):
        history = FolderHistory()
        for key in ("a", "b", "c"):
            history.visit(key)
        history.visit("c")  # the same folder twice is one step
        self.assertEqual(history.back(), "b")
        self.assertEqual(history.back(), "a")
        self.assertIsNone(history.back())
        self.assertEqual(history.forward(), "b")
        history.visit("d")
        self.assertFalse(history.can_forward())
        self.assertEqual(history.items, ["a", "b", "d"])

    def test_history_limit(self):
        history = FolderHistory(limit=3)
        for key in "abcde":
            history.visit(key)
        self.assertEqual(history.items, ["c", "d", "e"])
        self.assertEqual(history.back(), "d")

    def test_keys_parent_and_crumbs(self):
        key = folder_key({"image": "disk.E01", "volume": 2, "parts": ["Users", "alice"]})
        self.assertEqual(key, ("disk.E01", 2, ("Users", "alice")))
        self.assertEqual(parent_key(key), ("disk.E01", 2, ("Users",)))
        self.assertIsNone(parent_key(("disk.E01", 2, ())))
        self.assertEqual(crumbs(key, "[disk.E01]"), [("[disk.E01] 볼륨 2", ("disk.E01", 2, ())),
                                                     ("Users", ("disk.E01", 2, ("Users",))),
                                                     ("alice", key)])


if __name__ == "__main__":
    unittest.main()
