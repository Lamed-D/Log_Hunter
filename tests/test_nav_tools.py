"""Left tree helpers: find by name, back/forward history, selected path (no Tk)."""
import unittest

from log_hunter.ui import nav_tools

TREE = {"": ["a", "b"], "a": ["a1", "a2"], "b": ["b1"], "a1": [], "a2": [], "b1": []}
LABELS = {"a": "찾은 기록", "a1": "예약된 작업", "a2": "USB 장치", "b": "사용자 계정", "b1": "alice 예약"}
PARENT = {"a1": "a", "a2": "a", "b1": "b"}


class NavToolsTest(unittest.TestCase):
    def test_find_next_wraps_and_ignores_case(self):
        order = list(nav_tools.walk(TREE.get))
        self.assertEqual(order, ["a", "a1", "a2", "b", "b1"])
        self.assertEqual(nav_tools.find_next(order, LABELS.get, "예약"), "a1")
        self.assertEqual(nav_tools.find_next(order, LABELS.get, "예약", "a1"), "b1")
        self.assertEqual(nav_tools.find_next(order, LABELS.get, "예약", "b1"), "a1")
        self.assertEqual(nav_tools.find_next(order, LABELS.get, "usb"), "a2")
        self.assertIsNone(nav_tools.find_next(order, LABELS.get, "없음"))
        self.assertIsNone(nav_tools.find_next(order, LABELS.get, "  "))

    def test_path_and_history(self):
        self.assertEqual(nav_tools.path_text("a1", PARENT.get, LABELS.get), "찾은 기록 › 예약된 작업")
        h = nav_tools.History()
        for key in ("x", "y", "y", "z"):
            h.visit(key)
        self.assertEqual((h.back(), h.back(), h.back()), ("y", "x", None))
        self.assertEqual(h.forward(), "y")
        h.visit("w")
        self.assertIsNone(h.forward())
        h.drop(lambda k: k != "x")
        self.assertEqual(h.back_keys, ["y"])


if __name__ == "__main__":
    unittest.main()
