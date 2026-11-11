"""Issue #24: page results of one file must never show while another file is selected."""
import unittest

from log_hunter.ui.content import PAGE_SIZE, ContentSession


class Bytes:
    def __init__(self, fill, pages):
        self.data = fill * (PAGE_SIZE * pages)
        self.size = len(self.data)

    def read(self, offset, length):
        return self.data[offset:offset + length]

    def sha256(self):
        return "0" * 64

    def info(self):
        return {"path": "mem", "size": self.size}


class ContentSessionTests(unittest.TestCase):
    def test_page_of_previous_file_is_dropped_after_switch(self):
        session = ContentSession()
        kind, view = session.accept_content(session.open(lambda: Bytes(b"A", 2))())
        self.assertEqual((kind, view["pages"]), ("view", 2))
        page_a = session.turn(1)                     # user asks for A's page 2 ...
        load_b = session.open(lambda: Bytes(b"B", 1))  # ... then switches to B before it is read
        self.assertIsNone(session.turn(1))           # no page jobs while B is loading
        self.assertEqual(session.accept_content(load_b())[0], "view")
        self.assertIsNone(session.accept_page(page_a()))  # A's page arrives late: dropped
        self.assertEqual(session.pages, 1)

    def test_stale_file_result_and_errors(self):
        session = ContentSession()
        old = session.open(lambda: Bytes(b"A", 1))
        new = session.open(lambda: (_ for _ in ()).throw(OSError("읽기 실패")))
        self.assertIsNone(session.accept_content(old()))
        self.assertEqual(session.accept_content(new()), ("error", "읽기 실패"))
        self.assertIsNone(session.turn(1))

    def test_paging_within_one_file(self):
        session = ContentSession()
        session.accept_content(session.open(lambda: Bytes(b"A", 3))())
        self.assertIsNone(session.turn(-1))
        page, text = session.accept_page(session.turn(1)())
        self.assertEqual(page, 1)
        self.assertTrue(text.startswith("00001000  41 41"))
        stale = session.turn(1)
        session.turn(-1)                             # user went back before page 3 arrived
        self.assertIsNone(session.accept_page(stale()))


if __name__ == "__main__":
    unittest.main()
