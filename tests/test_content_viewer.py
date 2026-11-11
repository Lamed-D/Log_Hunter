"""Content viewer data (hex, strings, file info) and the background job runner."""
import queue
import tempfile
import threading
import unittest
from pathlib import Path

from log_hunter.ui import content
from log_hunter.ui.jobs import JobRunner


class ContentTests(unittest.TestCase):
    def test_hex_lines(self):
        lines = content.hex_lines(b"MZ\x90\x00" + bytes(12) + b"AB", base_offset=0x1000)
        self.assertEqual(lines[0], "00001000  4d 5a 90 00 00 00 00 00 00 00 00 00 00 00 00 00  |MZ..............|")
        self.assertTrue(lines[1].startswith("00001010  41 42 "))
        self.assertTrue(lines[1].endswith("|AB|"))

    def test_strings_ascii_and_utf16_in_order(self):
        data = b"\x00\x01Hello world\xff\xff" +"C:/Users/a".encode("utf-16-le") + b"\xff\xffabc"
        found = content.extract_strings(data)
        self.assertEqual([(kind, text) for _o, kind, text in found], [("ASCII", "Hello world"), ("UTF-16", "C:/Users/a")])
        self.assertEqual(found[0][0], 2)

    def test_load_local_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "a.bin"
            path.write_bytes(b"Hello world" + bytes(5000))
            view = content.load(content.LocalFile(path), {"image_path": r"\Windows\a.bin", "volume": 0})
        rows = dict(view["info"])
        self.assertEqual(rows["이미지 안 경로"], r"\Windows\a.bin")
        self.assertEqual(rows["크기"], "5,011바이트")
        self.assertEqual(len(rows["SHA-256"]), 64)
        self.assertEqual(view["pages"], 2)
        self.assertIn("Hello world", view["strings"])
        self.assertTrue(view["hex"].startswith("00000000  48 65 6c 6c 6f"))

    def test_empty_and_page_count(self):
        self.assertEqual(content.page_count(0), 1)
        self.assertEqual(content.page_count(4097), 2)
        self.assertEqual(content.strings_text([], False), "읽을 수 있는 문자열이 없습니다")

    def test_extracted_copy_does_not_show_extraction_time_as_modified(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "SYSTEM"
            path.write_bytes(b"regf")
            evidence = [SimpleNamespace(source=str(path), sha256="ab" * 32,
                                        metadata={"image": "case.E01", "image_path": "/Windows/SYSTEM", "volume": 0})]
            extraction = SimpleNamespace(file_index=lambda: {str(path.resolve()).casefold(): {"created": "2020-01-01T00:00:00+00:00"}})
            extra = content.record_file_extra(str(path), evidence, [extraction])
            rows = dict(content.load(content.LocalFile(path), extra)["info"])
        self.assertEqual(rows["생성 (UTC)"], "2020-01-01T00:00:00+00:00")
        self.assertNotIn("수정 (UTC)", rows)  # the copy's mtime is the extraction time
        self.assertEqual(rows["분석에 쓴 추출 사본"], str(path))
        self.assertEqual(rows["SHA-256"], "ab" * 32)
        self.assertEqual(rows["디스크 이미지"], "case.E01")


class JobRunnerTests(unittest.TestCase):
    def test_results_errors_and_stale_tokens(self):
        mailbox = queue.Queue()
        runner = JobRunner(mailbox)
        gate = threading.Event()
        runner.submit("block", gate.wait, 5)  # keeps the worker busy while the next jobs queue up
        old = runner.submit("view", lambda: "old")
        new = runner.submit("view", lambda: "new")
        runner.submit("other", lambda: 1 / 0)
        gate.set()
        results = [mailbox.get(timeout=5)[1] for _ in range(3)]
        by_tag = {(tag, token): (result, error) for tag, token, result, error in results}
        self.assertNotIn(("view", old), by_tag)  # superseded before it started
        self.assertEqual(by_tag[("view", new)], ("new", None))
        self.assertEqual(runner.latest("view"), new)
        self.assertIn("division by zero", by_tag[("other", 1)][1])


if __name__ == "__main__":
    unittest.main()
