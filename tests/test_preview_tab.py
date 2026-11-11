"""미리 보기 tab data: summary lines, text, image bytes and the disguised-extension warning (synthetic files)."""
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.ui import content


def tiny_png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"\x00" + b"\xff\x00\x00" * 2
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


class PreviewTabTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def view(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return content.preview_view(content.LocalFile(path))

    def test_text_file(self):
        view = self.view("notes.txt", "alice 메모\n두 번째 줄".encode("utf-8"))
        self.assertIn("미리보기 종류: 텍스트", view["lines"])
        self.assertIn("두 번째 줄", view["text"])
        self.assertIsNone(view["image"])

    def test_image_and_disguised_extension(self):
        png = self.view("photo.png", tiny_png())
        self.assertTrue(png["image"])
        self.assertEqual((png["format"] or "png").lower(), "png")
        self.assertFalse(any(line.startswith("⚠") for line in png["lines"]))
        disguised = self.view("report.txt", tiny_png())
        warning = [line for line in disguised["lines"] if line.startswith("⚠")]
        self.assertEqual(len(warning), 1)
        self.assertIn("확장자 위장 가능성", warning[0])

    def test_empty_file_says_why(self):
        view = self.view("empty.bin", b"")
        self.assertTrue(any(line.startswith("미리보기 없는 이유") or "데이터 상태" in line for line in view["lines"]))

    def test_unsupported_input_does_not_raise(self):
        view = content.preview_view(object())  # the engine reports why instead of raising
        self.assertIn("미리보기 없는 이유: 지원하지 않는 미리보기 입력입니다", view["lines"])

    def test_content_job_carries_the_preview(self):
        path = self.root / "a.txt"
        path.write_text("hello", encoding="utf-8")
        session = content.ContentSession()
        job = session.open(lambda: content.LocalFile(path))
        kind, view = session.accept_content(job())
        self.assertEqual(kind, "view")
        self.assertIn("hello", view["preview"]["text"])


if __name__ == "__main__":
    unittest.main()
