"""File preview cache (thumbcache) columns in the result table and report, from synthetic cache files only."""
import json
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.labels import ARTIFACT_DESCRIPTIONS, column_label
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.tree import TreeNode
from log_hunter.main import save_result
from log_hunter.parser.thumbcache import ThumbcacheParser
from log_hunter.ui import columns
from test_thumbcache import cache_entry, cache_file, synthetic_png


def _parse(data):
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "thumbcache_256.db"
        path.write_bytes(data)
        parser = ThumbcacheParser()
        return list(parser.parse(path)), parser


def _shown(event):
    cols = columns.columns_for(TreeNode("thumbnail_cache", "파일 미리 보기 흔적", "artifacts", ("thumbcache",)))
    return dict(zip([c.key for c in cols], columns.row(event, cols, {}, None)))


def _event(**details):
    base = {"cache_id": "0000000000000001", "entry_offset": 0x20, "data_offset": 0x60, "data_size": 10,
            "image_format": "png", "image_sha256": "ab" * 32, "image_hash_status": "complete",
            "stored_data_checksum": "0000000000001234", "checksum_verified": False}
    base.update(details)
    return ForensicEvent("thumbcache", r"C:\Evidence\thumbcache_256.db", "thumbnail_cached", locator="0x20",
                         details=base)


class ThumbcacheColumnsTest(unittest.TestCase):
    def test_category_columns_and_headers(self):
        shown = _shown(_event())
        self.assertEqual(list(shown)[:8], ["cache_id", "image_format", "data_size", "cache_location", "image_sha256",
                                           "image_hash_status", "stored_checksum", "cache_check"])
        self.assertNotIn("timestamp", shown)  # the cache has no time: no time column at all
        self.assertNotIn("path", shown)  # nor a source path
        self.assertEqual(column_label("image_format"), "형식 (시그니처만)")

    def test_values_from_a_synthetic_cache_file(self):
        events, parser = _parse(cache_file(32, [cache_entry(32, synthetic_png(), cache_id=0xABC)]))
        self.assertEqual(parser.errors, [])
        shown = _shown(events[0])
        self.assertEqual(shown["cache_id"], "0000000000000abc")
        self.assertEqual(shown["image_format"], "PNG")
        self.assertEqual(shown["data_size"], str(len(synthetic_png())))
        self.assertRegex(shown["cache_location"], r"^항목 0x[0-9a-f]+ · 데이터 0x[0-9a-f]+$")
        self.assertEqual(len(shown["image_sha256"]), 64)
        self.assertEqual(shown["image_hash_status"], "완료")
        self.assertEqual(shown["stored_checksum"], "검증 안 됨")
        self.assertEqual(shown["cache_check"], "")
        self.assertIn("확정이 아닙니다", shown["description"])

    def test_hash_states_and_checksum_never_shown_verified(self):
        self.assertEqual(_shown(_event(image_hash_status="limit", image_sha256=None))["image_hash_status"],
                         "일부만 (크기 상한)")
        empty = _shown(_event(image_hash_status="empty", image_format="empty", data_size=0, image_sha256=None))
        self.assertEqual((empty["image_hash_status"], empty["image_format"], empty["image_sha256"]),
                         ("비어 있음", "비어 있음", ""))
        self.assertEqual(_shown(_event(image_format="unknown"))["image_format"], "알 수 없음")
        no_flag = _event()
        del no_flag.details["checksum_verified"]
        self.assertEqual(_shown(no_flag)["stored_checksum"], "검증 안 됨")

    def test_raw_aux_values_are_not_columns_and_decode_error_is_its_own_flag(self):
        shown = _shown(_event(entry_aux_28=256, entry_aux_32=256, identifier_decode_error=True))
        self.assertNotIn("256", shown.values())  # never shown as width/height or any decoded result
        self.assertEqual(shown["cache_check"], "식별자 문자 해석 오류")

    def test_description_says_presence_is_not_proof(self):
        text = ARTIFACT_DESCRIPTIONS["thumbcache"]
        self.assertIn("실제로 열었거나 지웠다는 확정이 아닙니다", text)
        self.assertIn("원본 파일 경로와 연결하지 않았", text)


class ThumbcacheReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.out = Path(self.temp.name) / "out"

    def tearDown(self):
        self.temp.cleanup()

    def test_report_tab_uses_same_columns_escaped_and_without_images(self):
        event = _event(image_format="<b>png</b>")
        event.source = r"C:\Evidence\<script>alert(1)</script>\thumbcache_256.db"
        save_result(AnalysisResult(events=[event]), self.out)
        page = (self.out / "report.html").read_text(encoding="utf-8")
        self.assertIn('data-panel="thumbcache">파일 미리 보기 흔적', page)
        panel = page[page.index('<div class="panel" id="thumbcache">'):]
        panel = panel[:panel.index('<div class="panel"', 10)]
        for key in ("cache_id", "cache_location", "image_hash_status", "stored_checksum"):
            self.assertIn(f"<th>{column_label(key)}</th>", panel)
        self.assertIn("<td>검증 안 됨</td>", panel)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", panel)
        self.assertNotIn("<script>alert(1)", panel)
        self.assertNotIn("<script>alert(1)</script>", page)  # the embedded JSON keeps "<\/script>"
        self.assertNotIn("<img", panel)
        self.assertNotIn("data:image", page)

    def test_no_cache_records_leave_report_without_the_tab(self):
        plain = ForensicEvent("prefetch", r"C:\Evidence\APP.EXE-1234ABCD.pf", "execution", "2024-01-01T00:00:00+00:00",
                              "last_run", path=r"C:\Users\alice\app.exe")
        save_result(AnalysisResult(events=[plain]), self.out)
        self.assertNotIn('id="thumbcache"', (self.out / "report.html").read_text(encoding="utf-8"))
        self.assertTrue(json.loads((self.out / "report.json").read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
