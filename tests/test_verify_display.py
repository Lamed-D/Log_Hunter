"""#46: image verification result shown in plain words in the GUI evidence tab and the HTML report."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_hunter.core.labels import image_verification_lines
from log_hunter.core.pipeline import Pipeline
from log_hunter.main import save_result
from test_image import mbr_disk, windows_volume, write_e01


class VerificationTextTests(unittest.TestCase):
    def test_lines_for_each_state(self):
        self.assertEqual(image_verification_lines({}), [])
        match = image_verification_lines({"status": "match", "size": 2048, "bytes_read": 2048,
                                          "computed": {"sha256": "ab" * 32},
                                          "comparisons": [{"algorithm": "md5", "matches": True, "source": "ewf"}]})
        self.assertEqual(match[0], "이미지 무결성 검증: 저장 해시와 일치")
        self.assertIn("  MD5 일치 (저장값 출처: ewf)", match)
        self.assertIn("  읽은 데이터: 2,048 / 2,048바이트", match)
        self.assertTrue(any("출처의 진위" in line for line in match))
        cancelled = image_verification_lines({"status": "cancelled", "size": 4096, "bytes_read": 1024, "computed": {}})
        self.assertEqual(cancelled[0], "이미지 무결성 검증: 검증 취소")
        self.assertFalse(any("SHA-256" in line for line in cancelled))  # no partial hash shown as final
        self.assertFalse(any("출처의 진위" in line for line in cancelled))

    def test_report_shows_verification_for_a_verified_image(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            volume, _system = windows_volume()
            e01 = write_e01(root / "case.E01", mbr_disk(volume))[0]
            result = Pipeline().analyze_image(e01, root / "work", verify=True)
            save_result(result, root / "out")
            html = (root / "out" / "report.html").read_text(encoding="utf-8")
        self.assertIn("이미지 무결성 검증: 저장 해시와 일치", html)
        self.assertIn("MD5 일치", html)


if __name__ == "__main__":
    unittest.main()
