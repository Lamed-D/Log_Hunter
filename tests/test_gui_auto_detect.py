"""GUI side of automatic input detection (#13): what gets added, opened, asked about or only reported."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_hunter.core.auto_detect import detect_inputs
from log_hunter.ui import view_model
from test_image import mbr_disk, windows_volume


class DetectPlanTests(unittest.TestCase):
    def test_plan_sorts_detected_rows(self):
        rows = [("psreadline", "C:/Evidence/ConsoleHost_history.txt", None, "파일 이름"),
                ("image", "C:/Evidence/disk.E01", None, "E01 시그니처"),
                (None, "C:/Evidence/notes.bin", None, view_model.UNRECOGNIZED_REASON),
                (None, "C:/Evidence/SYSTEM.LOG1", None, "보조 파일입니다. 본 파일을 함께 선택하세요.")]
        plan = view_model.plan_detected(rows)
        self.assertEqual([r[0] for r in plan.inputs], ["psreadline"])
        self.assertEqual(plan.images, ["C:/Evidence/disk.E01"])
        self.assertEqual(plan.unknown, ["C:/Evidence/notes.bin"])
        self.assertEqual(plan.notes, [("C:/Evidence/SYSTEM.LOG1", "보조 파일입니다. 본 파일을 함께 선택하세요.")])
        summary = view_model.detect_summary(plan)
        self.assertIn("분석 대상으로 추가: 1개", summary)
        self.assertIn("PowerShell 명령어 기록: 1개", summary)
        self.assertIn("SYSTEM.LOG1: 보조 파일", summary)
        self.assertEqual(view_model.input_line("psreadline", "C:/a.txt", "파일 이름"),
                         "[PowerShell 명령어 기록] C:/a.txt  · 인식 근거: 파일 이름")

    def test_real_detection_matches_the_plan_rules(self):
        """Pins the engine's 'unrecognized' text: if it changes, this test says so."""
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "ConsoleHost_history.txt").write_text("whoami\n", encoding="utf-8")
            (folder / "notes.bin").write_bytes(b"xyz")
            (folder / "SYSTEM.LOG1").write_bytes(b"regf")
            volume, _system = windows_volume()
            (folder / "disk.dd").write_bytes(mbr_disk(volume))
            plan = view_model.plan_detected(detect_inputs([folder]))
        self.assertEqual([(a, Path(p).name) for a, p, _s, _r in plan.inputs], [("psreadline", "ConsoleHost_history.txt")])
        self.assertEqual([Path(p).name for p in plan.images], ["disk.dd"])
        self.assertEqual([Path(p).name for p in plan.unknown], ["notes.bin"])
        self.assertEqual([Path(p).name for p, _r in plan.notes], ["SYSTEM.LOG1"])


if __name__ == "__main__":
    unittest.main()
