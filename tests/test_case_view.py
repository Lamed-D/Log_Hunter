"""저장한 분석: recent list in the user settings, list rows, save-folder check (no Tk, fake paths)."""
import json
import tempfile
import unittest
from pathlib import Path

from log_hunter.ui import case_view
from log_hunter.ui.settings import RECENT_LIMIT, Settings


class CaseViewTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "settings.json"

    def test_recent_list_newest_first_unique_and_limited(self):
        prefs = Settings(self.path)
        for i in range(RECENT_LIMIT + 3):
            prefs.add_recent_case(rf"C:\Evidence\case{i}\case.sqlite", name=f"case{i}", events=i)
        prefs.add_recent_case(r"c:\evidence\CASE5\case.sqlite", name="again", events=50)
        self.assertTrue(prefs.save())
        rows = Settings(self.path).recent_cases()
        self.assertEqual(len(rows), RECENT_LIMIT)
        self.assertEqual(rows[0]["name"], "again")
        self.assertEqual(sum(1 for r in rows if "case5" in r["path"].casefold()), 1)
        prefs.remove_recent_case(rows[0]["path"])
        self.assertNotIn("again", [r["name"] for r in prefs.recent_cases()])

    def test_damaged_recent_rows_are_dropped(self):
        self.path.write_text(json.dumps({"recent_cases": [5, {"path": ""}, {"path": r"C:\Evidence\a\case.sqlite",
                                                                             "events": True, "name": 3}]}), encoding="utf-8")
        self.assertEqual(Settings(self.path).recent_cases(), [{"path": r"C:\Evidence\a\case.sqlite", "name": "",
                                                               "saved_at": "", "events": None, "source_state": ""}])
        self.path.write_text(json.dumps({"recent_cases": "x"}), encoding="utf-8")
        self.assertEqual(Settings(self.path).recent_cases(), [])

    def test_rows_mark_missing_files(self):
        entries = [{"path": r"C:\Evidence\alice\case.sqlite", "name": "", "saved_at": "2024-01-01T10:00:00+00:00",
                    "events": 1234, "source_state": "linked"},
                   {"path": r"C:\Evidence\gone\case.sqlite", "name": "gone", "saved_at": "", "events": None, "source_state": ""}]
        rows = case_view.recent_rows(entries, exists=lambda p: "alice" in p)
        self.assertEqual(rows[0][1][:4], ("alice", "2024-01-01 10:00:00 (UTC)", "1,234", "원본 연결됨"))
        self.assertFalse(rows[0][2])
        self.assertEqual(rows[1][1][:4], ("gone", "알 수 없음", "알 수 없음", "파일 없음"))
        self.assertTrue(rows[1][2])

    def test_case_file_and_save_folder(self):
        self.assertTrue(case_view.is_case_file(r"C:\Evidence\x\CASE.sqlite"))
        self.assertFalse(case_view.is_case_file(r"C:\Evidence\x\report.json"))
        evidence = [r"C:\Evidence\alice\NTUSER.DAT"]
        self.assertIn("원본 증거", case_view.save_folder_problem(r"C:\Evidence\alice", evidence))
        self.assertIsNone(case_view.save_folder_problem(r"C:\Evidence\out", evidence))

    def test_case_status_and_source_state(self):
        info = {"path": r"C:\Evidence\out\case.sqlite", "name": "alice-case", "created_at": "2024-01-01T10:00:00+00:00",
                "tool_version": "0.9", "warnings": ["저장 후 바뀜"], "partial": True, "missing_fields": ["settings"],
                "sources": [{"path": r"C:\Evidence\disk.E01", "kind": "image", "status": "missing", "expected_sha256": "a" * 64},
                            {"path": r"C:\Evidence\NTUSER.DAT", "kind": "file", "status": "present_unverified"}]}
        title, line, warnings = case_view.case_status(info, 1234)
        self.assertEqual(title, "Log Hunter - alice-case (저장한 분석)")
        self.assertEqual(line, "저장한 분석 'alice-case' · 저장 2024-01-01 10:00:00 (UTC) · 도구 0.9 · 기록 1,234건")
        self.assertEqual(warnings[0], "저장 후 바뀜")
        self.assertIn("일부만 불러왔습니다", warnings[1])
        self.assertIn("settings", warnings[2])
        self.assertEqual(warnings[3], r"원본 연결 문제: 원본 없음 — C:\Evidence\disk.E01")  # present_unverified is no problem
        self.assertEqual(case_view.source_state(info), "missing")
        self.assertEqual(case_view.image_sources(info), [(r"C:\Evidence\disk.E01", "a" * 64, "missing")])
        # an image-derived temporary copy is checked through its image: not reported on its own
        temp_copy = r"C:\Evidence\work\volume0\Windows\System32\config\SYSTEM"
        derived = dict(info, warnings=["원본을 찾을 수 없습니다: " + temp_copy], partial=False, missing_fields=[],
                       sources=[{"path": temp_copy, "kind": "file", "status": "missing"},
                                {"path": r"C:\Evidence\disk.E01", "kind": "image", "status": "present_unverified"}])
        self.assertEqual(case_view.case_status(derived, 1, derived=[temp_copy])[2], [])
        self.assertEqual(case_view.source_state(derived), "present_unverified")
        linked = dict(info, sources=[{"path": "x", "kind": "image", "status": "match"}], warnings=[], partial=False,
                      missing_fields=[])
        self.assertEqual(case_view.case_status(linked, 1)[2], [])
        self.assertEqual(case_view.source_state(linked), "match")
        self.assertEqual(case_view.source_state(dict(linked, sources=[{"kind": "image", "status": "changed"}])), "changed")
        self.assertEqual(case_view.source_state({}), "")

        from types import SimpleNamespace
        from log_hunter.core.tree import OriginIndex
        copy = r"C:\Evidence\work\volume0\Windows\System32\config\SYSTEM"
        saved = SimpleNamespace(image={"image_path": r"C:\Evidence\disk.E01", "image": {},
                                       "files": [{"extracted": copy, "image_path": r"\Windows\System32\config\SYSTEM", "volume": 0},
                                                 {"extracted": None}],
                                       "additional_images": [{"image_path": "x.E01"}]})
        extractions = case_view.saved_extractions(saved)
        self.assertEqual(len(extractions), 1)
        self.assertEqual(OriginIndex(extractions).text(copy), r"[disk.E01] 볼륨 0\Windows\System32\config\SYSTEM")
        self.assertEqual(case_view.saved_extractions(SimpleNamespace(image=None)), [])

        class Info:  # the engine's dataclass answers through to_dict()
            def to_dict(self):
                return linked
        self.assertEqual(case_view.case_status(Info(), 1)[0], "Log Hunter - alice-case (저장한 분석)")


if __name__ == "__main__":
    unittest.main()
