"""Well-known account names on screen and in the report; a name from the evidence wins; exports keep the SID."""
import json
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.sid_resolver import display_name, is_service_sid, well_known_sid_name
from log_hunter.core.tree import build_tree
from log_hunter.main import save_result
from log_hunter.ui import columns, record_fields, view_model

LOCAL = "S-1-5-21-" + "1000-2000-3000-"  # fake machine SID prefix


class WellKnownSidTest(unittest.TestCase):
    def test_table(self):
        cases = {"S-1-5-18": "시스템 (SYSTEM)", "S-1-5-19": "로컬 서비스 (LOCAL SERVICE)",
                 "S-1-5-20": "네트워크 서비스 (NETWORK SERVICE)", "s-1-5-18": "시스템 (SYSTEM)",
                 LOCAL + "500": "기본 관리자 계정 (Administrator)", LOCAL + "501": "게스트 (Guest)",
                 LOCAL + "503": "기본 계정 (DefaultAccount)", LOCAL + "504": "보호된 실행 계정 (WDAGUtilityAccount)",
                 LOCAL + "1000": "로컬 사용자 (RID 1000)", LOCAL + "1001": "로컬 사용자 (RID 1001)",
                 "S-1-5-32-544": "관리자 그룹 (Administrators)", "S-1-5-32-545": "사용자 그룹 (Users)",
                 "S-1-5-32-555": "원격 데스크톱 사용자 그룹 (Remote Desktop Users)",
                 "S-1-5-90-0-2": "창 관리자 (DWM-2)", "S-1-5-96-0-1": "글꼴 드라이버 호스트 (UMFD-1)",
                 "S-1-5-80-1-2-3-4-5": "서비스 계정 (NT SERVICE)", "S-1-1-0": "모든 사람 (Everyone)",
                 "S-1-5-7": "익명 (ANONYMOUS LOGON)", "S-1-5-11": "인증된 사용자 (Authenticated Users)",
                 "S-1-3-0": "작성자 소유자 (CREATOR OWNER)"}
        for sid, name in cases.items():
            with self.subTest(sid=sid):
                self.assertEqual(well_known_sid_name(sid), name)
        for sid in (LOCAL + "499", LOCAL + "999", "S-1-5-21-1-2", "S-1-5-99", "bad", "", None, "S-1-5-18x", "S-1-5-21-1-2-3-4x"):
            with self.subTest(sid=sid):
                self.assertIsNone(well_known_sid_name(sid))
        self.assertTrue(is_service_sid("S-1-5-18"))
        self.assertFalse(is_service_sid(LOCAL + "500"))
        self.assertFalse(is_service_sid("bad"))

    def test_evidence_name_first(self):
        names = {LOCAL + "1001": "alice", LOCAL + "500": "bob"}
        self.assertEqual(display_name(LOCAL + "1001", names), "alice")
        self.assertEqual(display_name(LOCAL + "500", names), "bob (기본 관리자 계정)")
        self.assertEqual(display_name("S-1-5-18", names), "시스템 (SYSTEM)")
        self.assertEqual(display_name("S-1-5-99", names), "")
        self.assertEqual(display_name(None, names), "")

    def events(self):
        make = lambda sid: ForensicEvent("run", r"C:\Evidence\NTUSER.DAT", "autorun", "2024-01-01T00:00:00+00:00",
                                         sid=sid, details={})
        return [make("S-1-5-18"), make(LOCAL + "1001"), make(LOCAL + "1002"), make("S-1-5-99")]

    def test_screen_places(self):
        names = {LOCAL + "1001": "alice"}
        events = self.events()
        cols = columns.DEFAULT
        user = [dict(zip([c.key for c in cols], columns.row(e, cols, names, None))).get("user") for e in events]
        self.assertEqual(user, ["시스템 (SYSTEM)", "alice", "로컬 사용자 (RID 1002)", ""])
        fields = dict(record_fields.properties(events[0], record_fields.Context(sid_map=names)).fields)
        self.assertEqual(fields["사용자"], "시스템 (SYSTEM) (S-1-5-18)")
        accounts = build_tree(events, sid_map=names)[3]
        self.assertEqual([c.label for c in accounts.children],
                         ["alice — " + LOCAL + "1001", "로컬 사용자 (RID 1002) — " + LOCAL + "1002",
                          "시스템 (SYSTEM) — S-1-5-18", "S-1-5-99"])
        self.assertTrue(view_model.matches_search(events[0], "system", names))
        pick = lambda text: [e.sid for e in view_model.filter_events(events, view_model.Filters(sid=text), names=names)]
        self.assertEqual(pick("시스템"), ["S-1-5-18"])
        self.assertEqual(pick("ALICE"), [LOCAL + "1001"])
        self.assertEqual(pick("S-1-5-18"), ["S-1-5-18"])

    def test_report_names_and_exports_keep_sid(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            save_result(AnalysisResult(events=self.events()), out, sid_names={LOCAL + "1001": "alice"})
            page = (out / "report.html").read_text(encoding="utf-8")
            data = json.loads((out / "report.json").read_text(encoding="utf-8"))
            csv_text = (out / "timeline.csv").read_text(encoding="utf-8-sig")
        self.assertIn('"S-1-5-18": "시스템 (SYSTEM)"', page)
        self.assertIn('"' + LOCAL + '1001": "alice"', page)
        self.assertIn("<th>사용자</th>", page)
        self.assertEqual([e["sid"] for e in data["events"]][:1], ["S-1-5-18"])
        self.assertNotIn("시스템 (SYSTEM)", json.dumps(data, ensure_ascii=False))
        self.assertNotIn("SYSTEM", csv_text)


if __name__ == "__main__":
    unittest.main()
