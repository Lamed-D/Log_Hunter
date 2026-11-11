"""백신 파일 기록 on screen: result columns and properties never claim execution or removal; unknowns are shown."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import TreeNode
from log_hunter.parser.defender import DefenderParser
from log_hunter.ui import columns, record_fields

NODE = TreeNode("art:security_detections", "백신 파일 기록", "artifacts", ("defender",))
LOG = ("2024-01-01T10:00:00.000Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Example file:C:\\Users\\alice\\Downloads\\tool.exe\n"
       "2024-01-01 10:05:00 Threat Name: Trojan:Win32/Example\n").encode()


def _shown(event):
    cols = columns.columns_for(NODE)
    return dict(zip([c.key for c in cols], columns.row(event, cols, {}, None)))


class DefenderViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "MPLog-20240101.log"
            path.write_bytes(LOG)
            cls.events = list(DefenderParser().parse(path))

    def test_columns_for_a_detection(self):
        cols = columns.columns_for(NODE)
        self.assertEqual([c.key for c in cols][:6], ["timestamp", "action", "threat_name", "threat_target",
                                                     "defender_result", "unconfirmed"])
        detection = next(e for e in self.events if e.action == "defender_detection")
        shown = _shown(detection)
        self.assertEqual(shown["threat_name"], "HackTool:Win32/Example")
        self.assertEqual(shown["threat_target"], r"C:\Users\alice\Downloads\tool.exe")
        self.assertEqual(shown["defender_result"], "제거·격리 완료 확인 안 됨")
        self.assertIn("위협 실행 확인 안 됨", shown["unconfirmed"])

    def test_time_without_zone_and_reference_lines(self):
        reference = next(e for e in self.events if e.action == "defender_log_reference")
        shown = _shown(reference)
        self.assertIsNone(reference.timestamp)
        self.assertIn("시각 시간대 미상 (원문 2024-01-01T10:05:00)", shown["unconfirmed"])
        self.assertEqual(shown["defender_result"], "로그 문구 (탐지 확정 아님)")
        fields = dict(record_fields.properties(reference).fields)
        self.assertEqual(fields["시각"], "알 수 없음 (원문 2024-01-01T10:05:00)")
        self.assertTrue(fields["원본 파일·위치"].endswith("2번째 줄"))

    def test_properties_of_a_detection(self):
        detection = next(e for e in self.events if e.action == "defender_detection")
        props = record_fields.properties(detection)
        fields = dict(props.fields)
        self.assertEqual(props.title, "속성 — 백신 파일 기록")
        self.assertEqual(fields["위험 이름"], "HackTool:Win32/Example")
        self.assertEqual(fields["위협 실행 확인"], "확인 안 됨")
        self.assertEqual(fields["제거·격리 완료 확인"], "확인 안 됨")
        self.assertEqual(fields["탐지 출처"], "MPSOURCE_REALTIME")
        self.assertEqual(fields["위협 ID"], "알 수 없음")
        self.assertEqual([name for name, _l, _s in props.tabs], ["로그 원문 줄", "원본 JSON"])

    def test_quarantine_and_recorded_action(self):
        quarantine = ForensicEvent("defender", r"C:\Evidence\Entries\{x}", "defender_quarantine_metadata", status="partial",
                                   details={"remediation_confirmed": False, "threat_execution_confirmed": False})
        shown = _shown(quarantine)
        self.assertIn("내부 형식 미지원", shown["defender_result"])
        self.assertIn("일부만 읽음", shown["unconfirmed"])
        action = ForensicEvent("defender", r"C:\Evidence\x", "defender_action", details={"defender_action_name": "Quarantine"})
        self.assertEqual(_shown(action)["defender_result"], "조치 기록: Quarantine")


if __name__ == "__main__":
    unittest.main()
