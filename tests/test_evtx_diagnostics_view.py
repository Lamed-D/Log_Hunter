"""파일별 결과 cause column and event log record properties (synthetic inputs only)."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent, ParserError
from log_hunter.core.pipeline import Pipeline
from log_hunter.ui import record_fields, view_model


def err(locator, message, severity="warning", source="a.evtx"):
    return ParserError(source, "evtx", locator, message, severity)


class CauseTest(unittest.TestCase):
    def cause(self, state, errors, events=0):
        return view_model.diagnostic_cause({"source": "a.evtx", "state": state, "events": events}, errors)

    def test_empty_log_is_normal(self):
        self.assertEqual(self.cause("no_data", []), "정상 (기록 0건)")
        self.assertEqual(self.cause("ok", [], 5), "정상")

    def test_header_damage_and_partial_read(self):
        self.assertTrue(self.cause("failed", [err("header", "EVTX 시그니처 없음", "error")]).startswith(
            "형식 미지원 또는 헤더 손상: EVTX 시그니처 없음"))
        partial = self.cause("partial", [err("flags", "기록 중 종료"), err("chunk:4096:data_crc", "청크 데이터 CRC32 불일치"),
                                          err("8320", "레코드 시그니처 오류"), err("BinXML", "BinXML 디코딩 실패 1건 (성공 3건)")], 3)
        self.assertIn("기록 중 종료된 로그", partial)
        self.assertIn("부분 읽기: 기록 3건 읽음, 손상·잘린 위치 2곳 (첫 위치 chunk:4096:data_crc)", partial)
        self.assertIn("본문 해석 실패: BinXML 디코딩 실패 1건", partial)

    def test_other_artifacts_use_the_first_problem(self):
        cause = self.cause("partial", [err("Software\Run", "키 없음"), err("Software\Run2", "키 없음")])
        self.assertEqual(cause, "키 없음 · 외 1건")
        self.assertEqual(self.cause("partial", [err("x", "참고", "info")]), "")
        self.assertEqual(self.cause("no_data", [err("Software\Run", "키 없음", "info")]), "정상 (기록 0건 · 참고: 키 없음)")

    def test_rows_pair_errors_with_their_file(self):
        rows = view_model.diagnostic_rows([{"source": "a.evtx", "artifact": "evtx", "state": "no_data", "events": 0},
                                           {"source": "b.evtx", "artifact": "evtx", "state": "failed", "events": 0}],
                                          [err("header", "손상", "error", source="b.evtx")])
        self.assertEqual(rows[0][-1], "정상 (기록 0건)")
        self.assertTrue(rows[1][-1].startswith("형식 미지원 또는 헤더 손상"))

    def test_a_damaged_file_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "System.evtx"
            path.write_bytes(b"not an event log" * 8)
            result = Pipeline().analyze([("evtx", path, None)])
        rows = view_model.diagnostic_rows(result.summaries, result.errors)
        self.assertTrue(rows[0][-1], rows)
        self.assertNotIn("정상", rows[0][-1])


class EventPropertiesTest(unittest.TestCase):
    def test_known_unregistered_and_undecoded(self):
        base = {"provider": "Example-Provider", "event_id": 9999, "channel": "Application", "record_id": 7, "xml_decoded": True}
        unknown = ForensicEvent("evtx", r"C:\Evidence\Application.evtx", "event_record", "2024-01-01T00:00:00+00:00",
                                "event_created", locator="69632",
                                details={**base, "known_event": "기타 이벤트 (Example-Provider, 이벤트 ID 9999)"})
        fields = dict(record_fields.properties(unknown, record_fields.Context(source_text="[case.E01] 볼륨 0\a.evtx")).fields)
        self.assertEqual(fields["등록 여부"], "미등록 이벤트 (설명 없음)")
        self.assertEqual((fields["공급자"], fields["이벤트 ID"], fields["레코드 번호"]), ("Example-Provider", "9999", "7"))
        self.assertEqual(fields["원본 위치"], "[case.E01] 볼륨 0\a.evtx @ 69632")
        broken = ForensicEvent("evtx", "a.evtx", "event_record", details={**base, "xml_decoded": False,
                                                                          "binxml_value_warnings": [{"type": 99}],
                                                                          "known_event": "이벤트 본문 해석 실패"})
        fields = dict(record_fields.properties(broken).fields)
        self.assertEqual(fields["등록 여부"], "해석 실패 (원시 값만)")
        self.assertEqual(fields["본문 해석"], "해석 실패 (원시 값만) · 해석하지 못한 값 1개 (형식 추정 안 함)")
        known = ForensicEvent("evtx", "a.evtx", "logon", details={**base, "known_event": "로그온 성공"})
        self.assertEqual(dict(record_fields.properties(known).fields)["등록 여부"], "알려진 이벤트")


if __name__ == "__main__":
    unittest.main()
