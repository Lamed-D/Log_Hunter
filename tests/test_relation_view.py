"""연관 분석 detail: rule, compared values, time difference, group size and member list from evidence_details."""
import unittest

from log_hunter.core.correlation import correlate
from log_hunter.core.models import ForensicEvent
from log_hunter.ui import relation_view as rv


def _events():
    return [ForensicEvent("prefetch", r"C:\Evidence\APP.EXE-1234ABCD.pf", "execution_trace", "2024-01-01T10:00:00+00:00",
                          "last_run_time", process="APP.EXE", path=r"C:\Users\alice\app.exe"),
            ForensicEvent("bam", r"C:\Evidence\SYSTEM", "execution_trace", "2024-01-01T10:00:30+00:00", "last_execution",
                          path=r"C:\Users\alice\app.exe", sid="S-1-5-21-1000-2000-3000-1001"),
            ForensicEvent("lnk", r"C:\Evidence\app.lnk", "file_access", "2024-01-01T10:00:40+00:00", "target_modified",
                          path=r"C:\Users\alice\app.exe")]


class RelationViewTest(unittest.TestCase):
    def setUp(self):
        from log_hunter.core.relation_evidence import add_relation_evidence
        self.events = _events()
        self.relations = correlate(self.events)
        if self.relations and "evidence_details" not in self.relations[0]:
            add_relation_evidence(self.relations, self.events)

    def test_pair_detail_lists_rule_values_and_time(self):
        pair = next(r for r in self.relations if "left" in r and "right" in r)
        text = "\n".join(rv.detail_lines(pair, self.events))
        self.assertIn("판단 규칙:", text)
        self.assertIn("신뢰도 이유:", text)
        self.assertIn("A ", text)
        self.assertIn("B ", text)
        self.assertIn("시각", text)
        self.assertIn("묶인 기록 2건", text)
        rows = rv.member_rows(pair, self.events)
        self.assertEqual({row[1][0] for row in rows}, {"A", "B"})
        self.assertTrue(all("(UTC)" in row[1][3] for row in rows))

    def test_execution_chain_explains_what_it_does_not_mean(self):
        chain = [r for r in self.relations if r.get("type") == "execution_chain"]
        if not chain:
            self.skipTest("engine made no execution chain for these records")
        text = "\n".join(rv.detail_lines(chain[0], self.events))
        self.assertIn("같은 실행 파일·같은 실행 건·인과관계를 확인한 것이 아니며", text)
        self.assertGreaterEqual(len(rv.member_rows(chain[0], self.events)), 2)

    def test_old_results_without_details(self):
        relation = {"type": "path_correlation", "left": 0, "right": 1, "confidence": "path_match"}
        self.assertEqual(rv.detail_lines(relation, self.events), [rv.L["no_details"]])
        self.assertEqual([r[0] for r in rv.member_rows(relation, self.events)], [0, 1])
        self.assertEqual(rv.member_rows({"left": 99, "right": -1}, self.events), [])  # bad indices are skipped

    def test_new_names(self):
        from log_hunter.core.labels import confidence_label, relation_label
        self.assertEqual(relation_label("execution_chain"), "여러 종류의 실행 기록에 나온 같은 프로그램")
        self.assertEqual(confidence_label("multi_source"), "기록 종류 2가지 이상에서 이름만 일치")
        self.assertEqual(rv._seconds(30), "30초")
        self.assertEqual(rv._seconds(600), "10.0분")


if __name__ == "__main__":
    unittest.main()
