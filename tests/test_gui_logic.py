"""GUI filter logic that does not need Tk."""
import unittest

from log_hunter.core.models import ForensicEvent
from log_hunter.core.timeline import parse_filter_date, timeline


def _at(stamp):
    return ForensicEvent("bam", "SYSTEM", "execution_trace", timestamp=stamp)


class FilterDateTests(unittest.TestCase):
    def test_end_date_includes_the_whole_day(self):
        events = [_at("2024-01-01T00:00:00+00:00"), _at("2024-01-01T23:59:59.500000+00:00"),
                  _at("2024-01-02T00:00:00+00:00")]
        start, end = parse_filter_date("2024-01-01"), parse_filter_date("2024-01-01", end=True)
        self.assertEqual(len(timeline(events, start=start, end=end)), 2)

    def test_end_minute_includes_its_seconds(self):
        events = [_at("2024-01-01T10:30:59+00:00"), _at("2024-01-01T10:31:00+00:00")]
        end = parse_filter_date("2024-01-01 10:30", end=True)
        self.assertEqual(len(timeline(events, end=end)), 1)

    def test_blank_and_unknown_text(self):
        self.assertIsNone(parse_filter_date("  "))
        self.assertEqual(parse_filter_date("2024-01"), "2024-01")


if __name__ == "__main__":
    unittest.main()


class ViewModelTests(unittest.TestCase):
    def setUp(self):
        from log_hunter.core.pipeline import AnalysisResult
        self.events = [ForensicEvent("bam", "SYSTEM", "execution_trace", "2024-01-01T10:00:00+00:00",
                                     sid="S-1-5-21-1-1001", path=r"C:\a.exe", time_field="last_execution"),
                       ForensicEvent("prefetch", "A.pf", "execution_trace", "2024-01-02T01:00:00+00:00", process="A.EXE")]
        self.result = AnalysisResult(events=self.events, relations=[{"type": "execution_chain", "process": "a",
                                                                     "confidence": "multi_source",
                                                                     "sources": ["bam", "prefetch"]}])

    def test_filters_use_shown_labels(self):
        from log_hunter.ui.view_model import Filters, filter_events
        self.assertEqual(len(filter_events(self.events, Filters())), 2)
        self.assertEqual(len(filter_events(self.events, Filters(artifact="최근 실행한 프로그램"))), 1)
        self.assertEqual(len(filter_events(self.events, Filters(sid=" S-1-5-21-1-1001 "))), 1)
        self.assertEqual(len(filter_events(self.events, Filters(end="2024-01-01"))), 1)

    def test_rows_and_texts(self):
        from log_hunter.ui import view_model
        values, tag = view_model.timeline_row(self.events[0], {"S-1-5-21-1-1001": "alice"})
        self.assertEqual(values[0], "최근 실행한 프로그램")
        self.assertEqual(values[2], "마지막 실행")
        self.assertEqual(values[4], "alice")
        self.assertEqual(tag, "bam")
        self.assertTrue(view_model.matches_search(self.events[0], "alice", {"S-1-5-21-1-1001": "alice"}))
        self.assertFalse(view_model.matches_search(self.events[1], "alice", {}))
        self.assertEqual(view_model.count_text(1, 2, 3, True), "표시: 1 / 필터: 2 / 전체: 3")
        self.assertIn("찾은 기록: 2건", view_model.summary_text(self.result))
        row = view_model.relation_rows(self.result.relations, self.events)[0]
        self.assertEqual(row[2], "프로그램: a")
        self.assertIn("기간: 2024-01-01T10:00:00+00:00 ~ 2024-01-02T01:00:00+00:00", view_model.stats_lines(self.result))


class ChartTests(unittest.TestCase):
    def test_dashboard_draws_on_a_canvas(self):
        import tkinter as tk
        from log_hunter.ui import charts
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("화면(Tk)을 쓸 수 없는 환경")
        try:
            canvas = tk.Canvas(root, width=900, height=400)
            events = [_at("2024-01-01T02:00:00+00:00"), _at("2024-01-06T13:00:00+00:00")]
            charts.draw_dashboard(canvas, events)
            self.assertGreater(len(canvas.find_all()), 50)
            charts.draw_dashboard(tk.Canvas(root), [])  # empty data must not fail
        finally:
            root.destroy()


class NavAndDetailTests(unittest.TestCase):
    def test_node_actions(self):
        from log_hunter.core.tree import TreeNode
        from log_hunter.ui.nav import node_action
        self.assertIsNone(node_action(None))
        self.assertIsNone(node_action(TreeNode("res", "분석 결과")))
        self.assertEqual(node_action(TreeNode("r", "x", "relation", "execution_chain")), ("relations", "execution_chain"))
        self.assertEqual(node_action(TreeNode("e", "x", "errors", "warning")), ("errors", "warning"))
        node = TreeNode("a", "x", "artifacts", ("bam",))
        self.assertEqual(node_action(node), ("events", node))

    def test_json_is_colored(self):
        import tkinter as tk
        from log_hunter.ui import detail
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("화면(Tk)을 쓸 수 없는 환경")
        try:
            text = tk.Text(root)
            detail.configure_json_tags(text)
            detail.show_json(text, ForensicEvent("bam", "S\\\"YS", "execution_trace", details={"n": 1, "ok": True}))
            for tag in ("json_key", "json_string", "json_number", "json_bool", "json_null"):
                self.assertTrue(text.tag_ranges(tag), tag)
        finally:
            root.destroy()


class StyleTests(unittest.TestCase):
    def test_every_parser_has_a_color_and_no_stale_keys(self):
        from log_hunter.core.pipeline import PARSERS
        from log_hunter.ui.style import ARTIFACT_COLORS
        self.assertEqual(sorted(set(PARSERS) - set(ARTIFACT_COLORS)), [])
        self.assertEqual(sorted(set(ARTIFACT_COLORS) - set(PARSERS)), [])


class DisplayLabelTests(unittest.TestCase):
    def test_raw_keys_have_plain_labels(self):
        from log_hunter.core import labels
        for key in ("burst", "off_hours", "time_gap", "deep_nesting", "lolbin_unusual_parent", "temp_execution"):
            self.assertNotEqual(labels.anomaly_label(key), key.replace("_", " "), key)
        for key in ("normalized_path", "candidate_group", "usb_temporal_window", "process_name"):
            self.assertNotEqual(labels.basis_label(key), key.replace("_", " "), key)
        for key in ("DIRECT_VOLUME", "RegSaveKeyExW", "EvtExportLog"):
            self.assertNotEqual(labels.method_label(key), key, key)
        self.assertNotIn("직후", labels.relation_label("usb_file_correlation"))

    def test_relation_table_shows_basis_label(self):
        from log_hunter.ui.view_model import relation_rows
        events = [ForensicEvent("prefetch", "a", "x", path="C:/a.exe"), ForensicEvent("lnk", "b", "x", path="C:/a.exe")]
        row = relation_rows([{"type": "path_correlation", "left": 0, "right": 1, "basis": "normalized_path",
                              "confidence": "path_match"}], events)[0]
        self.assertEqual(row[4], "같은 전체 경로")

    def test_report_labels_anomalies(self):
        import tempfile
        from pathlib import Path
        from log_hunter.core.report import export_reports
        events = [ForensicEvent("bam", "s", "x", f"2024-01-01T00:00:{i % 60:02d}+00:00") for i in range(120)]
        with tempfile.TemporaryDirectory() as temp:
            export_reports(Path(temp), [], events, [], [], [])
            html = (Path(temp) / "report.html").read_text(encoding="utf-8")
        self.assertIn('"burst": "짧은 시간에 몰린 기록"', html)
        self.assertIn("lab('anomaly', a.type)", html)


class RelationGroupTests(unittest.TestCase):
    def setUp(self):
        self.events = [ForensicEvent("usb", "SYSTEM", "last_arrival"), ForensicEvent("lnk", "a.lnk", "x", path="E:/a"),
                       ForensicEvent("lnk", "b.lnk", "x", path="E:/b")]
        self.group = {"type": "correlation_group", "relation_type": "usb_file_correlation", "basis": "usb_temporal_window",
                      "confidence": "candidate", "candidate_count": 22500, "event_indices": [1, 2],
                      "left_event_indices": [0], "window_seconds": 300, "same_clock_required": True}

    def test_group_row_says_counts_not_pairs(self):
        from log_hunter.ui.view_model import relation_rows
        kind, confidence, left, right, basis = relation_rows([self.group], self.events)[0]
        self.assertIn("관계 후보 묶음", kind)
        self.assertIn("USB", kind)
        self.assertEqual(left, "USB 연결 기록 1건 · 파일 기록 2건")
        self.assertIn("후보 22,500쌍", right)
        self.assertIn("모든 쌍이 관계인 것은 아님", right)
        self.assertIn("±300초", right)
        self.assertEqual(basis, "USB 기록 시각 전후 시간 창")

    def test_relation_records_for_timeline(self):
        from log_hunter.core.tree import TreeNode, matches
        from log_hunter.ui.view_model import relation_events
        records = relation_events(self.group, self.events)
        self.assertEqual(len(records), 3)
        node = TreeNode("rel:selected", "x", "event_set", frozenset(id(e) for e in records[:1]))
        self.assertEqual([matches(node, e, None) for e in self.events], [False, True, False])
        pair = relation_events({"type": "path_correlation", "left": 2, "right": 99}, self.events)
        self.assertEqual(pair, [self.events[2]])

    def test_report_renders_groups(self):
        import tempfile
        from pathlib import Path
        from log_hunter.core.report import export_reports
        with tempfile.TemporaryDirectory() as temp:
            export_reports(Path(temp), [], self.events, [], [self.group], [])
            html = (Path(temp) / "report.html").read_text(encoding="utf-8")
        self.assertIn("r.type === 'correlation_group'", html)
        self.assertIn("모든 쌍이 관계인 것은 아님", html)


class TimelinePageTests(unittest.TestCase):
    def test_page_bounds_and_text(self):
        from log_hunter.ui.view_model import page_bounds, page_text
        self.assertEqual(page_bounds(12000, 0, 5000), (0, 3, 0, 5000))
        self.assertEqual(page_bounds(12000, 2, 5000), (2, 3, 10000, 12000))
        self.assertEqual(page_bounds(12000, 9, 5000), (2, 3, 10000, 12000))  # clamped
        self.assertEqual(page_bounds(0, 0, 5000), (0, 1, 0, 0))
        self.assertEqual(page_text(*page_bounds(12000, 1, 5000), 12000), "5,001–10,000번째 / 12,000건 · 페이지 2/3")
        self.assertEqual(page_text(*page_bounds(10, 0, 5000), 10), "")
