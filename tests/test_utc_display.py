"""Every time on screen and in the report is UTC with a 'UTC' mark; values without a zone are never shown as UTC."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.ui import columns, view_model
from log_hunter.ui.record_fields import event_time_text, format_time, properties


def event(timestamp, **details):
    return ForensicEvent("bam", r"C:\Evidence\SYSTEM", "activity_update", timestamp, "last_execution",
                         path=r"C:\Windows\a.exe", details=details)


class UTCDisplayTests(unittest.TestCase):
    def test_table_timeline_and_properties_show_the_same_utc_text(self):
        e = event("2024-01-01T09:00:00.500000+09:00")
        expected = "2024-01-01 00:00:00 UTC"
        self.assertEqual(columns.cell("timestamp", e, {}, None), expected)
        self.assertEqual(view_model.timeline_row(e, {})[0][1], expected)
        self.assertEqual(dict(properties(e).fields)["시각"], expected)

    def test_unknown_zone_is_shown_with_its_original_value(self):
        e = event(None, timestamp_raw_local="2024-01-01T09:00:00", timezone_known=False)
        self.assertEqual(event_time_text(e), "2024-01-01 09:00:00 (시간대 미상)")
        self.assertNotIn("UTC", columns.cell("timestamp", e, {}, None))
        self.assertEqual(event_time_text(event(None)), "알 수 없음")

    def test_detail_time_columns_use_the_same_format(self):
        d = ForensicEvent("history", "History", "download", "2020-12-30T00:00:00+00:00", "start_time",
                          details={"download_start": "2020-12-30T00:00:00+00:00", "download_end": "2020-12-30T00:00:03+00:00"})
        self.assertEqual(columns.cell("download_end", d, {}, None), "2020-12-30 00:00:03 UTC")
        self.assertEqual(format_time("2020-12-30T00:00:03Z"), "2020-12-30 00:00:03 UTC")

    def test_report_marks_times_and_date_filter_as_utc(self):
        from log_hunter.core.report import export_reports
        with tempfile.TemporaryDirectory() as folder:
            export_reports(Path(folder), [], [event("2024-01-01T00:00:00+00:00")], [], [], [])
            page = (Path(folder) / "report.html").read_text(encoding="utf-8")
        self.assertIn("<th>시각 (UTC)</th>", page)
        self.assertIn("YYYY-MM-DD, UTC", page)
        self.assertIn("2024-01-01 00:00:00 UTC ~ 2024-01-01 00:00:00 UTC", page)


if __name__ == "__main__":
    unittest.main()
