"""report.json is written in fast chunks but must be byte-identical to encoding the whole payload with indent=2."""
import json
import unittest

from log_hunter.core.models import ForensicEvent
from log_hunter.core.report import _payload_json, event_json_row


def events(count):
    return [ForensicEvent("run", f"C:\\Evidence\\NTUSER{i}.DAT", "autorun", "2024-01-01T00:00:00+00:00",
                          "key_lastwrite", "S-1-5-21-1000-2000-3000-1001", path="C:\\Users\\alice\\a\nb.exe",
                          details={"nested": {"list": [1, {"k": "값 </script>"}], "empty": {}, "none": []},
                                   "text": "line1\nline2\t\x00"})
            for i in range(count)]


class ReportJsonStreamTests(unittest.TestCase):
    def test_same_bytes_as_whole_payload_encoding(self):
        payload = {"evidence": [{"path": "C:\\Evidence\\x", "note": "\x00log-hunter-events"}], "events": None,
                   "errors": [], "relations": [{"a": 1}], "summaries": [], "correlation_summary": {}}
        for count in (0, 1, 499, 500, 501, 1203):
            rows = events(count)
            expected = json.dumps({**payload, "events": [event_json_row(e) for e in rows]}, ensure_ascii=False, indent=2)
            self.assertEqual("".join(_payload_json(payload, rows)), expected, count)

    def test_evidence_text_cannot_take_the_html_events_placeholder(self):
        import tempfile
        from pathlib import Path
        from log_hunter.core.report import export_reports
        trap = "const ALL_EVENTS = __LOG_HUNTER_EVENTS_STREAM__; <img src=x onerror=alert(1)>"
        event = ForensicEvent("history", r"C:\Evidence\History", "url_visit", "2024-01-01T00:00:00+00:00", "visit_time",
                              url="https://example.com/", details={"title": trap})
        with tempfile.TemporaryDirectory() as folder:
            export_reports(folder, [], [event], [], [], [])
            page = (Path(folder) / "report.html").read_text(encoding="utf-8")
        import re
        outside_scripts = re.sub(r"<script.*?</script>", "", page, flags=re.S)
        self.assertNotIn("<img src=x", outside_scripts)  # evidence text in the page body stays escaped
        script = page.split("const ALL_EVENTS = [", 1)
        self.assertEqual(len(script), 2)  # the records went into the script line
        self.assertIn("example.com", script[1].split("];", 1)[0])
        self.assertIsNone(re.search(r"__LOG_HUNTER_EVENTS_[0-9a-f]{32}__", page))  # no placeholder left behind


if __name__ == "__main__":
    unittest.main()
