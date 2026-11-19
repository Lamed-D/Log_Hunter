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


if __name__ == "__main__":
    unittest.main()
