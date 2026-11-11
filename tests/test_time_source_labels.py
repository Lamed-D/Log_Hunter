"""Issue #23: show where each time comes from and do not present raw Jump List bytes as a count."""
import unittest

from log_hunter.core.labels import time_field_label
from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import event_properties


def _details(rows):
    return {child.name: child.value for row in rows if row.name == "세부 정보" for child in row.children}


class TimeSourceLabelTests(unittest.TestCase):
    def test_evtx_record_time_and_time_created_are_distinguished(self):
        self.assertIn("레코드", time_field_label("record_filetime"))
        event = ForensicEvent("evtx", "Security.evtx", "event_record", "2024-01-01T00:00:00+00:00", "record_filetime",
                              details={"event_id": 4624, "time_created": "2024-01-01T00:00:05+00:00"})
        rows = event_properties(event)
        self.assertEqual(next(r.value for r in rows if r.name == "시각의 의미"), time_field_label("record_filetime"))
        details = _details(rows)
        key = next(k for k in details if k.endswith("[time_created]"))
        self.assertIn("TimeCreated", key)
        self.assertEqual(details[key], "2024-01-01T00:00:05+00:00")
        self.assertEqual(details["event_id"], "4624")

    def test_jumplist_raw_count_is_not_a_confirmed_count(self):
        event = ForensicEvent("jumplist", "x.automaticDestinations-ms", "recent_file_access",
                              details={"access_count": None, "access_count_raw": "0a000000"})
        details = _details(event_properties(event))
        count = next(k for k in details if k.endswith("[access_count]"))
        raw = next(k for k in details if k.endswith("[access_count_raw]"))
        self.assertIn("확정 안 됨", count)
        self.assertEqual(details[count], "알 수 없음")
        self.assertIn("의미 미상", raw)
        self.assertEqual(details[raw], "0a000000")


if __name__ == "__main__":
    unittest.main()
