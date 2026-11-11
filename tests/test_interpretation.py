"""Relations and parser output must not claim more than the evidence shows."""
import unittest

from log_hunter.core.correlation import correlate
from log_hunter.core.labels import confidence_label
from log_hunter.core.models import ForensicEvent


def _chain(events):
    return next(r for r in correlate(events) if r["type"] == "execution_chain")


class CorrelationConfidenceTests(unittest.TestCase):
    def test_name_only_chain_is_not_reported_as_certain(self):
        events = [
            ForensicEvent("prefetch", "a", "trace", "2024-01-01T00:00:00+00:00", process=r"C:\Temp\evil.exe"),
            ForensicEvent("bam", "b", "activity", "2020-01-01T00:00:00+00:00", sid="S-1", path=r"D:\x\EVIL.exe"),
            ForensicEvent("evtx", "c", "event", "2023-01-01T00:00:00+00:00", process=r"E:\y\evil.exe",
                          details={"event_id": 1, "provider": "Some-Other-Provider"}),
        ]
        chain = _chain(events)
        self.assertNotIn(chain["confidence"], ("confirmed_execution", "probable_execution", "corroborated_execution"))
        self.assertIn("이름", confidence_label(chain["confidence"]))

    def test_close_execution_records_corroborate_each_other(self):
        events = [
            ForensicEvent("prefetch", "a", "trace", "2020-06-15T10:00:00+00:00", process="APP.EXE"),
            ForensicEvent("bam", "b", "activity", "2020-06-15T10:01:00+00:00", sid="S-1", path=r"C:\app.exe"),
            ForensicEvent("evtx", "c", "event", "2020-06-15T10:00:30+00:00", process=r"C:\app.exe",
                          details={"event_id": 4688}),
        ]
        chain = _chain(events)
        self.assertEqual(chain["confidence"], "corroborated_execution")
        self.assertFalse(chain["execution_confirmed"])
        self.assertNotIn("확실", confidence_label(chain["confidence"]))

    def test_filename_only_path_match_says_so(self):
        events = [ForensicEvent("prefetch", "a", "trace", "2020-06-15T10:00:00+00:00", path=r"C:\a\x.exe"),
                  ForensicEvent("lnk", "b", "trace", "2020-06-15T10:00:10+00:00", path=r"D:\b\x.exe")]
        relation = next(r for r in correlate(events) if r["type"] == "path_correlation")
        self.assertEqual(relation["confidence"], "filename_only")
        self.assertTrue(relation["temporal_proximity"])

    def test_url_host_prefix_is_not_stripped_character_by_character(self):
        events = [ForensicEvent("history", "a", "visit", url="https://web.com/x"),
                  ForensicEvent("cache", "b", "entry", url="https://eb.com/x")]
        self.assertFalse([r for r in correlate(events) if r["type"] == "url_correlation"])


if __name__ == "__main__":
    unittest.main()
