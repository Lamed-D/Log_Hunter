"""Every relation explains its compared fields and contributing evidence records."""
import json
import unittest
from unittest.mock import patch
from log_hunter.core.models import ForensicEvent
from log_hunter.core.correlation import correlate
from log_hunter.database.repository import Repository


def event(artifact, source="generated", timestamp="2024-01-01T00:00:00+00:00", **kwargs):
    return ForensicEvent(artifact, source, "trace", timestamp, "last_execution", **kwargs)


class RelationEvidenceTests(unittest.TestCase):
    def test_path_pair_preserves_raw_normalized_and_time_meaning(self):
        events = [event("bam", "SYSTEM", path=r"C:\Evidence\TEST.EXE"),
                  event("prefetch", "TEST.pf", timestamp="2024-01-01T00:00:20+00:00", process=r"c:\evidence\test.exe")]
        relation = next(r for r in correlate(events) if r["type"] == "path_correlation")
        details = relation["evidence_details"]
        compared = details["comparisons"][0]
        self.assertEqual(compared["left_field"], "path")
        self.assertEqual(compared["right_field"], "process")
        self.assertTrue(compared["matched"])
        self.assertEqual(compared["left_value"], events[0].path)
        self.assertEqual(compared["left_normalized"], compared["right_normalized"])
        self.assertEqual(details["time_comparison"]["signed_delta_seconds"], 20)
        self.assertEqual(details["time_comparison"]["left_time_field"], "last_execution")
        self.assertFalse(relation["execution_confirmed"])

    def test_filename_candidate_and_multi_source_show_distinct_files(self):
        events = [event("bam", "SYSTEM", path=r"C:\Evidence\one\test.exe"),
                  event("prefetch", "TEST.pf", process="TEST.EXE"),
                  event("bam", "SYSTEM", path=r"C:\Evidence\two\test.exe")]
        relations = correlate(events)
        chain = next(r for r in relations if r["type"] == "execution_chain")
        self.assertEqual(chain["confidence"], "multi_source")
        details = chain["evidence_details"]
        self.assertEqual(details["grouping"]["event_count"], 3)
        self.assertEqual(details["grouping"]["source_file_count"], 2)
        self.assertEqual(details["source_counts"], [{"artifact": "bam", "source": "SYSTEM", "count": 2},
                                                   {"artifact": "prefetch", "source": "TEST.pf", "count": 1}])
        self.assertEqual({ref["event_index"] for ref in details["event_refs"]}, {0,1,2})
        self.assertEqual({item["normalized"] for item in details["comparisons"]}, {"test"})
        pair = next(r for r in relations if r["type"] == "path_correlation")
        self.assertEqual(pair["evidence_details"]["confidence_reason"], "filename_only")

    def test_compacted_group_has_key_actual_candidate_count_and_sid_policy(self):
        events = [event("bam", path=r"C:\Evidence\test.exe"), event("prefetch", process="test.exe"),
                  event("lnk", path=r"C:\Evidence\test.exe")]
        with patch("log_hunter.core.correlation.PAIR_GROUP_LIMIT", 1):
            relations = correlate(events)
        group = next(r for r in relations if r["type"] == "correlation_group")
        details = group["evidence_details"]
        self.assertEqual(details["grouping"]["key"], "test.exe")
        self.assertEqual(details["grouping"]["candidate_count"], 3)
        self.assertEqual(details["grouping"]["pair_expansion_limit"], 1)
        self.assertIn("no_known_sid_conflict", details["grouping"]["candidate_rules"])
        self.assertEqual(details["grouping"]["event_count"], 3)

    def test_different_clock_types_do_not_crash_or_invent_a_delta(self):
        events = [event("bam", path=r"C:\Evidence\test.exe"),
                  event("prefetch", timestamp="2024-01-01T00:00:10", process="test.exe")]
        relations = correlate(events)
        pair = next(r for r in relations if r["type"] == "path_correlation")
        self.assertNotIn("delta_seconds", pair)
        self.assertFalse(pair["evidence_details"]["time_comparison"]["comparable"])
        self.assertIsNone(pair["evidence_details"]["time_comparison"]["delta_seconds"])

    def test_usb_and_url_explain_actual_values_and_time_window(self):
        usb = event("usb", details={"is_storage_device":True,"drive_letters":["E:"],"device":"TEST"})
        file = event("lnk", path=r"E:\test.txt", timestamp="2024-01-01T00:01:00+00:00")
        relation = next(r for r in correlate([usb, file]) if r["type"] == "usb_file_correlation")
        self.assertTrue(relation["evidence_details"]["comparisons"][0]["matched"])
        self.assertEqual(relation["evidence_details"]["time_comparison"]["window_seconds"], 300)
        events = [event("history", url="https://www.example.com/page?x=1"),
                  event("cache", url="https://example.com/page?x=2")]
        relation = next(r for r in correlate(events) if r["type"] == "url_correlation")
        self.assertEqual(relation["evidence_details"]["comparisons"][0]["left_normalized"], "https://example.com/page")

    def test_json_and_sqlite_preserve_evidence_details(self):
        events = [event("bam", path=r"C:\Evidence\test.exe"), event("prefetch", process="test.exe")]
        relations = correlate(events)
        repository = Repository(":memory:")
        try:
            repository.save("synthetic", [], events, [], relations)
            stored = [json.loads(row[0]) for row in repository.connection.execute("SELECT data FROM relations ORDER BY id")]
            self.assertEqual(stored, json.loads(json.dumps(relations)))
        finally:
            repository.connection.close()
        self.assertTrue(all(r["evidence_details"]["event_refs"] for r in relations))

    def test_rdp_account_normalization_and_key_time_remain_visible(self):
        left = ForensicEvent("rdp", "NTUSER.DAT", "rdp_server", "2024-01-01T00:00:00+00:00", "key_lastwrite",
                             details={"remote_host":"server.test", "username_hint":r"TEST\alice"})
        right = event("evtx", "remote.evtx", details={"event_id":1149,
            "provider":"Microsoft-Windows-TerminalServices-RemoteConnectionManager", "computer":"SERVER.TEST.",
            "event_data":{"Param1":"alice", "Param2":"TEST"}})
        relation = next(r for r in correlate([left, right]) if r["type"] == "rdp_session_correlation")
        details = relation["evidence_details"]
        self.assertTrue(all(item["matched"] for item in details["comparisons"]))
        self.assertEqual(details["time_comparison"]["left_time_field"], "key_lastwrite")
        self.assertFalse(relation["time_is_connection_time"])

    def test_deletion_and_program_group_use_the_fields_of_their_actual_rules(self):
        events = [event("recyclebin", path=r"C:\Evidence\test.exe"),
                  event("bam", path=r"C:\Evidence\TEST.EXE"),
                  event("prefetch", process="TEST.EXE", path=r"C:\Evidence\other.exe")]
        relations = correlate(events)
        deleted = next(r for r in relations if r["type"] == "deletion_correlation")
        self.assertTrue(deleted["evidence_details"]["comparisons"][0]["matched"])
        programs = [r for r in relations if r["type"] == "program_group"]
        self.assertTrue(programs)
        self.assertTrue(all(r["evidence_details"]["comparisons"][0]["matched"] for r in programs))
        self.assertTrue(any(r["evidence_details"]["comparisons"][0]["right_field"] == "process" for r in programs))

    def test_report_preserves_details_without_embedding_evidence_as_markup(self):
        from pathlib import Path
        import tempfile
        from log_hunter.core.report import export_reports
        malicious = "</script><script>synthetic()</script>"
        events = [event("bam", malicious, path=r"C:\Evidence\test.exe"), event("prefetch", process="test.exe")]
        relations = correlate(events)
        with tempfile.TemporaryDirectory() as folder:
            export_reports(folder, [], events, [], relations, [])
            payload = json.loads((Path(folder) / "report.json").read_text(encoding="utf-8"))
            markup = (Path(folder) / "report.html").read_text(encoding="utf-8")
        self.assertEqual(payload["relations"], relations)
        self.assertNotIn(malicious, markup)
