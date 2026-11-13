import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_hunter.core.models import ForensicEvent, ParserError
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import (ARTIFACT_CATEGORIES, DIRECT_SOURCE, OriginIndex, build_tree, category_of,
                                  event_properties, matches)
from log_hunter.image import extract_artifacts
from log_hunter.parser.bam import BAMParser  # noqa: F401  (pipeline import side effects)
from test_image import mbr_disk, windows_volume, write_e01


def event(artifact, source, sid=None, **extra):
    return ForensicEvent(artifact=artifact, source=source, action="execution_trace", sid=sid, **extra)


def find(roots, key):
    for root in roots:
        for node in root.walk():
            if node.key == key:
                return node
    return None


class TreeModelTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            event("bam", r"C:\Evidence\SYSTEM", "S-1-5-21-1-1001", path=r"\Windows\explorer.exe"),
            event("bam", r"C:\Evidence\SYSTEM", "S-1-5-21-1-1002"),
            event("prefetch", r"C:\Evidence\Prefetch\APP.EXE-1.pf"),
            event("recyclebin", r"C:\Evidence\$IABC.txt", "S-1-5-21-1-1001"),
            event("weird", r"D:\x.bin"),
        ]
        self.relations = [{"type": "execution_chain"}, {"type": "execution_chain"}, {"type": "url_match"}]
        self.errors = [ParserError("a", "bam", "x", "bad", "warning"), ParserError("b", "evtx", "y", "bad")]
        self.roots = build_tree(self.events, self.relations, self.errors, {"S-1-5-21-1-1001": "alice"})

    def test_every_parser_artifact_has_a_category(self):
        from log_hunter.core.pipeline import PARSERS
        self.assertEqual([a for a in PARSERS if category_of(a) == "other"], [])
        keys = [k for k, *_ in ARTIFACT_CATEGORIES]
        self.assertEqual(len(keys), len(set(keys)))

    def test_artifact_categories_use_plain_labels(self):
        run = find(self.roots, "art:run_programs")
        self.assertEqual(run.label, "실행한 프로그램")
        self.assertEqual(run.count, 3)
        self.assertEqual([c.value for c in run.children], [("prefetch",), ("bam",), ("userassist",)])
        self.assertEqual(find(self.roots, "art:shell_bags").analysis_state, "not_analyzed")
        self.assertEqual(find(self.roots, "art:other").count, 1)
        self.assertEqual(find(self.roots, "art").count, len(self.events))

    def test_empty_tree_keeps_all_supported_types_in_friendly_categories(self):
        from log_hunter.core.pipeline import PARSERS
        roots = build_tree([])
        categories = find(roots, "art").children
        self.assertEqual(len(categories), len(ARTIFACT_CATEGORIES))
        self.assertEqual({a for c in categories for a in c.value}, set(PARSERS))
        self.assertTrue(all(c.analysis_state == "not_analyzed" for c in categories))
        self.assertTrue(all("분석 입력 미확인" in c.text for c in categories))

    def test_parser_summary_distinguishes_empty_failed_partial_and_missing(self):
        summaries = [{"artifact": "bam", "state": "no_data"},
                     {"artifact": "prefetch", "state": "failed"},
                     {"artifact": "history", "state": "ok"},
                     {"artifact": "history", "state": "failed"}]
        roots = build_tree([event("history", "History")], summaries=summaries)
        self.assertEqual(find(roots, "art:run_programs:bam").analysis_state, "no_data")
        self.assertEqual(find(roots, "art:run_programs:prefetch").analysis_state, "failed")
        self.assertEqual(find(roots, "art:run_programs:userassist").analysis_state, "not_analyzed")
        self.assertEqual(find(roots, "art:web_history:history").analysis_state, "partial")
        self.assertEqual(find(roots, "art:autostart").value,
                         ("run", "startup", "services", "tasks", "taskcache"))
        self.assertTrue(matches(find(roots, "art:web_history"), event("history", "History"), OriginIndex()))

    def test_old_results_and_warnings_do_not_claim_no_records_or_success(self):
        roots = build_tree([event("bam", "SYSTEM")], errors=[ParserError("SYSTEM", "bam", "x", "bad", "warning")])
        self.assertEqual(find(roots, "art:run_programs:bam").analysis_state, "partial")
        self.assertEqual(find(roots, "art:run_programs:userassist").analysis_state, "not_analyzed")
        roots = build_tree([], errors=[ParserError("SYSTEM", "bam", "x", "bad", "warning")])
        self.assertEqual(find(roots, "art:run_programs:bam").analysis_state, "partial")

    def test_data_source_file_tree(self):
        evidence = find(self.roots, "src:" + "\\".join((DIRECT_SOURCE, "C:\\", "Evidence")))
        self.assertEqual(evidence.count, 4)
        labels = [c.label for c in evidence.children]
        self.assertEqual(labels[0], "Prefetch")  # folders first
        system = next(c for c in evidence.children if c.label == "SYSTEM")
        self.assertEqual(system.count, 2)
        origins = OriginIndex()
        self.assertEqual([matches(evidence, e, origins) for e in self.events], [True, True, True, True, False])
        self.assertEqual(sum(matches(system, e, origins) for e in self.events), 2)

    def test_results_and_accounts(self):
        self.assertEqual(find(self.roots, "res:rel").count, 3)
        self.assertEqual(find(self.roots, "res:rel:execution_chain").count, 2)
        self.assertEqual(find(self.roots, "res:err:warning").count, 1)
        alice = find(self.roots, "acct:S-1-5-21-1-1001")
        self.assertEqual((alice.label, alice.count), ("alice — S-1-5-21-1-1001", 2))
        self.assertEqual(sum(matches(alice, e, OriginIndex()) for e in self.events), 2)

    def test_event_properties_nest_details(self):
        item = event("bam", "SYSTEM", "S-1-5-21-1-1001", path="C:\\a.exe", timestamp="2022-10-11T04:12:26+00:00",
                     time_field="last_execution", details={"key": "UserSettings", "hashes": {"sha1": "abc"}, "list": [1, 2]})
        rows = event_properties(item, "[case.E01] 볼륨 0\\Windows\\System32\\config\\SYSTEM", "alice")
        names = {r.name: r for r in rows}
        self.assertEqual(names["기록 종류"].value, "최근 실행한 프로그램")
        self.assertEqual(names["사용자"].value, "alice (S-1-5-21-1-1001)")
        self.assertNotIn("주소", names)
        details = names["세부 정보"]
        self.assertEqual([c.name for c in details.children], ["key", "hashes", "list"])
        self.assertEqual(details.children[1].children[0].value, "abc")
        self.assertEqual([c.name for c in details.children[2].children], ["[0]", "[1]"])


class RecoveredHiveSourceTests(unittest.TestCase):
    def test_events_from_log_recovered_hive_point_at_the_evidence_file(self):
        from unittest import mock
        from log_hunter.parser.base import ArtifactParser
        from test_analysis import build_hive

        class EchoParser(ArtifactParser):
            artifact = "run"

            def parse(self, path):
                return [ForensicEvent("run", str(path), "registration")]

        dirty = bytearray(build_hive([]))
        dirty[4:12] = (10).to_bytes(4, "little") + (5).to_bytes(4, "little")
        with tempfile.TemporaryDirectory() as temp:
            hive = Path(temp) / "SOFTWARE"
            hive.write_bytes(bytes(dirty))
            with mock.patch.dict("log_hunter.core.pipeline.PARSERS", {"run": EchoParser}), \
                    mock.patch("log_hunter.core.pipeline.replay_logs", return_value=(bytes(dirty), {"recovered": True})):
                result = Pipeline().analyze([("run", str(hive))])
            self.assertEqual([e.source for e in result.events], [str(hive)])
            self.assertEqual(result.summaries[0]["source"], str(hive))


class TreeFromImageTests(unittest.TestCase):
    def test_tree_shows_paths_inside_the_image(self):
        volume, _system = windows_volume()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            segments = write_e01(root / "case.E01", mbr_disk(volume))
            extraction = extract_artifacts(segments[0], root / "work")
            result = Pipeline().analyze(extraction.inputs)
            origins = OriginIndex([extraction])
            roots = build_tree(result.events, result.relations, result.errors, {}, origins,
                               [e.source for e in result.evidence])
            config = find(roots, "src:" + "\\".join(("case.E01", "볼륨 0", "Windows", "System32", "config")))
            self.assertEqual(sorted(c.label for c in config.children), ["SOFTWARE", "SYSTEM", "SYSTEM.LOG1"])
            prefetch = find(roots, "src:" + "\\".join(("case.E01", "볼륨 0", "Windows", "Prefetch")))
            self.assertEqual(len(prefetch.children), 40)  # files with no parsed records still appear
            self.assertEqual(prefetch.count, sum(e.artifact == "prefetch" for e in result.events))
            self.assertFalse(any(n.label.startswith("log-hunter-") for root in roots for n in root.walk()))
            recycled = next(e for e in result.events if e.artifact == "recyclebin")
            self.assertTrue(origins.text(recycled.source).startswith("[case.E01] 볼륨 0\\$Recycle.Bin\\"))


if __name__ == "__main__":
    unittest.main()
