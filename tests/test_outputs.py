"""Saving results: relations without a left/right pair, CSV formula safety, output folder safety."""
import csv
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.correlation import correlate
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.main import save_result


def _event(artifact, path, timestamp="2024-01-01T00:00:00+00:00", **extra):
    return ForensicEvent(artifact=artifact, source=rf"C:\Evidence\{artifact}", action="execution_trace",
                         timestamp=timestamp, path=path, **extra)


def _result(events):
    result = AnalysisResult(events=events)
    result.relations = correlate(events)
    return result


class SaveResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_execution_chains_are_saved(self):
        events = [_event("prefetch", r"C:\Windows\evil.exe"), _event("bam", r"C:\Windows\evil.exe")]
        result = _result(events)
        self.assertTrue(any(r["type"] == "execution_chain" for r in result.relations))
        save_result(result, self.root / "out")
        self.assertTrue((self.root / "out" / "report.html").exists())
        with closing(sqlite3.connect(self.root / "out" / "case.sqlite")) as db:
            rows = db.execute("SELECT left_event, right_event FROM relations").fetchall()
        self.assertEqual(len(rows), len(result.relations))
        self.assertIn((None, None), rows)

    def test_timeline_csv_neutralizes_formulas(self):
        events = [_event("history", '=HYPERLINK("http://x")', url="=cmd|' /C calc'!A0",
                         details={"title": "+SUM(1)"}),
                  _event("lnk", " =1+1", process="\n=cmd")]
        save_result(_result(events), self.root / "out")
        from log_hunter.core.export import export_csv
        export_csv(events, self.root / "gui.csv")
        for path in (self.root / "out" / "timeline.csv", self.root / "gui.csv"):
            with path.open(encoding="utf-8-sig", newline="") as stream:
                cells = [cell for row in csv.reader(stream) for cell in row]
            risky = [c for c in cells if c.lstrip()[:1] in ("=", "+", "-", "@") and not c.startswith("'")]
            self.assertEqual(risky, [], path.name)

    def test_outputs_never_replace_existing_files(self):
        from log_hunter.collector.live_collector import register_evidence
        out = self.root / "out"
        out.mkdir()
        evidence = out / "timeline.json"  # an evidence file that happens to share an output name
        evidence.write_bytes(b"EVIDENCE")
        result = _result([_event("prefetch", "C:/a.exe")])
        result.evidence = [register_evidence(evidence, evidence, "OFFLINE")]
        with self.assertRaises(ValueError):
            save_result(result, out)
        self.assertEqual(evidence.read_bytes(), b"EVIDENCE")
        save_result(_result([_event("prefetch", "C:/a.exe")]), self.root / "second")
        with self.assertRaises(FileExistsError):
            save_result(_result([_event("prefetch", "C:/b.exe")]), self.root / "second")


class BodyfileTests(unittest.TestCase):
    def _lines(self, events):
        from log_hunter.core.export import export_bodyfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "timeline.bodyfile"
            export_bodyfile(events, path)
            return path.read_text(encoding="utf-8").splitlines()

    def test_each_time_meaning_fills_one_column(self):
        stamp = "2024-01-01T00:00:00+00:00"
        expected = {"si_created": 10, "fn_modified": 8, "si_accessed": 7, "si_mft_changed": 9, "key_lastwrite": 8,
                    "last_execution": 8}
        for time_field, column in expected.items():
            with self.subTest(time_field=time_field):
                fields = self._lines([_event("mft", "C:/a.txt", stamp, time_field=time_field)])[0].split("|")
                self.assertEqual([i for i in range(7, 11) if fields[i] != "0"], [column])
        unknown = self._lines([_event("bam", "C:/a.exe", stamp, time_field="last_execution")])[0]
        self.assertIn("last_execution", unknown.split("|")[1])

    def test_evidence_strings_cannot_add_fields_or_lines(self):
        lines = self._lines([_event("lnk", "C:/a|b\nfake|line.txt", time_field="si_created")])
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(lines[0].split("|")), 11)

class EvidenceFolderTests(unittest.TestCase):
    def test_srum_sqlite_is_read_without_touching_the_evidence_folder(self):
        from log_hunter.parser.srum import SRUMParser
        for folder_name in ("plain", "evidence #1 %20"):
            with self.subTest(folder=folder_name), tempfile.TemporaryDirectory() as temp:
                folder = Path(temp) / folder_name
                folder.mkdir()
                database = folder / "srum.sqlite"
                with closing(sqlite3.connect(database)) as db:
                    db.execute("PRAGMA journal_mode=WAL")
                    db.execute("CREATE TABLE [{973F5D5C-1D90-4944-BE8E-24B94231A174}](AppId, TimeStamp)")
                    db.execute("INSERT INTO [{973F5D5C-1D90-4944-BE8E-24B94231A174}] VALUES(1, 133000000000000000)")
                    db.commit()
                before = sorted(p.name for p in folder.iterdir())
                parser = SRUMParser()
                events = list(parser.parse(database))
                self.assertEqual(sorted(p.name for p in folder.iterdir()), before)
                self.assertTrue(events, [e.message for e in parser.errors])

if __name__ == "__main__":
    unittest.main()
