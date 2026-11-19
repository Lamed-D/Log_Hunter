"""Selective refresh preserves records for evidence whose hashes still match."""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from log_hunter.core.pipeline import Pipeline
from log_hunter.database.case_db import load_case, save_case
from log_hunter.database.incremental import reanalyze_case
from log_hunter.main import main
from test_browser_cache import simple_record
from test_image import NTFSBuilder


class IncrementalCaseTests(unittest.TestCase):
    def test_folder_membership_change_replaces_old_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "Cache"
            folder.mkdir()
            first = folder / "0123456789abcdef_0"
            first.write_bytes(simple_record(b"https://example.com/old", b""))
            case = root / "case.sqlite"
            save_case(case, Pipeline().analyze([("cache", folder)]))
            first.unlink()
            (folder / "fedcba9876543210_0").write_bytes(simple_record(b"https://example.com/new", b""))
            refreshed, counts, _ = reanalyze_case(case)
        self.assertEqual(counts["changed"], 1)
        self.assertEqual([event.url for event in refreshed.events if event.url], ["https://example.com/new"])

    def test_image_fingerprint_skips_equal_image_and_refreshes_changed_one(self):
        def image_data(command):
            builder = NTFSBuilder()
            folder = builder.makedirs("Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine")
            builder.add_file(folder, "ConsoleHost_history.txt", command.encode() + b"\n")
            return builder.build()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "generated.dd"
            image.write_bytes(image_data("Write-Output example-before"))
            case = root / "case.sqlite"
            save_case(case, Pipeline().analyze_image(image, root / "before", include_mft=True))
            with patch.object(Pipeline, "analyze_image", side_effect=AssertionError("unchanged image")):
                _, counts, _ = reanalyze_case(case)
            self.assertEqual(counts["reused"], 1)
            image.write_bytes(image_data("Write-Output example-after"))
            refreshed, counts, sources = reanalyze_case(case, workdir=root / "after" / "extracted")
        self.assertEqual(counts["reanalyzed"], 1)
        self.assertTrue(refreshed.settings["include_mft"])
        self.assertEqual([e.details["command"] for e in refreshed.events if e.artifact == "psreadline"],
                         ["Write-Output example-after"])
        self.assertEqual(sources[0]["kind"], "image")

    def test_new_database_sidecar_invalidates_the_main_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'History'
            with sqlite3.connect(source) as database:
                database.execute('CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,last_visit_time INTEGER)')
                database.execute("INSERT INTO urls VALUES(1,'https://example.com','example',0)")
            database.close()
            old = root / 'case.sqlite'
            save_case(old, Pipeline().analyze([('history', source)]))
            sidecar = root / 'History-shm'
            sidecar.write_bytes(b'synthetic sidecar')
            refreshed, counts, _ = reanalyze_case(old)
        self.assertEqual(counts['changed'], 1)
        self.assertEqual(counts['reanalyzed'], 1)
        self.assertTrue(any(item.source == str(sidecar) for item in refreshed.evidence))

    def test_cli_replaces_changed_source_and_reuses_the_other(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unchanged, changed = root / 'keep.txt', root / 'change.txt'
            unchanged.write_text('Write-Output example-keep\n', encoding='utf-8')
            changed.write_text('Write-Output example-before\n', encoding='utf-8')
            old = root / 'case.sqlite'
            inputs = [('psreadline', unchanged), ('psreadline', changed)]
            save_case(old, Pipeline().analyze(inputs))
            original = hashlib.sha256(old.read_bytes()).digest()
            changed.write_text('Write-Output example-after\n', encoding='utf-8')
            output = root / 'output'
            analyzed = []
            actual_analyze = Pipeline.analyze

            def trace(pipeline, inputs, **options):
                analyzed.extend(Path(path) for _, path, _ in inputs)
                return actual_analyze(pipeline, inputs, **options)

            with patch.object(Pipeline, 'analyze', trace):
                self.assertEqual(main(['reanalyze', str(old), '--output', str(output)]), 0)
            self.assertEqual(analyzed, [changed])
            refreshed, _ = load_case(output / 'case.sqlite')
            self.assertEqual({e.details['command'] for e in refreshed.events},
                             {'Write-Output example-keep', 'Write-Output example-after'})
            self.assertEqual(hashlib.sha256(old.read_bytes()).digest(), original)

    def test_same_source_skips_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'original.txt'
            source.write_text('Write-Output example\n', encoding='utf-8')
            old = root / 'case.sqlite'
            save_case(old, Pipeline().analyze([('psreadline', source)]))
            with patch.object(Pipeline, 'analyze', side_effect=AssertionError('already parsed')):
                refreshed, counts, _ = reanalyze_case(old)
            self.assertEqual(len(refreshed.events), 1)
            self.assertEqual(counts, {'inputs': 1, 'changed': 0, 'reanalyzed': 0, 'reused': 1})
