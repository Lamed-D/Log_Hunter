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
from test_image import CLUSTER, MFT_LCN, MFT_RECORDS, RECORD, NTFSBuilder
from test_vss_extract import STORE_ID, snapshot_image


class IncrementalCaseTests(unittest.TestCase):
    def test_snapshot_refresh_preserves_selection_and_checks_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "snapshot.img"
            image.write_bytes(snapshot_image())
            case = root / "case.sqlite"
            saved = Pipeline().analyze_snapshot(image, root / "initial", 0, STORE_ID, include_mft=True)
            save_case(case, saved)
            with patch.object(Pipeline, "analyze_snapshot", side_effect=AssertionError("unchanged snapshot")):
                _, counts, _ = reanalyze_case(case)
            self.assertEqual(counts["reused"], 1)

            image.write_bytes(snapshot_image(b"Write-Output refreshed\n"))
            fresh, counts, sources = reanalyze_case(case, workdir=root / "updated" / "extracted")
            self.assertEqual(counts["reanalyzed"], 1)
            self.assertTrue(fresh.settings["include_mft"])
            self.assertEqual(fresh.image["image"]["snapshot"]["store_id"], STORE_ID)
            self.assertEqual([event.details["command"] for event in fresh.events if event.artifact == "psreadline"],
                             ["Write-Output refreshed"])
            self.assertEqual(sources[0]["expected_sha256"], hashlib.sha256(image.read_bytes()).hexdigest())

            image.write_bytes(NTFSBuilder().build())
            with self.assertRaisesRegex(ValueError, "같은 스냅숏"):
                reanalyze_case(case, workdir=root / "missing" / "extracted")

    def test_folder_membership_change_replaces_old_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "Cache"
            data = folder / "Cache_Data"
            data.mkdir(parents=True)
            first = data / "0123456789abcdef_0"
            first.write_bytes(simple_record(b"https://example.com/old", b""))
            case = root / "case.sqlite"
            save_case(case, Pipeline().analyze([("cache", folder)]))
            first.unlink()
            (data / "fedcba9876543210_0").write_bytes(simple_record(b"https://example.com/new", b""))
            refreshed, counts, _ = reanalyze_case(case)
        self.assertEqual(counts["changed"], 1)
        self.assertEqual([event.url for event in refreshed.events if event.url], ["https://example.com/new"])
        self.assertEqual([event.source for event in refreshed.events if event.action == "cache_folder_status"],
                         [str(data)])

    def test_mft_refresh_replaces_and_removes_derived_jump_list(self):
        def mft_data(name):
            builder = NTFSBuilder()
            number = builder.add_file(5, name, b"synthetic", mode="resident")
            start = MFT_LCN * CLUSTER
            data = bytearray(builder.build()[start:start + MFT_RECORDS * RECORD])
            data[number * RECORD + 22:number * RECORD + 24] = b"\0\0"
            return data

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "$MFT"
            case = root / "case.sqlite"
            source.write_bytes(mft_data("1111111111111111.customDestinations-ms"))
            save_case(case, Pipeline().analyze([("mft", source)]))
            source.write_bytes(mft_data("2222222222222222.customDestinations-ms"))
            refreshed, _, _ = reanalyze_case(case)
            candidate, = [event for event in refreshed.events if event.artifact == "jumplist"]
            self.assertEqual(candidate.details["app_id"], "2222222222222222")
            source.write_bytes(mft_data("unrelated.txt"))
            refreshed, _, _ = reanalyze_case(case)
            self.assertFalse(any(event.artifact == "jumplist" for event in refreshed.events))

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
