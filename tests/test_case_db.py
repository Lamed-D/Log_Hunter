"""Saved analyses restore independently of original evidence, without changing case bytes."""
import copy
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout, redirect_stderr
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from log_hunter.core.models import Evidence, ForensicEvent, ParserError
from log_hunter.core.pipeline import AnalysisResult, Pipeline
from log_hunter.core.tags import TagBook, event_key, event_ref, save_to_sqlite
from log_hunter.database.case_db import load_case, save_case, merge_results
from log_hunter.database.repository import Repository
from log_hunter.main import main, save_result


class CaseDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'case.sqlite'
        self.source = self.root / 'generated.txt'
        self.source.write_bytes(b'synthetic evidence')
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def result(self):
        source = str(self.source)
        event = ForensicEvent('psreadline', source, 'command_history', locator='line:1',
                              sid='S-1-5-21-1000-2000-3000-1001', details={'command': 'Write-Output example'})
        book = TagBook()
        key = event_key(event)
        book.toggle(key, 'event', event_ref(event), 'red')
        book.set_note(key, 'event', event_ref(event), 'synthetic note')
        return AnalysisResult(
            evidence=[Evidence(source, source, self.digest, metadata={'snapshot': {'store_id': 'synthetic-store'}})],
            events=[event], errors=[ParserError(source, 'psreadline', 'line:2', 'synthetic warning', 'warning')],
            relations=[{'type': 'correlation_group', 'event_indices': [0], 'candidate_count': 1,
                        'evidence_details': {'event_refs': [{'event_index': 0}], 'comparisons': [],
                                             'grouping': {'criteria': {'left_event_indices': [0]}}}}],
            summaries=[{'artifact': 'psreadline', 'events': 1, 'state': 'ok'}],
            profiles={event.sid: 'alice'}, sid_names={event.sid: 'alice'},
            image={'image_path': source, 'image': {'format': 'raw', 'segments': [source]},
                   'files': [{'image_path': r'\Users\alice\NTUSER.DAT', 'volume': 0, 'mft_record': 42, 'sha256': self.digest}]},
            inputs=[{'artifact': 'psreadline', 'path': source, 'sid': event.sid, 'reason': 'synthetic signature'}],
            settings={'sid': event.sid, 'with_mft': True, 'analysis_at': '2026-01-01T00:00:00+00:00'}, tags=book.rows())

    def snapshot(self):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.iterdir() if p.is_file()}

    def test_complete_roundtrip_readonly_and_integrity_sources(self):
        original = self.result()
        saved = save_case(self.path, original, name='synthetic case')
        before = self.snapshot()
        restored, info = load_case(self.path, verify=True)
        self.assertEqual(asdict(restored), asdict(original))
        self.assertEqual(info.name, 'synthetic case')
        self.assertEqual(info.created_at, original.settings['analysis_at'])
        self.assertEqual(info.schema_version, 2)
        self.assertEqual(info.verification['database']['status'], 'match')
        self.assertTrue(all(s['status'] == 'match' for s in info.sources))
        self.assertFalse(info.partial)
        self.assertEqual(info.warnings, [])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(saved.tags, info.tags)
        with self.assertRaises(FileExistsError):
            save_case(self.path, original)

    def test_missing_and_changed_originals_do_not_block_saved_events(self):
        save_case(self.path, self.result())
        self.source.write_bytes(b'changed synthetic content')
        restored, info = load_case(self.path, verify=True)
        self.assertEqual(len(restored.events), 1)
        self.assertTrue(all(s['status'] == 'changed' for s in info.sources))
        self.source.unlink()
        restored, info = load_case(self.path)
        self.assertEqual(len(restored.events), 1)
        self.assertTrue(all(s['status'] == 'missing' for s in info.sources))
        self.assertTrue(info.warnings)
        self.assertEqual(info.verification['database']['status'], 'match')

    def test_legacy_in_memory_migration_keeps_tags_and_missing_fields_explicit(self):
        original = self.result()
        repo = Repository(self.path)
        repo.save('legacy', original.evidence, original.events, original.errors, original.relations)
        repo.close()
        save_to_sqlite(self.path, original.tags)
        before = self.snapshot()
        result, info = load_case(self.path, verify=True)
        self.assertEqual(info.schema_version, 0)
        self.assertEqual(result.events, original.events)
        self.assertEqual(result.tags, original.tags)
        self.assertIn('image', info.missing_fields)
        self.assertIsNone(info.created_at)
        self.assertEqual(info.verification['database']['status'], 'unknown')
        self.assertEqual(before, self.snapshot())

    def test_future_schema_and_changed_counts_are_warnings(self):
        save_case(self.path, self.result())
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
            db.execute("INSERT INTO parser_errors(case_id,data) SELECT case_id,data FROM parser_errors")
        result, info = load_case(self.path, verify=True)
        self.assertEqual(info.schema_version, 999)
        self.assertTrue(info.partial)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(info.verification['database']['status'], 'changed')
        self.assertEqual(len(result.errors), 2)

    def test_bad_event_never_retargets_a_relation_to_another_record(self):
        original = self.result()
        original.events += [ForensicEvent('test', 'generated', 'second'), ForensicEvent('test', 'generated', 'third')]
        original.relations = [{'type': 'pair', 'left': 0, 'right': 2},
                              {'type': 'pair', 'left': 1, 'right': 2},
                              {'type': 'group', 'event_indices': [0, 2],
                               'evidence_details': {'event_refs': [{'event_index': 2}]}}]
        save_case(self.path, original)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE events SET data='broken json' WHERE id=2")
            db.execute("UPDATE case_state SET data='broken state'")
        result, info = load_case(self.path)
        self.assertTrue(info.partial)
        self.assertEqual([e.action for e in result.events], ['command_history', 'third'])
        self.assertEqual(result.relations[0]['right'], 1)
        self.assertEqual(result.relations[1]['event_indices'], [0, 1])
        self.assertEqual(result.relations[1]['evidence_details']['event_refs'][0]['event_index'], 1)
        self.assertEqual(len(result.relations), 2)
        self.assertTrue(info.warnings)

    def test_invalid_file_and_truncated_database(self):
        with self.assertRaises(ValueError):
            load_case(self.path)
        self.path.write_bytes(b'not sqlite')
        with self.assertRaises(ValueError):
            load_case(self.path)
        self.path.write_bytes(b'SQLite format 3\0' + bytes(200))
        before = self.snapshot()
        result, info = load_case(self.path, verify=True)
        self.assertEqual(result.events, [])
        self.assertTrue(info.partial)
        self.assertEqual(before, self.snapshot())

    def test_wal_is_loaded_without_touching_original_db_or_sidecars(self):
        save_case(self.path, self.result())
        db = sqlite3.connect(self.path)
        self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute("INSERT INTO parser_errors(case_id,data) SELECT case_id,data FROM parser_errors")
        db.commit()
        before = self.snapshot()
        result, info = load_case(self.path, verify=True)
        self.assertEqual(len(result.errors), 2)
        self.assertEqual(info.verification['database']['status'], 'changed')
        self.assertEqual(before, self.snapshot())

    def test_case_selection_is_explicit_for_legacy_multiple_cases(self):
        original = self.result()
        repo = Repository(self.path)
        first = repo.save('first', [], original.events, [], [])
        repo.save('second', [], [], [], [])
        repo.close()
        result, info = load_case(self.path)
        self.assertEqual(info.name, 'second')
        self.assertTrue(info.warnings)
        result, info = load_case(self.path, case_id=first)
        self.assertEqual(len(result.events), 1)
        with self.assertRaises(ValueError):
            load_case(self.path, case_id=999)

    def test_merge_preserves_fingerprints_tags_notes_and_relation_indices(self):
        existing = self.result()
        additional = copy.deepcopy(existing)
        additional.events.append(ForensicEvent('psreadline', str(self.source), 'command_history', locator='line:1',
                                              details={'command': 'Write-Output changed'}))
        existing.events.append(ForensicEvent('test', 'generated', 'unrelated'))
        additional.relations.append({'type': 'pair', 'left': 0, 'right': 1,
                                     'evidence_details': {'event_refs': [{'event_index': 1}]}})
        additional.tags[0]['note'] = 'another note'
        before = copy.deepcopy((existing, additional))
        merged = merge_results(existing, additional)
        self.assertEqual((existing, additional), before)
        self.assertEqual(len(merged.evidence), 1)
        self.assertEqual(len(merged.events), 3)
        self.assertNotEqual(event_key(merged.events[0]), event_key(merged.events[2]))
        self.assertEqual(merged.tags[0]['note'], 'synthetic note\n\nanother note')
        self.assertEqual(merged.tags[0]['key'], event_key(existing.events[0]))
        self.assertEqual(merged.relations[-1]['right'], 2)
        self.assertEqual(merged.relations[-1]['evidence_details']['event_refs'][0]['event_index'], 2)

    def test_cli_open_and_report_do_not_reanalyze(self):
        save_result(self.result(), self.root / 'saved')
        path = self.root / 'saved/case.sqlite'
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.object(Pipeline, 'analyze', side_effect=AssertionError('must not reanalyze')):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['open', str(path), '--verify']), 0)
            self.assertEqual(json.loads(output.getvalue())['events'], 1)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['report', '--from', str(path), '--output', str(self.root / 'report')]), 0)
        report = json.loads((self.root / 'report/report.json').read_text(encoding='utf-8'))
        self.assertEqual(len(report['events']), 1)
        self.assertEqual(report['examiner_tags'][0]['note'], 'synthetic note')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['report', '--from', str(path), '--output', str(self.root / 'saved')])

    def test_relative_sources_keep_their_saved_location_after_cwd_changes(self):
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            result = self.result()
            result.evidence[0].source = 'generated.txt'
            result.image = {}
            save_case(self.path, result)
            os.chdir(self.root.parent)
            restored, info = load_case(self.path, verify=True)
            self.assertEqual(restored.evidence[0].source, 'generated.txt')
            self.assertEqual(info.sources[0]['status'], 'match')
        finally:
            os.chdir(previous)

    def test_bad_record_types_and_tag_rows_do_not_discard_other_rows(self):
        save_case(self.path, self.result())
        with closing(sqlite3.connect(self.path)) as db, db:
            data = json.loads(db.execute('SELECT data FROM events').fetchone()[0])
            data['action'] = {}
            db.execute('UPDATE events SET data=?', (json.dumps(data),))
            db.execute("INSERT INTO examiner_tags(key,data) VALUES('bad', ?)",
                       (json.dumps({'key': 'bad', 'tags': [{'not': 'a tag'}]}),))
        result, info = load_case(self.path)
        self.assertEqual(result.events, [])
        self.assertEqual(len(result.tags), 1)
        self.assertEqual(result.relations, [])
        self.assertTrue(info.partial)

    def test_bounded_loading_drops_relations_to_unread_events(self):
        result = self.result()
        result.events.append(ForensicEvent('test', 'generated', 'unread'))
        result.relations.append({'type': 'pair', 'left': 0, 'right': 1})
        save_case(self.path, result)
        with patch('log_hunter.database.case_db.MAX_ROWS', 1):
            restored, info = load_case(self.path)
        self.assertEqual(len(restored.events), 1)
        self.assertEqual(len(restored.relations), 1)
        self.assertTrue(info.partial)

    def test_bulk_rows_restore_in_order(self):
        result = AnalysisResult(events=[ForensicEvent('test', 'generated', 'row', locator=str(i)) for i in range(3000)])
        save_case(self.path, result)
        restored, info = load_case(self.path)
        self.assertEqual(restored.events, result.events)
        self.assertEqual(info.verification['database']['status'], 'match')
