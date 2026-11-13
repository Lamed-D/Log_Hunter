"""Synthetic regression coverage for complete, rollback-safe analysis saving."""
import ast
import errno
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.models import ForensicEvent, Evidence
from log_hunter.database.case_db import load_case
from log_hunter.database.save import (save_analysis, SaveExistsError, SaveCancelled,
    SaveSourceError, SaveSpaceError, SaveLockedError, SavePermissionError, SavePathError)
from log_hunter.main import main, save_result


class UnifiedSaveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / 'saved'
        self.result = AnalysisResult(events=[ForensicEvent('psreadline', 'synthetic', 'command_history',
            details={'command': '</script><script>example</script>'})],
            inputs=[{'artifact': 'psreadline', 'path': 'synthetic', 'sid': None}],
            settings={'analysis_at': '2024-01-01T00:00:00+00:00'})

    def test_roundtrip_complete_and_digest(self):
        report = save_analysis(self.folder, self.result)
        restored, info = load_case(self.folder / 'case.sqlite')
        again = self.root / 'again'
        save_analysis(again, restored, sources=info.sources)
        self.assertEqual(report.files and set(report.files), {p.name for p in again.iterdir()})
        self.assertEqual(restored.inputs, self.result.inputs)
        self.assertEqual(restored.settings, self.result.settings)
        self.assertEqual(json.loads((again / 'timeline.json').read_text()),
                         json.loads((self.folder / 'timeline.json').read_text()))
        manifest = json.loads((again / 'case.sqlite.integrity.json').read_text())
        self.assertEqual(manifest['sha256'], hashlib.sha256((again / 'case.sqlite').read_bytes()).hexdigest())
        html = (again / 'report.html').read_text(encoding='utf-8')
        self.assertNotIn('</script><script>example', html)
        self.assertIn('<\\/script>', html)

    def test_existing_report_is_never_overwritten(self):
        self.folder.mkdir()
        (self.folder / 'report.html').write_bytes(b'original')
        with self.assertRaises(SaveExistsError) as caught:
            save_result(self.result, self.folder)
        self.assertEqual(caught.exception.files, ('report.html',))
        self.assertEqual(list(self.folder.iterdir()), [self.folder / 'report.html'])
        self.assertEqual((self.folder / 'report.html').read_bytes(), b'original')

    def test_failure_and_cancel_leave_no_partial_result(self):
        for existing in (False, True):
            if existing:
                self.folder.mkdir()
                (self.folder / 'unrelated').write_bytes(b'keep')
            with patch('log_hunter.database.save.export_reports', side_effect=OSError(errno.ENOSPC, 'synthetic')):
                with self.assertRaises(SaveSpaceError):
                    save_analysis(self.folder, self.result)
            self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['saved'] if existing else [])
            if existing:
                self.assertEqual([p.name for p in self.folder.iterdir()], ['unrelated'])
        with self.assertRaises(SaveCancelled):
            save_analysis(self.folder, self.result, cancel=lambda: True)
        self.assertFalse(any(self.root.glob('.saving-*')))

    def test_publication_collision_rolls_back_only_owned_files(self):
        self.folder.mkdir()
        import os
        real_link = os.link
        count = 0
        def racing_link(source, target):
            nonlocal count
            count += 1
            if count == 3:
                Path(target).write_bytes(b'competing writer')
            real_link(source, target)
        with patch('log_hunter.database.save.os.link', side_effect=racing_link):
            with self.assertRaises(SaveExistsError):
                save_analysis(self.folder, self.result)
        self.assertEqual(len(list(self.folder.iterdir())), 1)
        self.assertEqual(next(self.folder.iterdir()).read_bytes(), b'competing writer')
        self.assertFalse(any(self.root.glob('.saving-*')))

    def test_source_folder_refused(self):
        source = self.root / 'synthetic'
        source.write_bytes(b'original')
        self.result.evidence = [Evidence(str(source), str(source), '')]
        with self.assertRaises(SaveSourceError):
            save_analysis(self.root, self.result)
        self.assertEqual(source.read_bytes(), b'original')

    def test_cancel_after_database_written(self):
        stopped = False
        def progress(stage, ratio):
            nonlocal stopped
            if ratio >= .4:
                stopped = True
        with self.assertRaises(SaveCancelled):
            save_analysis(self.folder, self.result, progress=progress, cancel=lambda: stopped)
        self.assertFalse(self.folder.exists())
        self.assertFalse(any(self.root.glob('.saving-*')))

    def test_oserror_mapping(self):
        for error, expected in [(PermissionError(errno.EACCES, 'synthetic'), SavePermissionError),
                                (OSError(errno.ENAMETOOLONG, 'synthetic'), SavePathError)]:
            with patch('log_hunter.database.save.export_reports', side_effect=error):
                with self.assertRaises(expected):
                    save_analysis(self.folder, self.result)
            self.assertFalse(self.folder.exists())

    def test_locked_file_error_and_cleanup(self):
        error = OSError('synthetic sharing violation')
        error.winerror = 32
        with patch('log_hunter.database.save.export_reports', side_effect=error):
            with self.assertRaises(SaveLockedError):
                save_analysis(self.folder, self.result)
        self.assertFalse(self.folder.exists())
        self.assertFalse(any(self.root.glob('.saving-*')))

    def test_korean_spaces_and_long_path(self):
        folder = self.root / '한글 공백'
        while len(str(folder)) < 275:
            folder = folder / 'synthetic-long-folder'
        report = save_analysis(folder, self.result)
        self.assertEqual(len(load_case(report.folder / 'case.sqlite')[0].events), 1)

    def test_cli_conflict_has_no_traceback(self):
        source = self.root / 'ConsoleHost_history.txt'
        source.write_text('Write-Output example', encoding='utf-8')
        save_result(self.result, self.folder)
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            code = main(['analyze', '--input', 'psreadline', str(source), '--output', str(self.folder)])
        self.assertEqual(code, 2)
        self.assertNotIn('Traceback', stderr.getvalue())
        self.assertIn('새 하위 폴더', stderr.getvalue())

    def test_gui_both_entries_use_same_worker(self):
        tree = ast.parse(Path('log_hunter/ui/app.py').read_text(encoding='utf-8'))
        functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        for name in ('export', 'save_case_dialog'):
            self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                and n.func.id == '_start_save' for n in ast.walk(functions[name])))
        # Execute the real shared GUI entry without Tk: capture and run its submitted job.
        from types import SimpleNamespace
        jobs = []
        class Widget:
            def __init__(self, *a, **kw): pass
            def __getattr__(self, name): return lambda *a, **kw: None
        nodes = ast.Module(body=[functions['_start_save']], type_ignores=[])
        import threading, queue
        env = dict(auto=SimpleNamespace(waiting=False), analysis_state={'busy': False, 'extracting': False}, Path=Path, result=self.result, book=SimpleNamespace(rows=lambda: []), sid_map={},
            loaded_case={'info': None}, inputs=[], saving={'dialog': None}, threading=threading, queue=queue,
            tk=SimpleNamespace(Toplevel=Widget), ttk=SimpleNamespace(Label=Widget,Progressbar=Widget,Button=Widget),
            root=Widget(), runner=SimpleNamespace(submit=lambda tag, job: jobs.append(job)))
        exec(compile(nodes, '<gui-save>', 'exec'), env)
        env['_start_save'](self.folder)
        report, *_ = jobs.pop()()
        self.assertEqual(set(report.files), {p.name for p in self.folder.iterdir()})
        self.assertEqual(load_case(self.folder / 'case.sqlite')[0].inputs, self.result.inputs)


    def test_browser_download_blob_roundtrips_in_all_exports(self):
        import sqlite3
        from contextlib import closing
        from log_hunter.core.pipeline import Pipeline
        source = self.root / 'History'
        with closing(sqlite3.connect(source)) as db:
            db.executescript('CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,last_visit_time INTEGER);'
                             'CREATE TABLE downloads(id INTEGER,start_time INTEGER,target_path TEXT,hash BLOB);')
            db.execute('INSERT INTO downloads VALUES(1,0,?,?)', ('C:/Evidence/example.bin', b"\x00\xff"))
            db.commit()
        result = Pipeline().analyze([('history', str(source), None)])
        save_analysis(self.folder, result)
        restored, _ = load_case(self.folder / 'case.sqlite')
        expected = {'encoding': 'hex', 'value': '00ff'}
        self.assertEqual(restored.events[0].details['hash'], expected)
        report = json.loads((self.folder / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(report['events'][0]['details']['hash'], expected)
        self.assertEqual(restored.events[0].details, result.events[0].details)

    def test_incomplete_db_explains_reanalysis_required(self):
        from log_hunter.database.repository import Repository
        db = Repository(self.root / 'empty.sqlite')
        db.close()
        with self.assertRaisesRegex(ValueError, '원본을 다시 분석'):
            load_case(self.root / 'empty.sqlite')
