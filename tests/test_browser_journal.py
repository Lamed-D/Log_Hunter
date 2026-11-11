from contextlib import closing, contextmanager
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from log_hunter.collector.windows import NativeAPI
from log_hunter.collector.browser_collector import BrowserCollector
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.pipeline import Pipeline, merge_history
from log_hunter.image.extract import extract_artifacts
from test_image import NTFSBuilder


HOT_JOURNAL_SCRIPT = '''
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('PRAGMA journal_mode=DELETE')
db.execute('PRAGMA cache_size=4')
db.execute('PRAGMA synchronous=FULL')
db.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)')
db.execute('CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,transition INTEGER)')
db.executemany('INSERT INTO urls VALUES(?,?,?,13253760000000000)',
               [(i, 'https://example.test/' + str(i), 'old' * 1000) for i in range(1,129)])
db.execute('INSERT INTO visits VALUES(1,1,13253760000000000,0)')
db.commit()
db.execute('BEGIN IMMEDIATE')
db.execute('UPDATE urls SET title=?', ('new' * 1000,))
os._exit(0)
'''


class BrowserJournalTests(unittest.TestCase):
    def test_hot_journal_recovers_only_disposable_copy_and_is_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'History'
            subprocess.run([sys.executable, '-c', HOT_JOURNAL_SCRIPT, str(source)], check=True, timeout=15)
            journal = Path(str(source) + '-journal')
            self.assertTrue(journal.exists())
            self.assertNotEqual(journal.read_bytes()[:8], bytes(8))
            sources = (source, journal)
            before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
            working = root / 'working'
            working.mkdir()
            normalized = merge_history(source, working)
            with closing(sqlite3.connect(normalized)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM urls WHERE title=?', ('old' * 1000,)).fetchone()[0], 128)
            result = Pipeline().analyze([('history', source)])
            self.assertEqual(len(result.events), 1)
            self.assertEqual({Path(e.source).name for e in result.evidence}, {'History', 'History-journal'})
            self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})

    def test_collection_copies_journal_in_same_volume_session(self):
        with tempfile.TemporaryDirectory() as directory:
            class Volume:
                def lookup(self, path):
                    return path
                def copy_file(self, entry, target):
                    target.write_bytes(entry.encode())
            class FakeAPI:
                calls = 0
                copy_browser = NativeAPI.copy_browser
                @contextmanager
                def volume_session(self, source):
                    self.calls += 1
                    yield Volume(), 'History'
            api = FakeAPI()
            copies = BrowserCollector(api=api).collect('History', Path(directory) / 'collected')
            self.assertEqual(api.calls, 1)
            self.assertEqual([Path(item.source).name for item in copies],
                             ['History', 'History-wal', 'History-shm', 'History-journal'])
            self.assertEqual(Path(copies[-1].collected).read_bytes(), b'History-journal')
            self.assertEqual(copies[-1].sha256, hashlib.sha256(b'History-journal').hexdigest())
            self.assertFalse(copies[-1].metadata['point_in_time_consistent'])

    def test_image_extraction_manifest_and_auto_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            builder = NTFSBuilder()
            profile = builder.makedirs('Users/alice/AppData/Local/Google/Chrome/User Data/Default')
            builder.add_file(profile, 'History', b'SQLite format 3\0synthetic', mode='resident')
            builder.add_file(profile, 'History-journal', b'synthetic rollback journal', mode='resident')
            image = root / 'synthetic.dd'
            image.write_bytes(builder.build())
            result = extract_artifacts(image, root / 'extracted')
            entry = next(f for f in result.files if f['image_path'].endswith('History-journal'))
            self.assertEqual(entry['sha256'], hashlib.sha256(b'synthetic rollback journal').hexdigest())
            inputs = detect_inputs([root / 'extracted'])
            self.assertFalse(any(item[0] == 'history' and str(item[1]).endswith('-journal') for item in inputs))
