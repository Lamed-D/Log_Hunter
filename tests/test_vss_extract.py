"""합성 스냅숏을 기존 추출·분석으로 연결하며 원본과 출처 보존을 확인합니다."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import struct
import sqlite3
import tempfile
import unittest
import uuid

from test_image import NTFSBuilder
from test_vss_catalog import header
from test_vss_sequence import sequence_fixture
from log_hunter.core.pipeline import Pipeline
from log_hunter.image.vss import BLOCK_SIZE
from log_hunter.image.vss_extract import extract_mapped_snapshot
from log_hunter.main import main


STORE_ID = str(uuid.UUID(int=1))
HISTORY = 'Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'


def snapshot_image(content=b'Write-Output example\n', missing_data=False):
    builder = NTFSBuilder()
    parent = builder.makedirs(HISTORY.rsplit('/', 1)[0])
    builder.add_file(parent, 'ConsoleHost_history.txt', content)
    old = builder.build()
    image, _, _ = sequence_fixture()
    data = bytearray(len(old)*2)
    data[:len(image.data)] = image.data
    data[len(old):] = old
    for number in (1, 2):
        struct.pack_into('<Q', data, BLOCK_SIZE*2 + number*128 + 8, len(old))
    for offset in (BLOCK_SIZE*5, BLOCK_SIZE*6):
        header(data, offset, 3)
    missing = (old.find(content) + len(content) - 1) // BLOCK_SIZE * BLOCK_SIZE if missing_data else -1
    index = 0
    for offset in range(0, len(old), BLOCK_SIZE):
        if offset == missing:
            continue
        struct.pack_into('<QQQII', data, BLOCK_SIZE*5 + 128 + index*32,
                         offset, 0, len(old) + offset, 0, 0)
        index += 1
    return bytes(data)


class VSSExtractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / 'synthetic.img'
        self.image.write_bytes(snapshot_image())

    def tearDown(self):
        self.temp.cleanup()

    def test_extraction_reuses_specs_and_preserves_snapshot_manifest(self):
        before = hashlib.sha256(self.image.read_bytes()).digest()
        result = extract_mapped_snapshot(self.image, self.root / 'work', 0, STORE_ID)
        self.assertEqual(len(result.inputs), 1)
        self.assertEqual(result.inputs[0][0], 'psreadline')
        self.assertEqual(Path(result.inputs[0][1]).read_bytes(), b'Write-Output example\n')
        note = result.files[0]['snapshot']
        self.assertEqual(note['store_id'], STORE_ID)
        self.assertEqual(note['snapshot_id'], str(uuid.UUID(int=101)))
        self.assertTrue(note['reconstruction_complete'])
        self.assertEqual(note['reconstruction_sha256'], hashlib.sha256(snapshot_image()[len(snapshot_image()) // 2:]).hexdigest())
        manifest = json.loads((self.root / 'work/image_manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['files'][0]['snapshot'], note)
        self.assertEqual(result.warnings, [])
        self.assertEqual(before, hashlib.sha256(self.image.read_bytes()).digest())

    def test_pipeline_keeps_creation_time_in_evidence_not_event_time(self):
        result = Pipeline().analyze_snapshot(self.image, self.root / 'analysis', 0, STORE_ID)
        self.assertEqual(len(result.events), 1)
        self.assertIsNone(result.events[0].timestamp)
        self.assertEqual(result.evidence[0].method, 'IMAGE')
        note = result.evidence[0].metadata['snapshot']
        self.assertEqual(note['time_field'], 'snapshot_creation_time')
        self.assertEqual(note['store_id'], STORE_ID)
        self.assertEqual(note['source'], str(self.image.resolve()))
        self.assertTrue(all(error.severity == 'warning' for error in result.errors))

    def test_unmapped_file_data_is_not_kept_as_partial_evidence(self):
        self.image.write_bytes(snapshot_image(b'X'*20000, missing_data=True))
        result = extract_mapped_snapshot(self.image, self.root / 'partial', 0, STORE_ID)
        self.assertEqual(result.inputs, [])
        self.assertEqual(result.files, [])
        self.assertTrue(result.warnings)
        self.assertFalse(list((self.root / 'partial').rglob('ConsoleHost_history.txt')))

    def test_nonempty_output_and_live_source_are_rejected(self):
        work = self.root / 'existing'
        work.mkdir()
        original = work / 'keep.txt'
        original.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            extract_mapped_snapshot(self.image, work, 0, STORE_ID)
        self.assertEqual(original.read_bytes(), b'keep')
        with self.assertRaises(ValueError):
            extract_mapped_snapshot(r'\\.\C:', self.root / 'live', 0, STORE_ID)
        self.assertFalse((self.root / 'live').exists())

    def test_missing_store_volume_and_corrupt_header_are_diagnostics(self):
        for number, identity in ((999, STORE_ID), (True, STORE_ID), (0, 'missing-store')):
            result = extract_mapped_snapshot(self.image, self.root / str(number) / identity, number, identity)
            self.assertEqual(result.files, [])
            self.assertTrue(result.warnings)
        data = bytearray(self.image.read_bytes())
        struct.pack_into('<I', data, BLOCK_SIZE*7 + 20, 3)
        self.image.write_bytes(data)
        result = extract_mapped_snapshot(self.image, self.root / 'corrupt', 0, STORE_ID)
        self.assertEqual(result.files, [])
        self.assertTrue(result.warnings)

    def test_cli_partial_analysis_and_argument_validation(self):
        output = self.root / 'cli'
        with redirect_stdout(io.StringIO()):
            code = main(['analyze', '--image', str(self.image), '--snapshot-store', STORE_ID,
                         '--snapshot-volume', '0', '--output', str(output)])
        self.assertEqual(code, 0)
        self.assertTrue((output / 'case.sqlite').exists())
        database = sqlite3.connect(output / 'case.sqlite')
        try:
            evidence = json.loads(database.execute('SELECT data FROM evidence_files').fetchone()[0])
        finally:
            database.close()
        self.assertEqual(evidence['metadata']['snapshot']['store_id'], STORE_ID)
        manifest = json.loads((output / 'image_manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['files'][0]['snapshot']['store_id'], STORE_ID)
        for arguments in (['--snapshot-store', STORE_ID], ['--snapshot-volume', '0'],
                          ['--snapshot-store', STORE_ID, '--snapshot-volume', '0', '--verify-image']):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['analyze', '--image', str(self.image), '--output', str(self.root / 'invalid'), *arguments])
        self.assertFalse((self.root / 'invalid').exists())
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['analyze', '--image', r'\\.\C:', '--snapshot-store', STORE_ID,
                  '--snapshot-volume', '0', '--output', str(self.root / 'live-cli')])
        self.assertFalse((self.root / 'live-cli').exists())
