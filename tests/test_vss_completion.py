"""Verify stored snapshot bytes and distinguish both histories from the current tree."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_vss_catalog import MemoryImage
from test_vss_extract import snapshot_image, STORE_ID
from test_vss_volume import mapped_fixture, prepare
from log_hunter.core.pipeline import Pipeline
from log_hunter.image.ewf import ImageError
from log_hunter.image.volumes import Volume
from log_hunter.image.vss import read_catalog, BLOCK_SIZE
from log_hunter.image.vss_volume import prepare_mapped_volume

spec = importlib.util.spec_from_file_location('vss_case', Path(__file__).parent / 'fixtures/vss_case.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class VSSCompletionTests(unittest.TestCase):
    def reader(self):
        data = snapshot_image()
        image = MemoryImage(data)
        volume = Volume(0, 0, len(data), 'test', 'volume', 'ntfs')
        catalog = read_catalog(image, volume)
        reader = prepare_mapped_volume(image, volume, catalog, STORE_ID).reader
        return image, reader, data[len(data) // 2:]

    def test_complete_view_is_verified_by_all_bytes_and_stable_hash(self):
        image, reader, expected = self.reader()
        before = hashlib.sha256(image.data).digest()
        self.assertFalse(reader.info()['reconstruction_complete'])
        self.assertTrue(reader.verify_reconstruction())
        self.assertTrue(reader.info()['reconstruction_complete'])
        self.assertEqual(reader.verification['bytes_verified'], len(expected))
        self.assertEqual(reader.origin['reconstruction_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(reader.read(0, len(expected)), expected)
        self.assertEqual(hashlib.sha256(image.data).digest(), before)

    def test_unknown_coverage_and_work_limit_remain_partial_before_data_io(self):
        image, volume, catalog = mapped_fixture()
        reader = prepare(image, volume, catalog).reader
        image.reads.clear()
        self.assertFalse(reader.verify_reconstruction())
        self.assertEqual(image.reads, [])
        self.assertEqual(reader.verification['status'], 'unmapped')
        self.assertIsNone(reader.origin['reconstruction_sha256'])
        image, reader, _ = self.reader()
        image.reads.clear()
        with patch('log_hunter.image.vss_volume.MAX_VERIFY_BLOCKS', 0):
            self.assertFalse(reader.verify_reconstruction())
        self.assertEqual(reader.verification['status'], 'limit')
        self.assertEqual(image.reads, [])
        with patch('log_hunter.image.vss_volume.MAX_RESOLUTION_STEPS', 0):
            self.assertFalse(reader.verify_reconstruction())
        self.assertEqual(reader.verification['status'], 'limit')
        self.assertEqual(image.reads, [])

    def test_short_io_does_not_publish_complete_hash_and_later_error_revokes_it(self):
        image, reader, _ = self.reader()
        with patch.object(image, 'read', return_value=b''):
            self.assertFalse(reader.verify_reconstruction())
        self.assertFalse(reader.info()['reconstruction_complete'])
        self.assertIsNone(reader.origin['reconstruction_sha256'])
        self.assertEqual(reader.verification['status'], 'read_error')
        self.assertTrue(reader.verify_reconstruction())
        with patch.object(image, 'read', side_effect=OSError('synthetic read failure')):
            with self.assertRaises(ImageError):
                reader.read(0, 1)
        self.assertFalse(reader.info()['reconstruction_complete'])
        self.assertIsNone(reader.origin['reconstruction_sha256'])

    def test_verification_budget_is_per_chunk_and_progress_has_both_phases(self):
        image, reader, expected = self.reader()
        updates = []
        with patch('log_hunter.image.vss_volume.MAX_READ', BLOCK_SIZE), patch(
                'log_hunter.image.vss_volume.MAX_RESOLUTION_STEPS', 40):
            self.assertTrue(reader.verify_reconstruction(lambda done, total, phase: updates.append((done, total, phase))))
        self.assertEqual({u[2] for u in updates}, {'mapping', 'hashing'})
        for phase in ('mapping', 'hashing'):
            phase_updates = [done for done, total, p in updates if p == phase]
            self.assertEqual(phase_updates[0], 0)
            self.assertEqual(phase_updates[-1], len(expected))
            self.assertEqual(phase_updates, sorted(phase_updates))
        self.assertEqual(reader.verification['sha256'], hashlib.sha256(expected).hexdigest())

    def test_fully_mapped_600_mib_view_does_not_hit_a_whole_volume_sector_budget(self):
        size = 600 * 1024 * 1024
        small_image, reader, _ = self.reader()
        # A generated zero-filled backing volume avoids allocating a 600 MiB fixture.
        class ZeroImage:
            def __init__(self):
                self.size = size + BLOCK_SIZE
                self.reads = 0
            def read(self, offset, length):
                if not 0 <= offset <= self.size or offset + length > self.size:
                    raise ImageError('synthetic bounds')
                self.reads += 1
                return bytes(length)
        image = ZeroImage()
        volume = Volume(0, 0, image.size, 'test', 'volume', 'ntfs')
        mapping = SimpleNamespace(blocks={offset: {'overlay': None,
            'base': {'flags': 0, 'store_offset': offset + BLOCK_SIZE}}
            for offset in range(0, size, BLOCK_SIZE)})
        reader.size, reader._image, reader._volume, reader._maps = size, image, volume, [mapping]
        self.assertTrue(reader.verify_reconstruction())
        self.assertEqual(reader.verification['bytes_verified'], size)
        digest = hashlib.sha256()
        for _ in range(600):
            digest.update(bytes(1024 * 1024))
        self.assertEqual(reader.verification['sha256'], digest.hexdigest())
        self.assertEqual(image.reads, 75)

    def test_cancel_before_io_or_during_hash_never_marks_complete(self):
        image, reader, _ = self.reader()
        image.reads.clear()
        self.assertFalse(reader.verify_reconstruction(cancel=lambda: True))
        self.assertEqual(reader.verification['status'], 'cancelled')
        self.assertEqual(image.reads, [])
        cancelled = [False]
        def update(done, total, phase):
            if phase == 'hashing' and done:
                cancelled[0] = True
        self.assertFalse(reader.verify_reconstruction(update, lambda: cancelled[0]))
        self.assertEqual(reader.verification['status'], 'cancelled')
        self.assertFalse(reader.origin['reconstruction_complete'])
        self.assertIsNone(reader.origin['reconstruction_sha256'])

    def test_pipeline_cancellation_does_not_start_ntfs_extraction(self):
        data, _ = fixture.build_case()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / 'synthetic.img'
            image.write_bytes(data)
            with patch('log_hunter.image.vss_extract.NTFSVolume', side_effect=AssertionError('cancelled')):
                result = Pipeline().analyze_snapshot(image, root / 'cancelled', 0, fixture.STORE_IDS[0],
                                                     verification_cancel=lambda: True)
            self.assertEqual(result.events, [])
            self.assertEqual(result.evidence, [])
            self.assertEqual(result.image['image']['snapshot_verification']['status'], 'cancelled')

    def test_current_and_two_snapshots_analyze_distinct_logs_with_complete_origins(self):
        data, snapshots = fixture.build_case()
        self.assertEqual(fixture.build_case(), (data, snapshots))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / 'synthetic.img'
            image.write_bytes(data)
            current = Pipeline().analyze_image(image, root / 'current')
            current_events = [e for e in current.events if e.artifact == 'psreadline']
            self.assertEqual(len(current_events), 1)
            self.assertIn('current', current_events[0].details['command'])
            for index, store_id in enumerate(fixture.STORE_IDS):
                result = Pipeline().analyze_snapshot(image, root / ('snapshot' + str(index)), 0, store_id)
                self.assertEqual({e.artifact for e in result.events}, {'psreadline', 'run'})
                event = next(e for e in result.events if e.artifact == 'psreadline')
                run = next(e for e in result.events if e.artifact == 'run')
                self.assertIn(('old-one', 'old-two')[index], run.path)
                self.assertIn(('old-one', 'old-two')[index], event.details['command'])
                self.assertIsNone(event.timestamp)
                note = result.evidence[0].metadata['snapshot']
                self.assertTrue(note['reconstruction_complete'])
                self.assertEqual(note['reconstruction_sha256'], hashlib.sha256(snapshots[index]).hexdigest())
                self.assertEqual(note['store_id'], store_id)
                self.assertEqual(note['time_field'], 'snapshot_creation_time')
                manifest = json.loads((root / ('snapshot' + str(index)) / 'image_manifest.json').read_text(encoding='utf-8'))
                self.assertEqual(manifest['image']['snapshot_verification']['status'], 'verified')
                self.assertTrue(all(e.severity == 'info' for e in result.errors))
                self.assertTrue(all(e.metadata['snapshot']['store_id'] == store_id for e in result.evidence))
            self.assertEqual(hashlib.sha256(image.read_bytes()).digest(), hashlib.sha256(data).digest())
