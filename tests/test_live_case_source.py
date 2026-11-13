"""Live-volume case metadata must not be treated as a missing image file."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from log_hunter.database.case_db import CaseInfo, _check_sources, save_case, load_case
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.ui import case_view

class LiveSourceTests(unittest.TestCase):
    def test_live_source_does_not_probe_or_hash_running_drive(self):
        for path in (r'\\.\C:', r'\\.\C'):
            for verify in (False, True):
                info = CaseInfo(sources=[{'path': path, 'resolved_path': path, 'kind': 'image'}])
                with patch('log_hunter.database.case_db._hash', side_effect=AssertionError('must not hash live volume')):
                    _check_sources(info, verify)
                self.assertEqual(info.sources[0]['status'], 'live_unverified')
                self.assertEqual(info.warnings, [])
                self.assertEqual(case_view.source_issues(info), [])
                self.assertEqual(case_view.image_sources(info), [])
                self.assertEqual(case_view.source_state(info), 'live_unverified')

    def test_legacy_gui_metadata_does_not_offer_image_relink_for_live_device(self):
        info = CaseInfo(sources=[{'path': r'\\.\C:', 'kind': 'image', 'status': 'unavailable'}])
        self.assertEqual(case_view.source_issues(info), [])
        self.assertEqual(case_view.image_sources(info), [])
        self.assertEqual(case_view.source_state(info), 'live_unverified')

    def test_actual_missing_image_is_still_reported(self):
        info = CaseInfo(sources=[{'path': 'synthetic-missing.E01', 'kind': 'image', 'status': 'missing'}])
        self.assertEqual(len(case_view.source_issues(info)), 1)
        self.assertEqual(len(case_view.image_sources(info)), 1)
        self.assertEqual(case_view.source_state(info), 'missing')

    def test_saved_live_case_reopens_without_source_problem(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'case.sqlite'
            result = AnalysisResult(image={'image_path': r'\\.\C:', 'image': {'drive': 'C:'}})
            save_case(path, result)
            for verify in (False, True):
                restored, info = load_case(path, verify=verify)
                self.assertEqual(restored.image, result.image)
                self.assertEqual(info.sources[0]['status'], 'live_unverified')
                self.assertIsNone(info.sources[0]['actual_sha256'])
                self.assertEqual(info.warnings, [])
                self.assertEqual(case_view.case_status(info, 0)[2], [])
                self.assertIn('live_unverified', case_view.source_state(info))

    def test_live_state_does_not_hide_a_missing_offline_image(self):
        info = CaseInfo(sources=[{'path': r'\\.\C:', 'kind': 'image', 'status': 'unavailable'},
                                {'path': 'synthetic.E01', 'kind': 'image', 'status': 'missing'}])
        self.assertEqual(case_view.source_state(info), 'missing')
        self.assertEqual(len(case_view.source_issues(info)), 1)
