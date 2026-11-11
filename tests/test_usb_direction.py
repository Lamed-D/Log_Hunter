import unittest
from unittest.mock import patch

from log_hunter.core.correlation import correlate
from log_hunter.core.models import ForensicEvent


class USBDirectionTests(unittest.TestCase):
    def events(self):
        return [ForensicEvent('usb', 'synthetic', 'connect', '2024-01-01T10:05:00+00:00')] + [
            ForensicEvent('lnk', 'synthetic', 'open', stamp, path=f'E:\\doc{i}.txt')
            for i, stamp in enumerate(('2024-01-01T10:01:00+00:00',
                                       '2024-01-01T10:05:00+00:00',
                                       '2024-01-01T19:09:00+09:00'))]

    def test_before_same_after_and_offset_equivalence(self):
        relations = [r for r in correlate(self.events()) if r['type'] == 'usb_file_correlation']
        self.assertEqual([r['direction'] for r in relations], ['before', 'same', 'after'])
        self.assertEqual([r['signed_delta_seconds'] for r in relations], [-240, 0, 240])
        self.assertEqual([r['delta_seconds'] for r in relations], [240, 0, 240])
        self.assertTrue(all(not r['execution_confirmed'] for r in relations))

    def test_group_retains_window_and_sign_contract_without_expanding(self):
        with patch('log_hunter.core.correlation.PAIR_GROUP_LIMIT', 1):
            group = next(r for r in correlate(self.events()) if r.get('relation_type') == 'usb_file_correlation')
        self.assertEqual(group['candidate_count'], 3)
        self.assertEqual(group['signed_window_seconds'], [-300, 300])
        self.assertEqual(group['signed_delta_basis'], 'file_time_minus_usb_time')
        self.assertFalse(group['execution_confirmed'])
