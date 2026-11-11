import unittest

from log_hunter.core.enrichment import enrich_events
from log_hunter.core.models import ForensicEvent


class RiskContextTests(unittest.TestCase):
    def score(self, **fields):
        event = ForensicEvent('psreadline', 'synthetic', 'command', **fields)
        return enrich_events([event])[0].details['risk_score']

    def test_no_local_off_hours_claim_without_target_timezone(self):
        for stamp in ('2024-01-01T02:00:00+00:00', '2024-01-01T11:00:00+09:00',
                      '2024-01-01T02:00:00', None):
            self.assertEqual(self.score(timestamp=stamp), 0)

    def test_command_path_process_and_nested_values_are_inspected(self):
        for fields in ({'details': {'command': 'DOWNLOADSTRING synthetic'}},
                       {'process': 'certutil.exe'}, {'path': r'C:\synthetic\procdump.exe'},
                       {'details': {'nested': [{'command': 'invoke-expression synthetic'}]}}):
            self.assertEqual(self.score(**fields), 30)

    def test_ambiguous_terms_have_lower_weight_and_do_not_stack(self):
        self.assertEqual(self.score(details={'command': 'hidden bypass synthetic'}), 5)
        self.assertEqual(self.score(details={'command': 'hidden downloadstring synthetic'}), 30)

    def test_keywords_are_not_matched_in_keys_or_generated_score_fields(self):
        event = ForensicEvent('psreadline', 'synthetic', 'command', details={'downloadstring': False})
        enrich_events([event])
        self.assertEqual(event.details['risk_score'], 0)
        enrich_events([event])
        self.assertEqual(event.details['risk_score'], 0)

    def test_oversized_strings_are_bounded(self):
        self.assertEqual(self.score(details={'command': 'x' * 100000 + 'downloadstring'}), 0)
