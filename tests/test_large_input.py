"""Operation-count regressions for repeated entity persistence."""
import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from log_hunter.core.models import ForensicEvent
from log_hunter.database.repository import Repository
from log_hunter.core.stats import detect_anomalies
from log_hunter.core.correlation import correlate, _parse_ts, _cross_artifact_pairs


class EntityPersistenceTests(unittest.TestCase):
    def test_dense_deletion_candidates_are_bipartite_and_sid_compatible(self):
        events = [ForensicEvent('recyclebin', 'generated', 'event', path='C:\\same.txt', sid='one')
                  for _ in range(150)]
        events += [ForensicEvent('mft', 'generated', 'event', path='D:\\same.txt', sid='one')
                   for _ in range(150)]
        events.append(ForensicEvent('lnk', 'generated', 'event', path='D:\\same.txt', sid='other'))
        relations = correlate(events)
        summary, = [r for r in relations if r.get('relation_type') == 'deletion_correlation']
        self.assertEqual(summary['candidate_count'], 22500)
        self.assertEqual(summary['left_event_indices'], list(range(150)))
        self.assertFalse(any(r['type'] == 'deletion_correlation' for r in relations))

    def test_dense_usb_time_windows_are_counted_without_expansion(self):
        events = [ForensicEvent('usb', 'generated', 'event', '2024-01-01T12:00:00+00:00')
                  for _ in range(150)]
        events += [ForensicEvent('mft', 'generated', 'event', '2024-01-01T12:05:00+00:00',
                                path=f'C:\\file{i}') for i in range(150)]
        events.append(ForensicEvent('mft', 'generated', 'event', '2024-01-01T13:00:00+00:00', path='C:\\outside'))
        relations = correlate(events)
        summary, = [r for r in relations if r['type'] == 'correlation_group']
        self.assertEqual(summary['candidate_count'], 22500)
        self.assertEqual(summary['event_indices'], list(range(300)))
        self.assertEqual(summary['left_event_indices'], list(range(150)))
        self.assertEqual(summary['relation_type'], 'usb_file_correlation')
        self.assertFalse(any(r['type'] == 'usb_file_correlation' for r in relations))

    def test_group_count_and_pairs_respect_conflicting_and_missing_sids(self):
        group = [(i, ForensicEvent(artifact, 'generated', 'event', sid=sid))
                 for i, (artifact, sid) in enumerate(
                     [(a, s) for a in ('a', 'b', 'c') for s in (None, 'one', 'two')])]
        expected = [(left[0], right[0]) for pos, left in enumerate(group) for right in group[pos + 1:]
                    if left[1].artifact != right[1].artifact and
                    not (left[1].sid and right[1].sid and left[1].sid != right[1].sid)]
        summaries = []
        pairs = list(_cross_artifact_pairs(group, summaries, 'synthetic'))
        self.assertEqual([(a[0], b[0]) for a, b in pairs], expected)
        with patch('log_hunter.core.correlation.PAIR_GROUP_LIMIT', 1):
            self.assertEqual(list(_cross_artifact_pairs(group, summaries, 'synthetic')), [])
        self.assertEqual(summaries[0]['candidate_count'], len(expected))

    def test_dense_path_group_preserves_candidate_count_without_pair_explosion(self):
        events = [ForensicEvent('a' if i % 2 else 'b', 'generated', 'event',
                               path='C:\\example.txt', sid='same') for i in range(4000)]
        relations = correlate(events)
        self.assertLess(len(relations), 10001)
        summary, = [r for r in relations if r['type'] == 'correlation_group']
        self.assertEqual(summary['candidate_count'], 4000000)
        self.assertEqual(summary['event_indices'], list(range(4000)))
        self.assertFalse(summary['execution_confirmed'])
        self.assertEqual(summary['relation_type'], 'path_correlation')

    def test_usb_window_boundaries_offsets_and_unknown_timezone(self):
        events = [ForensicEvent('usb', 'generated', 'event', '2024-01-01T12:00:00+00:00')]
        for index, stamp in enumerate(('2024-01-01T12:05:00+00:00',
                                       '2024-01-01T11:54:59.999999+00:00',
                                       '2024-01-01T13:00:00+01:00',
                                       '2024-01-01T12:00:00', None)):
            events.append(ForensicEvent('mft', 'generated', 'event', stamp, path=f'C:\\file{index}'))
        relations = [r for r in correlate(events) if r['type'] == 'usb_file_correlation']
        self.assertEqual([r['right'] for r in relations], [1, 3])
        self.assertEqual([r['delta_seconds'] for r in relations], [300, 0])

    def test_correlation_parses_each_distinct_timestamp_once(self):
        events = [ForensicEvent('prefetch' if i % 2 else 'bam', 'generated', 'event',
                               '2024-01-01T12:00:00+00:00', path='C:\\example.exe')
                  for i in range(100)]
        with patch('log_hunter.core.correlation._parse_ts', wraps=_parse_ts) as parse:
            relations = correlate(events)
        self.assertTrue(relations)
        self.assertEqual(parse.call_count, 1)

    def test_overlapping_burst_windows_merge_but_separate_runs_remain(self):
        origin = datetime(2024, 1, 1, 12)
        def event(seconds):
            return ForensicEvent('synthetic', 'generated', 'event',
                                 (origin + timedelta(seconds=seconds)).isoformat())
        events = [event(i / 10) for i in range(1000)]
        events += [event(1000 + i / 10) for i in range(51)]
        bursts = [a for a in detect_anomalies(list(reversed(events))) if a['type'] == 'burst']
        self.assertEqual(len(bursts), 2)
        self.assertEqual([b['event_count'] for b in bursts], [1000, 51])
        self.assertEqual(bursts[0]['peak_window_count'], 601)
        self.assertEqual(bursts[0]['severity'], 'high')
        self.assertEqual(bursts[1]['severity'], 'warning')
        self.assertFalse([a for a in detect_anomalies([event(i) for i in range(50)]) if a['type'] == 'burst'])

    def test_entity_lists_are_serialized_once_after_accumulation(self):
        events = [ForensicEvent('synthetic', 'generated', 'event', sid='S-1-5-21-test')
                  for _ in range(1000)]
        dumps = json.dumps
        sizes = []
        def counted(value, **kwargs):
            if isinstance(value, dict) and 'event_ids' in value:
                sizes.append(len(value['event_ids']))
            return dumps(value, **kwargs)
        repository = Repository(':memory:')
        try:
            with patch('log_hunter.database.repository.json.dumps', side_effect=counted):
                case = repository.save('synthetic', [], events, [], [])
            self.assertLessEqual(sum(sizes), 1001)
            self.assertEqual(len(repository.query_entity(case, 'users', 's-1-5-21-test')), 1000)
            self.assertEqual(repository.connection.execute('SELECT count(*) FROM entity_events').fetchone()[0], 1000)
        finally:
            repository.close()
