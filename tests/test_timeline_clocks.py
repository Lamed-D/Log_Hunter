import unittest

from log_hunter.core.models import ForensicEvent
from log_hunter.core.timeline import parse_filter_date, timeline


class TimelineClockTests(unittest.TestCase):
    def event(self, timestamp, source='synthetic'):
        return ForensicEvent('bam', source, 'run', timestamp)

    def test_z_fraction_and_offsets_sort_by_actual_time_without_mutation(self):
        stamps = ['2024-01-01T00:00:00.500000+00:00', '2024-01-01T00:00:00Z',
                  '2024-01-01T08:59:59+09:00']
        events = [self.event(stamp) for stamp in stamps]
        self.assertEqual([e.timestamp for e in timeline(events)], [stamps[2], stamps[1], stamps[0]])
        self.assertEqual([e.timestamp for e in events], stamps)
        self.assertEqual(timeline(events, start='2024-01-01T09:00:00+09:00',
                                  end='2024-01-01T00:00:00.500000Z'), events[:2][::-1])

    def test_unknown_clocks_stay_separate_from_utc(self):
        known = self.event('2024-01-01T12:00:00Z')
        unknown = self.event('2024-01-01T01:00:00')
        self.assertEqual(timeline([unknown, known]), [known, unknown])
        self.assertEqual(timeline([unknown, known], start='2024-01-01T00:00:00Z'), [known])
        self.assertEqual(timeline([unknown, known], start='2024-01-01'), [known, unknown])

    def test_typed_end_covers_whole_unit_but_excludes_next_boundary(self):
        events = [self.event('2024-01-01T23:59:59.999999Z'),
                  self.event('2024-01-02T09:00:00+09:00')]
        self.assertEqual(timeline(events, end=parse_filter_date('2024-01-01', end=True)), events[:1])

    def test_bad_and_missing_values_do_not_crash_or_pass_date_filter(self):
        events = [self.event(None), self.event('bad'), self.event('0001-01-01T00:00:00+14:00'),
                  self.event('2024-01-01T00:00:00Z')]
        self.assertEqual(timeline(events)[0], events[-1])
        self.assertEqual(timeline(events, start='2024-01-01'), events[-1:])
        self.assertEqual(timeline(events, start='bad'), [])
