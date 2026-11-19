"""Result filtering keeps timeline order without re-sorting on every click; time sort follows the timeline order."""
import unittest

from log_hunter.core.models import ForensicEvent
from log_hunter.core.timeline import timeline
from log_hunter.core.tree import OriginIndex, TreeNode
from log_hunter.ui import view_model
from log_hunter.ui.view_model import Filters, filter_events


def ev(artifact, timestamp, i, **details):
    return ForensicEvent(artifact, rf"C:\Evidence\{artifact}", "x", timestamp, "t", locator=str(i), details=details)


class OrderingTests(unittest.TestCase):
    def setUp(self):
        self.events = [ev("bam", "2024-01-03T00:00:00+00:00", 0), ev("mru", None, 1),
                       ev("bam", "2024-01-01T09:00:00+09:00", 2), ev("mru", "2024-01-02T00:00:00+00:00", 3),
                       ev("bam", None, 4, timestamp_raw_local="2024-01-01T00:00:00", timezone_known=False)]

    def test_node_filter_keeps_timeline_order_and_matches_the_old_result(self):
        node = TreeNode("art:x", "x", "artifacts", ("bam",))
        got = filter_events(self.events, Filters(), node, OriginIndex())
        self.assertEqual(got, [e for e in timeline(self.events) if e.artifact == "bam"])
        dated = filter_events(self.events, Filters(start="2024-01-02"), None, OriginIndex())
        self.assertEqual(dated, timeline(self.events, start=view_model.parse_filter_date("2024-01-02")))

    def test_cache_follows_a_new_or_grown_list(self):
        first = filter_events(self.events, Filters())
        self.events.append(ev("bam", "2023-12-31T00:00:00+00:00", 5))
        second = filter_events(self.events, Filters())
        self.assertEqual(len(second), len(first) + 1)
        self.assertEqual(second[0].locator, "5")
        other = list(reversed(self.events))
        self.assertEqual(filter_events(other, Filters()), timeline(other))

    def test_prepared_order_is_reused(self):
        from unittest import mock
        view_model.prepare_order(self.events)
        with mock.patch.object(view_model, "timeline", side_effect=AssertionError("sorted again")):
            self.assertEqual(filter_events(self.events, Filters()), timeline(self.events))

    def test_tag_tree_does_not_hash_records_when_nothing_is_tagged(self):
        from unittest import mock
        from log_hunter.core import tags
        with mock.patch.object(tags, "event_key", side_effect=AssertionError("hashed")):
            root = tags.tag_tree(tags.TagBook(), self.events)
        self.assertEqual([c.kind for c in root.children], ["group"])
        book = tags.TagBook()
        book.toggle(tags.event_key(self.events[0]), "event", tags.event_ref(self.events[0]), "red")
        self.assertEqual(tags.tag_tree(book, self.events).children[0].count, 1)

    def test_time_sort_uses_timeline_rank(self):
        rows = list(reversed(self.events))
        rows.sort(key=view_model.sort_key("timestamp", {}, None, self.events))
        self.assertEqual(rows, timeline(self.events))
        rows.sort(key=view_model.sort_key("artifact", {}, None, self.events))
        from log_hunter.core.labels import artifact_label
        labels = [artifact_label(e.artifact) for e in rows]
        self.assertEqual(labels, sorted(labels))  # other columns still sort by their shown text


if __name__ == "__main__":
    unittest.main()
