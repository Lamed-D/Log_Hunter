"""Recent files and folders: same-target grouping across sources, one row per shortcut, source location and time meaning."""
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.recent_targets import attach_target_keys, normalize_target, target_key
from log_hunter.core.tree import OriginIndex, build_tree, matches
from log_hunter.ui import columns
from log_hunter.ui.record_fields import Context, properties

T1, T2 = "2024-01-01T00:00:00+00:00", "2024-01-01T01:00:00+00:00"


def ev(artifact, path, action="x", timestamp=None, time_field=None, locator=None, source=r"C:\Evidence\NTUSER.DAT", **details):
    return ForensicEvent(artifact, source, action, timestamp, time_field, path=path, locator=locator, details=details)


def lnk_bytes():
    data = bytearray(256)
    data[0:4] = b"\x4C\x00\x00\x00"
    data[4:20] = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
    struct.pack_into("<QQQ", data, 28, 132537600000000000, 132537600000000000, 132537600000000000)
    return bytes(data)


class TargetKeyTests(unittest.TestCase):
    def test_normalize_drops_unnamed_items_and_doubled_separators(self):
        self.assertEqual(normalize_target(r"[0]\C:\\Users\alice\Documents"), r"C:\Users\alice\Documents")
        self.assertEqual(normalize_target(r"[0]\[1]"), None)
        self.assertEqual(normalize_target("C:"), "C:\\")
        self.assertEqual(normalize_target(r"\\server\share\a.txt"), r"\\server\share\a.txt")

    def test_keys_are_case_insensitive_and_name_only_is_marked(self):
        self.assertEqual(target_key(ev("lnk", r"C:\Users\alice\A.TXT")), r"path:c:\users\alice\a.txt")
        self.assertEqual(target_key(ev("mru", "a.txt")), "name:a.txt")
        self.assertIsNone(target_key(ev("mru", None)))

    def test_name_only_records_join_one_unique_full_path(self):
        events = [ev("lnk", r"C:\Users\alice\report.docx"), ev("jumplist", r"c:\users\alice\REPORT.docx"),
                  ev("mru", "report.docx"), ev("mru", "notes.txt"),
                  ev("jumplist", r"C:\a\same.txt"), ev("jumplist", r"C:\b\same.txt"), ev("mru", "same.txt")]
        attach_target_keys(events)
        group = r"path:c:\users\alice\report.docx"
        self.assertEqual([e.details["target_group"] for e in events[:3]], [group] * 3)
        self.assertEqual([e.details["target_match"] for e in events[:3]], ["path", "path", "name"])
        self.assertEqual(events[3].details["target_match"], "name_only")
        self.assertEqual(events[6].details["target_group"], "name:same.txt")  # two candidates: not joined


class RecentViewTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            ev("mru", "report.docx", "recent_document", T1, "key_lastwrite",
               r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx\0"),
            ev("lnk", r"C:\Users\alice\report.docx", "shortcut_target", T1, "lnk_target_accessed", "report.lnk",
               source=r"C:\Evidence\report.lnk", lnk_representative=True,
               lnk_times={"lnk_target_accessed": T1, "lnk_file_created": T2}),
            ev("lnk", r"C:\Users\alice\report.docx", "shortcut_file", T2, "lnk_file_created", "report.lnk",
               source=r"C:\Evidence\report.lnk", lnk_representative=False,
               lnk_times={"lnk_target_accessed": T1, "lnk_file_created": T2}),
            ev("jumplist", r"C:\Users\alice\report.docx", "recent_file_access", T2, "destlist_timestamp",
               "abc.automaticDestinations-ms:stream:1", source=r"C:\Evidence\abc.automaticDestinations-ms"),
            ev("shellbag", r"[0]\C:\\Users\alice", "folder_access", None, None, r"Local Settings\BagMRU\0"),
        ]
        attach_target_keys(self.events)
        self.roots = build_tree(self.events)
        self.nodes = {n.key: n for r in self.roots for n in r.walk()}

    def test_one_group_holds_every_source_of_the_target(self):
        node = self.nodes[r"art:recent_documents:target:path:c:\users\alice\report.docx"]
        self.assertEqual(node.kind, "target_group")
        self.assertIn("3종 출처 4건", node.label)
        self.assertEqual(sum(matches(node, e, OriginIndex()) for e in self.events), 4)
        single = self.nodes["art:recent_documents:target:single"]
        self.assertTrue(matches(single, self.events[4], OriginIndex()))  # the folder only one source recorded
        self.assertEqual(columns.columns_for(node), columns.CATEGORY_COLUMNS["recent_targets"])

    def test_shortcut_node_shows_one_row_per_shortcut_with_all_times(self):
        node = self.nodes["art:recent_documents:lnk:shortcuts"]
        self.assertEqual(node.count, 1)
        rows = [e for e in self.events if matches(node, e, OriginIndex())]
        cols = columns.columns_for(node)
        row = dict(zip([c.key for c in cols], columns.row(rows[0], cols, {}, None)))
        self.assertEqual((row["lnk_file_created"], row["lnk_target_accessed"]), (T2, T1))
        self.assertEqual(row["lnk_target_written"], "")

    def test_source_location_names_key_shortcut_and_jump_list_position(self):
        self.assertTrue(columns.source_location(self.events[0]).startswith("레지스트리 키 Software\\"))
        self.assertIn(r"C:\Evidence\report.lnk", columns.source_location(self.events[1]))
        self.assertTrue(columns.source_location(self.events[3]).endswith("@ stream:1"))

    def test_properties_explain_time_meaning_and_list_other_sources(self):
        lnk = self.events[1]
        props = properties(lnk, Context(related=[e for e in self.events if e.details.get("target_group") == lnk.details["target_group"]]))
        fields = dict(props.fields)
        self.assertEqual(fields["시각의 의미"], "바로가기에 적힌 대상 파일 접근 시각 (만들 때 복사된 값)")
        tabs = {name: lines for name, lines, _ in props.tabs}
        self.assertTrue(any("바로가기 생성 = 처음 연 시각 후보" in line for line in tabs["이 기록의 시각과 의미"]))
        self.assertEqual(len(tabs["같은 대상 묶어 보기"]), 3)
        mru = dict(properties(self.events[0]).fields)
        self.assertIn("목록 맨 앞 항목에만", mru["시각의 의미"])


class ShortcutFileTimeTests(unittest.TestCase):
    def test_image_file_times_become_shortcut_records_and_one_representative(self):
        with tempfile.TemporaryDirectory() as directory:
            lnk = Path(directory) / "a.lnk"
            lnk.write_bytes(lnk_bytes())
            times = {str(lnk.resolve()).casefold(): {"created": T1, "modified": T2, "accessed": T2}}
            events = [e for e in Pipeline(times).analyze([("lnk", lnk)]).events if e.artifact == "lnk"]
            self.assertEqual(sorted(e.time_field for e in events if e.action == "shortcut_file"),
                             ["lnk_file_created", "lnk_file_modified"])
            self.assertEqual(sum(1 for e in events if e.details["lnk_representative"]), 1)
            self.assertEqual(events[0].details["lnk_times"]["lnk_file_modified"], T2)
            # Without image times (a file given directly) nothing is taken from the copy's own file system times.
            plain = Pipeline().analyze([("lnk", lnk)]).events
            self.assertFalse(any(e.action == "shortcut_file" for e in plain))


if __name__ == "__main__":
    unittest.main()
