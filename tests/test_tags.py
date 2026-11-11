"""Examiner tags and notes: model, tree root, case.sqlite table and report tab (synthetic records only)."""
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from log_hunter.core import tags
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.main import save_result
from log_hunter.ui.nav import node_action

SID = "S-1-5-21-1000-2000-3000-1001"


def _event(path, stamp="2024-01-01T00:00:00+00:00"):
    return ForensicEvent("prefetch", r"C:\Evidence\APP.EXE-1234ABCD.pf", "execution", stamp, "last_run",
                         path=path, sid=SID)


class TagBookTest(unittest.TestCase):
    def test_toggle_note_and_clear(self):
        book, event = tags.TagBook(), _event(r"C:\Users\alice\app.exe")
        key, ref = tags.event_key(event), tags.event_ref(event)
        book.toggle(key, "event", ref, "notable")
        book.toggle(key, "event", ref, "follow_up")
        self.assertEqual(book.tags_for(key), {"red", "yellow"})  # old names land on their colour
        book.toggle(key, "event", ref, "red")
        self.assertEqual(book.tags_for(key), {"yellow"})
        book.set_note(key, "event", ref, "  alice가 실행한 것으로 보임 ")
        self.assertEqual(book.note_for(key), "alice가 실행한 것으로 보임")
        book.clear(key)
        self.assertEqual(book.items, {})

    def test_untagging_the_last_tag_without_note_forgets_the_item(self):
        book, event = tags.TagBook(), _event(r"C:\Users\alice\app.exe")
        key = tags.event_key(event)
        book.toggle(key, "event", tags.event_ref(event), "benign")
        book.toggle(key, "event", tags.event_ref(event), "benign")
        self.assertNotIn(key, book.items)

    def test_unknown_tag_is_rejected(self):
        with self.assertRaises(ValueError):
            tags.TagBook().toggle("event:x", "event", {}, "malicious")

    def test_event_key_is_stable_and_distinguishes_records(self):
        a1, a2 = _event(r"C:\Users\alice\a.exe"), _event(r"C:\Users\alice\a.exe")
        b = _event(r"C:\Users\alice\a.exe", "2024-01-02T00:00:00+00:00")
        self.assertEqual(tags.event_key(a1), tags.event_key(a2))  # same record in a re-run
        self.assertNotEqual(tags.event_key(a1), tags.event_key(b))

    def test_tree_root_lists_tagged_records_and_files(self):
        events = [_event(r"C:\Users\alice\a.exe"), _event(r"C:\Users\alice\b.exe")]
        book = tags.TagBook()
        book.toggle(tags.event_key(events[0]), "event", tags.event_ref(events[0]), "notable")
        book.set_note(tags.event_key(events[1]), "event", tags.event_ref(events[1]), "확인 필요")
        parts = ("Users", "alice", "notes.txt")
        book.toggle(tags.file_key(r"C:\Evidence\case.E01", 0, parts, 42), "file",
                    tags.file_ref(r"C:\Evidence\case.E01", 0, parts, 42, "case.E01"), "follow_up")
        root = tags.tag_tree(book, events)
        self.assertEqual([c.text for c in root.children], ["빨강 · 중요·확인 필요 (1)", "메모 있음 (1)", "태그한 파일 (1)"])
        self.assertEqual(root.children[0].value, frozenset({id(events[0])}))
        self.assertEqual(node_action(root.children[0])[0], "events")
        self.assertEqual(node_action(root.children[2])[0], "tagged_files")

    def test_empty_book_shows_how_to_tag(self):
        root = tags.tag_tree(tags.TagBook(), [_event(r"C:\Users\alice\a.exe")])
        self.assertEqual(len(root.children), 1)
        self.assertIn("오른쪽 클릭", root.children[0].label)
        self.assertIsNone(node_action(root.children[0]))


def _history(command):
    return ForensicEvent("psreadline", r"C:\Evidence\ConsoleHost_history.txt", "command_history", None,
                         locator="line:1-1", details={"command": command})


def _evtx(payload, record_id=7):
    return ForensicEvent("evtx", r"C:\Evidence\Security.evtx", "logon", "2024-01-01T00:00:00+00:00", "event_time",
                         sid=SID, locator=f"record:{record_id}",
                         details={"event_id": 4624, "record_id": record_id, "event_data": payload})


class TagIdentityTest(unittest.TestCase):
    """Issue #77: a note must not move to other evidence content at the same source and locator."""

    def test_changed_command_at_same_line_gets_its_own_key_and_note(self):
        alpha, beta = _history("Write-Output alpha"), _history("Write-Output beta")
        self.assertNotEqual(tags.event_key(alpha), tags.event_key(beta))
        book = tags.TagBook()
        book.set_note(tags.event_key(alpha), "event", tags.event_ref(alpha), "Note for alpha only")
        self.assertEqual(book.note_for(tags.event_key(beta)), "")
        self.assertEqual(tags.tag_tree(book, [beta]).children[0].key, "tags:none")

    def test_same_content_in_a_rerun_keeps_the_key(self):
        self.assertEqual(tags.event_key(_history("Write-Output alpha")), tags.event_key(_history("Write-Output alpha")))
        first, second = _evtx({"TargetUserName": "alice", "LogonType": "2"}), _evtx({"LogonType": "2",
                                                                                     "TargetUserName": "alice"})
        self.assertEqual(tags.event_key(first), tags.event_key(second))  # key order inside the payload does not matter

    def test_other_event_payload_at_same_record_gets_another_key(self):
        self.assertNotEqual(tags.event_key(_evtx({"TargetUserName": "alice"})),
                            tags.event_key(_evtx({"TargetUserName": "bob"})))
        self.assertNotEqual(tags.event_key(_evtx({"TargetUserName": "alice"}, 7)),
                            tags.event_key(_evtx({"TargetUserName": "alice"}, 8)))

    def test_only_derived_analysis_values_changed_keeps_the_key(self):
        before, after = _history("Write-Output alpha"), _history("Write-Output alpha")
        before.details.update(activity_class="execution", risk_score=10, session_id=3)
        after.details.update(activity_class="other", risk_score=40, session_id=9)
        self.assertEqual(tags.event_key(before), tags.event_key(after))

    def test_file_tag_does_not_move_to_other_file_at_same_image_path(self):
        image, parts = r"C:\Evidence\case.E01", ("Users", "alice", "notes.txt")
        key = tags.file_key(image, 0, parts, 42, 3, [1024, 1])
        self.assertEqual(key, tags.file_key(image, 0, parts, 42, 3, [1024, 1]))
        self.assertNotEqual(key, tags.file_key(image, 0, parts, 43, 3, [1024, 1]))  # other MFT record
        self.assertNotEqual(key, tags.file_key(image, 0, parts, 42, 4, [1024, 1]))  # record reused for a new file
        self.assertNotEqual(key, tags.file_key(image, 0, parts, 42, 3, [2048, 5]))  # other image at the same path

    def test_image_identity_follows_the_image_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "case.dd"
            path.write_bytes(bytes(512))
            first = tags.image_identity(str(path))
            self.assertEqual(first, tags.image_identity(str(path)))
            path.write_bytes(bytes(1024))
            self.assertNotEqual(first, tags.image_identity(str(path)))
        self.assertIsNone(tags.image_identity(str(Path(temp) / "missing.dd")))

    def test_tagged_file_from_a_changed_image_is_marked_for_checking(self):
        from log_hunter.core.labels import TAGGED_IMAGE_CHANGED
        from log_hunter.ui.fs_model import TABLE_COLUMNS, table_values
        values = table_values({"name": "notes.txt", "size": 13, "check": TAGGED_IMAGE_CHANGED})
        self.assertEqual(values[TABLE_COLUMNS.index("state")], TAGGED_IMAGE_CHANGED)

    def test_saved_rows_carry_the_key_version(self):
        book, event = tags.TagBook(), _history("Write-Output alpha")
        book.toggle(tags.event_key(event), "event", tags.event_ref(event), "notable")
        self.assertEqual(book.rows()[0]["key_version"], tags.KEY_VERSION)


class TagOutputTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_tags_go_to_their_own_table_and_report_tab_escaped(self):
        event = _event(r"C:\Users\alice\a.exe")
        book = tags.TagBook()
        book.toggle(tags.event_key(event), "event", tags.event_ref(event), "notable")
        book.set_note(tags.event_key(event), "event", tags.event_ref(event), "<script>alert(1)</script>")
        out = self.root / "out"
        save_result(AnalysisResult(events=[event]), out, book.rows())
        with closing(sqlite3.connect(out / "case.sqlite")) as db:
            rows = db.execute("SELECT key, data FROM examiner_tags").fetchall()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)  # evidence rows untouched
        self.assertEqual(len(rows), 1)
        data = json.loads(rows[0][1])
        self.assertEqual((data["target"], data["tags"], data["tag_format"]), ("event", ["red"], 2))
        self.assertEqual(data["tag_labels"], ["빨강 · 중요·확인 필요"])
        self.assertEqual(data["ref"]["path"], r"C:\Users\alice\a.exe")
        page = (out / "report.html").read_text(encoding="utf-8")
        self.assertIn('data-panel="tags">분석자 태그', page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)", page)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["examiner_tags"][0]["note"], "<script>alert(1)</script>")

    def test_no_tags_leaves_outputs_as_before(self):
        out = self.root / "plain"
        save_result(AnalysisResult(events=[_event(r"C:\Users\alice\a.exe")]), out)
        with closing(sqlite3.connect(out / "case.sqlite")) as db:
            names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("examiner_tags", names)
        self.assertNotIn('data-panel="tags"', (out / "report.html").read_text(encoding="utf-8"))
        self.assertNotIn("examiner_tags", json.loads((out / "report.json").read_text(encoding="utf-8")))


class TagColorTest(unittest.TestCase):
    def test_subcategories_tree_and_names(self):
        events = [_event(r"C:\Users\alice\a.exe"), _event(r"C:\Users\alice\b.exe")]
        book = tags.TagBook()
        leak = book.add_subcategory("red", " 유출 의심 ")
        self.assertEqual(leak, "red/유출 의심")
        book.toggle(tags.event_key(events[0]), "event", tags.event_ref(events[0]), leak)
        book.toggle(tags.event_key(events[1]), "event", tags.event_ref(events[1]), "green")
        book.rename_color("red", "꼭 볼 것")
        root = tags.tag_tree(book, events)
        self.assertEqual([c.text for c in root.children], ["빨강 · 꼭 볼 것 (1)", "초록 · 확인 완료 (1)"])
        self.assertEqual([c.text for c in root.children[0].children], ["빨강 › 유출 의심 (1)"])
        self.assertEqual(book.top_color(tags.event_key(events[0])), "red")
        self.assertEqual(sorted(l for r in book.rows() for l in r["tag_labels"]), ["빨강 › 유출 의심", "초록 · 확인 완료"])
        self.assertEqual(book.preferences()["color_names"]["red"], "꼭 볼 것")
        again = tags.TagBook(**book.preferences())
        self.assertEqual(again.subcategories["red"], ["유출 의심"])
        for bad in ("purple", "red/", "red/  "):
            with self.assertRaises(ValueError):
                tags.normalize_tag(bad)

    def test_rename_and_delete_subcategory(self):
        book = tags.TagBook()
        leak = book.add_subcategory("red", "유출 의심")
        book.add_subcategory("red", "악성 의심")
        book.toggle("event:a", "event", {}, leak)
        book.toggle("event:a", "event", {}, "red")
        book.toggle("event:b", "event", {}, leak)
        self.assertEqual(book.rename_subcategory("red", "유출 의심", "외부 유출"), "red/외부 유출")
        self.assertEqual(book.subcategories["red"], ["외부 유출", "악성 의심"])
        self.assertEqual(book.tags_for("event:a"), {"red", "red/외부 유출"})
        self.assertIsNone(book.rename_subcategory("red", "없는 이름", "x"))
        self.assertEqual(book.rename_subcategory("red", "외부 유출", "악성 의심"), "red/악성 의심")  # merge
        self.assertEqual(book.subcategories["red"], ["악성 의심"])
        self.assertEqual(book.delete_subcategory("red", "악성 의심"), 2)
        self.assertEqual(book.subcategories["red"], [])
        self.assertEqual(book.tags_for("event:a"), {"red"})  # the colour stays
        self.assertNotIn("event:b", book.items)  # nothing left on it
        with self.assertRaises(ValueError):
            book.rename_subcategory("red", "x", "  ")

    def test_old_rows_migrate_from_a_saved_case(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "case.sqlite"
            with closing(sqlite3.connect(path)) as db:
                with db:
                    db.execute("CREATE TABLE examiner_tags(id INTEGER PRIMARY KEY, key TEXT NOT NULL, data TEXT NOT NULL)")
                    old = {"key": "event:abc", "key_version": 2, "target": "event", "ref": {}, "updated_at": "x",
                           "tags": ["notable", "follow_up", "benign", "unknown"], "note": "메모"}
                    db.execute("INSERT INTO examiner_tags(key, data) VALUES(?, ?)", ("event:abc", json.dumps(old)))
                    db.execute("INSERT INTO examiner_tags(key, data) VALUES(?, ?)", ("bad", "{broken"))
            before = path.read_bytes()
            rows = tags.load_from_sqlite(path)
            self.assertEqual(path.read_bytes(), before)  # read-only
            plain = Path(temp) / "plain.sqlite"
            closing(sqlite3.connect(plain)).__enter__().close()
            self.assertEqual(tags.load_from_sqlite(plain), [])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["tags"], rows[0]["tag_format"]), (["green", "red", "yellow"], 2))
        book = tags.TagBook()
        book.load_rows(rows + [{"key": "event:new", "tags": ["red/악성 의심"], "target": "event"}])
        self.assertEqual(book.tags_for("event:abc"), {"red", "yellow", "green"})
        self.assertEqual(book.subcategories["red"], ["악성 의심"])


if __name__ == "__main__":
    unittest.main()
