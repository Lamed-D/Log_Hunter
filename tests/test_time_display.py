"""Record times on screen: UTC as stored, with how and where each time was written, kept apart from source-file times."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import display_event_time
from log_hunter.core.tree import event_properties, time_basis_text, time_source
from log_hunter.ui import record_fields

HIVE = r"C:\Evidence\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat"
KEY = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1"


def shell_item(field, stamp, **details):
    return ForensicEvent("shellbag", HIVE, "folder_access", stamp, field, "S-1-5-21-1000-2000-3000-1001",
                         path=r"C:\Users\alice\Downloads", locator=KEY + r"\0",
                         details={"registry_key_lastwrite": "2024-01-01T06:56:02.123456+00:00",
                                  "fat_time_hex": "00000000", **details})


def rows(event):
    return {row.name: row.value for row in event_properties(event)}


class RecordInfoTabTests(unittest.TestCase):
    def test_shell_item_time_is_shown_as_stored_with_basis_source_and_key_time(self):
        got = rows(shell_item("shell_item_modified", "2024-01-01T06:55:44+00:00"))
        self.assertEqual(got["시각 (UTC)"], "2024-01-01 06:55:44 UTC")  # no second conversion
        self.assertIn("2초 단위", got["시각 근거"])
        self.assertIn("UTC로 기록", got["시각 근거"])
        self.assertIn("셸 항목", got["시각 출처"])
        self.assertEqual(got["레지스트리 키 마지막 기록 (UTC)"], "2024-01-01 06:56:02 UTC")

    def test_key_time_record_names_the_registry_key(self):
        event = ForensicEvent("shellbag", HIVE, "folder_access", "2024-01-01T06:56:02+00:00", "key_lastwrite",
                              locator=KEY, details={"time_basis": "key_lastwrite",
                                                    "registry_key_lastwrite": "2024-01-01T06:56:02+00:00"})
        got = rows(event)
        self.assertIn("레지스트리 키", got["시각 근거"])
        self.assertIn("레지스트리 키", got["시각 출처"])
        self.assertNotIn("레지스트리 키 마지막 기록 (UTC)", got)  # it is the record's own time already

    def test_unknown_zone_shows_the_original_value_and_filter_note(self):
        event = ForensicEvent("mft", r"C:\Evidence\fat.img", "file_listed", None, "modified",
                              details={"timestamp_raw_local": "2024-01-01T08:00:00", "timezone_known": False})
        got = rows(event)
        self.assertEqual(got["시각 (UTC)"], "2024-01-01 08:00:00 (시간대 미상)")
        self.assertEqual(got["원래 값 (현지 시각)"], "2024-01-01T08:00:00")
        self.assertIn("시간대 미상", got["시각 근거"])
        self.assertIn("날짜 필터", got["날짜 필터·정렬"])

    def test_converted_local_time_keeps_raw_value_and_zone(self):
        event = ForensicEvent("tasks", r"C:\Evidence\Tasks\job", "task_registered", "2023-12-31T23:00:00+00:00",
                              "registration_date",
                              details={"timestamp_raw_local": "2024-01-01T08:00:00", "timezone_known": True,
                                       "time_basis": "로컬 기록 → UTC 환산, 시간대 근거: TimeZoneInformation",
                                       "time_zone_name": "Korea Standard Time"})
        got = rows(event)
        self.assertEqual(got["시각 (UTC)"], "2023-12-31 23:00:00 UTC")
        self.assertEqual(got["원래 값 (현지 시각)"], "2024-01-01T08:00:00")
        self.assertEqual(got["환산에 쓴 시간대"], "Korea Standard Time")
        self.assertIn("UTC 환산", got["시각 근거"])

    def test_record_without_time_shows_no_basis(self):
        got = rows(ForensicEvent("shellbag", HIVE, "folder_access", None, None, details={"time_basis": "unknown"}))
        self.assertEqual(got["시각 (UTC)"], "알 수 없음")
        self.assertNotIn("시각 근거", got)

    def test_basis_and_source_helpers(self):
        self.assertIn("MFT", time_source("si_created"))
        self.assertIn("바로가기", time_source("lnk_target_written"))
        event = ForensicEvent("cookies", "Cookies", "cookie_stored", "2024-01-01T00:00:00+00:00", "cookie_created")
        self.assertIn("1601년 기준 마이크로초", time_basis_text(event))
        event = ForensicEvent("autofill", "Web Data", "form_entry", "2024-01-01T00:00:00+00:00", "autofill_last_used")
        self.assertIn("Unix 초", time_basis_text(event))
        self.assertIn("따로 기록되지 않음", time_basis_text(ForensicEvent("x", "x", "y", "2024-01-01T00:00:00+00:00", "zz")))


class TimeTableTests(unittest.TestCase):
    def test_all_times_of_one_shell_item_with_sources_and_source_file_marked(self):
        key = ForensicEvent("shellbag", HIVE, "folder_access", "2024-01-01T06:56:02+00:00", "key_lastwrite",
                            locator=KEY + r"\0", details={"registry_key_lastwrite": "2024-01-01T06:56:02+00:00"})
        modified = shell_item("shell_item_modified", "2024-01-01T06:55:44+00:00")
        created = shell_item("shell_item_created", "2023-12-30T04:10:40+00:00")
        ctx = record_fields.Context(siblings=[key, created],
                                    file_extra={"modified": "2024-01-01T08:01:12+00:00", "image_path": r"\x"})
        lines = record_fields.time_table(modified, ctx)
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith("셸 항목에 기록된 생성 시각: 2023-12-30 04:10:40 UTC"))
        self.assertIn("2024-01-01 06:55:44 UTC  ·  출처: 셸 항목", lines[1])
        self.assertIn("2024-01-01 06:56:02 UTC  ·  출처: 레지스트리 키", lines[2])
        self.assertIn("원본 파일 수정 (MFT, 기록 시각 아님): 2024-01-01 08:01:12 UTC", lines[3])

    def test_shortcut_times_have_their_sources(self):
        event = ForensicEvent("lnk", r"C:\Evidence\a.lnk", "shortcut_target", "2024-01-01T00:00:00+00:00",
                              "lnk_target_written", locator="header",
                              details={"lnk_times": {"lnk_target_written": "2024-01-01T00:00:00+00:00",
                                                     "lnk_file_created": "2024-01-02T00:00:00+00:00"}})
        lines = record_fields.time_table(event, record_fields.Context())
        self.assertIn("출처: 바로가기 파일 안", lines[0])
        self.assertIn("출처: 파일 시스템 (MFT)", lines[1])


class ZoneIndependenceTests(unittest.TestCase):
    """The machine's own time zone never changes what is shown or saved."""

    SCRIPT = r"""
import json, sys, tempfile, time, os
from pathlib import Path
from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import event_properties
from log_hunter.ui import columns
from log_hunter.core.timestamp import display_event_time
events = [ForensicEvent("bam", "SYSTEM", "execution", "2024-01-01T23:30:00+00:00", "last_execution", path="a.exe"),
          ForensicEvent("mft", "fat.img", "file_listed", None, "modified",
                        details={"timestamp_raw_local": "2024-01-01T08:00:00", "timezone_known": False})]
out = {"offset": time.timezone, "shown": [display_event_time(e) for e in events],
       "props": [[(r.name, r.value) for r in event_properties(e)] for e in events]}
with tempfile.TemporaryDirectory() as temp:
    columns.save_category_csvs(Path(temp) / "csv", events)
    out["csv"] = {p.name: p.read_text(encoding="utf-8-sig") for p in sorted((Path(temp) / "csv").iterdir())}
print(json.dumps(out, ensure_ascii=False))
"""

    def run_in(self, zone):
        env = {**os.environ, "TZ": zone, "PYTHONIOENCODING": "utf-8"}
        root = Path(__file__).resolve().parents[1]
        done = subprocess.run([sys.executable, "-c", self.SCRIPT], cwd=root, env=env, capture_output=True,
                              text=True, encoding="utf-8", timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    def test_display_and_csv_are_the_same_in_any_local_zone(self):
        utc, seoul = self.run_in("UTC0"), self.run_in("KST-9")
        if utc["offset"] == seoul["offset"]:
            self.skipTest("this platform ignores TZ")
        utc.pop("offset"), seoul.pop("offset")
        self.assertEqual(utc, seoul)
        self.assertEqual(utc["shown"], ["2024-01-01 23:30:00 UTC", "2024-01-01 08:00:00 (시간대 미상)"])


if __name__ == "__main__":
    unittest.main()
