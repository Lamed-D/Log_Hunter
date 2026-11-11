"""Record properties dialog data: per-category fields, time format, unknown values, the Prefetch program check."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_hunter.core.models import ForensicEvent
from log_hunter.image.browse import ImageBrowser
from log_hunter.ui import record_fields as rf
from test_file_browser import build_volume

L = rf.L
VOL = r"\VOLUME{01d000000000abcd-A1B2C3D4}"


def prefetch(time, **details):
    base = {"run_count": 3, "references": [VOL + r"\WINDOWS\SYSTEM32\CMD.EXE", VOL + r"\WINDOWS\SYSTEM32\KERNEL32.DLL"],
            "volumes": [{"path": VOL, "serial": "A1B2C3D4", "creation_time": "2020-12-30T00:00:00+00:00"}]}
    return ForensicEvent("prefetch", r"C:\Evidence\CMD.EXE-1A2B3C4D.pf", "execution_trace", time, "last_run_time",
                         process="CMD.EXE", details={**base, **details})


class FormatTests(unittest.TestCase):
    def test_time_format(self):
        self.assertEqual(rf.format_time("2026-10-30T17:42:15+00:00"), "2026-10-30 17:42:15 (UTC)")
        self.assertEqual(rf.format_time("2026-10-30T17:42:15.123456+00:00", (540, "한국 표준시")),
                         "2026-10-30 17:42:15 (UTC) / 2026-10-31 02:42:15 (한국 표준시 +09:00)")
        self.assertEqual(rf.format_time("2026-10-30T17:42:15"), "2026-10-30 17:42:15 (시간대 미상)")
        self.assertEqual(rf.format_time(None), "알 수 없음")
        self.assertEqual(rf.format_time("garbage"), "garbage")
        self.assertEqual(rf.size_text(1234567), "1,234,567 바이트")
        self.assertEqual(rf.size_text(None), "알 수 없음")


class CategoryTests(unittest.TestCase):
    def test_prefetch_fields_and_more(self):
        events = [prefetch(f"2024-01-0{d}T00:00:00+00:00") for d in range(1, 10)]
        ctx = rf.Context(siblings=events[:-1], file_extra={"created": "2024-01-01T00:00:00+00:00"}, file_size=12345)
        props = rf.properties(events[-1], ctx)
        fields = dict(props.fields)
        self.assertEqual(props.title, "속성 — 프로그램 실행 기록")
        self.assertEqual([label for label, _ in props.fields],
                         [L[k] for k in ("pf_name", "created", "modified", "file_size", "exe_name", "exe_path", "run_count",
                                         "last_run", "exe_exists")])
        self.assertEqual(fields[L["pf_name"]], "CMD.EXE-1A2B3C4D.pf")
        self.assertEqual(fields[L["modified"]], "알 수 없음")  # never blank
        self.assertEqual(fields[L["file_size"]], "12,345 바이트")
        self.assertEqual(fields[L["exe_path"]], VOL + r"\WINDOWS\SYSTEM32\CMD.EXE")
        self.assertEqual(fields[L["last_run"]], "2024-01-09 00:00:00 (UTC)")
        self.assertEqual(fields[L["exe_exists"]], L["exe_unknown"])
        tabs = {name: lines for name, lines, _ in props.tabs}
        self.assertEqual(len(tabs[L["previous_runs"]]), 8)  # at most eight run times
        self.assertTrue(tabs[L["previous_runs"]][0].endswith("2024-01-09 00:00:00 (UTC)"))
        self.assertEqual(len(tabs[L["references"]]), 2)
        self.assertIn("A1B2C3D4", tabs[L["volumes"]][0])
        self.assertIn(L["raw_json"], tabs)
        self.assertEqual(props.check_label, L["exe_exists"])

    def test_prefetch_exe_target_forms(self):
        self.assertEqual(rf.prefetch_exe_target(prefetch(None)), ("A1B2C3D4", ("WINDOWS", "SYSTEM32", "CMD.EXE")))
        device = prefetch(None, references=[r"\DEVICE\HARDDISKVOLUME2\WINDOWS\CMD.EXE"],
                          volumes=[{"path": r"\DEVICE\HARDDISKVOLUME2", "serial": "0BADF00D"}])
        self.assertEqual(rf.prefetch_exe_target(device), ("0BADF00D", ("WINDOWS", "CMD.EXE")))
        no_serial = prefetch(None, references=[r"\DEVICE\HARDDISKVOLUME2\WINDOWS\CMD.EXE"], volumes=[])
        self.assertIsNone(rf.prefetch_exe_target(no_serial))
        self.assertIsNone(rf.prefetch_exe_target(prefetch(None, references=[r"\X\OTHER.EXE"])))

    def test_usb_recycle_web_and_common(self):
        ident = {"device": "VID_FFFF&PID_0001", "serial": "TESTSERIAL0001", "vid": "FFFF", "pid": "0001",
                 "friendlyname": "TEST drive", "device_kind_name": "저장 장치"}
        reg = ForensicEvent("usb", r"C:\Evidence\SYSTEM", "device_registration", "2024-01-01T00:00:00+00:00",
                            "key_lastwrite", details=ident)
        arrival = ForensicEvent("usb", r"C:\Evidence\SYSTEM", "last_arrival", "2024-01-03T00:00:00+00:00",
                                "last_arrival", details=ident)
        fields = dict(rf.properties(reg, rf.Context(siblings=[arrival])).fields)
        self.assertEqual(fields[L["vid_pid"]], "FFFF / 0001")
        self.assertEqual(fields["마지막 연결"], "2024-01-03 00:00:00 (UTC)")
        self.assertEqual(fields["최초 설치"], "알 수 없음")
        recycled = ForensicEvent("recyclebin", r"C:\Evidence\$IABC.txt", "파일 삭제", "2024-01-02T00:00:00+00:00",
                                 "deletion_time", details={"original_path": r"C:\Users\alice\a.txt", "file_size": 4096,
                                                           "r_file_exists": False})
        fields = dict(rf.properties(recycled).fields)
        self.assertEqual((fields[L["file_size"]], fields[L["pair_file"]]), ("4,096 바이트", L["pair_no"]))
        visit = ForensicEvent("history", r"C:\Evidence\History", "url_visit", "2024-01-02T00:00:00+00:00", "visit_time",
                              url="https://example.com/", details={"title": "Example"})
        fields = dict(rf.properties(visit).fields)
        self.assertEqual((fields[L["title"]], fields[L["visit_count"]]), ("Example", "알 수 없음"))
        other = ForensicEvent("bam", r"C:\Evidence\SYSTEM", "execution_trace", None, None, sid="S-1-5-21-1000-2000-3000-1001",
                              path=r"C:\Users\alice\a.exe")
        props = rf.properties(other, rf.Context(sid_map={"S-1-5-21-1000-2000-3000-1001": "alice"}))
        fields = dict(props.fields)
        self.assertEqual(fields[L["timestamp"]], "알 수 없음")
        self.assertEqual(fields[L["time_field"]], "알 수 없음")
        self.assertEqual(fields[L["user"]], "alice (S-1-5-21-1000-2000-3000-1001)")
        self.assertEqual([name for name, _l, _s in props.tabs], [L["raw_json"]])


class SourceTextTests(unittest.TestCase):
    def test_source_shows_where_the_file_really_is(self):
        event = ForensicEvent("bam", r"C:\Temp\log-hunter-image-x\volume0\ProgramData\MPLog.log", "defender_detection",
                              None, None)
        fields = dict(rf.properties(event, rf.Context(source_text=r"[case.E01] 볼륨 0\ProgramData\MPLog.log")).fields)
        self.assertEqual(fields[L["source"]], r"[case.E01] 볼륨 0\ProgramData\MPLog.log")
        self.assertEqual(dict(rf.properties(event).fields)[L["source"]], event.source)  # directly added file: as is


class ExeCheckTests(unittest.TestCase):
    def test_check_against_a_built_volume(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "disk.dd"
            path.write_bytes(build_volume()[0])
            browser = ImageBrowser(path)
            try:
                serial = browser.volume_serial(0)[-8:].upper()
                self.assertTrue(browser.exists(0, ("Tools", "run.ps1")))
                self.assertFalse(browser.exists(0, ("Tools", "gone.exe")))
                self.assertFalse(browser.exists(0, ("NoSuchFolder", "x.exe")))
                self.assertEqual(rf.check_exe(browser, (serial, ("Tools", "run.ps1"))), L["exe_present"])
                self.assertEqual(rf.check_exe(browser, (serial, ("Tools", "gone.exe"))), L["exe_missing"])
                other = "00000000" if serial != "00000000" else "11111111"
                self.assertEqual(rf.check_exe(browser, (other, ("Tools", "run.ps1"))), L["exe_no_volume"])
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
