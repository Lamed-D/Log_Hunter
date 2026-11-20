"""Synthetic evidence clock conversion tests."""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from log_hunter.core.models import ForensicEvent
from log_hunter.core.windows_time import (WindowsTimeRules, clock_for_source, local_time_to_utc,
                                         read_evidence_clocks, read_windows_time_rules, resolve_event_metadata_clock)
from fixtures.synthetic_windows_case import put, registry_bytes, text


class WindowsTimeTests(unittest.TestCase):
    def test_annual_rule_and_scope_are_read_from_the_same_installation(self):
        def dword(name, value):
            return name, 4, struct.pack("<i", value)

        system, software, other = {}, {}, {}
        for tree, bias in ((system, -540), (other, 300)):
            put(tree, "Select", [dword("Current", 1)])
            put(tree, r"ControlSet001\Control\TimeZoneInformation",
                [dword("Bias", bias), text("TimeZoneKeyName", "Synthetic Standard Time")])
        zone = r"Microsoft\Windows NT\CurrentVersion\Time Zones\Synthetic Standard Time\Dynamic DST"
        put(software, zone, [dword("FirstEntry", 2022), dword("LastEntry", 2024),
                             ("2022", 3, struct.pack("<iii16H", -420, 0, 0, *([0] * 16))),
                             ("2024", 3, struct.pack("<iii16H", -480, 0, 0, *([0] * 16)))])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for label, name, tree in (("volume0", "SYSTEM", system), ("volume0", "SOFTWARE", software),
                                      ("volume1", "SYSTEM", other)):
                path = root / label / "Windows" / "System32" / "config" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(registry_bytes(tree, name))
                inputs.append(path)
            clocks = read_evidence_clocks(inputs)
            first = clock_for_source(clocks, root / "volume0" / "NTUSER.DAT")
            second = clock_for_source(clocks, root / "volume1" / "NTUSER.DAT")
            self.assertIsNone(clock_for_source(clocks, root / "volume2" / "NTUSER.DAT"))
        raw = "2024-01-02T01:00:00"
        stamp, details = local_time_to_utc(raw, first)
        self.assertEqual(stamp, "2024-01-01T17:00:00+00:00")
        self.assertIn("SOFTWARE", details["time_basis"])
        self.assertEqual(local_time_to_utc("2021-01-02T01:00:00", first)[0], "2021-01-01T18:00:00+00:00")
        self.assertIsNone(local_time_to_utc("2023-01-02T01:00:00", first)[0])
        self.assertEqual(local_time_to_utc("2025-01-02T01:00:00", first)[0], "2025-01-01T17:00:00+00:00")
        self.assertEqual(local_time_to_utc(raw, second)[0], "2024-01-02T06:00:00+00:00")

    def test_network_observation_and_task_declaration_keep_distinct_semantics(self):
        clock = WindowsTimeRules("Synthetic", "SYSTEM\\ControlSet001", -540, -540, (0,) * 8, (0,) * 8)
        raw = "2024-01-02T01:00:00"
        network = ForensicEvent("network", "synthetic", "network_profile", details={"date_last_connected": raw})
        resolve_event_metadata_clock(network, clock)
        self.assertEqual(network.timestamp, "2024-01-01T16:00:00+00:00")
        self.assertEqual(network.details["timestamp_raw_local"], raw)
        self.assertEqual(network.time_field, "network_last_connected")
        task = ForensicEvent("tasks", "synthetic", "task_definition",
                             details={"registration_date": raw, "triggers": [{"startboundary": raw + "+09:00"}]})
        resolve_event_metadata_clock(task, clock)
        self.assertIsNone(task.timestamp)
        self.assertEqual(task.details["registration_date_utc"], network.timestamp)
        self.assertEqual(task.details["triggers"][0]["startboundary_utc"], network.timestamp)

    def test_fixed_bias_and_missing_rules(self):
        clock = WindowsTimeRules("Synthetic", "SYSTEM\\ControlSet001", -540, -540, (0,) * 8, (0,) * 8)
        stamp, details = local_time_to_utc("2024-01-02T01:00:00", clock)
        self.assertEqual(stamp, "2024-01-01T16:00:00+00:00")
        self.assertTrue(details["timezone_known"])
        self.assertIsNone(local_time_to_utc("2024-01-02T01:00:00", None)[0])
        self.assertIsNone(local_time_to_utc("2024-01-02T01:00:00+00:00", clock)[0])

    def test_dst_winter_summer_gap_and_fold(self):
        clock = WindowsTimeRules("Synthetic", "SYSTEM\\ControlSet001", 300, 240,
                                 (0, 11, 0, 1, 2, 0, 0, 0), (0, 3, 0, 2, 2, 0, 0, 0))
        for raw, expected in (
            ("2024-01-01T23:00:00", "2024-01-02T04:00:00+00:00"),
            ("2024-07-01T23:00:00", "2024-07-02T03:00:00+00:00"),
            ("2024-03-10T02:30:00", None),
            ("2024-11-03T01:30:00", None),
        ):
            with self.subTest(raw=raw):
                stamp, details = local_time_to_utc(raw, clock)
                self.assertEqual(stamp, expected)
                self.assertEqual(details["timestamp_raw_local"], raw)

    def test_registry_reads_signed_bias_and_disabled_daylight(self):
        hive = Mock(data=b"regf" + b"\0" * 8)
        hive.open.return_value.values.return_value = [
            {"name": "Bias", "type": 4, "raw": struct.pack("<i", -540)},
            {"name": "DynamicDaylightTimeDisabled", "type": 4, "raw": struct.pack("<i", 1)},
        ]
        with patch("log_hunter.core.windows_time.Hive", return_value=hive), \
                patch("log_hunter.core.windows_time.current_controlset", return_value="ControlSet001"):
            clock = read_windows_time_rules("synthetic")
        self.assertEqual(clock.standard_bias, -540)
        self.assertEqual(clock.standard_date, (0,) * 8)
