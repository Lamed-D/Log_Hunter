"""Synthetic evidence clock conversion tests."""
import struct
import unittest
from unittest.mock import Mock, patch

from log_hunter.core.windows_time import WindowsTimeRules, local_time_to_utc, read_windows_time_rules


class WindowsTimeTests(unittest.TestCase):
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
