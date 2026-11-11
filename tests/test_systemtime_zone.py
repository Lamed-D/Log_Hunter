import struct
import unittest

from log_hunter.parser.binxml import decode_value, VALUE_FILETIME, VALUE_SYSTEMTIME


class SystemTimeZoneTests(unittest.TestCase):
    def test_payload_clock_is_unknown_for_scalar_and_array(self):
        raw = struct.pack('<8H', 2024, 1, 1, 1, 2, 3, 4, 5)
        value, end = decode_value(raw, 0, VALUE_SYSTEMTIME, len(raw))
        self.assertEqual(value, '2024-01-01T02:03:04.005000')
        self.assertEqual(end, 16)
        values, end = decode_value(raw * 2, 0, VALUE_SYSTEMTIME | 0x80, 32)
        self.assertEqual(values, [value, value])
        self.assertEqual(end, 32)

    def test_invalid_date_and_milliseconds_stay_invalid(self):
        for month, millis in ((13, 0), (1, 1000)):
            raw = struct.pack('<8H', 2024, month, 1, 1, 2, 3, 4, millis)
            self.assertIsNone(decode_value(raw, 0, VALUE_SYSTEMTIME, 16)[0])

    def test_filetime_retains_utc(self):
        raw = struct.pack('<Q', 133485408000000000)
        self.assertTrue(decode_value(raw, 0, VALUE_FILETIME, 8)[0].endswith('+00:00'))
