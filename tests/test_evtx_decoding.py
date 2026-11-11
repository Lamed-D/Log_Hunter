"""Synthetic BinXML values and EVTX decoding regressions."""
import struct
import unittest

from log_hunter.parser.binxml import decode_value


class BinXmlValueTests(unittest.TestCase):
    def test_values_must_not_read_past_declared_length(self):
        value, end = decode_value(b"\x01\x02\x03\x04", 0, 0x08, 1)
        self.assertIsNone(value)
        self.assertEqual(end, 1)

    def test_negative_offset_and_truncated_value(self):
        for offset, length in ((-1, 2), (0, -1), (3, 2)):
            with self.subTest(offset=offset, length=length):
                self.assertIsNone(decode_value(b"abcd", offset, 0x06, length)[0])

    def test_systemtime_and_size_t(self):
        raw = struct.pack("<8H", 2024, 2, 4, 29, 12, 34, 56, 789)
        self.assertEqual(decode_value(raw, 0, 0x12, 16)[0], "2024-02-29T12:34:56.789000")
        self.assertEqual(decode_value(struct.pack("<Q", 123), 0, 0x10, 8)[0], 123)

    def test_invalid_systemtime_and_sid(self):
        self.assertIsNone(decode_value(struct.pack("<8H", 2024, 13, 0, 1, 0, 0, 0, 0), 0, 0x12, 16)[0])
        self.assertIsNone(decode_value(b"\x01\x02" + bytes(10), 0, 0x13, 12)[0])

    def test_numeric_and_string_arrays(self):
        self.assertEqual(decode_value(struct.pack("<3I", 1, 2, 3), 0, 0x88, 12)[0], [1, 2, 3])
        raw = "one\0two\0".encode("utf-16-le")
        self.assertEqual(decode_value(raw, 0, 0x81, len(raw))[0], ["one", "two"])
        self.assertIsNone(decode_value(b"abc", 0, 0x88, 3)[0])

    def test_guid_binary_sid_and_null(self):
        raw = bytes.fromhex("78563412bc9af0de123456789abcdef0")
        self.assertEqual(decode_value(raw, 0, 0x0f, 16)[0], "12345678-9abc-def0-1234-56789abcdef0")
        self.assertEqual(decode_value(b"\xab\xcd", 0, 0x0e, 2)[0], "abcd")
        raw = b"\x01\x01" + (5).to_bytes(6, "big") + struct.pack("<I", 18)
        self.assertEqual(decode_value(raw, 0, 0x13, len(raw))[0], "S-1-5-18")
        self.assertIsNone(decode_value(b"\x01", 0, 0, 1)[0])
