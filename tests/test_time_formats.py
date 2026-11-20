"""Time formats of the mail, FAT/exFAT and browser parsers: an offset gives UTC, no offset keeps the written value."""
import unittest


class FormatToUtcTests(unittest.TestCase):
    """Each claude1 parser's own time format: with an offset → UTC, without → kept as written (시간대 미상)."""

    def test_mail_date_offsets_including_a_daylight_saving_change(self):
        from email.message import EmailMessage
        from log_hunter.parser.email_message import _date
        cases = {"Sun, 10 Mar 2024 01:59:59 -0500": ("2024-03-10T06:59:59+00:00", "utc"),  # last standard second
                 "Sun, 10 Mar 2024 03:00:00 -0400": ("2024-03-10T07:00:00+00:00", "utc"),  # first daylight second
                 "Mon, 01 Jan 2024 09:00:00 +0900": ("2024-01-01T00:00:00+00:00", "utc"),
                 "Mon, 01 Jan 2024 09:00:00 GMT": ("2024-01-01T09:00:00+00:00", "utc"),
                 "Mon, 01 Jan 2024 09:00:00 -0000": ("2024-01-01T09:00:00", "zone_unknown"),
                 "Mon, 01 Jan 2024 09:00:00": ("2024-01-01T09:00:00", "zone_unknown")}
        for raw, (want, basis) in cases.items():
            message = EmailMessage()
            message["Date"] = raw
            stamp, kept, got = _date(message, "Date")
            self.assertEqual((stamp, got), (want, basis), raw)

    def test_exfat_offsets(self):
        from log_hunter.image.exfat import exfat_time
        stamp = (44 << 25) | (1 << 21) | (1 << 16) | (9 << 11) | (30 << 5) | 5  # 2024-01-01 09:30:10 local
        self.assertEqual(exfat_time(stamp, 50, 0x80 | 36), ("2024-01-01T00:30:10.500000+00:00", True))  # +09:00
        self.assertEqual(exfat_time(stamp, 0, 0x80 | (0x80 - 20)), ("2024-01-01T14:30:10+00:00", True))  # -05:00
        self.assertEqual(exfat_time(stamp, 50, 0), ("2024-01-01T09:30:10", False))  # no offset: local, kept raw

    def test_fat_dates_are_never_utc(self):
        from log_hunter.image.fat import _dos_datetime
        self.assertEqual(_dos_datetime((44 << 9) | (1 << 5) | 1, (9 << 11) | (30 << 5) | 5, 150), "2024-01-01T09:30:11")

    def test_browser_numbers(self):
        from log_hunter.core.timestamp import chromium_timestamp
        from log_hunter.parser.chromium_extra import _unix_time
        self.assertEqual(chromium_timestamp(13348540800000000), "2024-01-01T00:00:00+00:00")  # µs since 1601
        self.assertEqual(_unix_time(1704067200), "2024-01-01T00:00:00+00:00")  # Unix seconds


if __name__ == "__main__":
    unittest.main()
