"""Parser flags must not overstate what the evidence shows."""
import unittest
import sqlite3
import tempfile
import hashlib
from pathlib import Path
from contextlib import closing

from log_hunter.parser.services import _check_service_suspicious
from log_hunter.parser.wlan import parse_wlan_xml

PROFILE = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>Home</name>
  <SSIDConfig><SSID><name>Home</name></SSID></SSIDConfig>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>{protected}</protected><keyMaterial>{key}</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>"""


class ParserInterpretationTests(unittest.TestCase):
    def test_dpapi_protected_wifi_key_is_not_a_cleartext_password(self):
        protected = parse_wlan_xml(PROFILE.format(protected="true", key="01000000D08C9DDF0115D1118C7A00C0").encode())
        clear = parse_wlan_xml(PROFILE.format(protected="false", key="hunter2").encode())
        self.assertFalse(protected["cleartext_password_found"])
        self.assertTrue(clear["cleartext_password_found"])
        unknown = parse_wlan_xml(PROFILE.format(protected="", key="unknown-protection").encode())
        self.assertFalse(unknown["cleartext_password_found"])

    def test_standard_windows_service_paths_are_not_suspicious(self):
        for image_path in (r"%SystemRoot%\System32\svchost.exe -k netsvcs",
                           r'"C:\Program Files\Windows Defender\MsMpEng.exe"',
                           r"\??\C:\Windows\system32\drivers\x.sys",
                           r"System32\drivers\disk.sys"):
            with self.subTest(path=image_path):
                self.assertNotIn("auto_start_outside_system_dirs", _check_service_suspicious(image_path, "Svc", 2))
        self.assertIn("auto_start_outside_system_dirs", _check_service_suspicious(r"D:\x\evil.exe", "Svc", 2))

    def test_service_paths_cannot_escape_allowed_directory(self):
        for path in (r"C:\WindowsFake\evil.exe", r"%SystemRoot%\..\Temp\evil.exe",
                     r'"C:\Program Files\..\Users\Public\evil.exe"'):
            self.assertIn("auto_start_outside_system_dirs", _check_service_suspicious(path, "Svc", 2))

    def test_srum_wal_recovery_preserves_evidence_bytes(self):
        from log_hunter.core.pipeline import Pipeline
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "evidence #1 %20.sqlite")
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.execute("CREATE TABLE [{973F5D5C-1D90-4944-BE8E-24B94231A174}](AppId, TimeStamp)")
                connection.execute("INSERT INTO [{973F5D5C-1D90-4944-BE8E-24B94231A174}] VALUES(1, 133000000000000000)")
                connection.commit()
                files = list(Path(directory).iterdir())
                before = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in files}
                result = Pipeline().analyze([("srum", database)])
                self.assertEqual(len(result.events), 1, result.errors)
                self.assertEqual(result.events[0].source, str(database))
                self.assertTrue(all(error.source == str(database) for error in result.errors))
                after = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in Path(directory).iterdir()}
                self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
