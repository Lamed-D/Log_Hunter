"""Retired mount records remain private USB volume context only."""
from pathlib import Path
import hashlib
import tempfile
import unittest

from test_example_samples import load_demo
from log_hunter.core.pipeline import PARSERS, Pipeline
from log_hunter.core.auto_detect import HIVE_ARTIFACTS
from log_hunter.image.extract import ARTIFACT_SPECS
from log_hunter.parser.mountpoints2 import read_volume_hints, attach_volume_hints
from log_hunter.parser.usb import _match_mounted_device
from log_hunter.core.models import ForensicEvent

GUID = "{00000000-0000-1000-8000-00005e005301}"
SID = "S-1-5-21-1000-2000-3000-1001"


class RetiredMountTests(unittest.TestCase):
    def test_public_registration_removed(self):
        self.assertNotIn("mountpoints2", PARSERS)
        self.assertNotIn("mountpoints2", HIVE_ARTIFACTS["ntuser.dat"])
        self.assertNotIn("mountpoints2", repr(ARTIFACT_SPECS))

    def test_private_hints_no_public_events_and_original_hash_unchanged(self):
        b = load_demo().HiveBuilder()
        volume = b.key(GUID, 0)
        share = b.key("##server.test#share", 0)
        child = b.key("MountPoints2", 0, children=[volume, share])
        for name in reversed(["Software", "Microsoft", "Windows", "CurrentVersion", "Explorer"]):
            child = b.key(name, 0, children=[child])
        data = b.build(b.key("ROOT", 0, children=[child]))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "NTUSER.DAT"
            path.write_bytes(data)
            before = hashlib.sha256(data).hexdigest()
            hints, errors = read_volume_hints(path, SID)
            result = Pipeline().analyze([("userassist", path)])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        self.assertEqual(errors, [])
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["volume_guid"], GUID)
        self.assertEqual(hints[0]["sid"], SID)
        self.assertNotIn("mac_address", hints[0])
        self.assertFalse(any(e.artifact == "mountpoints2" for e in result.events))

    def test_volume_alias_requires_identical_recorded_bytes(self):
        raw = "USBSTOR#TESTSERIAL0001".encode("utf-16-le")
        matches = _match_mounted_device([
            {"name": "\\DosDevices\\E:", "raw": raw},
            {"name": "\\??\\Volume" + GUID, "raw": raw},
            {"name": "\\??\\Volume{00000000-0000-0000-0000-000000000002}", "raw": raw + b"xx"},
        ], "TEST", "TESTSERIAL0001")
        self.assertEqual(matches[0]["volume_guids"], ["\\??\\Volume" + GUID])
        usb = ForensicEvent("usb", "generated", "device_registration", details={
            "is_storage_device": True, "mounted_device_matches": matches})
        other = ForensicEvent("usb", "generated", "device_registration", details={
            "is_storage_device": False, "mounted_device_matches": matches})
        hints = [{"volume_guid": GUID, "source": "generated", "sid": SID,
                  "key_lastwrite": None, "label": "TestVolume"}]
        attach_volume_hints([usb, other], hints)
        self.assertEqual(usb.details["mountpoint_context"][0]["match_basis"], "volume_guid_match")
        self.assertNotIn("mountpoint_context", other.details)
        usb.details.pop("mountpoint_context")
        usb.details["mounted_device_matches"] = [{"drive_letter": "E:"}]
        attach_volume_hints([usb], hints)
        self.assertNotIn("mountpoint_context", usb.details)
