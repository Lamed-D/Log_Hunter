"""Device inventory counts physical candidates, retaining every timed observation."""
from pathlib import Path
import tempfile
import unittest

from test_usb_devices import usb_hive
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import Pipeline
from log_hunter.parser.usb import USBParser
from log_hunter.parser.usb_inventory import usb_device_inventory

CID = "{00000000-0000-0000-0000-000000000001}"


def record(device, serial="TESTSERIAL0001", bus="USB", source="generated", **details):
    return ForensicEvent("usb", source, "device_registration", details={
        "device": device, "serial": serial, "serial_raw": serial, "bus": bus,
        "device_kind": "unknown", **details})


class USBInventoryTests(unittest.TestCase):
    def test_same_hive_stages_and_pipeline_annotations(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "SYSTEM"
            path.write_bytes(usb_hive())
            raw = list(USBParser().parse(path))
            result = Pipeline().analyze([("usb", path)])
        self.assertEqual(len(raw), 13)  # nine registrations plus four property times
        inventory = usb_device_inventory(raw)
        self.assertEqual(inventory["counts"], {"registration_records": 9, "physical_groups": 8,
            "default_visible_groups": 7, "system_groups": 1, "auxiliary_groups": 0, "unknown_groups": 0})
        self.assertEqual(sum(e.details["physical_device_representative"] for e in result.events), 8)
        self.assertEqual(len(result.events), 13)
        self.assertTrue(all("physical_device_id" in e.details for e in result.events))
        composite = next(g for g in inventory["groups"] if len(g["registration_indices"]) == 2)
        self.assertEqual(composite["device_kinds"], ["keyboard", "mouse"])
        self.assertEqual(len(composite["event_indices"]), 6)

    def test_same_vid_pid_generated_serial_never_merges(self):
        events = [record("VID_FFFF&PID_FF01&MI_00", "7&TEST&0&0000"),
                  record("VID_FFFF&PID_FF01&MI_01", "7&TEST&0&0001")]
        self.assertEqual(usb_device_inventory(events)["counts"]["physical_groups"], 2)

    def test_container_groups_hid_storage_and_portable_observations(self):
        events = [record("VID_FFFF&PID_FF01", containerid=CID),
                  record("VID_FFFF&PID_FF01&MI_00", bus="HID", containerid=CID),
                  record("Disk&Ven_TEST&Prod_TEST&Rev_1", bus="USBSTOR", containerid=CID),
                  record("TESTPORTABLE", bus=r"SWD\WPDBUSENUM", containerid=CID)]
        inventory = usb_device_inventory(events)
        self.assertEqual(inventory["counts"]["physical_groups"], 1)
        self.assertEqual(inventory["groups"][0]["registration_indices"], [0, 1, 2, 3])

    def test_conflicting_or_zero_container_and_different_sources_do_not_merge(self):
        for other in ("{00000000-0000-0000-0000-000000000002}",):
            events = [record("VID_FFFF&PID_FF01", containerid=CID),
                      record("VID_FFFF&PID_FF01", containerid=other)]
            self.assertEqual(usb_device_inventory(events)["counts"]["physical_groups"], 2)
        events = [record("one", containerid=CID), record("two", containerid=CID, source="other")]
        self.assertEqual(usb_device_inventory(events)["counts"]["physical_groups"], 2)
        events = [record("one", containerid="{00000000-0000-0000-0000-000000000000}"),
                  record("two", containerid="{00000000-0000-0000-0000-000000000000}")]
        self.assertEqual(usb_device_inventory(events)["counts"]["physical_groups"], 2)

    def test_explicit_parent_and_unique_prefix_are_candidate_evidence(self):
        parent = record("VID_FFFF&PID_FF01", "TESTPARENT", parentidprefix="7&TEST&0")
        child = record("VID_FFFF&PID_FF01&MI_00", "7&TEST&0&0000", bus="HID")
        inventory = usb_device_inventory([parent, child])
        self.assertEqual(inventory["counts"]["physical_groups"], 1)
        self.assertEqual(inventory["groups"][0]["grouping_evidence"][0]["basis"], "unique_parent_prefix")
        child.details["parent"] = r"USB\VID_FFFF&PID_FF01\TESTPARENT"
        inventory = usb_device_inventory([parent, child])
        self.assertEqual(inventory["groups"][0]["grouping_evidence"][0]["basis"], "recorded_parent")

    def test_hubs_and_bluetooth_service_are_default_hidden_with_raw_records(self):
        events = [record("ROOT_HUB30"), record("{00000000-0000-0000-0000-000000000001}_SERVICE", bus="BTHENUM"),
                  record("VID_FFFF&PID_FF01", "TESTSERIAL0002")]
        inventory = usb_device_inventory(events)
        self.assertEqual(inventory["counts"]["default_visible_groups"], 1)
        self.assertEqual(inventory["counts"]["system_groups"], 1)
        self.assertEqual(inventory["counts"]["auxiliary_groups"], 1)
        self.assertEqual(len(events), 3)

    def test_unknown_reasons_are_recorded_and_property_subkeys_are_not_instances(self):
        from test_example_samples import load_demo
        b = load_demo().HiveBuilder()
        instance = b.key("TESTSERIAL0001", 0)
        properties = b.key("Properties", 0)
        device = b.key("VID_FFFF&PID_FF01", 0, children=[instance, properties])
        usb = b.key("USB", 0, children=[device])
        enum = b.key("Enum", 0, children=[usb])
        control = b.key("ControlSet002", 0, children=[enum])
        inactive = b.key("ControlSet001", 0, children=[enum])
        select = b.key("Select", 0, values=[("Current", 4, bytes([2,0,0,0]))])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "SYSTEM"
            path.write_bytes(b.build(b.key("ROOT", 0, children=[select, control, inactive])))
            events = list(USBParser().parse(path))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].details["unknown_reasons"], ["description_missing", "classification_missing"])
        self.assertEqual(len(events[0].details["unknown_reason_labels"]), 2)

    def test_parent_hub_does_not_swallow_attached_devices(self):
        hub = record("ROOT_HUB30", "TESTHUB", device_kind="hub", parentidprefix="7&TEST&0")
        child = record("VID_FFFF&PID_FF01&MI_00", "7&TEST&0&0000", bus="HID",
                       parent=r"USB\ROOT_HUB30\TESTHUB")
        self.assertEqual(usb_device_inventory([hub, child])["counts"]["physical_groups"], 2)
