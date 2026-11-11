"""Synthetic cross-bus USB observations with duplicate control sets and metadata-only sources."""
from pathlib import Path
import struct
import tempfile
import unittest
from collections import Counter

from test_example_samples import load_demo
from log_hunter.parser.usb import USBParser
from log_hunter.parser.usb_inventory import usb_device_inventory

STAMP = 133485408000000000


def synthetic_usb_hives(damaged_peer=False):
    system, software = {}, {}

    def put(tree, path, values=()):
        node = tree
        for part in path.split("\\"):
            node = node.setdefault(part, {})
        node[":values"] = list(values)

    def text(name, value, kind=1):
        return name, kind, (value + "\0").encode("utf-16-le")

    def cid(number):
        return "{00000000-0000-0000-0000-" + f"{number:012d}" + "}"

    def device(bus, name, serial, kind=None, container=None, label=True):
        path = "ControlSet002\\Enum\\" + bus + "\\" + name + "\\" + serial
        values = [text("FriendlyName", "Test " + (kind or "device"))] if label else []
        if kind:
            classes = {"keyboard":"03&SubClass_01&Prot_01", "mouse":"03&SubClass_01&Prot_02",
                       "storage":"08", "camera":"0E", "hub":"09", "bluetooth":"E0&SubClass_01&Prot_01"}
            if kind in classes:
                values.append(text("CompatibleIDs", "USB\\Class_" + classes[kind], 7))
            elif kind == "portable":
                values.append(text("Class", "WPD"))
        if container:
            values.append(text("ContainerID", cid(container)))
        put(system, path, values)
        return path

    receiver = device("USB", "VID_FFFF&PID_FF10", "TESTRECEIVER", container=1)
    device("USB", "VID_FFFF&PID_FF10&MI_00", "7&TESTRECEIVER&0&0000", "keyboard", 1)
    device("USB", "VID_FFFF&PID_FF10&MI_01", "7&TESTRECEIVER&0&0001", "mouse", 1)
    device("HID", "VID_FFFF&PID_FF10&MI_00", "8&TESTHID&0&0000", "keyboard", 1)
    device("HID", "VID_FFFF&PID_FF10&MI_01", "8&TESTHID&0&0001", "mouse", 1)
    device("USB", "VID_FFFF&PID_FF11", "TESTMEMORY001", "storage", 2)
    device("USBSTOR", "Disk&Ven_TEST&Prod_TEST&Rev_1", "TESTMEMORY001&0", "storage", 2)
    device("SWD\\WPDBUSENUM", "TESTPORTABLE", "TESTMEMORYPORT", "portable", 2)
    device("USB", "VID_FFFF&PID_FF12", "TESTCAMERA001", "camera", 3)
    device("USB", "ROOT_HUB30", "TESTHUB", "hub", 4)
    device("USB", "VID_FFFF&PID_FF13", "TESTRADIO001", "bluetooth", 5)
    device("BTHENUM", "{00000000-0000-0000-0000-000000000005}_SERVICE", "TESTSERVICE", container=5)
    device("USB", "VID_FFFF&PID_FF14", "9&TESTUNKNOWN&0", label=False)
    device("HID", "VID_FFFF&PID_FF15", "9&TESTORPHAN&0", label=False)
    put(system, receiver + "\\Properties")  # Not an instance or a physical device.
    for prop in ("0064", "0065", "0066", "0067"):
        put(system, receiver + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\" + prop,
            [("", 3, struct.pack("<Q", STAMP))])
    put(system, "Select", [("Current", 4, struct.pack("<I", 2))])
    # Same entries in an inactive control set must not double the registrations.
    system["ControlSet001"] = system["ControlSet002"]
    put(system, "ControlSet002\\services\\BTHPORT\\Parameters\\Devices\\00005e005301",
        [("Name", 3, b"\xff") if damaged_peer else text("Name", "Test Bluetooth peer"),
         ("LastSeen", 3, b"bad" if damaged_peer else struct.pack("<Q", STAMP)),
         ("LastConnected", 3, struct.pack("<Q", STAMP))])
    if damaged_peer:
        put(system, "ControlSet002\\services\\BTHPORT\\Parameters\\Devices\\invalid-address")
    mount = "USBSTOR#TESTMEMORY001".encode("utf-16-le")
    put(system, "MountedDevices", [("\\DosDevices\\E:", 3, mount),
        ("\\??\\Volume" + cid(2), 3, mount)])
    put(system, "ControlSet002\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\TESTMEMORY001")
    put(system, "ControlSet002\\Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\\TESTMEMORY001")
    put(software, "Microsoft\\Windows Portable Devices\\Devices\\USB#VID_FFFF&PID_FF11#TESTMEMORY001",
        [text("FriendlyName", "Test memory"), text("physical_observation", "true")])
    put(software, "Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt\\TESTMEMORY001",
        [("LastTestedTime", 3, struct.pack("<Q", STAMP))])

    def build(tree):
        b = load_demo().HiveBuilder()
        def emit(name, node):
            children = [emit(name, child) for name, child in node.items() if name != ":values"]
            return b.key(name, STAMP, values=node.get(":values", []), children=children)
        return b.build(emit("ROOT", tree))
    return build(system), build(software)


def comparison_events():
    events = []
    with tempfile.TemporaryDirectory() as folder:
        for name, data in zip(("SYSTEM", "SOFTWARE"), synthetic_usb_hives()):
            path = Path(folder) / name
            path.write_bytes(data)
            parser = USBParser()
            parsed = list(parser.parse(path))
            assert not parser.errors, parser.errors
            for event in parsed:
                event.source = name  # Fixed synthetic evidence identity.
            events.extend(parsed)
    return events


class USBReferenceTests(unittest.TestCase):
    def test_same_scenario_has_expected_registry_observation_counts(self):
        events = comparison_events()
        registrations = [e for e in events if e.action == "device_registration"]
        self.assertEqual(len(events), 22)
        self.assertEqual(Counter(e.details["bus"] for e in registrations), {
            "USB":8, "USBSTOR":1, "HID":3, "BTHENUM":1, r"SWD\WPDBUSENUM":1,
            "Windows Portable Devices":1, "BTHPORT":1})
        self.assertTrue(all("ControlSet001" not in (e.locator or "") for e in events))

    def test_metadata_only_observation_does_not_add_a_physical_device(self):
        events = comparison_events()
        inventory = usb_device_inventory(events)
        self.assertEqual(inventory["counts"], {"registration_records":16, "physical_groups":8,
            "default_visible_groups":7, "system_groups":1, "auxiliary_groups":1, "unknown_groups":2})
        metadata = next(e for e in events if e.source == "SOFTWARE")
        self.assertFalse(metadata.details["physical_observation"])
        self.assertFalse(metadata.details["device_inventory_visible"])
        self.assertFalse(metadata.details["physical_device_representative"])
        self.assertTrue(metadata.details["auxiliary_device"])

    def test_unresolved_hid_and_every_unknown_device_explain_why(self):
        events = comparison_events()
        inventory = usb_device_inventory(events)
        orphan = next(e for e in events if e.details.get("serial_raw") == "9&TESTORPHAN&0")
        self.assertIn("parent_device_unknown", orphan.details["unknown_reasons"])
        for group in inventory["groups"]:
            if group["device_kinds"] == ["unknown"]:
                self.assertTrue(group["unknown_reasons"])
                self.assertTrue(group["unknown_reason_labels"])

    def test_malformed_bluetooth_name_and_time_do_not_hide_valid_peer_records(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "SYSTEM"
            path.write_bytes(synthetic_usb_hives(damaged_peer=True)[0])
            parser = USBParser()
            events = list(parser.parse(path))
        peers = [e for e in events if e.details.get("bus") == "BTHPORT"]
        self.assertEqual({e.action for e in peers}, {"device_registration", "bluetooth_last_connected"})
        self.assertGreaterEqual(len(parser.errors), 3)
        self.assertTrue(all("description_missing" in e.details["unknown_reasons"] for e in peers))
        self.assertEqual(peers[0].details["bluetooth_address"], "00:00:5E:00:53:01")
        self.assertFalse(peers[0].details["is_storage_device"])
        self.assertIsNone(peers[0].details["currently_connected"])
