"""USB physical device candidates in the tree and table, from the engine's inventory on a synthetic SYSTEM hive."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import build_tree, matches
from log_hunter.parser.usb import USBParser
from log_hunter.parser.usb_inventory import usb_device_inventory
from log_hunter.ui import columns
from test_usb_devices import usb_hive


def _find(node, key):
    if node.key == key:
        return node
    for child in node.children:
        hit = _find(child, key)
        if hit:
            return hit


class USBGroupsViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "SYSTEM"
            path.write_bytes(usb_hive())
            cls.events = list(USBParser().parse(path))
        cls.inventory = usb_device_inventory(cls.events)
        cls.usb = _find(build_tree(cls.events)[1], "art:usb_devices")

    def test_device_nodes_hold_every_record_of_their_group(self):
        keyboard = _find(self.usb, "art:usb_devices:kind:keyboard")
        self.assertTrue(keyboard.text.startswith("키보드 · 장치 2개"))
        device = keyboard.children[0]
        self.assertEqual(device.kind, "usb_device")
        group = next(g for g in self.inventory["groups"] if g["group_id"] == device.value)
        shown = [i for i, e in enumerate(self.events) if matches(device, e, None)]
        self.assertEqual(shown, group["event_indices"])  # interfaces, HID children and property times together
        self.assertEqual(device.count, len(shown))

    def test_hubs_fold_into_system_devices_not_the_kind_filters(self):
        system = _find(self.usb, "art:usb_devices:system")
        self.assertEqual(system.text, "시스템 장치 (허브·컨트롤러) (1)")
        hub = [e for e in self.events if matches(system, e, None)]
        self.assertTrue(hub and all(e.details["system_device"] for e in hub))
        kinds = [c for c in self.usb.children if c.kind == "device_kind"]
        self.assertFalse(any(matches(k, e, None) for k in kinds for e in hub))
        self.assertEqual(sum(c.count for c in self.usb.children), len(self.events))
        visible_groups = sum(len(k.children) for k in kinds)
        self.assertLessEqual(visible_groups, self.inventory["counts"]["default_visible_groups"])

    def test_group_and_unknown_reason_columns(self):
        device = _find(self.usb, "art:usb_devices:kind:keyboard").children[0]
        cols = columns.columns_for(device)
        self.assertEqual(cols, columns.CATEGORY_COLUMNS["usb_devices"])
        event = next(e for e in self.events if matches(device, e, None))
        shown = dict(zip([c.key for c in cols], columns.row(event, cols, {}, None)))
        self.assertTrue(shown["physical_group"].startswith(device.value + " · "))
        self.assertIn("확정 아님", shown["physical_group"])
        unknown = ForensicEvent("usb", r"C:\Evidence\SYSTEM", "device_registration", None, details={
            "device_kind": "unknown", "unknown_reason_labels": ["장치 이름·설명 기록 없음", "기록된 장치 종류가 서로 다름"]})
        cell = dict(zip([c.key for c in cols], columns.row(unknown, cols, {}, None)))
        self.assertEqual(cell["unknown_reason"], "장치 이름·설명 기록 없음; 기록된 장치 종류가 서로 다름")
        self.assertEqual(cell["physical_group"], "")  # no inventory fields: no group claimed

    def test_metadata_only_entry_is_not_shown_as_a_physical_candidate(self):
        from test_example_samples import load_demo
        b = load_demo().HiveBuilder()
        node = b.key("USBSTOR#TESTSERIAL0001", 0, values=[("FriendlyName", 1, "TEST volume\0".encode("utf-16-le"))])
        for name in ("Devices", "Windows Portable Devices", "Microsoft"):
            node = b.key(name, 0, children=[node])
        with tempfile.TemporaryDirectory() as folder:
            system, software = Path(folder) / "SYSTEM", Path(folder) / "SOFTWARE"
            system.write_bytes(usb_hive())
            software.write_bytes(b.build(b.key("ROOT", 0, children=[node])))
            events = list(USBParser().parse(software)) + list(USBParser().parse(system))
        inventory = usb_device_inventory(events)
        usb = _find(build_tree(events)[1], "art:usb_devices")
        auxiliary = _find(usb, "art:usb_devices:auxiliary")
        self.assertEqual(auxiliary.text, "보조 항목 (이름만 남은 기록·블루투스 서비스 등) (1)")
        metadata = next(e for e in events if matches(auxiliary, e, None))
        cols = columns.CATEGORY_COLUMNS["usb_devices"]
        shown = dict(zip([c.key for c in cols], columns.row(metadata, cols, {}, None)))
        self.assertTrue(shown["physical_group"].endswith("보조 항목(별도 물리 장치 아님)"))
        self.assertNotIn("물리 장치 후보", shown["physical_group"])
        self.assertIn("별도 물리 장치 아님", shown["unknown_reason"])
        self.assertIn("레지스트리 위치", shown["kind_basis"])
        kinds = [c for c in usb.children if c.kind == "device_kind"]
        self.assertEqual(sum(len(k.children) for k in kinds), inventory["counts"]["default_visible_groups"])

    def test_records_without_inventory_fields_stay_visible(self):
        plain = ForensicEvent("usb", r"C:\Evidence\SYSTEM", "device_registration", None, details={"device_kind": "storage"})
        usb = _find(build_tree([plain])[1], "art:usb_devices")
        self.assertEqual([c.key for c in usb.children], ["art:usb_devices:kind:storage"])
        self.assertEqual(usb.children[0].children, [])


if __name__ == "__main__":
    unittest.main()
