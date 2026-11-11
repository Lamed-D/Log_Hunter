"""USB device kind columns and the 장치 종류별 tree filter, from the engine's synthetic SYSTEM hive only."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.labels import column_label
from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import build_tree, matches
from log_hunter.parser.usb import USBParser
from log_hunter.ui import columns
from test_usb_devices import usb_hive


def _parse(**kwargs):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "SYSTEM"
        path.write_bytes(usb_hive(**kwargs))
        return list(USBParser().parse(path))


def _find(node, key):
    if node.key == key:
        return node
    for child in node.children:
        hit = _find(child, key)
        if hit:
            return hit


def _shown(event, node):
    cols = columns.columns_for(node)
    return dict(zip([c.key for c in cols], columns.row(event, cols, {}, None)))


class USBKindViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = _parse()
        cls.art = build_tree(cls.events)[1]
        cls.registrations = [e for e in cls.events if e.action == "device_registration"]

    def test_tree_has_one_filter_node_per_device_kind(self):
        category = _find(self.art, "art:usb_devices")
        labels = [c.text for c in category.children]
        self.assertIn("키보드 (6)", labels)  # 2 registrations + 4 property times of the first keyboard
        self.assertIn("USB 저장 장치 (1)", labels)
        self.assertIn("휴대용 장치 (1)", labels)
        keyboard = _find(self.art, "art:usb_devices:kind:keyboard")
        shown = [e for e in self.events if matches(keyboard, e, None)]
        self.assertEqual({e.details["device_kind"] for e in shown}, {"keyboard"})
        self.assertEqual(sum(c.count for c in category.children), len(self.events))

    def test_retired_mountpoints_are_not_a_usb_category(self):
        from log_hunter.core.tree import category_of
        self.assertEqual(category_of("mountpoints2"), "other")

    def test_columns_separate_usb_interface_class_from_install_class(self):
        node = _find(self.art, "art:usb_devices:kind:keyboard")
        keyboard = self.registrations[0]
        shown = _shown(keyboard, node)
        self.assertEqual(list(shown)[:14], ["timestamp", "device_kind_name", "artifact", "device_name", "physical_group",
                                            "unknown_reason", "device", "vid_pid", "usb_class", "install_class", "serial",
                                            "composite", "kind_basis", "time_field"])
        self.assertEqual(shown["device_kind_name"], "키보드")
        self.assertEqual(shown["device_name"], "TEST keyboard")
        self.assertEqual(shown["vid_pid"], "FFFF/FF01")
        self.assertEqual(shown["usb_class"], "03/01/01")
        self.assertEqual(shown["install_class"], "")  # no Class value recorded for this device
        self.assertIn("기록된 식별자 기준", shown["kind_basis"])
        self.assertIn("하드웨어 ID USB\\CLASS_03&SUBCLASS_01&PROT_01".casefold(), shown["kind_basis"].casefold())
        portable = next(e for e in self.registrations if e.details["device_kind"] == "portable")
        self.assertEqual(_shown(portable, node)["install_class"], "WPD")
        self.assertEqual(column_label("usb_class"), "USB 인터페이스 클래스")

    def test_usb_columns_have_no_user_column(self):
        for key in ("art:usb_devices", "art:usb_devices:kind:keyboard"):
            self.assertNotIn("user", [c.key for c in columns.columns_for(_find(self.art, key))])

    def test_composite_group_only_from_recorded_container(self):
        node = _find(self.art, "art:usb_devices")
        keyboard, mouse = self.registrations[:2]
        self.assertEqual(_shown(keyboard, node)["composite"], _shown(mouse, node)["composite"])
        self.assertTrue(_shown(keyboard, node)["composite"].startswith("컨테이너 "))
        no_container = [e for e in _parse(container=False) if e.action == "device_registration"]
        self.assertEqual(_shown(no_container[0], node)["composite"], "인터페이스 00 · 묶음 근거 없음")
        camera = next(e for e in self.registrations if e.details["device_kind"] == "camera")
        self.assertEqual(_shown(camera, node)["composite"], "")  # same VID alone never groups devices

    def test_conflict_and_generated_serial_are_marked(self):
        event = ForensicEvent("usb", r"C:\Evidence\SYSTEM", "device_registration", None, details={
            "device": "VID_FFFF&PID_FF09", "device_kind": "unknown", "device_kind_name": "알 수 없는 장치",
            "classification_conflict": True, "classification_confidence": "low",
            "device_classification_basis": [{"kind": "storage", "basis": "compatible_id", "identifier": "USB\\Class_08"},
                                            {"kind": "keyboard", "basis": "class_guid", "identifier": "{guid}"}],
            "serial": "7&1A2B3C&0", "serial_may_be_generated": True})
        shown = _shown(event, _find(self.art, "art:usb_devices"))
        self.assertEqual(shown["device_kind_name"], "알 수 없는 장치 (근거 충돌)")
        self.assertEqual(shown["serial"], "7&1A2B3C&0 (Windows 생성 값일 수 있음)")
        self.assertTrue(shown["kind_basis"].startswith("판정 약함 · 호환 ID USB\\Class_08; 설치 클래스 GUID {guid}"))
        unknown = _find(build_tree([event])[1], "art:usb_devices:kind:unknown")
        self.assertEqual(unknown.text, "알 수 없는 장치 (1)")


if __name__ == "__main__":
    unittest.main()
