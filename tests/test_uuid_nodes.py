"""UUID node values are candidates, never proof of a network adapter."""
import unittest
from log_hunter.parser.mountpoints2 import extract_mac_from_uuid_v1, uuid_node_info


class UUIDNodeTests(unittest.TestCase):
    def guid(self, node):
        return "{12345678-1234-1234-9234-" + node + "}"

    def test_documentation_address_candidate(self):
        self.assertEqual(extract_mac_from_uuid_v1(self.guid("00005e005301")), "00:00:5E:00:53:01")

    def test_non_adapter_values_are_not_mac_candidates(self):
        for node in ("806e6f6e6963", "01005e005301", "000000000000"):
            with self.subTest(node=node):
                self.assertIsNone(extract_mac_from_uuid_v1(self.guid(node)))

    def test_invalid_and_non_v1_uuid_are_not_mac_candidates(self):
        for value in ("bad", "", "{12345678-1234-4234-9234-00005e005301}",
                      "{12345678-1234-1234-1234-00005e005301}"):
            with self.subTest(value=value):
                self.assertIsNone(extract_mac_from_uuid_v1(value))

    def test_node_reasons_preserve_raw_value_without_claiming_hardware(self):
        for node, kind in (("806e6f6e6963", "no_adapter_placeholder"),
                           ("01005e005301", "random_node"),
                           ("000000000000", "zero_node"),
                           ("00005e005301", "mac_candidate")):
            info = uuid_node_info(self.guid(node))
            self.assertEqual(info["node_raw"], node.upper())
            self.assertEqual(info["node_kind"], kind)
            self.assertTrue(info["node_description"])
            self.assertFalse(info["mac_is_hardware_confirmed"])

    def test_private_hints_retain_node_reasons_without_public_records(self):
        from pathlib import Path
        import tempfile
        from test_example_samples import load_demo
        from log_hunter.parser.mountpoints2 import read_volume_hints, attach_volume_hints
        from log_hunter.core.pipeline import Pipeline, PARSERS
        from log_hunter.core.models import ForensicEvent
        b = load_demo().HiveBuilder()
        nodes = ("806e6f6e6963", "01005e005301", "000000000000", "00005e005301")
        children = [b.key(self.guid(node), 0) for node in nodes]
        children.append(b.key("##server.test#share", 0))
        child = b.key("MountPoints2", 0, children=children)
        for name in reversed(["Software", "Microsoft", "Windows", "CurrentVersion", "Explorer"]):
            child = b.key(name, 0, children=[child])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "NTUSER.DAT"
            path.write_bytes(b.build(b.key("ROOT", 0, children=[child])))
            hints, errors = read_volume_hints(path)
            result = Pipeline().analyze([("userassist", path)])
        self.assertEqual(errors, [])
        self.assertEqual(len(hints), 4)
        self.assertNotIn("mountpoints2", PARSERS)
        self.assertFalse(any(e.artifact == "mountpoints2" for e in result.events))
        by_node = {hint["uuid_node"]["node_raw"].lower(): hint for hint in hints}
        for node in nodes:
            hint = by_node[node]
            self.assertNotIn("mitre", hint)
            self.assertNotIn("mac_address", hint)
            self.assertFalse(hint["uuid_node"]["mac_is_hardware_confirmed"])
            if node != "00005e005301":
                self.assertIsNone(hint["uuid_node"]["mac_candidate"])
            usb = ForensicEvent("usb", "generated", "device_registration", details={
                "is_storage_device": True, "mounted_device_matches": [{"volume_guids": [self.guid(node)]}]})
            attach_volume_hints([usb], hints)
            self.assertEqual(usb.details["mountpoint_context"][0]["uuid_node"], hint["uuid_node"])
            self.assertEqual(usb.details["mountpoint_context"][0]["match_basis"], "volume_guid_match")

    def test_no_display_label_for_a_retired_mac_record(self):
        from log_hunter.core.labels import ACTION_LABELS
        # The volume-hint record that showed a node value as an address is retired; hints stay private details.
        self.assertFalse([k for k in ACTION_LABELS if "mac" in k.lower()])

    def test_unparsed_lnk_tracker_nodes_never_become_mac_claims(self):
        import struct
        import uuid
        from log_hunter.parser.lnk import parse_lnk, LNK_CLSID
        header = bytearray(76)
        struct.pack_into("<I", header, 0, 76)
        header[4:20] = LNK_CLSID
        for node in ("806e6f6e6963", "01005e005301", "000000000000"):
            guid = uuid.UUID(self.guid(node)).bytes_le
            tracker = struct.pack("<IIII", 96, 0xA0000003, 88, 0) + bytes(16) + guid * 4
            info = parse_lnk(bytes(header) + tracker + bytes(4))
            # TrackerDataBlock decoding is currently unsupported; no MAC claim is emitted.
            self.assertFalse(any("mac" in key.lower() or "node" in key.lower() for key in info))
