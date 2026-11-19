"""Deleted registry keys/values in hive free cells: found as candidates with a confidence, never as certain records."""
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import build_tree
from log_hunter.parser.registry_deleted import RegistryDeletedParser
from log_hunter.ui import columns
from log_hunter.ui.record_fields import properties

FT = 132537600000000000  # 2020-12-30 00:00:00 UTC


def nk(name, parent, lastwrite=FT):
    data = bytearray(76)
    data[:2] = b"nk"
    struct.pack_into("<HQ", data, 2, 0x20, lastwrite)
    struct.pack_into("<I", data, 16, parent)
    struct.pack_into("<H", data, 72, len(name))
    return bytes(data) + name.encode("latin1")


def vk(name, kind, data_offset_or_inline, size, inline=False):
    data = bytearray(20)
    data[:2] = b"vk"
    struct.pack_into("<HIIIH", data, 2, len(name), size | (0x80000000 if inline else 0),
                     data_offset_or_inline if not inline else 0, kind, 1)
    if inline:
        data[8:8 + size] = data_offset_or_inline
    return bytes(data) + name.encode("latin1")


def hive(cells):
    """cells: [(payload, allocated)] -> regf bytes with one hbin; returns (bytes, relative offsets)."""
    body = bytearray()
    offsets = []
    for payload, allocated in cells:
        size = (len(payload) + 4 + 7) & ~7
        offsets.append(32 + len(body))
        body += struct.pack("<i", -size if allocated else size) + payload + bytes(size - 4 - len(payload))
    bin_size = ((32 + len(body) + 4095) // 4096) * 4096
    hbin = bytearray(b"hbin" + bytes(28))
    struct.pack_into("<I", hbin, 8, bin_size)
    data = bytes(hbin) + body
    data += bytes(bin_size - len(data))
    header = bytearray(4096)
    header[:4] = b"regf"
    struct.pack_into("<II", header, 4, 1, 1)
    struct.pack_into("<I", header, 0x24, offsets[0])
    return bytes(header) + data, offsets


class RegistryDeletedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # Offsets are fixed by order: compute them with a first pass.
        _probe, offsets = hive([(nk("ROOT", 0), True), (nk("Software", 32), True), (nk("Gone", 0), False),
                                (nk("Software", 32, FT - 1), False), (b"\x00" * 16, True), (vk("Path", 1, 0, 0), False),
                                (vk("Count", 4, b"\x07\x00\x00\x00", 4, inline=True), False), (nk("x", 0), False)])
        software = offsets[1]
        data_cell = offsets[4]
        text = "C:\\Users\\alice\\tool.exe\x00".encode("utf-16-le")
        cells = [(nk("ROOT", offsets[0]), True), (nk("Software", offsets[0]), True), (nk("Gone", software), False),
                 (nk("Software", offsets[0], FT - 1), False), (text, True), (vk("Path", 1, data_cell, len(text)), False),
                 (vk("Count", 4, b"\x07\x00\x00\x00", 4, inline=True), False), (b"garbage-not-a-cell" * 3, False)]
        data, self.offsets = hive(cells)
        self.path = Path(self.temp.name) / "NTUSER.DAT"
        self.path.write_bytes(data)
        self.events = list(RegistryDeletedParser().parse(self.path))

    def tearDown(self):
        self.temp.cleanup()

    def by(self, action):
        return [e for e in self.events if e.action == action]

    def test_deleted_key_with_path_time_and_confidence(self):
        keys = {e.details["key_name"]: e for e in self.by("deleted_registry_key")}
        gone = keys["Gone"]
        self.assertEqual(gone.path, "Software\\Gone")
        self.assertEqual((gone.timestamp, gone.time_field), ("2020-12-30T00:00:00+00:00", "key_lastwrite"))
        self.assertEqual(gone.details["deleted_confidence"], "intact")
        self.assertEqual(gone.status, "partial")  # a candidate, never a confirmed record
        self.assertEqual(keys["Software"].details["deleted_confidence"], "old_copy")  # the live key still exists

    def test_deleted_values_and_preview(self):
        values = {e.details["value_name"]: e for e in self.by("deleted_registry_value")}
        self.assertEqual(values["Path"].details["value_preview"], "C:\\Users\\alice\\tool.exe")
        self.assertEqual(values["Count"].details["value_preview"], "7")
        self.assertEqual(values["Count"].details["deleted_confidence"], "value_only")
        self.assertIsNone(values["Path"].timestamp)  # a value cell has no time of its own

    def test_garbage_and_live_cells_are_not_reported(self):
        self.assertEqual(len(self.events), 4)
        self.assertFalse(any(e.details.get("key_name") == "ROOT" for e in self.events))

    def test_pipeline_tree_columns_properties(self):
        result = Pipeline().analyze([("registry_deleted", self.path)])
        self.assertEqual(len(result.events), 4)
        nodes = {n.key: n for r in build_tree(result.events) for n in r.walk()}
        node = nodes["art:deleted_records"]
        self.assertEqual(node.count, 4)
        self.assertEqual(columns.columns_for(node), columns.CATEGORY_COLUMNS["deleted_records"])
        gone = next(e for e in result.events if e.details.get("key_name") == "Gone")
        self.assertEqual(columns.cell("deleted_confidence", gone, {}, None), "구조 온전")
        self.assertEqual(dict(properties(gone).fields)["신뢰도"], "구조 온전")

    def test_truncated_or_foreign_files(self):
        broken = Path(self.temp.name) / "broken"
        broken.write_bytes(self.path.read_bytes()[:4096 + 40])
        self.assertEqual(list(RegistryDeletedParser().parse(broken)), [])
        other = Path(self.temp.name) / "other"
        other.write_bytes(b"\x00" * 8192)
        self.assertEqual(Pipeline().analyze([("registry_deleted", other)]).summaries[0]["state"], "failed")


if __name__ == "__main__":
    unittest.main()
