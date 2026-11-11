"""Bounded registry graph traversal and corrupt sibling lookup regressions."""
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from log_hunter.parser.registry import Hive, walk
from test_auto_detect import hive_bytes


class RegistryGuardTests(unittest.TestCase):
    def test_shared_child_is_walked_once(self):
        leaf = SimpleNamespace(offset=3, name="leaf", subkeys=lambda: [])
        child = SimpleNamespace(offset=2, name="child", subkeys=lambda: [leaf, leaf])
        root = SimpleNamespace(offset=1, name="root", subkeys=lambda: [child, child])
        self.assertEqual(len(list(walk(root))), 3)

    def test_lookup_skips_corrupt_sibling(self):
        data = bytearray(hive_bytes(("Broken", "Run")))
        root = struct.unpack_from("<I", data, 0x24)[0]
        listing = struct.unpack_from("<I", data, 4096 + root + 4 + 28)[0]
        broken = struct.unpack_from("<I", data, 4096 + listing + 8)[0]
        data[4096 + broken + 4:4096 + broken + 6] = b"xx"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "hive")
            path.write_bytes(data)
            errors = []
            hive = Hive(path, on_error=lambda offset, error: errors.append((offset, error)))
            self.assertEqual(hive.open("Run").name, "Run")
            self.assertEqual(len(errors), 1)
            hive.open("Run")
            self.assertEqual(len(errors), 1)
