"""Retired automatic technique mapping must not appear in engine output."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_example_samples import load_demo
from log_hunter.parser.userassist import UserAssistParser
from log_hunter.parser.mountpoints2 import read_volume_hints


class RemovedMappingTests(unittest.TestCase):
    def test_user_execution_output_has_no_technique_mapping(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "NTUSER.DAT"
            load_demo().make_ntuser(path)
            events = list(UserAssistParser().parse(path))
        self.assertTrue(events)
        for event in events:
            self.assertNotIn("mitre", event.details)

    def test_private_volume_hints_have_no_technique_mapping_or_share_records(self):
        children = [SimpleNamespace(name=name, lastwrite=0, values=lambda: [])
                    for name in ("{00000000-0000-1000-8000-00005e005301}",
                                 "##server.test#share")]
        root = SimpleNamespace(lastwrite=0, subkeys=lambda: children)
        with patch("log_hunter.parser.mountpoints2.Hive") as hive:
            hive.return_value.open.return_value = root
            hints, errors = read_volume_hints("generated")
        self.assertEqual(errors, [])
        self.assertEqual(len(hints), 1)
        self.assertNotIn("mitre", hints[0])
        self.assertNotIn("mac_address", hints[0])
        self.assertIn("uuid_node", hints[0])
