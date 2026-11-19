"""Synthetic registry inventory through the image and direct input paths."""
import struct
import tempfile
import unittest
from pathlib import Path

from fixtures.synthetic_windows_case import put, registry_bytes, text
from log_hunter.core.auto_detect import detect_inputs
from log_hunter.core.pipeline import Pipeline
from log_hunter.parser.windows_inventory import (
    ACCOUNT_NAMES_KEY, OS_VERSION_KEY, PROFILE_LIST_KEY, REGISTRY_UNINSTALL,
)
from test_image import NTFSBuilder


class WindowsInventoryTests(unittest.TestCase):
    def test_image_records_program_os_and_account_metadata(self):
        software, system, sam = {}, {}, {}
        put(software, REGISTRY_UNINSTALL + r'\Example-1', [text('DisplayName', 'Example App')])
        put(software, 'Wow6432Node\\' + REGISTRY_UNINSTALL + r'\Example-1',
            [text('DisplayVersion', '1.0')])
        put(software, OS_VERSION_KEY, [text('ProductName', 'Synthetic Windows'),
                                       ('InstallDate', 4, struct.pack('<I', 1704067200))])
        sid = 'S-1-5-21-1000-2000-3000-1001'
        put(software, PROFILE_LIST_KEY + '\\' + sid, [text('ProfileImagePath', r'C:\Users\alice')])
        put(system, 'Select', [('Current', 4, struct.pack('<I', 1))])
        put(system, r'ControlSet001\Control\ComputerName\ComputerName',
            [text('ComputerName', 'DESKTOP-TEST01')])
        put(sam, ACCOUNT_NAMES_KEY + r'\alice', [('', 1001, b'')])
        ntfs = NTFSBuilder()
        folder = ntfs.makedirs('Windows/System32/config')
        for name, tree in (('SOFTWARE', software), ('SYSTEM', system), ('SAM', sam)):
            ntfs.add_file(folder, name, registry_bytes(tree, name))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / 'synthetic.dd'
            image.write_bytes(ntfs.build())
            result = Pipeline().analyze_image(image, root / 'work')
            sam_copy = next(Path(item.source) for item in result.evidence if Path(item.source).name == 'SAM')
            self.assertEqual([row[0] for row in detect_inputs([sam_copy])], ['windows_accounts', 'registry_deleted'])
        programs = [e for e in result.events if e.artifact == 'windows_installed']
        self.assertEqual(len(programs), 2)
        self.assertEqual({e.details['registry_view'] for e in programs}, {'default', 'wow64'})
        config, = [e for e in result.events if e.artifact == 'windows_os']
        self.assertEqual(config.timestamp, '2024-01-01T00:00:00+00:00')
        self.assertEqual(config.details['computer_name'], 'DESKTOP-TEST01')
        self.assertTrue(config.details['system_settings_locator'].endswith('ComputerName'))
        account, = [e for e in result.events if e.action == 'local_account_name']
        self.assertEqual(account.details['account_rid'], 1001)
        profile, = [e for e in result.events if e.action == 'account_profile']
        self.assertEqual(profile.sid, sid)
