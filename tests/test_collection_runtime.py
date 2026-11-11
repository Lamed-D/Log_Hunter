"""Collection fallback, grouping and privilege cleanup without reading live evidence."""
import ctypes
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from log_hunter.collector.live_collector import LiveCollector
from log_hunter.collector.browser_collector import BrowserCollector
from log_hunter.collector.windows import NativeAPI, TOKEN_PRIVILEGES


class CollectionTests(unittest.TestCase):
    def test_platform_guard(self):
        with patch("log_hunter.collector.windows.os.name", "posix"):
            with self.assertRaisesRegex(OSError, "Windows"):
                NativeAPI()

    def test_shared_failure_uses_volume_and_does_not_claim_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory, "source"), Path(directory, "target")
            source.write_bytes(b"synthetic")
            error = OSError("sharing violation")
            error.winerror = 32
            api = Mock()
            api.copy_shared.side_effect = error
            api.copy_from_volume.side_effect = lambda src, dst: dst.write_bytes(src.read_bytes())
            result = LiveCollector(api=api).collect(source, target)
            self.assertEqual(result.method, "DIRECT_VOLUME")
            self.assertFalse(result.metadata["point_in_time_consistent"])
            self.assertEqual(source.read_bytes(), target.read_bytes())

    def test_missing_file_does_not_trigger_volume_access(self):
        api = Mock()
        api.copy_shared.side_effect = FileNotFoundError("missing")
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(FileNotFoundError):
            LiveCollector(api=api).collect(Path(directory, "missing"), Path(directory, "out"))
        api.copy_from_volume.assert_not_called()

    def test_browser_group_uses_single_api_call_and_marks_live_state(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory, "History"), Path(directory, "collected")
            source.write_bytes(b"synthetic database")
            def copy_group(src, dst):
                result = []
                for suffix in ("", "-wal", "-shm"):
                    output = dst / (src.name + suffix)
                    output.write_bytes(b"synthetic" + suffix.encode())
                    result.append((suffix, output))
                return result
            api = Mock()
            api.copy_browser.side_effect = copy_group
            rows = BrowserCollector(api=api).collect(source, target)
            self.assertEqual(len(rows), 3)
            api.copy_browser.assert_called_once()
            self.assertTrue(all(not row.metadata["point_in_time_consistent"] for row in rows))
            with self.assertRaises(FileExistsError):
                BrowserCollector(api=api).collect(source, target)

    @unittest.skipUnless(os.name == "nt", "Windows privilege cleanup")
    def test_registry_failure_closes_handles_and_restores_privilege(self):
        api = NativeAPI()
        closed, adjusted = [], []
        def adjust(token, disable, desired, size, previous, returned):
            adjusted.append(ctypes.cast(desired, ctypes.POINTER(TOKEN_PRIVILEGES)).contents.attributes)
            if previous is not None:
                old = ctypes.cast(previous, ctypes.POINTER(TOKEN_PRIVILEGES)).contents
                old.count, old.attributes = 1, 0
            ctypes.set_last_error(0)
            return 1
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(api, "open_token", return_value=1), patch.object(api, "lookup_privilege", return_value=1), \
                 patch.object(api, "adjust_privilege", side_effect=adjust), patch.object(api, "open_key", return_value=0), \
                 patch.object(api, "save_key", return_value=5), patch.object(api, "close_key") as close_key, \
                 patch.object(api, "close_handle", side_effect=lambda handle: closed.append(handle)):
                with self.assertRaises(OSError):
                    api.save_registry(0xFFFFFFFF80000002, "SYNTHETIC", Path(directory, "out"))
            self.assertEqual(adjusted, [2, 0])
            self.assertEqual(len(closed), 1)
            close_key.assert_called_once()

    @unittest.skipUnless(os.name == "nt", "Windows API failure cleanup")
    def test_read_failure_removes_only_new_output_and_closes_source(self):
        api = NativeAPI()
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory, "source"), Path(directory, "target")
            source.write_bytes(b"synthetic")
            with patch.object(api, "read_file", return_value=0), \
                 patch.object(api, "close_handle", wraps=api.close_handle) as close:
                with self.assertRaises(OSError):
                    api.copy_shared(source, target)
                close.assert_called_once()
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(), b"synthetic")
