import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from log_hunter import launcher

ROOT = Path(__file__).resolve().parents[1]


class LauncherTests(unittest.TestCase):
    def test_batch_files_ascii_crlf_and_source_root(self):
        for name in ('run.bat', 'run-live.bat', 'test.bat'):
            with self.subTest(name=name):
                data = (ROOT / name).read_bytes()
                data.decode('ascii')
                self.assertIn(b'%~dp0', data)
                self.assertIn(b'exit /b %ERRORLEVEL%', data)
                self.assertIn(b'py -3', data)
                self.assertIn(b'\r\n', data)
                self.assertNotIn(b'\n', data.replace(b'\r\n', b''))
                self.assertNotIn(b':\\', data)

    def test_no_arguments_launches_gui_and_cli_preserves_arguments(self):
        with patch.object(launcher, '_gui_available', return_value=True), \
                patch('log_hunter.main.main', return_value=0) as app:
            self.assertEqual(launcher.main(['run']), 0)
            app.assert_called_once_with(['gui'])
        args = ['analyze', '--image', 'folder with spaces/disk.E01', '--output', 'relative result']
        with patch('log_hunter.main.main', return_value=7) as app:
            self.assertEqual(launcher.main(['run', *args]), 7)
            app.assert_called_once_with(args)

    def test_missing_tk_and_old_python_have_actionable_error(self):
        with patch.object(launcher, '_gui_available', return_value=False):
            self.assertEqual(launcher.main(['run']), 1)
        output = io.StringIO()
        with patch.object(launcher.sys, 'version_info', (3, 10)), contextlib.redirect_stderr(output):
            self.assertEqual(launcher.main(['run', '--help']), 1)
        self.assertIn('3.11', output.getvalue())

    def test_live_reuses_existing_uac_and_validates_drive(self):
        with patch.object(launcher, '_gui_available', return_value=True), \
                patch('log_hunter.image.live.is_admin', return_value=False), \
                patch('log_hunter.image.live.relaunch_as_admin', return_value=True) as elevate:
            self.assertEqual(launcher.main(['live', 'D:']), 0)
            elevate.assert_called_once_with(['-m', 'log_hunter.launcher', 'live', 'D:'])
        with patch.object(launcher, '_gui_available', return_value=True), \
                patch('log_hunter.image.live.is_admin', return_value=True), \
                patch('log_hunter.main.main', return_value=0) as app:
            self.assertEqual(launcher.main(['live', 'D']), 0)
            app.assert_called_once_with(['gui', '--live', 'D:'])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(launcher.main(['live', 'bad drive']), 1)

    def test_test_mode_uses_repo_and_dedicated_temp_without_recursion(self):
        with patch.object(launcher.subprocess, 'call', return_value=3) as run:
            self.assertEqual(launcher.main(['test']), 3)
        args, kwargs = run.call_args
        self.assertEqual(args[0][-4:], ['unittest', 'discover', '-s', 'tests'])
        self.assertEqual(kwargs['cwd'], ROOT)
        self.assertEqual(kwargs['env']['TEMP'], str(ROOT / 'outputs' / 'test-temp'))
        self.assertEqual(kwargs['env']['TMP'], kwargs['env']['TEMP'])

    def test_only_explorer_errors_pause(self):
        with patch.object(launcher, 'main', return_value=2), \
                patch.object(launcher, '_explorer_launch', return_value=False), \
                patch('builtins.input') as pause:
            self.assertEqual(launcher.entrypoint(), 2)
            pause.assert_not_called()
        with patch.object(launcher, 'main', return_value=2), \
                patch.object(launcher, '_explorer_launch', return_value=True), \
                patch('builtins.input') as pause:
            self.assertEqual(launcher.entrypoint(), 2)
            pause.assert_called_once()

    @unittest.skipUnless(os.name == 'nt', 'Windows batch launchers')
    def test_cmd_help_exit_status_and_caller_relative_paths(self):
        with tempfile.TemporaryDirectory(prefix='launcher space ') as directory:
            def run(arguments):
                return subprocess.run('cmd /d /s /c ""' + str(ROOT / 'run.bat') + '" ' + arguments + '"',
                                      cwd=directory, stdin=subprocess.DEVNULL, capture_output=True,
                                      timeout=30)
            self.assertEqual(run('--help').returncode, 0)
            self.assertEqual(run('analyze --help').returncode, 0)
            self.assertNotEqual(run('unknown-command').returncode, 0)
            source = Path(directory) / 'history with spaces.txt'
            source.write_text('Write-Output synthetic\n', encoding='utf-8')
            result = run('analyze --input psreadline "history with spaces.txt" --output "case with spaces"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(directory) / 'case with spaces' / 'report.json').is_file())
