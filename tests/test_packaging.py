"""Execute a built zipapp outside the source directory with synthetic evidence."""
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

from tools.build_pyz import build


class PackagingTests(unittest.TestCase):
    def test_entrypoint_and_zipapp_analysis(self):
        root = Path(__file__).resolve().parents[1]
        config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8-sig"))
        self.assertEqual(config["project"]["dependencies"], [])
        self.assertEqual(config["project"]["scripts"]["log-hunter"], "log_hunter.main:main")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            app = build(directory / "log-hunter.pyz", root)
            with zipfile.ZipFile(app) as archive:
                names = archive.namelist()
                self.assertIn("log_hunter/parser/xpress.py", names)
                self.assertFalse(any("__pycache__" in name or name.startswith("tests/") for name in names))
            source = directory / "ConsoleHost_history.txt"
            source.write_text("Get-Date\n", encoding="utf-8")
            environment = dict(os.environ, PYTHONPATH="")
            run = subprocess.run([sys.executable, str(app), "analyze", "--input", "psreadline", str(source),
                                  "--output", str(directory / "result")], cwd=directory,
                                 capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["events"], 1)
            self.assertTrue((directory / "result" / "report.json").is_file())
            help_run = subprocess.run([sys.executable, str(app), "collect", "--help"], cwd=directory,
                                      capture_output=True, text=True, env=environment, timeout=10)
            self.assertEqual(help_run.returncode, 0, help_run.stderr)
            self.assertNotIn("--dll", help_run.stdout)
            broken = directory / "broken.pf"
            broken.write_bytes(b"bad")
            failure = subprocess.run([sys.executable, str(app), "analyze", "--input", "prefetch", str(broken),
                                      "--output", str(directory / "failed")], cwd=directory,
                                     capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(failure.returncode, 1, failure.stdout + failure.stderr)
            self.assertEqual(json.loads(failure.stdout)["errors"], 1)
