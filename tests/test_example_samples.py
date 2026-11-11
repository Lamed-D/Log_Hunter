"""Only script-generated, reproducible synthetic sample data may be published."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_demo():
    spec = importlib.util.spec_from_file_location('synthetic_demo', ROOT / 'example/samples/demo.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_bytes(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for folder in ('evidence', 'output') for path in (root / folder).rglob('*') if path.is_file()}


class SyntheticSampleTests(unittest.TestCase):
    def test_generation_is_independent_of_working_directory_and_reproducible(self):
        demo = load_demo()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    demo.main(root / 'first')
                    demo.main(root / 'second')
            finally:
                os.chdir(old_cwd)
            first = sample_bytes(root / 'first')
            self.assertEqual(first, sample_bytes(root / 'second'))
            self.assertEqual(first, sample_bytes(ROOT / 'example/samples'))
            for data in first.values():
                for encoding in ('utf-8', 'utf-16-le', 'utf-16-be'):
                    self.assertNotIn(str(root), data.decode(encoding, errors='ignore'))
