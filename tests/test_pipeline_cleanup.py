"""The pipeline must not leave copies of evidence behind in TEMP."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _dirty_hive():
    """Minimal hive whose sequence numbers differ, so the pipeline tries LOG recovery."""
    from test_analysis import build_hive
    data = bytearray(build_hive([]))
    struct.pack_into("<II", data, 4, 2, 1)
    return bytes(data)


class PipelineRecoveryTests(unittest.TestCase):
    def test_recovered_hive_copies_are_removed(self):
        from unittest import mock
        from log_hunter.core.models import ForensicEvent
        from log_hunter.core.pipeline import Pipeline

        class EchoParser:
            def __init__(self, sid=None, environment=None):
                self.errors = []

            def error(self, *_args, **_kwargs):
                pass

            def parse(self, path):
                self.seen = Path(path)
                assert self.seen.exists()
                return [ForensicEvent("run", str(path), "registration")]

        with tempfile.TemporaryDirectory() as temp:
            hive = Path(temp) / "SOFTWARE"
            hive.write_bytes(_dirty_hive())
            created = []
            real_mkdtemp = tempfile.mkdtemp

            def tracking_mkdtemp(*args, **kwargs):
                created.append(Path(real_mkdtemp(*args, **kwargs)))
                return str(created[-1])

            with mock.patch.dict("log_hunter.core.pipeline.PARSERS", {"run": EchoParser}),                     mock.patch("log_hunter.core.pipeline.replay_logs", return_value=(hive.read_bytes(), {"recovered": True})),                     mock.patch("tempfile.mkdtemp", tracking_mkdtemp):
                result = Pipeline().analyze([("run", str(hive))])
            self.assertEqual([e.source for e in result.events], [str(hive)])
            self.assertTrue(created)
            self.assertEqual([p for p in created if p.exists()], [])


if __name__ == "__main__":
    unittest.main()
