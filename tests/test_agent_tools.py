"""Agent workspace tools: confidential-term checker, hook files and setup script."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfidentialCheckTests(unittest.TestCase):
    def setUp(self):
        self.check = load("check_confidential")

    def test_terms_file_comments_and_case(self):
        with tempfile.TemporaryDirectory() as folder:
            terms = Path(folder) / ".confidential-terms"
            terms.write_text("# comment\n\nSecretWord\n  other term  \n", encoding="utf-8")
            self.check.TERMS_FILE = terms
            self.assertEqual(self.check.load_terms(), ["secretword", "other term"])

    def test_missing_terms_file_skips(self):
        self.check.TERMS_FILE = ROOT / "does-not-exist" / ".confidential-terms"
        self.assertEqual(self.check.load_terms(), [])

    def test_hits_do_not_echo_the_whole_term(self):
        hits = self.check.find_hits("line one\nhas SECRETWORD here", ["secretword"], "x")
        self.assertEqual(len(hits), 1)
        self.assertIn("x:2", hits[0])
        self.assertNotIn("secretword", hits[0].lower().replace("se…", ""))

    def test_only_added_lines_are_checked(self):
        diff = "+++ b/file\n+added line\n-removed secret\n context"
        self.assertEqual(self.check.added_lines(diff), "added line")


class HookFileTests(unittest.TestCase):
    def test_hooks_exist_with_lf_endings(self):
        for name in ("pre-commit", "commit-msg", "pre-push"):
            data = (ROOT / "tools" / "hooks" / name).read_bytes()
            self.assertTrue(data.startswith(b"#!/bin/sh"), name)
            self.assertNotIn(b"\r\n", data, name)


class SetupAgentTests(unittest.TestCase):
    def setUp(self):
        self.setup = load("setup_agent")

    def test_agent_names(self):
        for good in ("claude1", "codex1", "claude12"):
            self.assertTrue(self.setup.NAME_RE.match(good), good)
        for bad in ("claude", "codex0", "gpt1", "claude1x"):
            self.assertFalse(self.setup.NAME_RE.match(bad), bad)

    def test_shared_labels_cover_agent_protocol(self):
        names = {label for label, _color, _desc in self.setup.SHARED_LABELS}
        self.assertEqual(names, {"to:user", "agent:question", "agent:request", "agent:blocker", "agent:info"})


if __name__ == "__main__":
    unittest.main()
