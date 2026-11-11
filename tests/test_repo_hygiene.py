"""Tracked files must not carry names, code or text from external reference tools."""
import re
import shutil
import subprocess
import unittest
import json
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Built from pieces so this file does not match itself.
FORBIDDEN = re.compile("|".join(["auto" + "psy", "sleuth" + r"\s?kit", "org" + r"\." + "sleuth" + "kit",
                                  "reg" + r"\s?ripper", r"\brr-" + "full", "nir" + "soft"]), re.IGNORECASE)
# .gitignore must name these folders to keep them out, so its contents are not checked.
CONTENT_EXEMPT = {".gitignore"}
OWNER = re.compile("la" + "med|pec" + "201177", re.I)
USER_PATH = re.compile(r"[cC]:\\+Users\\+([A-Za-z0-9_.-]+)")
USER_NAMES = {"alice", "bob", "analyst", "testuser", "public"}  # Public is a built-in shared directory.
SID_PATTERN = re.compile(r"S-1-5-21-\d+-\d+-\d+(?:-\d+)?", re.I)
IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EVIDENCE_SUFFIXES = {".e01", ".ex01", ".l01", ".dd", ".raw", ".img", ".001", ".vhd", ".vhdx",
                     ".vmdk", ".aff", ".mem", ".dmp", ".evtx", ".pf", ".lnk"}


def unsafe_identifiers(data):
    hits = set()
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        text = data.decode(encoding, errors="ignore")
        if OWNER.search(text):
            hits.add("owner identity")
        if any(m[1].lower() not in USER_NAMES and m[1] != "..." for m in USER_PATH.finditer(text)):
            hits.add("user path")
        for match in SID_PATTERN.finditer(text):
            if not match[0].upper().startswith(("S-1-5-21-" + "1000-2000-3000-", "S-1-5-21-" + "1-2-3-")):
                hits.add("SID")
        for match in IP_PATTERN.finditer(text):
            value = match[0]
            if all(int(part) < 256 for part in value.split('.')) and not value.startswith(
                    ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.")):
                hits.add("IP")
    return sorted(hits)


def tracked_files():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [name for name in out.decode("utf-8", errors="replace").split("\0") if name]


class RepoHygieneTests(unittest.TestCase):
    def test_only_synthetic_identities_in_tracked_content(self):
        hits = []
        for name in self.files:
            path = ROOT / name
            if path.is_file():
                found = unsafe_identifiers(path.read_bytes())
                if found:
                    hits.append((name, found))
        self.assertEqual(hits, [])

    def test_evidence_is_small_and_has_a_generator(self):
        manifest_path = ROOT / "example/samples/generated.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(manifest["synthetic"])
        self.assertTrue((ROOT / manifest["generator"]).is_file())
        total = 0
        for name in self.files:
            path = ROOT / name
            if not path.is_file():
                continue
            size = path.stat().st_size
            if name.startswith("example/"):
                total += size
                self.assertLessEqual(size, 10 * 1024 * 1024, name)
            with path.open("rb") as stream:
                header = stream.read(32)
            evidence = path.suffix.lower() in EVIDENCE_SUFFIXES or header.startswith(
                (b"regf", b"EVF", b"ElfFile", b"MAM", b"SQLite format 3", b'CMMM', b'IMMM')) or header[4:8] == b"SCCA"
            if evidence:
                self.assertTrue(name.startswith(("example/", "tests/fixtures/")), name)
                self.assertLessEqual(size, 10 * 1024 * 1024, name)
                if name.startswith("example/samples/"):
                    relative = name.removeprefix("example/samples/")
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), manifest["files"].get(relative), name)
                else:
                    self.fail(f"add a reproducible generator manifest for {name}")
        self.assertLessEqual(total, 50 * 1024 * 1024)

    def setUp(self):
        self.files = tracked_files()
        if self.files is None:
            self.skipTest("git 저장소가 아니거나 git이 없습니다")

    def test_paths_do_not_name_reference_tools(self):
        self.assertEqual([name for name in self.files if FORBIDDEN.search(name)], [])

    def test_contents_do_not_name_reference_tools(self):
        hits = []
        for name in self.files:
            path = ROOT / name
            if name in CONTENT_EXEMPT or not path.is_file():
                continue
            text = path.read_bytes().decode("utf-8", errors="ignore")
            for number, line in enumerate(text.splitlines(), 1):
                if FORBIDDEN.search(line):
                    hits.append(f"{name}:{number}")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
