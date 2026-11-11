"""Every relative link and image in the README and docs must point at a file that exists."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_SRC = re.compile(r"""(?:src|href)=["']([^"']+)["']""")


def markdown_files():
    files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    return [f for f in files if f.is_file() and "reviews" not in f.relative_to(ROOT).parts]


def relative_targets(path):
    text = path.read_text(encoding="utf-8")
    for target in LINK.findall(text) + HTML_SRC.findall(text):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE) or target.startswith("#"):
            continue  # external URL, mailto:, or in-page anchor
        yield target.split("#", 1)[0]


class DocsLinkTests(unittest.TestCase):
    def test_relative_links_and_images_exist(self):
        missing = []
        for doc in markdown_files():
            for target in relative_targets(doc):
                if target and not (doc.parent / target).exists():
                    missing.append(f"{doc.relative_to(ROOT)} -> {target}")
        self.assertEqual(missing, [])

    def test_images_are_small(self):
        images = list((ROOT / "docs" / "images").glob("*")) if (ROOT / "docs" / "images").exists() else []
        self.assertEqual([p.name for p in images if p.stat().st_size > 500 * 1024], [])


if __name__ == "__main__":
    unittest.main()
