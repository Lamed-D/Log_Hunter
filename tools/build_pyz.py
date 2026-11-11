"""Build a portable standard-library zipapp from the package sources only."""
import argparse
import shutil
import tempfile
import zipapp
from pathlib import Path


def build(output, root=None):
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    output = Path(output).resolve()
    if output.is_relative_to((root / "log_hunter").resolve()):
        raise ValueError("빌드 출력은 패키지 소스 폴더 밖에 지정하세요")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="log-hunter-build-") as directory:
        staging = Path(directory)
        shutil.copytree(root / "log_hunter", staging / "log_hunter",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
        (staging / "__main__.py").write_text("from log_hunter.main import main\nraise SystemExit(main())\n", encoding="utf-8")
        zipapp.create_archive(staging, output, compressed=True, interpreter="/usr/bin/env python3")
    return output


def main():
    parser = argparse.ArgumentParser(description="Log Hunter 단일 Python 실행 파일 만들기")
    parser.add_argument("--output", default="dist/log-hunter.pyz")
    print(build(parser.parse_args().output))


if __name__ == "__main__":
    main()
