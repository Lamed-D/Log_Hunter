# ▶ 원본: log_hunter/parser/startup.py
# ▶ 시작프로그램 파일과 LNK를 읽습니다. 입력 사본 mtime은 대상 시스템의 이력 시각과 구별합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Windows Startup folder persistence detection parser."""
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent

SUSPICIOUS_PATTERNS = [
    re.compile(rb"(?i)-enc(?:odedcommand)?\s"),
    re.compile(rb"(?i)powershell\s.*-e\s"),
    re.compile(rb"(?i)frombase64string"),
    re.compile(rb"(?i)invoke-expression|iex\s"),
    re.compile(rb"(?i)downloadstring|downloadfile|webclient"),
    re.compile(rb"(?i)\\temp\\|\\tmp\\|%temp%"),
    re.compile(rb"(?i)hidden|windowstyle\s+hidden"),
]

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".vbs", ".ps1", ".js", ".wsf", ".hta"}
EXECUTABLE_EXTENSIONS = SCRIPT_EXTENSIONS | {".exe", ".com", ".scr", ".pif"}


def _check_suspicious(file_path, ext):
    indicators = []
    if ext in SCRIPT_EXTENSIONS:
        try:
            data = Path(file_path).read_bytes()[:8192]
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(data):
                    indicators.append(pattern.pattern.decode("utf-8", errors="replace"))
        except OSError:
            pass
    try:
        attrs = os.stat(file_path).st_file_attributes
        if attrs & 0x2:  # FILE_ATTRIBUTE_HIDDEN
            indicators.append("hidden_attribute")
    except (OSError, AttributeError):
        pass
    return indicators


class StartupParser(ArtifactParser):
    artifact = "startup"

    def parse(self, path):
        source = Path(path)
        if source.is_file():
            files = [source]
        else:
            files = sorted(f for f in source.rglob("*") if f.is_file())

        for file in files:
            ext = file.suffix.lower()
            if ext not in EXECUTABLE_EXTENSIONS and ext != ".lnk":
                continue

            try:
                stat = file.stat()
            except OSError as exc:
                self.error(file, "stat", exc)
                continue

            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

            details = {
                "filename": file.name,
                "extension": ext,
                "size_bytes": stat.st_size,
                "is_lnk": ext == ".lnk",
                "input_file_mtime": mtime.isoformat(),
            }

            if ext == ".lnk":
                try:
                    from log_hunter.parser.lnk import parse_lnk
                    lnk_data = file.read_bytes()
                    lnk_info = parse_lnk(lnk_data)
                    if lnk_info:
                        details["target_path"] = lnk_info.get("target_path")
                        details["arguments"] = lnk_info.get("arguments")
                        details["working_dir"] = lnk_info.get("working_dir")
                except (OSError, ValueError, IndexError, struct.error) as exc:
                    self.error(file, "lnk", exc, "warning")

            indicators = _check_suspicious(file, ext)
            action = "startup_entry"
            status = "ok"
            if indicators:
                action = "suspicious_startup"
                status = "warning"
                details["indicators"] = indicators
                details["risk_level"] = "high"

            yield ForensicEvent(
                self.artifact, str(file), action,
                None, None,
                sid=self.sid,
                path=str(file),
                locator=str(file),
                status=status,
                details=details,
            )
