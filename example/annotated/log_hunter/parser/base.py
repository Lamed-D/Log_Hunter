# ▶ 원본: log_hunter/parser/base.py
# ▶ 파서의 sid·environment와 오류 수집 공통 인터페이스입니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
from log_hunter.core.models import ParserError


class ArtifactParser:
    artifact = "unknown"

    def __init__(self, sid=None, environment=None):
        self.sid = sid
        self.environment = environment or {}
        self.errors = []

    def error(self, source, locator, message, severity="error"):
        self.errors.append(ParserError(str(source), self.artifact, str(locator), str(message), severity))
