from log_hunter.core.models import ParserError


class ArtifactParser:
    artifact = "unknown"

    def __init__(self, sid=None, environment=None):
        self.sid = sid
        self.environment = environment or {}
        self.errors = []

    def error(self, source, locator, message, severity="error"):
        self.errors.append(ParserError(str(source), self.artifact, str(locator), str(message), severity))
