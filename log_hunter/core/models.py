from dataclasses import asdict, dataclass, field
from typing import Protocol, Iterable


@dataclass
class Evidence:
    source: str
    collected: str
    sha256: str
    method: str = "OFFLINE"
    collected_at: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ForensicEvent:
    artifact: str
    source: str
    action: str
    timestamp: str | None = None
    time_field: str | None = None
    sid: str | None = None
    path: str | None = None
    process: str | None = None
    url: str | None = None
    locator: str | None = None
    status: str = "ok"
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class ParserError:
    source: str
    artifact: str
    locator: str
    message: str
    severity: str = "error"


class Parser(Protocol):
    def parse(self, path: str) -> Iterable[ForensicEvent]: ...


class Collector(Protocol):
    def collect(self, source: str, destination: str) -> Evidence: ...
