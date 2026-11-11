# ▶ 원본: log_hunter/collector/live_collector.py
# ▶ 읽기 전용 수집 결과에 SHA-256과 방법·시점 일관성 메타데이터를 붙입니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from log_hunter.core.models import Evidence
from .winapi import NativeAPI


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def register_evidence(source, destination, method, metadata=None):
    return Evidence(str(source), str(destination), sha256(destination), method,
                    datetime.now(timezone.utc).isoformat(), metadata or {})


def write_manifest(evidence, path):
    Path(path).write_text(json.dumps([asdict(item) for item in evidence], ensure_ascii=False, indent=2), encoding="utf-8")


class LiveCollector:
    def __init__(self, vss=None, api=None):
        self.api = api or NativeAPI()
        self.vss = vss

    def collect(self, source, destination):
        source, destination = Path(source).resolve(), Path(destination).resolve()
        if source == destination or destination.exists():
            raise FileExistsError("수집 대상은 원본과 다른 새 파일이어야 합니다")
        destination.parent.mkdir(parents=True, exist_ok=True)
        method, metadata = "SHARED_READ", {"point_in_time_consistent": False}
        try:
            self.api.copy_shared(source, destination)
        except OSError as exc:
            if getattr(exc, "winerror", None) not in (5, 32, 33):
                raise
            self.api.copy_from_volume(source, destination)
            from log_hunter.image.live import LIVE_WARNING
            method = "DIRECT_VOLUME"
            metadata = {"point_in_time_consistent": False, "warning": LIVE_WARNING}
        return register_evidence(source, destination, method, metadata)
