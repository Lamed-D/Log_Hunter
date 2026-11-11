# ▶ 원본: log_hunter/collector/eventlog_collector.py
# ▶ 이벤트 로그 내보내기 API로 별도 출력 파일을 만듭니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
from pathlib import Path
from .live_collector import register_evidence
from .winapi import NativeAPI


class EventLogCollector:
    def __init__(self, api=None):
        self.api = api or NativeAPI()

    def collect(self, source, destination):
        destination = Path(destination).resolve()
        if destination.exists():
            raise FileExistsError(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.api.export_eventlog(source, destination)
        return register_evidence(source, destination, "EvtExportLog")
