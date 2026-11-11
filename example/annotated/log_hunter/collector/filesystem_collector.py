# ▶ 원본: log_hunter/collector/filesystem_collector.py
# ▶ 수집 가능한 일반 파일을 원본과 다른 목적지로 복사합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
from .live_collector import LiveCollector


class FilesystemCollector(LiveCollector):
    """File evidence collection. Raw-volume $MFT extraction is not implemented.

    Extracted offline $MFT files can be analyzed by MFTParser. Direct live access
    is attempted only when explicitly supplied and errors are propagated.
    """
