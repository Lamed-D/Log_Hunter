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
