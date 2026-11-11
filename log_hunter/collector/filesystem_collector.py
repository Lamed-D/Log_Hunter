from .live_collector import LiveCollector


class FilesystemCollector(LiveCollector):
    """File evidence collection. Raw-volume $MFT extraction is not implemented.

    Extracted offline $MFT files can be analyzed by MFTParser. Direct live access
    is attempted only when explicitly supplied and errors are propagated.
    """
