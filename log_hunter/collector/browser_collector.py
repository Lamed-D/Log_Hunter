from pathlib import Path
from .live_collector import register_evidence
from .winapi import NativeAPI


def find_browser_profiles(user_profile):
    local = Path(user_profile) / "AppData/Local"
    for browser, relative in (("chrome", "Google/Chrome/User Data"), ("edge", "Microsoft/Edge/User Data")):
        root = local / relative
        if root.is_dir():
            for profile in sorted(root.iterdir()):
                if profile.is_dir() and (profile / "History").exists():
                    yield browser, profile


class BrowserCollector:
    def __init__(self, vss=None, api=None):
        self.api = api or (vss.api if vss is not None else NativeAPI())

    def collect(self, source, destination):
        # One volume session reads the database and sidecars without promising a snapshot.
        source, destination = Path(source).resolve(), Path(destination).resolve()
        destination.mkdir(parents=True, exist_ok=False)
        from log_hunter.image.live import LIVE_WARNING
        evidence = []
        for suffix, target in self.api.copy_browser(source, destination):
            evidence.append(register_evidence(str(source) + suffix, target, "DIRECT_VOLUME",
                            {"point_in_time_consistent": False, "warning": LIVE_WARNING}))
        return evidence
