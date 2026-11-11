from .base import ArtifactParser
from .registry import Hive
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.normalization import split_windows_command, expand_environment_path


class RunParser(ArtifactParser):
    artifact = "run"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        # Both input types, and both registry views. Source identity is retained.
        for base in (r"Microsoft\Windows\CurrentVersion", r"Wow6432Node\Microsoft\Windows\CurrentVersion",
                     r"Software\Microsoft\Windows\CurrentVersion", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion"):
            for kind in ("Run", "RunOnce"):
                locator = base + "\\" + kind
                try:
                    key = hive.open(locator)
                except KeyError:
                    self.error(path, locator, "키 없음", "info")
                    continue
                values = list(key.values())
                if not values:
                    self.error(path, locator, "빈 키", "info")
                for value in values:
                    if value["type"] not in (1, 2) or not isinstance(value["value"], str):
                        self.error(path, locator + "\\" + value["name"], value.get("error", "문자열 유형이 아닙니다"))
                        continue
                    command = value["value"]
                    expanded = expand_environment_path(command, self.environment)
                    split = split_windows_command(expanded)
                    yield ForensicEvent(self.artifact, str(path), "autorun_registration", filetime(key.lastwrite),
                                        "key_lastwrite", self.sid, path=split["executable"],
                                        locator=locator + "\\" + value["name"], status="warning" if split["ambiguous"] else "ok",
                                        details={**split, "command": command, "expanded_command": expanded,
                                                 "name": value["name"], "raw": value["raw"].hex(), "type": value["type"],
                                                 "view": "32" if "Wow6432Node" in base else "native",
                                                 "scope": "user" if base.startswith("Software") else "machine",
                                                 "run_type": kind, "execution_confirmed": False,
                                                 "defer_deletion": kind == "RunOnce" and "!" in value["name"][:2],
                                                 "safe_mode": kind == "RunOnce" and "*" in value["name"][:2]})
