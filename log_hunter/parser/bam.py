import re
import struct
from pathlib import Path
from .base import ArtifactParser
from .registry import Hive, current_controlset
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime


def parse_bam_binary(data):
    if len(data) < 8:
        raise ValueError("BAM FILETIME에 8바이트가 필요합니다")
    return filetime(struct.unpack_from("<Q", data)[0])


_NT_DEVICE_RE = re.compile(r"\\Device\\HarddiskVolume(\d+)\\(.*)", re.IGNORECASE)


def _nt_to_dos_path(nt_path, volume_map=None):
    """Best-effort NT device path to DOS path conversion.

    volume_map overrides the default {1: "C:\\"}. Returns the original
    path unchanged when no mapping applies.
    """
    if volume_map is None:
        volume_map = {1: "C:\\", 2: "D:\\"}
    m = _NT_DEVICE_RE.match(nt_path)
    if m:
        vol = int(m.group(1))
        rest = m.group(2)
        drive = volume_map.get(vol)
        if drive:
            return drive + rest
    return nt_path


def load_profile_list(software_hive_path):
    """Load SID -> username mapping from a SOFTWARE hive's ProfileList."""
    try:
        hive = Hive(software_hive_path)
    except (ValueError, OSError):
        return {}
    if hive.data[:4] != b"regf":
        return {}
    profiles = {}
    try:
        root = hive.open(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
    except KeyError:
        return {}
    for key in root.subkeys():
        sid = key.name
        if not sid.startswith("S-1-5-"):
            continue
        for v in key.values():
            if v.get("error"):
                continue
            if v["name"] == "ProfileImagePath":
                profile_path = v.get("value", "")
                if isinstance(profile_path, str) and profile_path:
                    username = profile_path.rstrip("\\").rsplit("\\", 1)[-1]
                    profiles[sid] = username
                break
    return profiles


class BAMParser(ArtifactParser):
    artifact = "bam"

    def parse(self, path, profiles=None):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        control = current_controlset(hive)
        if profiles is None:
            profiles = {}
        for suffix in (r"Services\bam\UserSettings", r"Services\bam\State\UserSettings"):
            locator = control + "\\" + suffix
            try:
                root = hive.open(locator)
            except KeyError:
                self.error(path, locator, "키 없음", "info")
                continue
            for key in root.subkeys():
                sid = key.name
                username = profiles.get(sid)
                for value in key.values():
                    name = value["name"]
                    if name in ("SequenceNumber", "Version"):
                        self.error(path, locator + "\\" + name, "관리용 값 제외", "excluded")
                        continue
                    try:
                        if value["type"] != 3:
                            raise ValueError("REG_BINARY가 아닙니다")
                        timestamp = parse_bam_binary(value["raw"])
                        dos_path = _nt_to_dos_path(name)
                        details = {"raw": value["raw"].hex(), "type": value["type"],
                                   "controlset": control, "key_lastwrite": filetime(key.lastwrite),
                                   "execution_start_confirmed": False}
                        if dos_path != name:
                            details["dos_path"] = dos_path
                        if username:
                            details["username"] = username
                        yield ForensicEvent(self.artifact, str(path), "activity_update", timestamp,
                                            "activity_update", sid, path=name,
                                            locator=locator + "\\" + sid + "\\" + name,
                                            status="ok" if timestamp else "warning",
                                            details=details)
                    except (ValueError, struct.error) as exc:
                        self.error(path, locator + "\\" + sid + "\\" + name, exc)
