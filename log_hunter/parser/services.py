"""Windows services persistence parser.

Parses SYSTEM hive ControlSet\\Services for service persistence analysis.
"""
import re
import ntpath
from pathlib import Path
from .base import ArtifactParser
from .registry import Hive
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.normalization import split_windows_command

SERVICE_TYPES = {
    0x1: "KERNEL_DRIVER", 0x2: "FILE_SYSTEM_DRIVER",
    0x10: "WIN32_OWN_PROCESS", 0x20: "WIN32_SHARE_PROCESS",
    0x110: "WIN32_OWN_PROCESS_INTERACTIVE",
}

START_TYPES = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}

SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"(?i)\\temp\\"), re.compile(r"(?i)\\tmp\\"),
    re.compile(r"(?i)\\appdata\\"), re.compile(r"(?i)\\users\\public\\"),
    re.compile(r"(?i)\\downloads\\"), re.compile(r"(?i)cmd\.exe\s*/c"),
    re.compile(r"(?i)powershell"), re.compile(r"(?i)-enc(odedcommand)?"),
    re.compile(r"(?i)mshta|wscript|cscript|regsvr32"),
]


def _check_service_suspicious(image_path, display_name, start_type):
    indicators = []
    if image_path:
        for pat in SUSPICIOUS_PATH_PATTERNS:
            if pat.search(image_path):
                indicators.append(f"suspicious_path:{pat.pattern}")
                break
    if display_name and len(display_name) == 1:
        indicators.append("single_char_display_name")
    if start_type in (0, 1, 2) and image_path and not _in_system_dirs(image_path):
        indicators.append("auto_start_outside_system_dirs")
    return indicators


def _in_system_dirs(image_path):
    """Classify only the executable component without using analyst environment values."""
    executable = split_windows_command(image_path)["executable"]
    if not executable:
        return False
    path = executable.lower()
    if path.startswith("\\??\\"):
        path = path[4:]
    path = ntpath.normpath(path)
    return path.startswith(("\\systemroot\\", "system32\\", "c:\\windows\\", "c:\\program files\\",
                            "c:\\program files (x86)\\", "%systemroot%\\", "%windir%\\",
                            "%programfiles%\\", "%programfiles(x86)%\\"))


class ServicesParser(ArtifactParser):
    artifact = "services"

    def parse(self, path):
        path = Path(path)
        try:
            hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        except Exception as exc:
            self.error(path, "hive", exc)
            return

        for cs_name in ("ControlSet001", "ControlSet002"):
            try:
                services_key = hive.open(f"{cs_name}\\Services")
            except KeyError:
                continue

            for svc_key in services_key.subkeys():
                svc_name = svc_key.name
                values = {}
                for val_name in ("ImagePath", "DisplayName", "Start", "Type", "ObjectName"):
                    try:
                        values[val_name] = svc_key.value(val_name)
                    except (KeyError, ValueError):
                        pass

                image_path = values.get("ImagePath", "")
                if isinstance(image_path, bytes):
                    image_path = image_path.decode("utf-16-le", errors="replace").rstrip("\x00")
                display_name = values.get("DisplayName", "")
                if isinstance(display_name, bytes):
                    display_name = display_name.decode("utf-16-le", errors="replace").rstrip("\x00")

                start_val = values.get("Start")
                start_type = start_val if isinstance(start_val, int) else None
                type_val = values.get("Type")
                svc_type = type_val if isinstance(type_val, int) else None

                details = {
                    "service_name": svc_name,
                    "control_set": cs_name,
                }
                if image_path:
                    details["image_path"] = image_path
                if display_name:
                    details["display_name"] = display_name
                if start_type is not None:
                    details["start_type"] = START_TYPES.get(start_type, str(start_type))
                if svc_type is not None:
                    details["service_type"] = SERVICE_TYPES.get(svc_type, str(svc_type))

                obj_name = values.get("ObjectName")
                if obj_name:
                    if isinstance(obj_name, bytes):
                        obj_name = obj_name.decode("utf-16-le", errors="replace").rstrip("\x00")
                    details["account"] = obj_name

                indicators = _check_service_suspicious(image_path, display_name, start_type)
                action = "service_entry"
                status = "ok"
                if indicators:
                    action = "suspicious_service"
                    status = "warning"
                    details["indicators"] = indicators
                    details["risk_level"] = "high"

                timestamp = None
                try:
                    timestamp = filetime(svc_key.lastwrite) if svc_key.lastwrite else None
                except Exception:
                    pass

                yield ForensicEvent(
                    self.artifact, str(path), action,
                    timestamp, "key_last_write" if timestamp else None,
                    sid=self.sid,
                    path=image_path or str(path),
                    locator=f"{cs_name}\\Services\\{svc_name}",
                    status=status,
                    details=details,
                )
