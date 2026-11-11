import codecs
import re
import struct
from .base import ArtifactParser
from .registry import Hive
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime

# Known folder GUIDs (KNOWNFOLDERID) mapped to the default path in Microsoft's
# KNOWNFOLDERID reference; virtual folders map to their display name.
# Architecture-dependent folders (SystemX86, ProgramFilesX86, ProgramFilesCommonX86)
# and GUIDs outside that reference stay unresolved.
KNOWN_GUIDS = {
    "{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}": "Get Programs",
    "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "{A305CE99-F527-492B-8B1A-7E76FA98D6E4}": "Installed Updates",
    "{9E52AB10-F80D-49DF-ACB8-4330F5687855}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn",
    "{DF7266AC-9274-4867-8D55-3BD661DE872D}": "Programs and Features",
    "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}": "%ProgramData%\\OEM Links",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A4115719-D62E-491D-AA7C-E74B8BE3B067}": "%ProgramData%\\Microsoft\\Windows\\Start Menu",
    "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "{0AC0837C-BBF8-452A-850D-79D08E667CA7}": "Computer",
    "{82A74AEB-AEB4-465C-A014-D097EE346D63}": "Control Panel",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%USERPROFILE%\\Desktop",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%USERPROFILE%\\Documents",
    "{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms",
    "{374DE290-123F-4565-9164-39C4925E467B}": "%USERPROFILE%\\Downloads",
    "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}": "%APPDATA%\\Microsoft\\Windows\\Libraries",
    "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "%LOCALAPPDATA%",
    "{A520A1A4-1780-4FF6-BD18-167343C5AF16}": "%USERPROFILE%\\AppData\\LocalLow",
    "{4BD8D571-6D19-48D3-BE97-422220080E43}": "%USERPROFILE%\\Music",
    "{2112AB0A-C86A-4FFE-A368-0DE96E47012E}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms",
    "{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}": "Network",
    "{33E28130-4E1E-4676-835A-98395C3BC3BB}": "%USERPROFILE%\\Pictures",
    "{A990AE9F-A03B-4E80-94BC-9912D7504104}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms",
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "%USERPROFILE%",
    "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "%ProgramData%",
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "%ProgramFiles%",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
    "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": "%ProgramFiles%\\Common Files",
    "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": "%ProgramFiles%\\Common Files",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{DFDF76A2-C82A-4D63-906A-5644AC457385}": "%PUBLIC%",
    "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "%PUBLIC%\\Desktop",
    "{ED4824AF-DCE4-45A8-81E2-FC7965083634}": "%PUBLIC%\\Documents",
    "{3D644C9B-1FB8-4F30-9B45-F670235F79C0}": "%PUBLIC%\\Downloads",
    "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": "%PUBLIC%\\Music",
    "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": "%PUBLIC%\\Pictures",
    "{2400183A-6185-49FB-A2D8-4A392A602BA3}": "%PUBLIC%\\Videos",
    "{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch",
    "{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}": "Recycle Bin",
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "%APPDATA%",
    "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": "%APPDATA%\\Microsoft\\Windows\\Start Menu",
    "{B97D20BB-F46A-4C97-BA10-5E3608430854}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%windir%\\system32",
    "{0762D272-C50A-4BB0-A382-697DCD729B80}": "%SystemDrive%\\Users",
    "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}": "%LOCALAPPDATA%\\Programs",
    "{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}": "%LOCALAPPDATA%\\Programs\\Common",
    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "%USERPROFILE%\\Videos",
    "{491E922F-5643-4AF4-A7EB-4E7A138D8174}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%windir%",
}
_GUID_RE = re.compile(r"\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}")


def decode_rot13(value):
    return codecs.decode(value, "rot_13")


def resolve_guid_path(path):
    def _replace(m):
        guid = m.group(0).upper()
        return KNOWN_GUIDS.get(guid, guid)
    return _GUID_RE.sub(_replace, path)


def parse_userassist_value(data):
    if len(data) == 72:
        count, focus, duration = struct.unpack_from("<III", data, 4)
        time, = struct.unpack_from("<Q", data, 60)
        return {"run_count": count, "focus_count": focus, "focus_time_ms": duration,
                "last_execution": filetime(time), "raw_filetime": time, "version": "72-byte"}
    if len(data) == 16:
        count, = struct.unpack_from("<I", data, 4)
        time, = struct.unpack_from("<Q", data, 8)
        return {"run_count_raw": count, "run_count": max(0, count - 5),
                "last_execution": filetime(time), "raw_filetime": time, "version": "16-byte legacy"}
    raise ValueError(f"지원하지 않는 UserAssist 길이: {len(data)}")


class UserAssistParser(ArtifactParser):
    artifact = "userassist"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        root = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        try:
            groups = hive.open(root)
        except KeyError:
            self.error(path, root, "키 없음", "info")
            return

        nolog = False
        try:
            settings = hive.open(root + "\\Settings")
            for val in settings.values():
                if val["name"] == "NoLog":
                    nolog_val = val.get("value")
                    if nolog_val == 1 or val.get("raw", b"") == b"\x01\x00\x00\x00":
                        nolog = True
                        self.error(path, root + "\\Settings\\NoLog",
                                   "Settings\\NoLog=1: XP에서 새 항목 기록 비활성화됨", "warning")
        except KeyError:
            pass

        for group in groups.subkeys():
            locator = root + "\\" + group.name + "\\Count"
            try:
                key = hive.open(locator)
            except KeyError:
                continue
            for value in key.values():
                try:
                    if value["type"] != 3:
                        raise ValueError("REG_BINARY가 아닙니다")
                    result = parse_userassist_value(value["raw"])
                    raw_name = decode_rot13(value["name"])
                    name = resolve_guid_path(raw_name)
                    details = {**result, "encoded_name": value["name"],
                               "raw_path": raw_name if raw_name != name else None,
                               "raw": value["raw"].hex()}
                    if nolog:
                        details["nolog_enabled"] = True
                    yield ForensicEvent(self.artifact, str(path), "execution_trace", result["last_execution"],
                                        "last_execution", self.sid, path=name, locator=locator + "\\" + value["name"],
                                        details=details)
                except (ValueError, struct.error) as exc:
                    self.error(path, locator + "\\" + value["name"], exc)
