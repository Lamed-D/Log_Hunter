"""Read Windows inventory metadata from installed software, system and account hives."""
from datetime import datetime, timezone
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from .base import ArtifactParser
from .registry import Hive, current_controlset


REGISTRY_UNINSTALL = r"Microsoft\Windows\CurrentVersion\Uninstall"
OS_VERSION_KEY = r"Microsoft\Windows NT\CurrentVersion"
ACCOUNT_NAMES_KEY = r"SAM\Domains\Account\Users\Names"
PROFILE_LIST_KEY = OS_VERSION_KEY + r"\ProfileList"
SYSTEM_NAME_SUFFIX = r"\Control\ComputerName\ComputerName"


def _key(hive, path):
    try:
        return hive.open(path)
    except KeyError:
        return None


def _values(key, fields):
    if key is None:
        return {}
    return {fields[v["name"].casefold()]: v["value"] for v in key.values()
            if "error" not in v and v["name"].casefold() in fields
            and isinstance(v["value"], (str, int))}


def _epoch(value):
    if not isinstance(value, int) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


class InstalledProgramsParser(ArtifactParser):
    artifact = "windows_installed"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        fields = {"displayname": "display_name", "displayversion": "version",
                  "publisher": "publisher", "installdate": "install_date_raw",
                  "installlocation": "install_location", "systemcomponent": "system_component"}
        for key_path, view in ((REGISTRY_UNINSTALL, "default"), ("Wow6432Node\\" + REGISTRY_UNINSTALL, "wow64")):
            root = _key(hive, key_path)
            if root is None:
                continue
            for entry in root.subkeys():
                values = _values(entry, fields)
                locator = key_path + "\\" + entry.name
                program = values.get("display_name")
                yield ForensicEvent(self.artifact, str(path), "installed_registration", filetime(entry.lastwrite),
                                    "key_lastwrite", self.sid, process=program if isinstance(program, str) else None,
                                    locator=locator, status="ok" if program else "partial",
                                    details={**values, "registration_id": entry.name, "registry_view": view,
                                             "source_locator": locator, "time_basis": "key_lastwrite"})


class OSInfoParser(ArtifactParser):
    artifact = "windows_os"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        version = _values(_key(hive, OS_VERSION_KEY), {
            "productname": "product_name", "editionid": "edition", "displayversion": "version",
            "currentbuild": "build", "currentbuildnumber": "build_number", "ubr": "build_revision",
            "installationtype": "installation_type", "installdate": "install_date_epoch",
            "installtime": "install_time_filetime"})
        if version:
            raw = version.get("install_time_filetime")
            precise = filetime(raw) if isinstance(raw, int) else None
            epoch = _epoch(version.get("install_date_epoch"))
            yield ForensicEvent(self.artifact, str(path), "windows_system_info", precise or epoch,
                                "os_installation" if precise or epoch else None, self.sid,
                                locator=OS_VERSION_KEY,
                                details={**version, "source_locator": OS_VERSION_KEY,
                                         "install_time_utc": precise, "install_date_utc": epoch,
                                         "time_basis": "FILETIME" if precise else "Unix epoch" if epoch else None})
        try:
            control_set = current_controlset(hive)
        except (KeyError, ValueError):
            return
        name_key = control_set + SYSTEM_NAME_SUFFIX
        zone_key = control_set + r"\Control\TimeZoneInformation"
        name = _values(_key(hive, name_key), {"computername": "computer_name"})
        zone = _values(_key(hive, zone_key), {"timezonekeyname": "time_zone_name"})
        if name or zone:
            locator = name_key if name else zone_key
            yield ForensicEvent(self.artifact, str(path), "windows_system_settings", sid=self.sid,
                                locator=locator, details={**name, **zone, "source_locator": locator,
                                                         "time_zone_locator": zone_key if zone else None})


class LocalAccountsParser(ArtifactParser):
    artifact = "windows_accounts"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        names = _key(hive, ACCOUNT_NAMES_KEY)
        if names is not None:
            for node in names.subkeys():
                # The default value on a name mapping uses its registry type as the account RID.
                rid = next((v["type"] for v in node.values() if v.get("name") == ""
                            and not v.get("error") and v["type"] > 0), None)
                locator = ACCOUNT_NAMES_KEY + "\\" + node.name
                yield ForensicEvent(self.artifact, str(path), "local_account_name", sid=self.sid,
                                    locator=locator, details={"account_name": node.name, "account_rid": rid,
                                                             "source_locator": locator})
        profiles = _key(hive, PROFILE_LIST_KEY)
        if profiles is not None:
            for node in profiles.subkeys():
                if not node.name.startswith("S-1-5-"):
                    continue
                locator = PROFILE_LIST_KEY + "\\" + node.name
                details = _values(node, {"profileimagepath": "profile_path"})
                yield ForensicEvent(self.artifact, str(path), "account_profile", sid=node.name,
                                    locator=locator, details={**details, "source_locator": locator})


def combine_os_records(events):
    """Join the two original SYSTEM/SOFTWARE facts only when the files share a config folder."""
    settings = {Path(e.source).resolve().parent: e for e in events
                if e.artifact == "windows_os" and e.action == "windows_system_settings"
                and Path(e.source).name.casefold() == "system"}
    merged = set()
    for event in events:
        if event.artifact != "windows_os" or event.action != "windows_system_info":
            continue
        path = Path(event.source)
        companion = settings.get(path.resolve().parent) if path.name.casefold() == "software" else None
        if companion is not None:
            additions = {key: companion.details[key] for key in ("computer_name", "time_zone_name", "time_zone_locator")
                         if key in companion.details}
            event.details.update(additions, system_settings_source=companion.source,
                                 system_settings_locator=companion.locator)
            merged.add(id(companion))
    return [event for event in events if id(event) not in merged]
