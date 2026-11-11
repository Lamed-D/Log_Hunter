"""Network profile and interface parser from SYSTEM and SOFTWARE hives.

Extracts network connection history from:
  - SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles
  - SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures
  - SYSTEM\\ControlSetXXX\\Services\\Tcpip\\Parameters\\Interfaces
"""
import struct
from datetime import datetime
from .base import ArtifactParser
from .registry import Hive, current_controlset
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime


NETWORK_CATEGORIES = {0: "Public", 1: "Private", 2: "Domain"}


def _parse_network_time(raw):
    if len(raw) < 16:
        return None
    year, month, dow, day, hour, minute, second, ms = struct.unpack_from("<HHHHHHHH", raw)
    if year < 1970 or year > 2100:
        return None
    try:
        return datetime(year, month, day, hour, minute, second, ms * 1000).isoformat(timespec="milliseconds")
    except ValueError:
        return None


class NetworkProfileParser(ArtifactParser):
    artifact = "network"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        header = hive.data[:4]
        if header != b"regf":
            return

        yield from self._parse_profiles(hive, path)
        yield from self._parse_signatures(hive, path)
        yield from self._parse_interfaces(hive, path)

    def _parse_profiles(self, hive, path):
        base = r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        try:
            root = hive.open(base)
        except KeyError:
            return
        for profile in root.subkeys():
            details = {"profile_guid": profile.name}
            for v in profile.values():
                if v.get("error"):
                    continue
                name = v["name"]
                if name == "ProfileName":
                    details["profile_name"] = v.get("value", "")
                elif name == "Description":
                    details["description"] = v.get("value", "")
                elif name == "Category":
                    cat = v.get("value", -1)
                    details["category"] = NETWORK_CATEGORIES.get(cat, f"Unknown({cat})")
                    details["category_raw"] = cat
                elif name == "NameType":
                    details["name_type"] = v.get("value")
                elif name == "Managed":
                    details["managed"] = bool(v.get("value"))
                elif name == "DateCreated" and v["type"] == 3:
                    ts = _parse_network_time(v["raw"])
                    if ts:
                        details["date_created"] = ts
                elif name == "DateLastConnected" and v["type"] == 3:
                    ts = _parse_network_time(v["raw"])
                    if ts:
                        details["date_last_connected"] = ts
            action = "network_profile"
            # SYSTEMTIME stores no offset; the analyst's timezone is not evidence.
            details["timezone_known"] = False
            yield ForensicEvent(
                self.artifact, str(path), action, None, None,
                locator=base + "\\" + profile.name,
                details=details)

    def _parse_signatures(self, hive, path):
        for sig_type in ("Managed", "Unmanaged"):
            base = rf"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\{sig_type}"
            try:
                root = hive.open(base)
            except KeyError:
                continue
            for sig in root.subkeys():
                details = {"signature_type": sig_type, "signature_key": sig.name}
                for v in sig.values():
                    if v.get("error"):
                        continue
                    name = v["name"]
                    if name == "ProfileGuid":
                        details["profile_guid"] = v.get("value", "")
                    elif name == "Description":
                        details["description"] = v.get("value", "")
                    elif name == "Source":
                        details["source"] = v.get("value")
                    elif name == "DnsSuffix":
                        details["dns_suffix"] = v.get("value", "")
                    elif name == "FirstNetwork":
                        details["first_network"] = v.get("value", "")
                    elif name == "DefaultGatewayMac" and v["type"] == 3:
                        raw = v["raw"]
                        if len(raw) >= 6:
                            details["gateway_mac"] = ":".join(f"{b:02x}" for b in raw[:6])
                yield ForensicEvent(
                    self.artifact, str(path), "network_signature",
                    filetime(sig.lastwrite), "key_lastwrite",
                    locator=base + "\\" + sig.name,
                    details=details)

    def _parse_interfaces(self, hive, path):
        try:
            control = current_controlset(hive)
        except (KeyError, ValueError):
            return
        base = control + r"\Services\Tcpip\Parameters\Interfaces"
        try:
            root = hive.open(base)
        except KeyError:
            return
        for iface in root.subkeys():
            details = {"interface_guid": iface.name}
            for v in iface.values():
                if v.get("error"):
                    continue
                name = v["name"]
                if name in ("DhcpIPAddress", "IPAddress", "DhcpSubnetMask", "SubnetMask",
                            "DhcpDefaultGateway", "DefaultGateway", "DhcpServer",
                            "DhcpNameServer", "NameServer", "Domain"):
                    val = v.get("value", "")
                    if isinstance(val, str) and val.strip():
                        details[name.lower()] = val
                elif name == "EnableDHCP":
                    details["dhcp_enabled"] = bool(v.get("value"))
                elif name == "LeaseObtainedTime" and v["type"] == 4:
                    details["lease_obtained"] = v.get("value")
                elif name == "LeaseTerminatesTime" and v["type"] == 4:
                    details["lease_terminates"] = v.get("value")
            if len(details) > 1:
                yield ForensicEvent(
                    self.artifact, str(path), "network_interface",
                    filetime(iface.lastwrite), "key_lastwrite",
                    locator=base + "\\" + iface.name,
                    details=details)
