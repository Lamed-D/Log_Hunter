"""Private user-volume hints and conservative UUID node interpretation for USB context."""
import re
import uuid
from .registry import Hive
from log_hunter.core.models import ParserError
from log_hunter.core.timestamp import filetime
from log_hunter.core.labels import UUID_NODE_LABELS

def uuid_node_info(guid_str):
    """Classify a UUID node without asserting that an adapter existed."""
    result = {"node_raw": None, "mac_candidate": None,
              "mac_is_hardware_confirmed": False}
    try:
        value = uuid.UUID(guid_str)
    except (ValueError, AttributeError, TypeError):
        kind = "invalid_uuid"
    else:
        if value.version != 1 or value.variant != uuid.RFC_4122:
            kind = "not_v1"
        else:
            node = value.node
            result["node_raw"] = f"{node:012X}"
            if node == 0x806e6f6e6963:
                kind = "no_adapter_placeholder"
            elif node == 0:
                kind = "zero_node"
            elif (node >> 40) & 1:
                kind = "random_node"
            else:
                kind = "mac_candidate"
                raw = result["node_raw"]
                result["mac_candidate"] = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    result["node_kind"] = kind
    result["node_description"] = UUID_NODE_LABELS[kind]
    return result


def extract_mac_from_uuid_v1(guid_str):
    """Return only unicast, non-placeholder v1 node address candidates."""
    return uuid_node_info(guid_str)["mac_candidate"]


def read_volume_hints(path, sid=None, source=None):
    """Read private USB volume hints, including the UUID node interpretation."""
    original = source or str(path)
    errors = []

    def on_error(offset, exc):
        errors.append(ParserError(original, "usb", str(offset), str(exc), "warning"))

    hive = Hive(path, on_error=on_error)
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    try:
        root = hive.open(base)
    except KeyError:
        return [], errors
    hints = []
    for subkey in root.subkeys():
        if not subkey.name.startswith("{"):
            continue  # Share names and drive letters are not published as records or hints.
        label = None
        for value in subkey.values():
            if value["name"] == "_LabelFromReg" and value.get("value"):
                label = value["value"]
                break
        hints.append({"source": original, "sid": sid, "locator": base + "\\" + subkey.name,
                      "key_lastwrite": filetime(subkey.lastwrite), "volume_guid": subkey.name,
                      "label": label, "uuid_node": uuid_node_info(subkey.name)})
    return hints, errors


def attach_volume_hints(events, hints):
    """Attach recorded volume GUID matches; drive letters alone are ambiguous."""
    for event in events:
        if event.artifact != "usb" or not event.details.get("is_storage_device"):
            continue
        matches = event.details.get("mounted_device_matches", [])
        guids = set()
        for match in matches:
            for text in [match.get("raw_text", ""), *match.get("volume_guids", [])]:
                guids.update(re.findall(r"\{[0-9a-fA-F-]{36}\}", text or ""))
        guids = {guid.casefold() for guid in guids}
        context = [dict(hint, match_basis="volume_guid_match") for hint in hints
                   if hint["volume_guid"].casefold() in guids]
        if context:
            event.details["mountpoint_context"] = context
