"""Read scheduled-task registration observations without executing their payloads."""
import hashlib
import struct
import uuid
from pathlib import Path

from .base import ArtifactParser
from .registry import Hive, walk
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime

ROOT = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"


def task_path(value):
    if not isinstance(value, str):
        return None
    parts = value.replace("/", "\\").strip("\\").split("\\")
    if not parts or any(p in ("", ".", "..") for p in parts):
        return None
    return "\\" + "\\".join(parts)


def task_guid(value):
    try:
        parsed = uuid.UUID(str(value).strip("{}"))
        return "{" + str(parsed) + "}" if parsed.int else None
    except (ValueError, AttributeError):
        return None


def blob_info(data):
    if not isinstance(data, bytes):
        return None
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "hex_preview": data[:4096].hex(), "preview_truncated": len(data) > 4096}


def dynamic_info(data):
    result = {"raw": blob_info(data), "time_semantics_verified": False, "time_values": []}
    if not isinstance(data, bytes) or len(data) not in (28, 36):
        result["parse_state"] = "unsupported_length"
        return result
    version, = struct.unpack_from("<I", data)
    result.update(version=version, parse_state="decoded" if version == 3 else "unsupported_version")
    if version == 3:
        for offset in (4, 12) + ((28,) if len(data) == 36 else ()):
            value, = struct.unpack_from("<Q", data, offset)
            result["time_values"].append({"offset": offset, "raw_filetime": value,
                                          "decoded_utc": filetime(value), "meaning": None})
    return result


def actions_info(data):
    result = {"raw": blob_info(data), "actions": [], "parse_state": "unsupported"}
    if not isinstance(data, bytes) or len(data) < 2 or len(data) > 4 * 1024 * 1024:
        return result
    pos = 0

    def take(size):
        nonlocal pos
        if size < 0 or pos + size > len(data):
            raise ValueError("truncated action")
        value = data[pos:pos + size]
        pos += size
        return value

    def text():
        size, = struct.unpack("<I", take(4))
        if size > 1024 * 1024 or size % 2:
            raise ValueError("invalid action string length")
        return take(size).decode("utf-16-le").rstrip("\0")

    try:
        version, = struct.unpack("<H", take(2))
        result["version"] = version
        if version != 3:
            return result
        result["execution_context"] = text()  # Principal reference, not an account name.
        while pos < len(data):
            if len(result["actions"]) >= 256:
                raise ValueError("action count limit")
            kind, = struct.unpack("<H", take(2))
            action_id = text()
            if kind == 0x6666:
                action = {"type": "Exec", "id": action_id, "command": text(),
                          "arguments": text(), "working_directory": text()}
            elif kind == 0x7777:
                action = {"type": "ComHandler", "id": action_id,
                          "class_id": "{" + str(uuid.UUID(bytes_le=take(16))) + "}",
                          "data": text() if pos < len(data) else None}
            else:
                result.update(parse_state="unsupported_action", unsupported_tag=kind)
                return result
            result["actions"].append(action)
        result["parse_state"] = "decoded"
    except (ValueError, UnicodeError, struct.error) as exc:
        result.update(parse_state="damaged", error=str(exc))
    return result


def _values(key):
    return {v["name"].casefold(): v["value"] for v in key.values() if "error" not in v}


class TaskCacheParser(ArtifactParser):
    artifact = "taskcache"

    def parse(self, path):
        path = Path(path)
        try:
            hive = Hive(path, on_error=lambda off, exc: self.error(path, off, exc, "warning"))
            root = hive.open(ROOT)
        except KeyError:
            return
        except Exception as exc:
            self.error(path, "hive", exc)
            return
        trees, registrations, catalogs = {}, {}, {}
        for name in ("Tree", "Tasks", "Boot", "Logon", "Plain", "Maintenance"):
            try:
                parent = hive.open(ROOT + "\\" + name)
            except KeyError:
                continue
            try:
                entries = walk(parent) if name == "Tree" else ((k.name, k) for k in parent.subkeys())
                for relative, key in entries:
                    try:
                        values = _values(key)
                        guid = task_guid(values.get("id") if name == "Tree" else key.name)
                        if name == "Tree" and relative and "id" in values:
                            identity = guid or "invalid-tree:" + relative
                            trees.setdefault(identity, []).append((task_path(relative), key, values))
                        elif name == "Tasks" and guid:
                            registrations[guid] = (key, values)
                        elif guid:
                            catalogs.setdefault(guid, []).append(name)
                    except Exception as exc:
                        self.error(path, ROOT + "\\" + name + "\\" + relative, exc, "warning")
            except Exception as exc:
                self.error(path, ROOT + "\\" + name, exc, "warning")
        for guid in sorted(set(trees) | set(registrations) | set(catalogs), key=str):
            key, values = registrations.get(guid, (None, {}))
            tree_entries = trees.get(guid, [])
            names = [entry[0] for entry in tree_entries]
            registered_path = task_path(values.get("path"))
            namespace = registered_path or (names[0] if len(names) == 1 else None)
            consistent = bool(task_guid(guid) and registered_path and len(names) == 1 and
                              names[0] and names[0].casefold() == registered_path.casefold())
            signals = []
            if not consistent:
                signals.append({"code": "registry_identity_incomplete", "reason": "Tree Id and Tasks Path are not a unique consistent mapping"})
            sd_missing = any("sd" not in entry[2] for entry in tree_entries)
            if sd_missing:
                signals.append({"code": "security_descriptor_absent", "reason": "Tree SD was not observed; review registration visibility"})
            actions = actions_info(values.get("actions"))
            if isinstance(values.get("actions"), bytes) and actions["parse_state"] != "decoded":
                signals.append({"code": "actions_not_decoded", "reason": actions["parse_state"]})
                self.error(path, ROOT + "\\Tasks\\" + str(guid) + "\\Actions",
                           actions.get("error", actions["parse_state"]), "warning")
            for action in actions["actions"]:
                if action["type"] == "ComHandler":
                    try:
                        dll = hive.open("Classes\\CLSID\\" + action["class_id"] + "\\InprocServer32").value("")
                        action["com_handler_dll"] = dll if isinstance(dll, str) else None
                    except (KeyError, ValueError, OSError) as exc:
                        action["com_handler_dll"] = None
                        if not isinstance(exc, KeyError):
                            self.error(path, "Classes\\CLSID\\" + action["class_id"], exc, "warning")
                    dll = action["com_handler_dll"]
                    if dll and not dll.casefold().startswith(("%systemroot%\\", "%windir%\\", "c:\\windows\\")):
                        signals.append({"code": "com_dll_outside_system_path", "reason": "Recorded DLL does not use a recognized Windows path", "evidence": dll})
            first_action = next(iter(actions["actions"]), {})
            details = {"task_name": namespace.rsplit("\\", 1)[-1] if namespace else None,
                       "task_path": namespace, "task_guid": task_guid(guid), "identity_consistent": consistent,
                       "command": first_action.get("command"), "arguments": first_action.get("arguments"),
                       "com_handler_uuid": first_action.get("class_id"),
                       "com_handler_dll": first_action.get("com_handler_dll"), "run_user": None,
                       "launch_catalogs": catalogs.get(guid, []), "task_signals": signals,
                       "hidden_indicator": sd_missing if tree_entries else None, "execution_confirmed": False,
                       "registration_time": None, "last_run_time": None, "last_completed_time": None,
                       "time_semantics_verified": False,
                       "registry_details": {"path": values.get("path"), "tree": [
                           {"path": n, "id": v.get("id"), "index": v.get("index"), "sd": blob_info(v.get("sd")),
                            "key_last_write": filetime(k.lastwrite) if k.lastwrite else None}
                           for n, k, v in tree_entries], "dynamic_info": dynamic_info(values.get("dynamicinfo")),
                           "key_last_write": filetime(key.lastwrite) if key and key.lastwrite else None,
                           "hash": blob_info(values.get("hash")), "triggers": blob_info(values.get("triggers")),
                           "actions": actions}}
            stamp = filetime(key.lastwrite) if key and key.lastwrite else None
            locator = (ROOT + "\\Tasks\\" + str(guid) if key else
                       ROOT + "\\Tree" + str(namespace) if tree_entries else
                       ROOT + "\\" + catalogs[guid][0] + "\\" + str(guid))
            yield ForensicEvent(self.artifact, str(path), "task_registration", stamp,
                                "key_last_write" if stamp else None, self.sid, path=namespace,
                                process=" ".join(str(first_action.get(k) or "") for k in ("command", "arguments")).strip() or None,
                                locator=locator,
                                status="warning" if signals else "ok", details=details)
