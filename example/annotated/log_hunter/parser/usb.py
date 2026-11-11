# Teaching copy: runtime tokens are verified by tools/check_annotated.py.
import re
import struct
from .base import ArtifactParser
from .registry import Hive, current_controlset, walk
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from .usb_devices import classify_device
from log_hunter.core.labels import USB_DEVICE_KINDS, USB_UNKNOWN_REASON_LABELS


def _match_mounted_device(mounted_values, device_name, serial):
    matches = []
    volumes = {}
    for entry in mounted_values:
        if re.fullmatch(r"\\\?\?\\Volume\{[0-9a-fA-F-]{36}\}", entry.get("name", "")):
            volumes.setdefault(entry.get("raw", b""), []).append(entry["name"])
    for entry in mounted_values:
        name = entry.get("name", "")
        raw = entry.get("raw", b"")
        if not name.startswith("\\DosDevices\\") or len(raw) < 12:
            continue
        drive_letter = name.replace("\\DosDevices\\", "")
        try:
            text = raw.decode("utf-16-le").rstrip("\0")
        except (UnicodeDecodeError, ValueError):
            text = raw.hex()
        if serial and serial.lower() in text.lower():
            matches.append({"drive_letter": drive_letter, "match_type": "serial", "raw_text": text,
                            "volume_guids": volumes.get(raw, [])})
        elif device_name and device_name.lower() in text.lower():
            matches.append({"drive_letter": drive_letter, "match_type": "device_name", "raw_text": text,
                            "volume_guids": volumes.get(raw, [])})
    return matches


class USBParser(ArtifactParser):
    artifact = "usb"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        try:
            control = current_controlset(hive)
        except KeyError:
            # SOFTWARE supplies recorded portable-device names, not USB arrival times.
            base = r'Microsoft\Windows Portable Devices\Devices'
            try:
                root = hive.open(base)
            except KeyError:
                return
            for device in root.subkeys():
                values = {v['name'].lower(): v.get('value') for v in device.values()
                          if not v.get('error') and isinstance(v.get('value'), (str, int))}
                details = {**values, 'device': device.name, 'bus': 'Windows Portable Devices',
                           'device_kind': 'portable', 'device_kind_name': USB_DEVICE_KINDS['portable'],
                           'is_storage_device': False, 'currently_connected': None,
                           'classification_confidence': 'recorded_identifier',
                           'device_classification_basis': [{'kind':'portable', 'basis':'registry_location', 'identifier':base}],
                           'physical_observation': False, 'unknown_reasons': ['metadata_only'],
                           'unknown_reason_labels': [USB_UNKNOWN_REASON_LABELS['metadata_only']]}
                yield ForensicEvent(self.artifact, str(path), 'device_registration', filetime(device.lastwrite),
                                    'key_lastwrite', locator=base+'\\'+device.name, details=details)
            return
        mounted_raw = []
        try:
            for v in hive.open("MountedDevices").values():
                if not v.get("error"):
                    mounted_raw.append(v)
        except KeyError:
            pass

        friendly_names = {}
        try:
            portable = hive.open(control + "\\Enum\\SWD\\WPDBUSENUM")
            for child in portable.subkeys():
                for val in child.values():
                    if val["name"] == "FriendlyName" and val.get("value"):
                        friendly_names[child.name] = val["value"]
        except (KeyError, ValueError):
            pass

        yield from self._bluetooth_peers(hive, control, path)

        for bus in ("USB", "USBSTOR", "HID", "BTHENUM", r"SWD\WPDBUSENUM"):
            base = control + "\\Enum\\" + bus
            try:
                root = hive.open(base)
            except KeyError:
                continue
            for device in root.subkeys():
                instances = list(device.subkeys())
                if bus == r'SWD\WPDBUSENUM' and not instances:
                    instances = [device]
                for instance in instances:
                    if instance.name in ("Properties", "Device Parameters", "Control", "LogConf"):
                        continue
                    locator = base + "\\" + device.name + ("\\" + instance.name if instance is not device else '')
                    serial = instance.name.rsplit('&', 1)[0] if bus == 'USBSTOR' else instance.name
                    identity = {"device": device.name, "serial_raw": instance.name, "serial": serial,
                                "bus": bus, "currently_connected": None,
                                "serial_is_hardware_confirmed": False,
                                "serial_may_be_generated": '&' in serial}
                    match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", device.name, re.I)
                    if match:
                        identity.update(vid=match[1], pid=match[2])
                    if bus == "USBSTOR":
                        parts = device.name.split("&")
                        if len(parts) >= 3:
                            identity["device_type"] = parts[0].replace("Disk&Ven_", "").replace("_", " ").strip()
                            identity["vendor"] = parts[1].replace("Ven_", "").replace("_", " ").strip()
                            identity["product"] = parts[2].replace("Prod_", "").replace("_", " ").strip()
                            if len(parts) >= 4:
                                identity["revision"] = parts[3].replace("Rev_", "").strip()

                    friendly = friendly_names.get(instance.name)
                    if friendly:
                        identity["friendly_name"] = friendly

                    for val in instance.values():
                        if val.get("error"):
                            continue
                        if val["name"] in ("DeviceDesc", "FriendlyName", "Mfg", "Service", "Driver", "Class", "ClassGUID", "HardwareID", "CompatibleIDs", "LocationInformation", "ParentIdPrefix", "Parent", "ContainerID", "ConfigFlags"):
                            value = val.get('value')
                            if val['type'] == 7:
                                try:
                                    value = [part for part in val['raw'].decode('utf-16-le').split('\0') if part]
                                except UnicodeDecodeError:
                                    self.error(path, locator, '장치 식별 문자열 인코딩 손상', 'warning')
                                    value = []
                                    identity[val['name'].lower() + '_raw_hex'] = val['raw'].hex()
                            elif isinstance(value, bytes) or value is None:
                                value = val['raw'].hex()
                            identity[val['name'].lower()] = value

                    identity.update(classify_device(bus, identity))
                    identity['device_kind_name'] = USB_DEVICE_KINDS[identity['device_kind']]
                    reasons = []
                    if not any(identity.get(k) for k in ('friendlyname', 'friendly_name', 'devicedesc')):
                        reasons.append('description_missing')
                    if identity['device_kind'] == 'unknown':
                        if identity['classification_conflict']:
                            reasons.append('classification_conflict')
                        elif not any(identity.get(k) for k in ('hardwareid', 'compatibleids', 'class', 'classguid')):
                            reasons.append('classification_missing')
                        else:
                            reasons.append('identifier_unsupported')
                    identity['unknown_reasons'] = reasons
                    identity['unknown_reason_labels'] = [USB_UNKNOWN_REASON_LABELS[r] for r in reasons]
                    mi = re.search(r'&MI_([0-9A-F]{2})', device.name, re.I)
                    if mi:
                        identity['interface_number'] = mi[1].upper()
                        identity['composite_parent_device'] = re.sub(r'&MI_[0-9A-F]{2}', '', device.name, flags=re.I)
                        # VID/PID alone cannot distinguish two physical receivers.
                        identity['composite_group'] = identity.get('containerid')
                        identity['composite_group_basis'] = 'container_id' if identity.get('containerid') else 'unknown'
                    driver = identity.get('driver', '')
                    if isinstance(driver, str) and re.fullmatch(r'\{[0-9A-Fa-f-]{36}\}\\[0-9]{4}', driver):
                        try:
                            driver_key = hive.open(control + '\\Control\\Class\\' + driver)
                            for value in driver_key.values():
                                if not value.get('error') and value['name'] in ('ProviderName', 'DriverVersion', 'DriverDate'):
                                    identity['driver_' + value['name'].lower()] = value.get('value')
                        except (KeyError, ValueError):
                            self.error(path, locator, '드라이버 메타데이터를 읽을 수 없음', 'warning')
                    try:
                        params = hive.open(locator + r'\Device Parameters')
                        identity['device_parameters'] = {v['name']: v.get('value') if v.get('value') is not None and not isinstance(v.get('value'), bytes) else v.get('raw', b'').hex()
                                                         for v in params.values() if not v.get('error')}
                    except KeyError:
                        pass
                    if identity['is_storage_device']:
                        drives = _match_mounted_device(mounted_raw, device.name, serial)
                        if drives:
                            identity['drive_letters'] = [d['drive_letter'] for d in drives]
                            identity['mounted_device_matches'] = drives

                    yield ForensicEvent(self.artifact, str(path), "device_registration", filetime(instance.lastwrite),
                                        "key_lastwrite", locator=locator, details=identity)
                    prop = locator + r"\Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
                    try:
                        properties = hive.open(prop)
                    except KeyError:
                        continue
                    labels = {"0064": "install", "0065": "first_install", "0066": "last_arrival", "0067": "last_removal"}
                    for key in properties.subkeys():
                        if key.name not in labels:
                            continue
                        for subpath, leaf in walk(key):
                            for value in leaf.values():
                                if value.get('error') or value['type'] != 3 or len(value['raw']) != 8:
                                    self.error(path, prop, '장치 속성 FILETIME 크기 또는 형식 손상', 'warning')
                                    continue
                                if value["type"] == 3 and len(value["raw"]) == 8:
                                    timestamp = filetime(struct.unpack("<Q", value["raw"])[0])
                                    if timestamp is None:
                                        self.error(path, prop, '유효하지 않은 장치 속성 FILETIME', 'warning')
                                        continue
                                    yield ForensicEvent(self.artifact, str(path), labels[key.name], timestamp,
                                                        labels[key.name], locator=prop + "\\" + key.name + subpath,
                                                        details={**identity, "raw": value["raw"].hex()})

    def _bluetooth_peers(self, hive, control, path):
        """Read recorded Bluetooth peers; key/seen/connected times keep their own meanings."""
        base = control + r"\services\BTHPORT\Parameters\Devices"
        try:
            root = hive.open(base)
        except KeyError:
            return
        for peer in root.subkeys():
            if not re.fullmatch(r"[0-9a-fA-F]{12}", peer.name) or int(peer.name, 16) == 0:
                self.error(path, base + "\\" + peer.name, "블루투스 장치 주소 형식 오류", "warning")
                continue
            values = {value["name"].casefold(): value for value in peer.values() if not value.get("error")}
            identity = {"bus": "BTHPORT", "device": peer.name, "serial_raw": peer.name,
                        "serial_is_hardware_confirmed": False, "currently_connected": None,
                        "device_kind": "bluetooth", "device_kind_name": USB_DEVICE_KINDS["bluetooth"],
                        "is_storage_device": False, "physical_observation": True,
                        "bluetooth_address": ":".join(peer.name[i:i+2].upper() for i in range(0,12,2)),
                        "classification_confidence": "recorded_identifier",
                        "device_classification_basis": [{"kind":"bluetooth", "basis":"registry_location", "identifier":base}]}
            name = values.get("name", {})
            if isinstance(name.get("value"), str):
                identity["friendlyname"] = name["value"]
            elif name.get("raw"):
                try:
                    identity["friendlyname"] = name["raw"].decode("utf-8").rstrip("\0")
                    identity["text_decoding"] = [{"encoding":"utf-8", "inferred":True, "decode_error":False}]
                except UnicodeDecodeError:
                    identity["bluetooth_name_raw_hex"] = name["raw"].hex()
                    self.error(path, base + "\\" + peer.name, "블루투스 장치 이름 인코딩을 확인할 수 없음", "warning")
            reasons = [] if identity.get("friendlyname") else ["description_missing"]
            identity["unknown_reasons"] = reasons
            identity["unknown_reason_labels"] = [USB_UNKNOWN_REASON_LABELS[r] for r in reasons]
            locator = base + "\\" + peer.name
            yield ForensicEvent(self.artifact, str(path), "device_registration", filetime(peer.lastwrite),
                                "key_lastwrite", locator=locator, details=identity)
            for value_name, action in (("lastseen", "bluetooth_last_seen"), ("lastconnected", "bluetooth_last_connected")):
                value = values.get(value_name)
                if value is None:
                    continue
                raw = value.get("raw", b"")
                if value.get("type") != 3 or len(raw) != 8:
                    self.error(path, locator + "\\" + value_name, "블루투스 시각의 형식 또는 크기 오류", "warning")
                    continue
                stamp = filetime(struct.unpack("<Q", raw)[0])
                if stamp is None:
                    self.error(path, locator + "\\" + value_name, "블루투스 시각 값이 유효하지 않음", "warning")
                    continue
                yield ForensicEvent(self.artifact, str(path), action, stamp, action,
                                    locator=locator + "\\" + value_name, details={**identity, "raw":raw.hex()})
