# Teaching copy: recorded device identifier classification.
"""Classify recorded USB/HID identifiers without vendor databases."""
import re

USB_CLASSES = {'01': 'audio', '02': 'communications', '03': 'hid', '07': 'printer',
               '08': 'storage', '09': 'hub', '0A': 'communications', '0E': 'camera',
               'E0': 'wireless', 'FF': 'vendor_specific'}
CLASS_NAMES = {'keyboard': 'keyboard', 'mouse': 'mouse', 'diskdrive': 'storage',
               'image': 'camera', 'camera': 'camera', 'media': 'audio',
               'bluetooth': 'bluetooth', 'hidclass': 'hid', 'wpd': 'portable'}
CLASS_GUIDS = {
    '4d36e96b-e325-11ce-bfc1-08002be10318': 'keyboard',
    '4d36e96f-e325-11ce-bfc1-08002be10318': 'mouse',
    '4d36e967-e325-11ce-bfc1-08002be10318': 'storage',
    '6bdd1fc6-810f-11d0-bec7-08002be2092f': 'camera',
    'ca3e7ab9-b4c3-4ae6-8251-579ef933890f': 'camera',
    '4d36e96c-e325-11ce-bfc1-08002be10318': 'audio',
    'e0cbf06c-cd8b-4647-bb8a-263b43f0f974': 'bluetooth',
    '745a17a0-74d3-11d0-b6fe-00a0c90f57da': 'hid',
    '36fc9e60-c465-11cf-8056-444553540000': 'usb',
    'eec5ad98-8080-425f-922a-dabf3de3f69a': 'portable',
}


def classify_device(bus, values):
    candidates, interfaces = [], []
    for field, basis in (('compatibleids', 'compatible_id'), ('hardwareid', 'hid_hardware_id')):
        raw = values.get(field, [])
        identifiers = raw if isinstance(raw, list) else [raw]
        for identifier in identifiers[:256]:
            if not isinstance(identifier, str):
                continue
            text = identifier.upper()
            match = re.search(r'USB\\CLASS_([0-9A-F]{2})(?:&SUBCLASS_([0-9A-F]{2}))?(?:&PROT_([0-9A-F]{2}))?', text)
            if match:
                cls, sub, protocol = match.groups()
                kind = USB_CLASSES.get(cls, 'unknown')
                if (cls, sub, protocol) == ('03', '01', '01'):
                    kind = 'keyboard'
                elif (cls, sub, protocol) == ('03', '01', '02'):
                    kind = 'mouse'
                elif (cls, sub, protocol) == ('E0', '01', '01'):
                    kind = 'bluetooth'
                interfaces.append({'class': cls, 'subclass': sub, 'protocol': protocol})
                candidates.append({'kind': kind, 'basis': basis, 'identifier': identifier})
            for marker, kind in (('HID_DEVICE_SYSTEM_KEYBOARD', 'keyboard'),
                                 ('HID_DEVICE_SYSTEM_MOUSE', 'mouse'),
                                 ('HID_DEVICE_UP:0001_U:0006', 'keyboard'),
                                 ('HID_DEVICE_UP:0001_U:0002', 'mouse'),
                                 ('HID_DEVICE_UP:0001_U:0004', 'gamepad'),
                                 ('HID_DEVICE_UP:0001_U:0005', 'gamepad'),
                                 ('HID_DEVICE_UP:000C_U:0001', 'consumer_control')):
                if text == marker:
                    candidates.append({'kind': kind, 'basis': 'hid_hardware_id', 'identifier': identifier})
    guid = values.get('classguid', '')
    if isinstance(guid, str) and guid.strip('{}').lower() in CLASS_GUIDS:
        candidates.append({'kind': CLASS_GUIDS[guid.strip('{}').lower()], 'basis': 'class_guid', 'identifier': guid})
    cls = values.get('class', '')
    if isinstance(cls, str) and cls.lower() in CLASS_NAMES:
        candidates.append({'kind': CLASS_NAMES[cls.lower()], 'basis': 'class_name', 'identifier': cls})
    if bus == 'USBSTOR':
        candidates.append({'kind': 'storage', 'basis': 'bus', 'identifier': bus})
    if not candidates and bus == 'BTHENUM':
        candidates.append({'kind': 'bluetooth', 'basis': 'bus', 'identifier': bus})
    kinds = {candidate['kind'] for candidate in candidates} - {'unknown', 'usb'}
    if kinds & {'keyboard', 'mouse', 'gamepad', 'consumer_control'}:
        kinds.discard('hid')
    if 'bluetooth' in kinds:
        kinds.discard('wireless')
    conflict = len(kinds) > 1
    kind = next(iter(kinds)) if len(kinds) == 1 else 'unknown'
    return {'device_kind': kind, 'device_classification_basis': candidates,
            'classification_conflict': conflict,
            'classification_confidence': 'low' if conflict or kind == 'unknown' else 'recorded_identifier',
            'usb_interfaces': interfaces, 'is_storage_device': kind == 'storage' and not conflict}
