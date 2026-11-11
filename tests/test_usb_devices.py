import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from test_example_samples import load_demo
from log_hunter.parser.usb import USBParser
from log_hunter.parser.usb_devices import classify_device
from log_hunter.core.correlation import correlate
from log_hunter.core.models import ForensicEvent

STAMP = 133485408000000000
GUID = '{4d36e96b-e325-11ce-bfc1-08002be10318}'


def usb_hive(damaged=False, container=True):
    builder = load_demo().HiveBuilder()
    tree = {}

    def key(path, values):
        node = tree
        for part in path.split('\\'):
            node = node.setdefault(part, {})
        node[':values'] = values

    def text(name, value, kind=1):
        return name, kind, (value + '\0').encode('utf-16-le')

    key('Select', [('Current', 4, struct.pack('<I', 2))])
    specs = [('USB', 'VID_FFFF&PID_FF01&MI_00', 'USB\\Class_03&SubClass_01&Prot_01', 'keyboard'),
             ('USB', 'VID_FFFF&PID_FF01&MI_01', 'USB\\Class_03&SubClass_01&Prot_02', 'mouse'),
             ('USBSTOR', 'Disk&Ven_TEST&Prod_TEST&Rev_1', 'USB\\Class_08', 'storage'),
             ('USB', 'VID_FFFF&PID_FF02', 'USB\\Class_0E', 'camera'),
             ('USB', 'VID_FFFF&PID_FF03', 'USB\\Class_09', 'hub'),
             ('USB', 'VID_FFFF&PID_FF04', 'USB\\Class_E0&SubClass_01&Prot_01', 'bluetooth'),
             ('HID', 'VID_FFFF&PID_FF05', 'HID_DEVICE_SYSTEM_KEYBOARD', 'keyboard'),
             ('BTHENUM', 'TESTDEVICE', '', 'bluetooth'),
             ('SWD\\WPDBUSENUM', 'TESTPORTABLE', '', 'portable')]
    for index, (bus, device, identifier, kind) in enumerate(specs):
        path = 'ControlSet002\\Enum\\' + bus + '\\' + device + '\\TESTSERIAL0001'
        values = [text('FriendlyName', 'TEST '+kind), text('Mfg', 'TEST'),
                  text('HardwareID', identifier, 7), text('LocationInformation', 'TESTPORT1'),
                  ('ConfigFlags', 4, bytes(4))]
        if 'MI_' in device and container:
            values.append(text('ContainerID', '{00000000-0000-0000-0000-000000000001}'))
        if index == 0:
            values += [text('ClassGUID', GUID), text('Driver', GUID+'\\0000')]
        if damaged and index == 1:
            values.append(('CompatibleIDs', 7, b'\xff'))
        if kind == 'portable':
            values.append(text('Class', 'WPD'))
        key(path, values)
        key(path+'\\Device Parameters', [text('TestParameter', 'synthetic')])
        if index == 0:
            for prop in ('0064','0065','0066','0067'):
                key(path+'\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\'+prop,
                    [('', 3, b'bad' if damaged and prop == '0064' else struct.pack('<Q', STAMP))])
    key('ControlSet002\\Control\\Class\\'+GUID+'\\0000',
        [text('ProviderName','TEST'), text('DriverVersion','1.0'), text('DriverDate','01-01-2024')])
    key('MountedDevices', [('\\DosDevices\\E:', 3, '\\??\\USBSTOR#TESTSERIAL0001'.encode('utf-16-le'))])

    def emit(name, node):
        children = [emit(n, v) for n, v in node.items() if n != ':values']
        return builder.key(name, STAMP, values=node.get(':values', []), children=children)
    return builder.build(emit('ROOT', tree))


class USBDevicesTests(unittest.TestCase):
    def test_classification_specificity_conflicts_and_unknown(self):
        keyboard = classify_device('HID', {'compatibleids':['USB\\Class_03'],
                                         'hardwareid':['HID_DEVICE_SYSTEM_KEYBOARD']})
        self.assertEqual(keyboard['device_kind'], 'keyboard')
        self.assertFalse(keyboard['classification_conflict'])
        conflict = classify_device('USB', {'compatibleids':['USB\\Class_08'], 'classguid': GUID})
        self.assertTrue(conflict['classification_conflict'])
        self.assertFalse(conflict['is_storage_device'])
        self.assertEqual(conflict['classification_confidence'], 'low')
        self.assertEqual(classify_device('USB', {'hardwareid':[7, None]})['device_kind'], 'unknown')
        for identifier, kind in [('HID_DEVICE_UP:0001_U:0005','gamepad'),
                                 ('HID_DEVICE_UP:000C_U:0001','consumer_control'),
                                 ('USB\\Class_01','audio'), ('USB\\Class_07','printer'),
                                 ('USB\\Class_FF','vendor_specific')]:
            self.assertEqual(classify_device('USB', {'hardwareid':[identifier]})['device_kind'],kind)

    def test_synthetic_hive_all_buses_driver_times_and_composite_receiver(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'SYSTEM'
            path.write_bytes(usb_hive())
            before = hashlib.sha256(path.read_bytes()).digest()
            parser = USBParser()
            events = list(parser.parse(path))
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),before)
        registrations = [e for e in events if e.action == 'device_registration']
        self.assertEqual(len(registrations),9)
        self.assertEqual(len(events),13)
        self.assertEqual(parser.errors,[])
        kinds = {e.details['device_kind'] for e in registrations}
        self.assertTrue({'keyboard','mouse','storage','camera','hub','bluetooth','portable'} <= kinds)
        keyboard, mouse = registrations[:2]
        self.assertEqual(keyboard.details['composite_group'],mouse.details['composite_group'])
        self.assertEqual(keyboard.details['driver_providername'],'TEST')
        self.assertEqual(keyboard.time_field,'key_lastwrite')
        self.assertEqual({e.time_field for e in events if e.action != 'device_registration'},
                         {'install','first_install','last_arrival','last_removal'})
        storage, = [e for e in registrations if e.details['is_storage_device']]
        self.assertEqual(storage.details['drive_letters'],['E:'])
        self.assertTrue(all('drive_letters' not in e.details for e in registrations if not e.details['is_storage_device']))
        self.assertFalse(keyboard.details['serial_is_hardware_confirmed'])
        self.assertEqual(keyboard.details['configflags'],0)

    def test_non_storage_cannot_create_file_or_mountpoint_correlations(self):
        stamp='2024-01-01T10:00:00+00:00'
        usb=ForensicEvent('usb','generated','device_registration',stamp,
                          details={'is_storage_device':False,'drive_letters':['E:']})
        file=ForensicEvent('lnk','generated','file_open',stamp,path='E:\\report.txt')
        mount=ForensicEvent('mountpoints2','generated','mount',stamp,
                            details={'mount_type':'drive_letter','drive_letter':'E:'})
        self.assertFalse(any('usb' in r.get('type','') for r in correlate([usb,file,mount])))

    def test_damage_warns_and_later_devices_continue_without_invented_group(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'SYSTEM'
            path.write_bytes(usb_hive(damaged=True,container=False))
            parser=USBParser()
            events=list(parser.parse(path))
        registrations=[e for e in events if e.action=='device_registration']
        self.assertEqual(len(registrations),9)
        self.assertGreaterEqual(len(parser.errors),2)
        self.assertIsNone(registrations[0].details['composite_group'])
        self.assertEqual(registrations[0].details['composite_group_basis'],'unknown')
        self.assertEqual(registrations[1].details['compatibleids_raw_hex'],'ff')
        json.dumps([e.details for e in events])

    def test_portable_device_software_names_do_not_claim_arrival_or_storage(self):
        b=load_demo().HiveBuilder()
        child=b.key('USBSTOR#TESTSERIAL0001',STAMP,values=[('FriendlyName',1,'TEST volume\0'.encode('utf-16-le'))])
        node=b.key('Devices',STAMP,children=[child])
        node=b.key('Windows Portable Devices',STAMP,children=[node])
        node=b.key('Microsoft',STAMP,children=[node])
        root=b.key('ROOT',STAMP,children=[node])
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'SOFTWARE';p.write_bytes(b.build(root))
            events=list(USBParser().parse(p))
        self.assertEqual(len(events),1)
        self.assertEqual(events[0].details['friendlyname'],'TEST volume')
        self.assertFalse(events[0].details['is_storage_device'])
        self.assertEqual(events[0].time_field,'key_lastwrite')
