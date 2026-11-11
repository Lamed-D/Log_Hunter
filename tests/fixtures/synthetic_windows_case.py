"""Generate a reproducible, entirely fictional Windows evidence image (stdlib only)."""
import argparse
import hashlib
import json
import struct
import sys
import tempfile
import uuid
import zlib
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(TESTS.parent))
from test_example_samples import load_demo
from test_usb_reference import synthetic_usb_hives
from test_image import (NTFSBuilder, write_e01, mbr_disk, recycle_record, _record,
                        _resident, _nonresident, _file_name, MFT_LCN, MFT_RECORDS,
                        CLUSTER, RECORD)
from test_prefetch_v31 import fixture as prefetch_fixture
from test_custom_jumplist import link
from test_text_encoding import shell_item
from test_evtx_chunks import ChunkWriter
from log_hunter.parser.registry import Hive

STAMP = 133485408000000000
SIDS = {"alice": "S-1-5-21-1000-2000-3000-1001",
        "bob": "S-1-5-21-1000-2000-3000-1002"}
GUID = "{11111111-2222-3333-4444-555555555555}"
NODES = {"placeholder": "806e6f6e6963", "multicast": "01005e005301",
         "zero": "000000000000", "candidate": "00005e005301"}
VOLUME_GUIDS = {kind: "{11111111-2222-1333-8444-" + node + "}" for kind, node in NODES.items()}
TASK = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"


def text(name, value):
    return name, 1, (value + "\0").encode("utf-16-le")


def put(tree, path, values):
    for part in path.split("\\"):
        tree = tree.setdefault(part, {})
    tree[":values"] = values


def read_tree(data):
    with tempfile.TemporaryDirectory() as temporary:
        p = Path(temporary) / "generated-hive"
        p.write_bytes(data)
        root = Hive(p).root

        def read(key):
            result = {k.name: read(k) for k in key.subkeys()}
            result[":values"] = [(v["name"], v["type"], v["raw"]) for v in key.values() if "error" not in v]
            return result
        return read(root)


def registry_bytes(tree, filename):
    """Populate parent references, aligned bins, base metadata and XOR checksum."""
    b = load_demo().HiveBuilder()

    def emit(name, node):
        children = [emit(k, v) for k, v in node.items() if k != ":values"]
        offset = b.key(name, STAMP, node.get(":values", []), children)
        for child in children:
            struct.pack_into("<I", b.cells, child + 4 + 16, offset)
        return offset

    root = emit(filename, tree)
    struct.pack_into("<H", b.cells, root + 4 + 2, 0x22)
    struct.pack_into("<I", b.cells, root + 4 + 16, 0xffffffff)
    remaining = (-len(b.cells)) % 4096
    if remaining:
        b.cells += struct.pack("<i", remaining) + bytes(remaining - 4)
    struct.pack_into("<II", b.cells, 4, 0, len(b.cells))
    result = bytearray(b.build(root))
    struct.pack_into("<Q", result, 12, STAMP)
    struct.pack_into("<IIII", result, 20, 1, 5, 0, 1)
    struct.pack_into("<II", result, 40, len(b.cells), 1)
    encoded = (filename + "\0").encode("utf-16-le")[:64]
    result[48:48 + len(encoded)] = encoded
    checksum = 0
    for offset in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", result, offset)[0]
    checksum = 1 if checksum == 0 else 0xfffffffe if checksum == 0xffffffff else checksum
    struct.pack_into("<I", result, 508, checksum)
    return bytes(result)


def scheduled_tasks(software):
    """Return XML definitions and record known registration cases independently."""
    from test_taskcache import actions, CLSID
    definitions, expected = {}, {}
    cases = ("Task", "RegistryOnly", "XmlOnly", "Hidden", "Mismatch", "Com",
             "Dynamic28", "DynamicOdd", "DamagedActions")
    for index, name in enumerate(cases, 1):
        guid = "{" + str(uuid.UUID(int=0x11111111222243338444000000000000 + index)) + "}"
        namespace = "\\Demo\\" + name
        if name != "XmlOnly":
            dynamic = struct.pack("<IQQII", 3, STAMP, STAMP, 0, 0)
            if name != "Dynamic28":
                dynamic += struct.pack("<Q", STAMP)
            if name == "DynamicOdd":
                dynamic += b"x"
            payload = b"bad" if name == "DamagedActions" else actions(com=name == "Com")
            put(software, TASK + "\\Tasks\\" + guid,
                [text("Path", namespace), ("DynamicInfo", 3, dynamic), ("Actions", 3, payload)])
            values = [text("Id", guid), ("Index", 4, struct.pack("<I", 1))]
            if name != "Hidden":
                values.append(("SD", 3, bytes.fromhex("01000480000000000000000000000000140000000200080000000000")))
            put(software, TASK + "\\Tree" + namespace, values)
            put(software, TASK + "\\Plain\\" + guid, [])
        if name == "Com":
            put(software, "Classes\\CLSID\\" + CLSID + "\\InprocServer32",
                [text("", r"C:\Windows\System32\demo.dll")])
            action = "<ComHandler><ClassId>" + CLSID + "</ClassId><Data></Data></ComHandler>"
        else:
            command = "other.exe" if name == "Mismatch" else "cmd.exe"
            action = "<Exec><Command>C:\\Windows\\System32\\" + command + "</Command><Arguments>/c exit</Arguments></Exec>"
        if name != "RegistryOnly":
            definitions[name] = ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                '<RegistrationInfo><Author>alice</Author><URI>' + namespace + '</URI></RegistrationInfo>'
                '<Principals><Principal id="Author"><UserId>alice</UserId></Principal></Principals>'
                '<Actions Context="Author">' + action + '</Actions></Task>').encode()
        expected[namespace] = {"registry": name != "XmlOnly", "xml": name != "RegistryOnly"}
    return definitions, expected


def event_log():
    w = ChunkWriter()
    last_start = 512
    for event_id in (106, 140, 141, 200, 201):
        last_start = w.begin()
        w.element("Event", children=[dict(name="System", children=[
            dict(name="Provider", attrs=[("Name", "Microsoft-Windows-TaskScheduler")]),
            dict(name="EventID", text=event_id),
            dict(name="TimeCreated", attrs=[("SystemTime", "2024-01-01T00:00:00.0000000Z")]),
            dict(name="EventRecordID", text=w.records + 1),
            dict(name="Channel", text="Microsoft-Windows-TaskScheduler/Operational"),
            dict(name="Computer", text="synthetic-host"),
            dict(name="Security", attrs=[("UserID", SIDS["alice"])])]),
            dict(name="EventData", children=[dict(name="Data", attrs=[("Name", "TaskName")], text=r"\Demo\Task")])])
        w.finish(last_start)
    result = bytearray(w.file())
    struct.pack_into("<QQQIHHHH", result, 8, 0, 0, w.records + 1, 128, 1, 3, 4096, 1)
    struct.pack_into("<I", result, 124, zlib.crc32(result[:120]))
    base = 4096
    struct.pack_into("<QQQQII", result, base + 8, 1, w.records, 1, w.records, 128, last_start)
    struct.pack_into("<I", result, base + 124, zlib.crc32(result[base:base + 120] + result[base + 128:base + 512]))
    return bytes(result)


def complete_volume(builder):
    """Add allocation maps and standard NTFS metadata records to the tiny volume."""
    builder.build()
    used = {0, 1, 3, 5, 6, 7, 10} | set(builder.records)
    bitmap = sum(1 << n for n in used).to_bytes(MFT_RECORDS // 8, "little")
    records = {
        0: [builder._si(), _resident(0x30, _file_name(5, "$MFT")),
            _nonresident(0x80, [(MFT_LCN, MFT_RECORDS * RECORD // CLUSTER)], MFT_RECORDS * RECORD),
            _resident(0xB0, bitmap)],
        1: [builder._si(), _resident(0x30, _file_name(5, "$MFTMirr")), _nonresident(0x80, [(2, 1)], CLUSTER)],
        3: [builder._si(), _resident(0x30, _file_name(5, "$Volume")),
            _resident(0x60, "Synthetic".encode("utf-16-le")), _resident(0x70, bytes(8) + b"\x03\x01\0\0")],
        6: [builder._si(), _resident(0x30, _file_name(5, "$Bitmap")), _resident(0x80, b"\xff" * (builder.clusters // 8))],
        7: [builder._si(), _resident(0x30, _file_name(5, "$Boot")), _nonresident(0x80, [(0, 1)], CLUSTER)],
    }
    upcase = b"".join(struct.pack("<H", ord(c.upper()) if len(c.upper()) == 1 else n)
                      for n in range(65536) for c in (chr(n),))
    lcn, count = builder._alloc(upcase)
    records[10] = [builder._si(), _resident(0x30, _file_name(5, "$UpCase")), _nonresident(0x80, [(lcn, count)], len(upcase))]
    for number, attrs in records.items():
        start = MFT_LCN * CLUSTER + number * RECORD
        builder.data[start:start + RECORD] = _record(number, attrs)
    builder.data[2 * CLUSTER:3 * CLUSTER] = builder.data[MFT_LCN * CLUSTER:MFT_LCN * CLUSTER + CLUSTER]
    return bytes(builder.data)


def complete_ewf(paths):
    """Set section payload checksums in the shared test writer output."""
    for path in paths:
        data = bytearray(path.read_bytes())
        position = 13
        while position + 76 <= len(data):
            kind = bytes(data[position:position + 16]).split(b"\0", 1)[0]
            next_position, size = struct.unpack_from("<QQ", data, position + 16)
            start, end = position + 76, position + size
            if kind in (b"volume", b"data"):
                struct.pack_into("<I", data, end - 4, zlib.adler32(data[start:end - 4]))
            elif kind in (b"table", b"table2"):
                struct.pack_into("<I", data, end - 4, zlib.adler32(data[start + 24:end - 4]))
            if next_position <= position:
                break
            position = next_position
        path.write_bytes(data)


def generate(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if any((destination / name).exists() for name in ("synth.E01", "synth.E02", "fixture-manifest.json")):
        raise FileExistsError("Choose a new output directory")
    b = NTFSBuilder(clusters=1024)
    files = {}

    def add(path, data):
        parent, name = path.rsplit("/", 1)
        b.add_file(b.makedirs(parent, large={"Demo"}), name, data)
        files[path] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    system, software = (read_tree(raw) for raw in synthetic_usb_hives())
    task_xml, expected_tasks = scheduled_tasks(software)
    mounted = system["MountedDevices"][":values"]
    mounted.extend(("\\??\\Volume" + guid, 3, "USBSTOR#TESTMEMORY001".encode("utf-16-le"))
                   for guid in VOLUME_GUIDS.values())
    for user, sid in SIDS.items():
        put(software, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid,
            [text("ProfileImagePath", "C:\\Users\\" + user)])
    add("Windows/System32/config/SYSTEM", registry_bytes(system, "SYSTEM"))
    add("Windows/System32/config/SOFTWARE", registry_bytes(software, "SOFTWARE"))
    for name, xml in task_xml.items():
        add("Windows/System32/Tasks/Demo/" + name, xml)
    add("Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx", event_log())
    for version in (30, 31):
        add(f"Windows/Prefetch/TESTAPP{version}.EXE-1234ABCD.pf", prefetch_fixture(version))
    add("Evidence/TESTAPP.EXE", b"MZ" + b"synthetic-not-executable\0" * 4)
    demo = load_demo()
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        for user in ("alice", "bob"):
            hive = temporary / (user + ".dat")
            demo.make_ntuser(hive)
            tree = read_tree(hive.read_bytes())
            for kind, guid in VOLUME_GUIDS.items():
                put(tree, r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" + "\\" + guid,
                    [text("_LabelFromReg", "Test " + kind)])
            put(tree, r"Software\Microsoft\Windows\Shell\BagMRU", [
                ("0", 3, shell_item("Evidence")), ("MRUListEx", 3, struct.pack("<II", 0, 0xffffffff))])
            if user == "bob":
                def rename(node):
                    node[":values"] = [(n, t, raw.replace("alice".encode("utf-16-le"), "bob".encode("utf-16-le")))
                                       for n, t, raw in node.get(":values", [])]
                    for k, v in node.items():
                        if k != ":values":
                            rename(v)
                rename(tree)
            add(f"Users/{user}/NTUSER.DAT", registry_bytes(tree, "NTUSER.DAT"))
            history = temporary / (user + ".sqlite")
            demo.make_history(history)
            add(f"Users/{user}/AppData/Local/Google/Chrome/User Data/Default/History", history.read_bytes())
            add(f"Users/{user}/AppData/Roaming/Microsoft/Windows/Recent/demo.lnk", link(r"C:\Evidence\TESTAPP.EXE"))
            add(f"Users/{user}/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/1b4dd67f29cb1962.customDestinations-ms",
                link(r"C:\Evidence\first.txt") + link(r"C:\Evidence\second.txt"))
    add("$Recycle.Bin/" + SIDS["alice"] + "/$IABC123.txt", recycle_record(r"C:\Users\alice\Documents\demo.txt"))
    add("$Recycle.Bin/" + SIDS["alice"] + "/$RABC123.txt", b"synthetic deleted content\n")
    wifi = (b'<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>TestNetwork</name>'
            b'<SSIDConfig><SSID><name>TestNetwork</name></SSID></SSIDConfig><connectionType>ESS</connectionType>'
            b'<connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>WPA2PSK</authentication>'
            b'<encryption>AES</encryption></authEncryption></security></MSM></WLANProfile>')
    add("ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/" + GUID + "/" + GUID + ".xml", wifi)
    disk = mbr_disk(complete_volume(b))
    paths = write_e01(destination / "synth.E01", disk)
    complete_ewf(paths)
    manifest = {"synthetic": True, "disk_sha256": hashlib.sha256(disk).hexdigest(), "disk_size": len(disk),
                "expected_tasks": expected_tasks, "expected_usb_counts": {"registration_records": 16, "physical_groups": 8,
                "default_visible_groups": 7, "system_groups": 1, "auxiliary_groups": 1, "unknown_groups": 2},
                "files": files, "segments": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}
    (destination / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    result = generate(args.destination)
    print(json.dumps({"files": len(result["files"]), "disk_size": result["disk_size"]}))
