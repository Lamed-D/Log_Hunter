import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
import uuid
import zlib
from pathlib import Path

from unittest import mock
from log_hunter.core.labels import evidence_origin
from log_hunter.core.pipeline import Pipeline
from log_hunter.image import extract_artifacts, live, open_image, ImageError
from log_hunter.image.ewf import EWFImage, RawImage
from log_hunter.image.ntfs import NTFSVolume
from log_hunter.image.volumes import find_volumes
from log_hunter.main import main, save_result

FILETIME = 132537600000000000  # 2020-12-30T00:00:00Z
CLUSTER = 4096
RECORD = 1024
MFT_RECORDS = 128
MFT_LCN = 4


def _align8(value):
    return (value + 7) & ~7


def _encode_runs(runs):
    out, previous = bytearray(), 0
    for lcn, length in runs:
        length_bytes = length.to_bytes((length.bit_length() + 8) // 8, "little")
        if lcn is None:
            out += bytes([len(length_bytes)]) + length_bytes
            continue
        delta = lcn - previous
        size = 1
        while not -(1 << (size * 8 - 1)) <= delta < (1 << (size * 8 - 1)):
            size += 1
        out += bytes([len(length_bytes) | size << 4]) + length_bytes + delta.to_bytes(size, "little", signed=True)
        previous = lcn
    return bytes(out + b"\0")


def _resident(kind, value, name=""):
    encoded = name.encode("utf-16-le")
    value_offset = _align8(24 + len(encoded))
    length = _align8(value_offset + len(value))
    out = bytearray(length)
    struct.pack_into("<IIBBHHH", out, 0, kind, length, 0, len(name), 24, 0, 0)
    struct.pack_into("<IH", out, 16, len(value), value_offset)
    out[24:24 + len(encoded)] = encoded
    out[value_offset:value_offset + len(value)] = value
    return bytes(out)


def _nonresident(kind, runs, real_size, name="", start_vcn=0):
    encoded = name.encode("utf-16-le")
    run_offset = _align8(64 + len(encoded))
    run_bytes = _encode_runs(runs)
    length = _align8(run_offset + len(run_bytes))
    clusters = sum(r[1] for r in runs)
    out = bytearray(length)
    struct.pack_into("<IIBBHHH", out, 0, kind, length, 1, len(name), 64, 0, 0)
    struct.pack_into("<QQHH", out, 16, start_vcn, start_vcn + clusters - 1, run_offset, 0)
    struct.pack_into("<QQQ", out, 40, clusters * CLUSTER, real_size, real_size)
    out[64:64 + len(encoded)] = encoded
    out[run_offset:run_offset + len(run_bytes)] = run_bytes
    return bytes(out)


def _file_name(parent, name, directory=False, size=0):
    value = bytearray(66)
    struct.pack_into("<Q", value, 0, parent | (1 << 48))
    struct.pack_into("<QQQQ", value, 8, FILETIME, FILETIME, FILETIME, FILETIME)
    struct.pack_into("<QQI", value, 40, size, size, 0x10000000 if directory else 0)
    value[64], value[65] = len(name.encode('utf-16-le')) // 2, 3
    return bytes(value) + name.encode("utf-16-le")


def _record(number, attributes, directory=False, base=0):
    data = bytearray(RECORD)
    data[:4] = b"FILE"
    struct.pack_into("<HH", data, 4, 48, 3)
    struct.pack_into("<HHHH", data, 16, 1, 1, 56, 1 | (2 if directory else 0))
    body = b"".join(attributes) + b"\xff\xff\xff\xff"
    struct.pack_into("<II", data, 24, 56 + len(body), RECORD)
    struct.pack_into("<Q", data, 32, base | (1 << 48) if base else 0)
    struct.pack_into("<I", data, 44, number)
    data[56:56 + len(body)] = body
    return _protect(data)


def _protect(data):
    count = len(data) // 512 + 1
    usa, = struct.unpack_from("<H", data, 4)
    struct.pack_into("<H", data, usa, 0x0001)
    for index in range(1, count):
        end = index * 512
        data[usa + index * 2:usa + index * 2 + 2] = data[end - 2:end]
        data[end - 2:end] = b"\x01\x00"
    return bytes(data)


def _index_entry(record, key, last=False):
    if last:
        return struct.pack("<QHHI", 0, 16, 0, 2)
    length = _align8(16 + len(key))
    return struct.pack("<QHHI", record | (1 << 48), length, len(key), 0) + key + bytes(length - 16 - len(key))


class NTFSBuilder:
    """Builds a tiny but structurally real NTFS volume for reader tests."""

    def __init__(self, clusters=512):
        self.clusters = clusters
        self.data = bytearray(clusters * CLUSTER)
        self.next_cluster = MFT_LCN + MFT_RECORDS * RECORD // CLUSTER + 4
        self.next_record = 16
        self.records = {}
        self.children = {5: []}
        self.large = set()

    def _alloc(self, data):
        count = max(1, (len(data) + CLUSTER - 1) // CLUSTER)
        lcn = self.next_cluster
        self.next_cluster += count
        self.data[lcn * CLUSTER:lcn * CLUSTER + len(data)] = data
        return lcn, count

    def _new(self):
        number = self.next_record
        assert number < MFT_RECORDS, "test MFT too small"
        self.next_record += 1
        return number

    def mkdir(self, parent, name, large=False):
        number = self._new()
        self.children[number] = []
        self.children[parent].append((number, name, True, 0))
        self.records[number] = ("dir", parent, name)
        if large:
            self.large.add(number)
        return number

    def add_file(self, parent, name, content, mode="nonresident"):
        number = self._new()
        self.children[parent].append((number, name, False, len(content)))
        self.records[number] = (mode, parent, name, content)
        return number

    def makedirs(self, path, large=()):
        current = 5
        for part in path.split("/"):
            existing = next((n for n, nm, d, _s in self.children[current] if d and nm.lower() == part.lower()), None)
            current = existing or self.mkdir(current, part, large=part in large)
        return current

    def _si(self):
        return _resident(0x10, struct.pack("<QQQQ", FILETIME, FILETIME, FILETIME, FILETIME) + bytes(16))

    def _directory_attributes(self, number):
        entries = sorted(self.children[number], key=lambda c: c[1].upper())
        keys = b"".join(_index_entry(child, _file_name(number, name, d, size)) for child, name, d, size in entries)
        if number not in self.large:
            node = keys + _index_entry(0, b"", last=True)
            root = struct.pack("<IIIB3x", 0x30, 1, 4096, 1) + struct.pack("<IIIB3x", 16, 16 + len(node), 16 + len(node), 0) + node
            return [_resident(0x90, root, "$I30")]
        end = struct.pack("<QHHIQ", 0, 24, 0, 3, 0)
        root = struct.pack("<IIIB3x", 0x30, 1, 4096, 1) + struct.pack("<IIIB3x", 16, 40, 40, 1) + end
        groups, current = [], b""
        for child, name, d, size in entries:
            entry = _index_entry(child, _file_name(number, name, d, size))
            if len(current) + len(entry) + 16 > 4096 - 64:
                groups.append(current)
                current = b""
            current += entry
        groups.append(current)
        blocks = bytearray()
        for vcn, group in enumerate(groups):
            block = bytearray(4096)
            block[:4] = b"INDX"
            struct.pack_into("<HHQQ", block, 4, 40, 9, 0, vcn)
            node = group + _index_entry(0, b"", last=True)
            struct.pack_into("<IIIB", block, 24, 40, 40 + len(node), 4096 - 24, 0)
            block[64:64 + len(node)] = node
            blocks += _protect(block)
        stale = bytearray(4096)  # unallocated block (bitmap bit clear) holding a deleted entry
        stale[:4] = b"INDX"
        struct.pack_into("<HHQQ", stale, 4, 40, 9, 0, len(groups))
        node = _index_entry(99, _file_name(number, "STALE.EXE-00000000.pf")) + _index_entry(0, b"", last=True)
        struct.pack_into("<IIIB", stale, 24, 40, 40 + len(node), 4096 - 24, 0)
        stale[64:64 + len(node)] = node
        blocks += _protect(stale)
        lcn, count = self._alloc(bytes(blocks))
        bitmap = ((1 << len(groups)) - 1).to_bytes(8, "little")
        return [_resident(0x90, root, "$I30"), _nonresident(0xA0, [(lcn, count)], len(blocks), "$I30"),
                _resident(0xB0, bitmap, "$I30")]

    def build(self):
        mft = bytearray(MFT_RECORDS * RECORD)
        records = {0: [self._si(), _resident(0x30, _file_name(5, "$MFT")),
                       _nonresident(0x80, [(MFT_LCN, MFT_RECORDS * RECORD // CLUSTER)], MFT_RECORDS * RECORD)]}
        self.children[5].append((0, "$MFT", False, MFT_RECORDS * RECORD))
        directories = {5}
        for number, spec in self.records.items():
            parent, name = spec[1], spec[2]
            attrs = [self._si(), _resident(0x30, _file_name(parent, name, spec[0] == "dir"))]
            if spec[0] == "dir":
                directories.add(number)
                continue
            content = spec[3]
            if spec[0] == "resident":
                attrs.append(_resident(0x80, content))
            elif spec[0] == "nonresident":
                lcn, count = self._alloc(content)
                attrs.append(_nonresident(0x80, [(lcn, count)], len(content)))
            elif spec[0] == "sparse":
                first, _c = self._alloc(content[:CLUSTER])
                last, _c = self._alloc(content[2 * CLUSTER:3 * CLUSTER])
                attrs.append(_nonresident(0x80, [(first, 1), (None, 1), (last, 1)], len(content)))
            elif spec[0] == "attribute_list":
                half = (len(content) // CLUSTER // 2) * CLUSTER
                a_lcn, a_count = self._alloc(content[:half])
                self._alloc(b"\xAA" * CLUSTER)
                b_lcn, b_count = self._alloc(content[half:])
                ext1, ext2 = self._new(), self._new()
                records[ext1] = ([_nonresident(0x80, [(a_lcn, a_count)], len(content))], number)
                records[ext2] = ([_nonresident(0x80, [(b_lcn, b_count)], len(content), start_vcn=a_count)], number)
                listing = b""
                for kind, vcn, ref in ((0x10, 0, number), (0x30, 0, number), (0x80, 0, ext1), (0x80, a_count, ext2)):
                    listing += struct.pack("<IHBBQQH6x", kind, 32, 0, 26, vcn, ref | (1 << 48), 0)
                attrs.append(_resident(0x20, listing))
            records[number] = attrs
        for number in directories:
            base = records.get(number, [self._si(), _resident(0x30, _file_name(5, "."))])
            if number in self.records:
                parent, name = self.records[number][1], self.records[number][2]
                base = [self._si(), _resident(0x30, _file_name(parent, name, True))]
            records[number] = base + self._directory_attributes(number)
        for number, attrs in records.items():
            base = 0
            if isinstance(attrs, tuple):
                attrs, base = attrs
            raw = _record(number, attrs, directory=number in directories, base=base)
            mft[number * RECORD:(number + 1) * RECORD] = raw
        self.data[MFT_LCN * CLUSTER:MFT_LCN * CLUSTER + len(mft)] = mft
        boot = bytearray(512)
        boot[3:11] = b"NTFS    "
        struct.pack_into("<HB", boot, 0x0B, 512, CLUSTER // 512)
        struct.pack_into("<QQQ", boot, 0x28, self.clusters * CLUSTER // 512 - 1, MFT_LCN, 2)
        boot[0x40] = 0xF6  # -10 -> 1024-byte records
        boot[0x44] = 1
        struct.pack_into("<Q", boot, 0x48, 0x1234ABCD)
        boot[510:512] = b"\x55\xaa"
        self.data[:512] = boot
        return bytes(self.data)


def mbr_disk(volume, start_sector=2048):
    disk = bytearray(start_sector * 512 + len(volume) + 512 * 8)
    entry = struct.pack("<B3sB3sII", 0x80, b"\0\0\0", 0x07, b"\0\0\0", start_sector, len(volume) // 512)
    disk[446:462] = entry
    disk[510:512] = b"\x55\xaa"
    disk[start_sector * 512:start_sector * 512 + len(volume)] = volume
    return bytes(disk)


def gpt_disk(volume, start_lba=34):
    disk = bytearray(start_lba * 512 + len(volume) + 34 * 512)
    disk[446:462] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0xEE, b"\0\0\0", 1, len(disk) // 512 - 1)
    disk[510:512] = b"\x55\xaa"
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<QII", header, 72, 2, 128, 128)
    disk[512:512 + 92] = header
    entry = bytearray(128)
    entry[:16] = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
    entry[16:32] = uuid.uuid4().bytes_le
    struct.pack_into("<QQ", entry, 32, start_lba, start_lba + len(volume) // 512 - 1)
    entry[56:56 + 18] = "Basic data".encode("utf-16-le")[:18]
    disk[1024:1024 + 128] = entry
    disk[start_lba * 512:start_lba * 512 + len(volume)] = volume
    return bytes(disk)


def _section(kind, next_offset, size):
    raw = bytearray(76)
    raw[:len(kind)] = kind.encode()
    struct.pack_into("<QQ", raw, 16, next_offset, size)
    struct.pack_into("<I", raw, 72, zlib.adler32(bytes(raw[:72])))
    return bytes(raw)


def write_e01(path, disk, chunk_sectors=64, segments=2, use_base_offset=True):
    chunk_size = chunk_sectors * 512
    chunks = [disk[i:i + chunk_size] for i in range(0, len(disk), chunk_size)]
    per_segment = (len(chunks) + segments - 1) // segments
    header_text = "1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\nCASE-7\tEV-1\ttest disk\tanalyst\tnotes\t6.19\tWin10\t2020 12 30 0 0 0\t2020 12 30 0 0 0\t0\n\n"
    md5 = hashlib.md5(disk).digest()
    paths = []
    for segment in range(segments):
        target = Path(path).with_suffix(f".E{segment + 1:02d}")
        paths.append(target)
        out = bytearray(b"EVF\x09\x0d\x0a\xff\x00\x01" + struct.pack("<HH", segment + 1, 0))

        def add(kind, body, last=False):
            start = len(out)
            size = 76 + len(body)
            out.extend(_section(kind, start if last else start + size, size) + body)

        if segment == 0:
            add("header", zlib.compress(header_text.encode("latin-1")))
        volume = bytearray(1052)
        struct.pack_into("<IIIQ", volume, 4, len(chunks), chunk_sectors, 512, len(disk) // 512)
        add("volume" if segment == 0 else "data", bytes(volume))
        sectors_start = len(out)
        body, offsets = bytearray(), []
        for chunk in chunks[segment * per_segment:(segment + 1) * per_segment]:
            compressed = zlib.compress(chunk)
            relative = 76 + len(body)
            if len(compressed) < len(chunk):
                offsets.append(relative | 0x80000000)
                body += compressed
            else:
                offsets.append(relative)
                body += chunk + struct.pack("<I", zlib.adler32(chunk))
        add("sectors", bytes(body))
        base = sectors_start if use_base_offset else 0
        entries = [(o & 0x80000000) | ((o & 0x7FFFFFFF) + (0 if use_base_offset else sectors_start)) for o in offsets]
        table_header = bytearray(struct.pack("<IIQI", len(entries), 0, base, 0))
        table_header += struct.pack("<I", zlib.adler32(bytes(table_header)))
        table = bytes(table_header) + struct.pack(f"<{len(entries)}I", *entries) + b"\0\0\0\0"
        add("table", table)
        add("table2", table)
        if segment == segments - 1:
            hash_body = md5 + bytes(16)
            add("hash", hash_body + struct.pack('<I', zlib.adler32(hash_body)))
            add("done", b"", last=True)
        else:
            add("next", b"", last=True)
        target.write_bytes(out)
    return paths


def recycle_record(name):
    encoded = (name + "\0").encode("utf-16-le")
    return struct.pack("<QQQI", 2, 4096, FILETIME, len(encoded) // 2) + encoded


def windows_volume():
    builder = NTFSBuilder()
    config = builder.makedirs("Windows/System32/config")
    system = os.urandom(3 * CLUSTER) + b"SYSTEM-TAIL"
    builder.add_file(config, "SYSTEM", system, mode="attribute_list")
    builder.add_file(config, "SYSTEM.LOG1", b"LOG1" * 100, mode="resident")
    builder.add_file(config, "SAM", b"not extracted", mode="resident")
    builder.add_file(config, "SOFTWARE", os.urandom(16 * CLUSTER))
    prefetch = builder.makedirs("Windows/Prefetch", large={"Prefetch"})
    for index in range(40):
        builder.add_file(prefetch, f"APP{index:02d}.EXE-1234ABCD.pf", b"MAM\x04" + bytes(60), mode="resident")
    builder.add_file(prefetch, "Layout.ini", b"ignored", mode="resident")
    history = builder.makedirs("Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine")
    builder.add_file(history, "ConsoleHost_history.txt", (b"whoami\r\nnet user\r\n" * 700)[:3 * CLUSTER], mode="sparse")
    recycle = builder.makedirs("$Recycle.Bin/S-1-5-21-1-2-3-1001")
    builder.add_file(recycle, "$IABC123.txt", recycle_record("C:\\Users\\alice\\secret.txt"), mode="resident")
    builder.add_file(recycle, "$RABC123.txt", b"content", mode="resident")
    return builder.build(), system


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.volume, self.system = windows_volume()

    def tearDown(self):
        self.temp.cleanup()

    def test_ntfs_reader_lists_and_copies_files(self):
        disk = self.root / "disk.dd"
        disk.write_bytes(self.volume)
        with RawImage(disk) as image:
            ntfs = NTFSVolume(image, 0)
            self.assertIn("$MFT", [e.name for e in ntfs.listdir(5)])
            prefetch = ntfs.lookup("windows/prefetch")
            names = [e.name for e in ntfs.listdir(prefetch.record)]
            self.assertEqual(len([n for n in names if n.endswith(".pf")]), 40)
            self.assertNotIn("STALE.EXE-00000000.pf", names)
            entry = ntfs.lookup("Windows\\System32\\config\\SYSTEM")
            info = ntfs.copy_file(entry, self.root / "SYSTEM")
            self.assertEqual((self.root / "SYSTEM").read_bytes(), self.system)
            self.assertEqual(info["sha256"], hashlib.sha256(self.system).hexdigest())
            self.assertEqual(info["created"], "2020-12-30T00:00:00+00:00")
            sparse = ntfs.lookup("Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
            ntfs.copy_file(sparse, self.root / "history.txt")
            data = (self.root / "history.txt").read_bytes()
            self.assertEqual(data[CLUSTER:2 * CLUSTER], bytes(CLUSTER))
            self.assertIsNone(ntfs.lookup("Windows/Nope"))

    def test_partition_tables(self):
        for name, disk in (("mbr.dd", mbr_disk(self.volume)), ("gpt.dd", gpt_disk(self.volume))):
            path = self.root / name
            path.write_bytes(disk)
            with RawImage(path) as image:
                volumes = find_volumes(image)
            self.assertEqual([v.filesystem for v in volumes], ["ntfs"], name)
        bitlocker = bytearray(self.volume)
        bitlocker[3:11] = b"-FVE-FS-"
        path = self.root / "bitlocker.dd"
        path.write_bytes(mbr_disk(bytes(bitlocker)))
        extraction = extract_artifacts(path, self.root / "out-bitlocker")
        self.assertTrue(any("BitLocker" in w for w in extraction.warnings))

    def test_e01_multi_segment_matches_raw(self):
        disk = mbr_disk(self.volume)
        for use_base in (True, False):
            folder = self.root / f"e01-{use_base}"
            folder.mkdir()
            segments = write_e01(folder / "case.E01", disk, use_base_offset=use_base)
            self.assertEqual(len(segments), 2)
            with open_image(segments[0]) as image:
                self.assertIsInstance(image, EWFImage)
                self.assertEqual(image.size, len(disk))
                self.assertEqual(image.read(0, len(disk)), disk)
                self.assertEqual(image.read(70000, 100000), disk[70000:170000])
                info = image.info()
                self.assertEqual(info["stored_md5"], hashlib.md5(disk).hexdigest())
                self.assertEqual(info["acquisition"]["case_number"], "CASE-7")
                self.assertEqual(info["acquisition"]["examiner"], "analyst")

    def test_e01_missing_segment_is_reported(self):
        segments = write_e01(self.root / "case.E01", mbr_disk(self.volume), segments=3)
        segments[1].unlink()
        with self.assertRaises(ImageError):
            open_image(segments[0])

    def test_extract_artifacts_from_e01(self):
        segments = write_e01(self.root / "case.E01", mbr_disk(self.volume))
        extraction = extract_artifacts(segments[0], self.root / "extracted")
        paths = {f["image_path"]: f for f in extraction.files}
        self.assertIn("\\Windows\\System32\\config\\SYSTEM", paths)
        self.assertIn("\\Windows\\System32\\config\\SYSTEM.LOG1", paths)
        self.assertNotIn("\\Windows\\System32\\config\\SAM", paths)
        self.assertNotIn("\\Windows\\Prefetch\\Layout.ini", paths)
        system = Path(paths["\\Windows\\System32\\config\\SYSTEM"]["extracted"])
        self.assertEqual(system.read_bytes(), self.system)
        self.assertTrue(Path(str(system) + ".LOG1").exists())
        artifacts = sorted({a for a, _p, _s in extraction.inputs})
        self.assertEqual(artifacts, ["bam", "network", "prefetch", "psreadline", "recyclebin", "run", "services", "taskcache", "usb"])
        recycle = next(i for i in extraction.inputs if i[0] == "recyclebin")
        self.assertEqual(recycle[2], "S-1-5-21-1-2-3-1001")
        manifest = json.loads((self.root / "extracted" / "image_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["image"]["format"], "ewf")
        with self.assertRaises(FileExistsError):
            extract_artifacts(segments[0], self.root / "extracted")

    def test_pipeline_analyze_image_end_to_end(self):
        segments = write_e01(self.root / "case.E01", mbr_disk(self.volume))
        result = Pipeline().analyze_image(segments[0], self.root / "work")
        recycled = [e for e in result.events if e.artifact == "recyclebin"]
        self.assertEqual(len(recycled), 1)
        self.assertEqual(recycled[0].sid, "S-1-5-21-1-2-3-1001")
        self.assertTrue(any(e.artifact == "psreadline" for e in result.events))
        image_evidence = [e for e in result.evidence if e.method == "IMAGE"]
        self.assertTrue(image_evidence)
        self.assertTrue(all(e.metadata["image_path"].startswith("\\") for e in image_evidence))
        save_result(result, self.root / "report")
        self.assertTrue((self.root / "report" / "image_manifest.json").exists())

    def test_cli_image_option(self):
        disk = self.root / "disk.dd"
        disk.write_bytes(mbr_disk(self.volume))
        code = main(["analyze", "--image", str(disk), "--output", str(self.root / "cli")])
        self.assertIn(code, (0, 1))
        self.assertTrue((self.root / "cli" / "extracted" / "image_manifest.json").exists())
        self.assertTrue((self.root / "cli" / "report.html").exists())


class AlignedDevice(io.BytesIO):
    """Behaves like a Windows volume handle: seeks and reads must be sector aligned."""

    def seek(self, offset, whence=0):
        assert whence == 0 and offset % 512 == 0, f"unaligned seek {offset}"
        return super().seek(offset)

    def read(self, size=-1):
        assert size > 0 and size % 512 == 0, f"unaligned read {size}"
        return super().read(size)


class LiveVolumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.volume, self.system = windows_volume()
        self.patches = [mock.patch.object(live, "is_admin", return_value=True),
                        mock.patch.object(live, "_open_device", side_effect=lambda _d: AlignedDevice(self.volume))]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        self.temp.cleanup()

    def test_drive_names(self):
        for spec in ("c", "C:", "C:\\", "\\\\.\\C:", "\\\\?\\c:"):
            self.assertEqual(live.live_device(spec), "\\\\.\\C:", spec)
        self.assertIsNone(live.live_device("C:\\Windows"))
        self.assertTrue(live.is_live_path("\\\\.\\D:"))
        self.assertFalse(live.is_live_path("disk.dd"))

    def test_unaligned_reads_are_widened(self):
        with open_image("\\\\.\\C:") as volume:
            self.assertIsInstance(volume, live.LiveVolume)
            self.assertEqual(volume.size, len(self.volume))
            self.assertEqual(volume.read(1000, 7000), self.volume[1000:8000])
            self.assertEqual(volume.read(len(self.volume) - 10, 100), self.volume[-10:])

    def test_requires_admin(self):
        with mock.patch.object(live, "is_admin", return_value=False):
            with self.assertRaises(PermissionError):
                open_image("\\\\.\\C:")
            with self.assertRaises(SystemExit):
                main(["analyze", "--live", "C:", "--output", str(self.root / "cli")])

    def test_locked_files_are_read_from_live_volume(self):
        result = Pipeline().analyze_image("\\\\.\\C:", self.root / "work")
        self.assertEqual(result.image["image_path"], "\\\\.\\C:")
        self.assertIn(live.LIVE_WARNING, result.image["warnings"])
        system = next(f for f in result.image["files"] if f["image_path"].endswith("\\config\\SYSTEM"))
        self.assertEqual(Path(system["extracted"]).read_bytes(), self.system)
        live_evidence = [e for e in result.evidence if e.method == "LIVE"]
        self.assertTrue(live_evidence)
        self.assertTrue(all(evidence_origin(e).startswith("[이 PC C:] \\") for e in live_evidence))
        self.assertTrue(any(e.artifact == "recyclebin" for e in result.events))

    def test_cli_live_option(self):
        code = main(["analyze", "--live", "C:", "--output", str(self.root / "cli")])
        self.assertIn(code, (0, 1))
        report = (self.root / "cli" / "report.html").read_text(encoding="utf-8")
        self.assertIn("이 PC 직접 분석", report)


class LabelAndReportTests(unittest.TestCase):
    def test_every_parser_has_plain_label(self):
        from log_hunter.core.labels import ARTIFACT_LABELS, artifact_from_label, artifact_label
        from log_hunter.core.pipeline import PARSERS
        for key in PARSERS:
            self.assertIn(key, ARTIFACT_LABELS)
            self.assertEqual(artifact_from_label(artifact_label(key)), key)
        self.assertEqual(artifact_label("bam"), "최근 실행한 프로그램")

    def test_report_uses_labels_and_escapes_evidence_strings(self):
        from log_hunter.core.models import ForensicEvent
        from log_hunter.core.report import export_reports
        hostile = "C:\\x\\</script><img src=x onerror=alert(1)>.exe"
        events = [ForensicEvent("prefetch", "a.pf", "execution_trace", "2020-12-30T00:00:00+00:00", "last_run_time", path=hostile)]
        with tempfile.TemporaryDirectory() as temp:
            export_reports(temp, [], events, [], [], [])
            page = (Path(temp) / "report.html").read_text(encoding="utf-8")
        self.assertIn("프로그램 실행 기록", page)
        script = page.split("<script>", 1)[1]
        self.assertNotIn("</script><img", script)


if __name__ == "__main__":
    unittest.main()
