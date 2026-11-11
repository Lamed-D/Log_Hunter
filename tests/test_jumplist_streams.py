"""Synthetic compound streams and versioned destination records, with no real evidence."""
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.parser.jumplist import CFBF_MAGIC, LNK_SIGNATURE, JumpListParser, _extract_cfbf_streams, _parse_destlist

END, FREE, FAT = 0xfffffffe, 0xffffffff, 0xfffffffd
STAMP = 132537600000000000


def lnk(target):
    raw = bytearray(76)
    raw[:20] = LNK_SIGNATURE
    struct.pack_into("<I", raw, 20, 0x88)  # Unicode relative path.
    encoded = target.encode("utf-16-le")
    return bytes(raw) + struct.pack("<H", len(encoded) // 2) + encoded


def destlist(version, entries):
    raw = bytearray(32)
    struct.pack_into("<II", raw, 0, version, len(entries))
    for identifier, path, stamp in entries:
        size = 114 if version == 1 else 130
        entry = bytearray(size)
        struct.pack_into("<I", entry, 88, identifier)
        struct.pack_into("<Q", entry, 100, stamp)
        struct.pack_into("<i", entry, 108, -1)
        encoded = path.encode("utf-16-le")
        struct.pack_into("<H", entry, size - 2, len(encoded) // 2)
        raw.extend(entry + encoded + (bytes(4) if version != 1 else b""))
    return bytes(raw)


def compound(streams, mini=True, sector_size=512):
    """One FAT, directory, MiniFAT and mini stream; enough to cross mini-sector boundaries."""
    sectors, allocation = [], []
    def add(payload):
        start = len(sectors)
        chunks = [payload[i:i + sector_size] for i in range(0, len(payload), sector_size)] or [b""]
        for chunk in chunks:
            sectors.append(chunk.ljust(sector_size, b"\0"))
            allocation.append(len(sectors) if len(sectors) < start + len(chunks) else END)
        return start
    fat_sector = add(bytes(sector_size))
    directory_sector = add(bytes(sector_size))
    mini_fat, mini_data, records = [], bytearray(), []
    for name, payload in streams.items():
        if mini and len(payload) < 4096:
            start = len(mini_fat)
            count = (len(payload) + 63) // 64
            mini_fat.extend(range(start + 1, start + count))
            mini_fat.append(END)
            mini_data.extend(payload.ljust(count * 64, b"\0"))
        else:
            payload = payload.ljust(4096, b"\0") if not mini else payload
            start = add(payload)
        records.append((name, start, len(payload)))
    mini_fat_start = add(struct.pack(f"<{len(mini_fat)}I", *mini_fat)) if mini_fat else END
    root_start = add(bytes(mini_data)) if mini_data else END
    def entry(name, kind, start, size, right=FREE, child=FREE):
        data = bytearray(128)
        encoded = (name + "\0").encode("utf-16-le")
        data[:len(encoded)] = encoded
        struct.pack_into("<H", data, 64, len(encoded))
        data[66:68] = bytes([kind, 1])
        struct.pack_into("<III", data, 68, FREE, right, child)
        struct.pack_into("<IQ", data, 116, start, size)
        return data
    directory = entry("Root Entry", 5, root_start, len(mini_data), child=1 if records else FREE)
    for index, (name, start, size) in enumerate(records, 1):
        directory.extend(entry(name, 2, start, size, right=index + 1 if index < len(records) else FREE))
    if len(directory) > sector_size:
        raise ValueError("test directory too large")
    sectors[directory_sector] = bytes(directory).ljust(sector_size, b"\0")
    allocation[fat_sector] = FAT
    fat_bytes = struct.pack(f"<{len(allocation)}I", *allocation)
    sectors[fat_sector] = fat_bytes + b"\xff" * (sector_size - len(fat_bytes))
    header = bytearray(sector_size)
    header[:8] = CFBF_MAGIC
    struct.pack_into("<HHHHH", header, 24, 0x3e, 3 if sector_size == 512 else 4, 0xfffe,
                     9 if sector_size == 512 else 12, 6)
    struct.pack_into("<II", header, 44, 1, directory_sector)
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<II", header, 60, mini_fat_start, 1 if mini_fat else 0)
    struct.pack_into("<II", header, 68, END, 0)
    struct.pack_into("<109I", header, 76, fat_sector, *([FREE] * 108))
    return bytes(header) + b"".join(sectors)


class JumpListStreamTests(unittest.TestCase):
    def test_hexadecimal_stream_ids_keep_their_own_timestamps(self):
        index = destlist(1, [(10, r"C:\ten.txt", STAMP), (16, r"C:\sixteen.txt", STAMP + 10000000)])
        data = compound({"DestList": index, "a": lnk(r"C:\ten.txt"), "10": lnk(r"C:\sixteen.txt")}, mini=False)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "synthetic.automaticDestinations-ms")
            path.write_bytes(data)
            events = list(JumpListParser().parse(path))
        by_path = {event.path: event for event in events}
        self.assertEqual(len(events), 2)
        self.assertEqual(by_path[r"C:\ten.txt"].details["stream_index"], "a")
        self.assertEqual(by_path[r"C:\sixteen.txt"].details["stream_index"], "10")
        self.assertNotEqual(by_path[r"C:\ten.txt"].timestamp, by_path[r"C:\sixteen.txt"].timestamp)

    def test_small_lnk_and_destlist_streams_use_minifat(self):
        source = {"DestList": destlist(3, [(10, r"C:\mini.txt", STAMP)]), "a": lnk(r"C:\mini.txt")}
        for sector_size in (512, 4096):
            with self.subTest(sector_size=sector_size):
                streams, index = _extract_cfbf_streams(compound(source, sector_size=sector_size))
                self.assertEqual(streams["a"], source["a"])
                self.assertEqual(index, source["DestList"])

    def test_destlist_versions_keep_second_entry_aligned(self):
        for version in (1, 3, 4):
            with self.subTest(version=version):
                rows = _parse_destlist(destlist(version, [(10, r"C:\one.txt", STAMP), (16, r"C:\two.txt", STAMP)]))
                self.assertEqual([row["entry_id"] for row in rows], [10, 16])
                self.assertEqual([row["path"] for row in rows], [r"C:\one.txt", r"C:\two.txt"])

    def test_cyclic_minifat_does_not_hide_other_stream(self):
        data = bytearray(compound({"a": lnk(r"C:\broken.txt"), "b": lnk(r"C:\valid.txt")}))
        mini_fat = struct.unpack_from("<I", data, 60)[0]
        struct.pack_into("<I", data, (mini_fat + 1) * 512, 0)
        errors = []
        streams, _ = _extract_cfbf_streams(data, lambda locator, message: errors.append((locator, message)))
        self.assertNotIn("a", streams)
        self.assertIn("b", streams)
        self.assertTrue(errors)

    def test_invalid_header_shift_is_rejected_before_allocation(self):
        data = bytearray(compound({"a": lnk(r"C:\small.txt")}))
        struct.pack_into("<H", data, 30, 0xffff)
        with self.assertRaises(ValueError):
            _extract_cfbf_streams(data)

    def test_unknown_version_and_truncated_path_are_reported(self):
        with self.assertRaises(ValueError):
            _parse_destlist(destlist(99, [(1, "x", STAMP)]))
        errors = []
        data = destlist(3, [(1, "one", STAMP), (2, "two", STAMP)])[:-5]
        rows = _parse_destlist(data, lambda locator, message: errors.append(message))
        self.assertEqual(len(rows), 1)
        self.assertTrue(errors)

    def test_invalid_lnk_preserves_valid_destlist_path(self):
        data = compound({"DestList": destlist(4, [(10, r"C:\retained.txt", STAMP)]), "a": b"bad LNK"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "synthetic.automaticDestinations-ms")
            path.write_bytes(data)
            parser = JumpListParser()
            events = list(parser.parse(path))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].path, r"C:\retained.txt")
        self.assertEqual(events[0].status, "partial")
        self.assertTrue(parser.errors)

    def test_difat_extension_is_used_for_high_numbered_sector(self):
        fat_count, directory, difat = 111, 111, 112
        first_data = 109 * 128 + 1
        size = (first_data + 8 + 1) * 512
        data = bytearray(size)
        basic = compound({"DestList": b"index"}, mini=False)
        data[:512] = basic[:512]
        struct.pack_into("<II", data, 44, fat_count, directory)
        struct.pack_into("<II", data, 68, difat, 1)
        struct.pack_into("<109I", data, 76, *range(109))
        allocation = [FREE] * (fat_count * 128)
        for index in range(fat_count):
            allocation[index] = FAT
        allocation[directory], allocation[difat] = END, 0xfffffffc
        for index in range(first_data, first_data + 8):
            allocation[index] = index + 1 if index < first_data + 7 else END
        for index in range(fat_count):
            struct.pack_into("<128I", data, (index + 1) * 512, *allocation[index * 128:(index + 1) * 128])
        data[(directory + 1) * 512:(directory + 2) * 512] = basic[1024:1536]
        struct.pack_into("<I", data, (directory + 1) * 512 + 128 + 116, first_data)
        struct.pack_into("<128I", data, (difat + 1) * 512, 109, 110, *([FREE] * 125), END)
        data[(first_data + 1) * 512:(first_data + 1) * 512 + 5] = b"index"
        streams, index = _extract_cfbf_streams(data)
        self.assertEqual(streams, {})
        self.assertEqual(index[:5], b"index")

    def test_duplicate_destination_id_does_not_assign_either_timestamp(self):
        index = destlist(4, [(10, r"C:\first.txt", STAMP), (10, r"C:\second.txt", STAMP + 10000000)])
        data = compound({"DestList": index, "a": lnk(r"C:\target.txt")})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "synthetic.automaticDestinations-ms")
            path.write_bytes(data)
            parser = JumpListParser()
            events = list(parser.parse(path))
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].timestamp)
        self.assertEqual(events[0].status, "partial")
        self.assertTrue(parser.errors)

    def test_undocumented_counter_is_kept_raw(self):
        for version, offset in ((1, 96), (3, 116), (4, 116)):
            data = bytearray(destlist(version, [(10, "x", STAMP)]))
            struct.pack_into("<I", data, 32 + offset, 0x3f800000)
            entry = _parse_destlist(data)[0]
            self.assertIsNone(entry["access_count"])
            self.assertEqual(entry["access_count_raw"], "0000803f")
