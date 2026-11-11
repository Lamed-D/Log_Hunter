"""Crafted hives whose subkey lists share children (a DAG) must be walked in linear time."""
import struct
import tempfile
import time
import unittest
from pathlib import Path

from log_hunter.parser.amcache import AmcacheParser
from log_hunter.parser.mru import MRUParser
from log_hunter.parser.registry import Hive, marvin32, replay_logs, walk, base_checksum
from log_hunter.parser.shellbag import ShellBagParser


class HiveBuilder:
    """Minimal REGF writer: nk keys with lf subkey lists, enough for walk() tests."""

    def __init__(self):
        self.bins = bytearray(b"hbin" + bytes(28))

    def cell(self, payload):
        size = 4 + len(payload)
        size += (-size) % 8
        offset = len(self.bins)
        self.bins += struct.pack("<i", -size) + payload + bytes(size - 4 - len(payload))
        return offset

    def reserve(self, name):
        return self.cell(bytes(76 + len(name)))

    def key(self, offset, name, children=()):
        data = bytearray(76 + len(name))
        data[:2] = b"nk"
        struct.pack_into("<HQ", data, 2, 0x20, 133000000000000000)
        subkeys = self.cell(b"lf" + struct.pack("<H", len(children)) +
                            b"".join(struct.pack("<II", c, 0) for c in children)) if children else 0xFFFFFFFF
        struct.pack_into("<I", data, 20, len(children))
        struct.pack_into("<I", data, 28, subkeys)
        struct.pack_into("<I", data, 40, 0xFFFFFFFF)
        struct.pack_into("<H", data, 72, len(name))
        data[76:] = name.encode("latin1")
        self.bins[offset + 4:offset + 4 + len(data)] = data

    def build(self, root):
        base = bytearray(4096)
        base[:4] = b"regf"
        struct.pack_into("<II", base, 4, 1, 1)
        struct.pack_into("<I", base, 0x24, root)
        struct.pack_into("<I", base, 0x28, len(self.bins))
        return bytes(base + self.bins)


def dag_hive(path_names, depth=40):
    """path_names lead to a chain where every key lists the next key twice: 2**depth naive paths."""
    builder = HiveBuilder()
    chain = [builder.reserve(name) for name in path_names]
    dag = [builder.reserve(f"d{i}") for i in range(depth)]
    for index, name in enumerate(path_names):
        builder.key(chain[index], name, [chain[index + 1] if index + 1 < len(chain) else dag[0]])
    for index in range(depth):
        builder.key(dag[index], f"d{index}", [dag[index + 1]] * 2 if index + 1 < depth else ())
    return builder.build(chain[0])


class RegistryDagTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _hive(self, names):
        path = self.root / "hive"
        path.write_bytes(dag_hive(names))
        return path

    def test_walk_visits_each_key_once(self):
        hive = Hive(self._hive(["ROOT", "A"]))
        started = time.monotonic()
        keys = list(walk(hive.root))
        self.assertEqual(len(keys), 42)
        self.assertLess(time.monotonic() - started, 5)

    def test_parsers_finish_on_dag_hives(self):
        cases = [(AmcacheParser, ["ROOT", "Root", "InventoryApplicationFile"]),
                 (MRUParser, ["ROOT", "Software", "Microsoft", "Windows", "CurrentVersion", "Explorer", "RecentDocs"]),
                 (ShellBagParser, ["ROOT", "Software", "Microsoft", "Windows", "Shell", "BagMRU"])]
        for parser, names in cases:
            with self.subTest(parser=parser.__name__):
                started = time.monotonic()
                list(parser().parse(self._hive(names)))
                self.assertLess(time.monotonic() - started, 5)


def _dirty_hive(text):
    """One-value hive (Name=text, UTF-16) with mismatched sequence numbers 2/1 and 4096 bytes of bins."""
    from test_analysis import build_hive
    data = bytearray(build_hive([("Name", 1, (text + "\0").encode("utf-16-le"))]))
    data.extend(bytes(8192 - len(data)))
    struct.pack_into("<II", data, 4, 2, 1)
    struct.pack_into("<I", data, 0x28, 4096)
    struct.pack_into("<I", data, 508, base_checksum(data))
    return bytes(data)


def _log_entry(sequence, pages, bins_size=4096, corrupt=False):
    body = b"".join(struct.pack("<II", offset, len(page)) for offset, page in pages) + b"".join(p for _o, p in pages)
    size = 40 + len(body)
    size += (-size) % 512
    body += bytes(size - 40 - len(body))
    head = b"HvLE" + struct.pack("<IIIII", size, 0, sequence, bins_size, len(pages))
    head += struct.pack("<Q", marvin32(body))
    head += struct.pack("<Q", marvin32(head))
    entry = bytearray(head + body)
    if corrupt:
        entry[-1] ^= 0xFF
    return bytes(entry)


def _log(*entries):
    base = bytearray(512)
    base[:4] = b"regf"
    sequence = struct.unpack_from("<I", entries[0], 12)[0] if entries else 9
    struct.pack_into("<II", base, 4, sequence, sequence)
    struct.pack_into("<I", base, 28, 6)
    struct.pack_into("<I", base, 508, base_checksum(base))
    return bytes(base) + b"".join(entries)


class LogReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.hive = Path(self.temp.name) / "SYSTEM"
        self.hive.write_bytes(_dirty_hive("before"))
        bins = bytearray(self.hive.read_bytes()[4096:8192])
        old, new = "before".encode("utf-16-le"), "after!".encode("utf-16-le")
        bins[bins.index(old):bins.index(old) + len(old)] = new
        self.page = bytes(bins)

    def tearDown(self):
        self.temp.cleanup()

    def _value(self, data):
        recovered = Path(self.temp.name) / "recovered"
        recovered.write_bytes(data)
        return Hive(recovered).root.value("Name")

    def test_verified_entries_are_applied(self):
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(1, [(0, self.page)])))
        data, info = replay_logs(self.hive)
        self.assertTrue(info["recovered"], info)
        self.assertEqual(info["pages_applied"], 1)
        self.assertEqual(self._value(data), "after!")
        self.assertEqual(self._value(self.hive.read_bytes()), "before")  # original untouched
        self.assertEqual(info["new_sequence"], 1)
        self.assertEqual(struct.unpack_from("<II", data, 4), (1, 1))
        self.assertEqual(struct.unpack_from("<I", data, 508)[0], base_checksum(data))

    def test_microsoft_public_hash_vector(self):
        self.assertEqual(marvin32(b"abc", 0xd53cd9cecd0893b7), 0x22c74339492769bf)

    def test_consecutive_entries_from_both_logs(self):
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(1, [(0, self.page)])))
        next_page = self.page.replace("after!".encode("utf-16-le"), "final!".encode("utf-16-le"))
        Path(str(self.hive) + ".LOG2").write_bytes(_log(_log_entry(2, [(0, next_page)])))
        data, info = replay_logs(self.hive)
        self.assertTrue(info["recovered"])
        self.assertEqual(info["entries_applied"], 2)
        self.assertEqual(self._value(data), "final!")

    def test_conflicting_sequence_does_not_choose_arbitrarily(self):
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(1, [(0, self.page)])))
        Path(str(self.hive) + ".LOG2").write_bytes(_log(_log_entry(1, [(0, self.hive.read_bytes()[4096:])])))
        data, info = replay_logs(self.hive)
        self.assertFalse(info["recovered"])
        self.assertEqual(data, self.hive.read_bytes())
        self.assertTrue(any("충돌" in message for message in info["warnings"]))

    def test_torn_second_entry_preserves_verified_prefix(self):
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(1, [(0, self.page)]),
                                                        _log_entry(2, [(0, self.page)], corrupt=True)))
        data, info = replay_logs(self.hive)
        self.assertEqual(info["entries_applied"], 1)
        self.assertTrue(info["warnings"])
        self.assertEqual(self._value(data), "after!")

    def test_untrusted_hive_header_does_not_expand_growth_limit(self):
        hive = bytearray(self.hive.read_bytes())
        struct.pack_into("<I", hive, 0x28, 0xfffff000)
        struct.pack_into("<I", hive, 508, base_checksum(hive))
        self.hive.write_bytes(hive)
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(1, [(0, self.page)], bins_size=0xfffff000)))
        data, info = replay_logs(self.hive)
        self.assertFalse(info["recovered"])
        self.assertEqual(len(data), 8192)

    def test_invalid_base_checksum_is_not_recovered_by_guessing(self):
        hive = bytearray(self.hive.read_bytes())
        hive[508] ^= 1
        self.hive.write_bytes(hive)
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(1, [(0, self.page)])))
        data, info = replay_logs(self.hive)
        self.assertFalse(info["recovered"])
        self.assertEqual(data, bytes(hive))

    def test_sequence_wrap_across_logs(self):
        hive = bytearray(self.hive.read_bytes())
        struct.pack_into("<II", hive, 4, 0, 0xffffffff)
        struct.pack_into("<I", hive, 508, base_checksum(hive))
        self.hive.write_bytes(hive)
        Path(str(self.hive) + ".LOG1").write_bytes(_log(_log_entry(0xffffffff, [(0, self.page)])))
        Path(str(self.hive) + ".LOG2").write_bytes(_log(_log_entry(0, [(0, self.page)])))
        data, info = replay_logs(self.hive)
        self.assertEqual(info["entries_applied"], 2)
        self.assertEqual(struct.unpack_from("<II", data, 4), (0, 0))

    def test_torn_or_out_of_range_entries_are_not_applied(self):
        cases = {"hash": _log(_log_entry(1, [(0, self.page)], corrupt=True)),
                 "range": _log(_log_entry(1, [(0x7FFF0000, self.page)], bins_size=0x7FFF1000)),
                 "gap": _log(_log_entry(5, [(0, self.page)])),
                 "legacy": _log()[:512] + b"DIRT" + bytes(508)}
        for name, log in cases.items():
            with self.subTest(case=name):
                Path(str(self.hive) + ".LOG1").write_bytes(log)
                data, info = replay_logs(self.hive)
                self.assertFalse(info["recovered"], info)
                self.assertEqual(len(data), 8192)
                self.assertTrue(info["warnings"])


if __name__ == "__main__":
    unittest.main()
