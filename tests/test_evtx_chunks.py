"""Synthetic EVTX records with chunk-relative names and shared template definitions."""
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from log_hunter.parser.evtx import EVTXParser
from log_hunter.parser.binxml import BinXmlParser

STAMP = 132537600000000000


class ChunkWriter:
    def __init__(self):
        self.data = bytearray(512)
        self.data[:8] = b"ElfChnk\0"
        self.names = {}
        self.records = 0
        self.dependency = True

    def name(self, name):
        if name in self.names:
            self.data.extend(struct.pack("<I", self.names[name]))
            return
        position = len(self.data) + 4
        self.data.extend(struct.pack("<I", position))
        self.names[name] = position
        self.data.extend(struct.pack("<IHH", 0, 0, len(name)) + name.encode("utf-16-le") + b"\0\0")

    def value(self, value):
        if isinstance(value, tuple):
            index, kind, *optional = value
            self.data.extend((b"\x0e" if optional and optional[0] else b"\x0d") + struct.pack("<HB", index, kind))
        else:
            encoded = str(value).encode("utf-16-le")
            self.data.extend(b"\x05\x01" + struct.pack("<H", len(encoded) // 2) + encoded)

    def element(self, name, attrs=(), children=(), text=None):
        start = len(self.data)
        prefix = struct.pack("<HI", 0xffff, 0) if self.dependency else bytes(4)
        header_size = 7 if self.dependency else 5
        self.data.extend(bytes([0x41 if attrs else 1]) + prefix)
        self.name(name)
        if attrs:
            count_at = len(self.data)
            self.data.extend(bytes(4))
            for index, (key, value) in enumerate(attrs):
                self.data.append(0x46 if index + 1 < len(attrs) else 6)
                self.name(key)
                self.value(value)
            struct.pack_into("<I", self.data, count_at, len(self.data) - count_at - 4)
        self.data.append(2)
        if text is not None:
            self.value(text)
        for child in children:
            self.element(**child)
        self.data.append(4)
        struct.pack_into("<I", self.data, start + (3 if self.dependency else 1), len(self.data) - start - header_size)

    def event(self, event_id):
        self.element("Event", children=[
            dict(name="System", children=[
                dict(name="Provider", attrs=[("Name", "Microsoft-Windows-Security-Auditing")]),
                dict(name="EventID", text=event_id),
                dict(name="TimeCreated", attrs=[("SystemTime", "2020-12-30T00:00:00.0000000Z")]),
                dict(name="Channel", text="Security"),
                dict(name="Security", attrs=[("UserID", "S-1-5-18")]),
            ]),
            dict(name="EventData", children=[dict(name="Data", attrs=[("Name", "TargetUserName")], text="operator")]),
        ])

    def begin(self):
        start = len(self.data)
        self.data.extend(bytes(24) + b"\x0f\x01\x01\x00")
        return start

    def finish(self, start):
        self.data.append(0)
        self.data.extend(bytes((-(len(self.data) - start + 4)) % 8))
        size = len(self.data) - start + 4
        self.data.extend(struct.pack("<I", size))
        self.records += 1
        struct.pack_into("<IIQQ", self.data, start, 0x2a2a, size, self.records, STAMP)

    def direct(self, event_id=4624):
        start = self.begin()
        self.event(event_id)
        self.finish(start)

    def templated(self, event_id=4624, reference=None):
        start = self.begin()
        self.data.extend(b"\x0c\x01" + struct.pack("<II", 1, reference if reference is not None else len(self.data) + 10))
        definition = reference
        if reference is None:
            definition = len(self.data)
            self.data.extend(bytes(24))
            body = len(self.data)
            self.data.extend(b"\x0f\x01\x01\x00")
            self.event((0, 6))
            self.data.append(0)
            struct.pack_into("<I", self.data, definition + 20, len(self.data) - body)
        self.data.extend(struct.pack("<I HBB H", 1, 2, 6, 0, event_id))
        self.finish(start)
        return definition

    def custom_template(self, body_writer, values):
        start = self.begin()
        definition = len(self.data) + 10
        self.data.extend(b"\x0c\x01" + struct.pack("<II", 1, definition))
        self.last_definition = definition
        self.data.extend(bytes(24) + b"\x0f\x01\x01\x00")
        body_writer(self)
        self.data.append(0)
        struct.pack_into("<I", self.data, definition + 20, len(self.data) - definition - 24)
        self.data.extend(struct.pack("<I", len(values)))
        descriptors = len(self.data)
        self.data.extend(bytes(len(values) * 4))
        for index, (kind, value) in enumerate(values):
            value_start = len(self.data)
            if callable(value):
                value(self)
            else:
                self.data.extend(value)
            struct.pack_into("<HBB", self.data, descriptors + index * 4, len(self.data) - value_start, kind, 0)
        self.finish(start)

    def file(self, corrupt_prefix=False):
        chunk = bytearray(self.data)
        struct.pack_into("<I", chunk, 48, len(chunk))
        struct.pack_into("<I", chunk, 52, zlib.crc32(chunk[512:]))
        struct.pack_into("<I", chunk, 124, zlib.crc32(chunk[:120] + chunk[128:512]))
        chunk.extend(bytes(65536 - len(chunk)))
        header = bytearray(4096)
        header[:8] = b"ElfFile\0"
        struct.pack_into("<HH", header, 36, 1, 3)
        struct.pack_into("<H", header, 42, 2 if corrupt_prefix else 1)
        struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
        return bytes(header) + (b"bad" + bytes(65533) if corrupt_prefix else b"") + bytes(chunk)


class EVTXChunkTests(unittest.TestCase):
    def parse(self, writer, corrupt_prefix=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "synthetic.evtx")
            path.write_bytes(writer if isinstance(writer, bytes) else writer.file(corrupt_prefix))
            parser = EVTXParser()
            events = list(parser.parse(path))
        return events, parser.errors

    def test_real_fields_and_chunk_crc(self):
        writer = ChunkWriter()
        writer.direct()
        events, errors = self.parse(writer)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.details["event_id"], 4624)
        self.assertEqual(event.details["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(event.details["event_data"]["TargetUserName"], "operator")
        self.assertEqual(event.sid, "S-1-5-18")
        self.assertEqual(event.details["time_created"], "2020-12-30T00:00:00.0000000Z")
        self.assertTrue(event.details["checksums_verified"])
        self.assertEqual(errors, [])

    def test_bad_name_reference_is_partial_and_record_is_preserved(self):
        writer = ChunkWriter()
        writer.direct()
        struct.pack_into("<I", writer.data, 512 + 24 + 4 + 7, 0xfffffff0)
        events, errors = self.parse(writer)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, "partial")
        self.assertTrue(any("BinXML" in error.message for error in errors))

    def test_truncated_fragment_raises_without_looping(self):
        for data in (b"\x0f", b"\x01", b"\x0c\x01", b"\x0d\0\0"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                BinXmlParser(data).parse()

    def test_template_and_names_reused_from_earlier_record(self):
        writer = ChunkWriter()
        definition = writer.templated(4624)
        writer.templated(4625, definition)
        events, errors = self.parse(writer)
        self.assertEqual([event.details["event_id"] for event in events], [4624, 4625])
        self.assertEqual(errors, [])

    def test_nested_binxml_typed_values_and_optional_null(self):
        writer = ChunkWriter()
        def nested(w):
            w.data.extend(b"\x0f\x01\x01\x00")
            w.dependency = False
            w.element("Data", attrs=[("Name", "Nested")], text="child")
            w.dependency = True
            w.data.append(0)
        def template(w):
            w.element("Event", children=[
                dict(name="System", children=[
                    dict(name="Provider", attrs=[("Name", "Microsoft-Windows-Security-Auditing")]),
                    dict(name="EventID", text=(0, 6)),
                    dict(name="TimeCreated", attrs=[("SystemTime", (1, 0x11))]),
                    dict(name="Security", attrs=[("UserID", (2, 0x13))]),
                ]),
                dict(name="EventData", text=(3, 0x21), children=[
                    dict(name="Data", attrs=[("Name", "Numbers")], text=(4, 0x88)),
                    dict(name="Data", attrs=[("Name", "Missing")], text=(5, 0, True)),
                    dict(name="Data", attrs=[("Name", "Binary")], text=(6, 0x0e)),
                    dict(name="Data", attrs=[("Name", "EmptyArray")], text=(7, 0x88)),
                ]),
            ])
        sid = b"\x01\x01" + (5).to_bytes(6, "big") + struct.pack("<I", 18)
        writer.custom_template(template, [(6, struct.pack("<H", 4624)), (0x11, struct.pack("<Q", STAMP)),
                                         (0x13, sid), (0x21, nested), (0x88, struct.pack("<2I", 1, 2)),
                                         (0, b""), (0x0e, b"\xab\xcd"), (0x88, b"")])
        events, errors = self.parse(writer)
        self.assertEqual(errors, [])
        event = events[0]
        self.assertEqual(event.details["event_id"], 4624)
        self.assertEqual(event.sid, "S-1-5-18")
        self.assertEqual(event.details["time_created"], "2020-12-30T00:00:00+00:00")
        data = event.details["event_data"]
        self.assertEqual(data["Nested"], "child")
        self.assertEqual(data["Numbers"], [1, 2])
        self.assertEqual(data["EmptyArray"], [])
        self.assertEqual(data["Binary"], "abcd")
        self.assertNotIn("Missing", data)

    def test_recursive_template_is_partial_without_hanging(self):
        writer = ChunkWriter()
        def recursive(w):
            w.data.extend(b"\x0c\x01" + struct.pack("<II", 1, w.last_definition) + bytes(4))
        writer.custom_template(recursive, [])
        events, errors = self.parse(writer)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, "partial")
        self.assertTrue(errors)

    def test_bad_provider_type_does_not_hide_next_record(self):
        writer = ChunkWriter()
        def invalid(w):
            w.element("Event", children=[dict(name="System", children=[
                dict(name="Provider", attrs=[("Name", (0, 0x88))]), dict(name="EventID", text="4624")])])
        writer.custom_template(invalid, [(0x88, struct.pack("<2I", 1, 2))])
        writer.direct(4625)
        events, errors = self.parse(writer)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].status, "partial")
        self.assertEqual(events[1].details["event_id"], 4625)
        self.assertTrue(errors)

    def test_inline_unicode_counts_utf16_code_units(self):
        writer = ChunkWriter()
        start = writer.begin()
        writer.element("Event", children=[dict(name="System", children=[dict(name="EventID", text="4624")]),
            dict(name="EventData", children=[dict(name="Data", attrs=[("Name", "Text")], text="실행🙂")])])
        writer.finish(start)
        events, errors = self.parse(writer)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].details["event_data"]["Text"], "실행🙂")

    def test_direct_fragment_without_dependency_ids(self):
        writer = ChunkWriter()
        writer.dependency = False
        writer.direct()
        events, errors = self.parse(writer)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].details["event_id"], 4624)

    def test_crc_ignores_unused_padding_but_marks_wrong_checksum_partial(self):
        writer = ChunkWriter()
        writer.direct()
        payload = bytearray(writer.file())
        payload[-1] = 42
        events, errors = self.parse(bytes(payload))
        self.assertEqual(errors, [])
        self.assertEqual(events[0].status, "ok")
        payload[4096 + 52] ^= 1
        events, errors = self.parse(bytes(payload))
        self.assertTrue(errors)
        self.assertEqual(events[0].status, "partial")

    def test_archived_zero_padding_is_not_a_bad_record(self):
        writer = ChunkWriter()
        writer.direct()
        payload = bytearray(writer.file())
        chunk = payload[4096:]
        struct.pack_into("<I", chunk, 48, 65536)
        struct.pack_into("<I", chunk, 52, zlib.crc32(chunk[512:]))
        struct.pack_into("<I", chunk, 124, zlib.crc32(chunk[:120] + chunk[128:512]))
        events, errors = self.parse(bytes(payload[:4096] + chunk))
        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])

    def test_bad_chunk_does_not_hide_later_records(self):
        writer = ChunkWriter()
        writer.direct()
        events, errors = self.parse(writer, True)
        self.assertEqual(events[0].details["event_id"], 4624)
        self.assertTrue(any("시그니처" in error.message for error in errors))
