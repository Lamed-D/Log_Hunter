"""Independent fixed-code encoder and native cross-checks for synthetic XPRESS data."""
import ctypes
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.parser.xpress import decompress, decompress_prefetch
from log_hunter.parser.prefetch import PrefetchParser


class Encoder:
    """Test-only encoder using a complete, fixed nine-bit alphabet."""
    def __init__(self):
        self.data = bytearray(b"\x99" * 256)
        self.words, self.bits, self.consumed = [], 0, 0
        self.reserve()
        self.reserve()

    def reserve(self):
        self.words.append(len(self.data))
        self.data.extend(b"\0\0")

    def emit(self, value, count):
        for shift in range(count - 1, -1, -1):
            word, bit = divmod(self.bits, 16)
            offset = self.words[word]
            current = int.from_bytes(self.data[offset:offset + 2], "little")
            current |= ((value >> shift) & 1) << (15 - bit)
            self.data[offset:offset + 2] = current.to_bytes(2, "little")
            self.bits += 1
        self.consumed += count
        while self.consumed > 16 * (len(self.words) - 1):
            self.reserve()

    def literal(self, value):
        self.emit(value, 9)

    def match(self, distance, length):
        width = distance.bit_length() - 1
        self.emit(256 + 16 * width + min(length - 3, 15), 9)
        if length >= 18:
            if length < 273:
                self.data.append(length - 18)
            else:
                self.data.append(255)
                if length - 3 <= 65535:
                    self.data.extend(struct.pack("<H", length - 3))
                else:
                    self.data.extend(bytes(2) + struct.pack("<I", length - 3))
        self.emit(distance - (1 << width), width)

    def finish(self):
        self.emit(256, 9)
        return bytes(self.data)


def encode_literals(data):
    blocks = []
    for offset in range(0, len(data), 65536):
        encoder = Encoder()
        for value in data[offset:offset + 65536]:
            encoder.literal(value)
        blocks.append(bytes(encoder.data) if offset + 65536 < len(data) else encoder.finish())
    return b"".join(blocks)


def native_decompress(compressed, size):
    api = ctypes.WinDLL("ntdll", use_last_error=True)
    workspace_size, fragment = ctypes.c_ulong(), ctypes.c_ulong()
    api.RtlGetCompressionWorkSpaceSize.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    api.RtlGetCompressionWorkSpaceSize.restype = ctypes.c_long
    api.RtlDecompressBufferEx.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                         ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    api.RtlDecompressBufferEx.restype = ctypes.c_long
    status = api.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(workspace_size), ctypes.byref(fragment))
    if status < 0:
        raise OSError(status)
    workspace = ctypes.create_string_buffer(workspace_size.value)
    output, source = ctypes.create_string_buffer(size), ctypes.create_string_buffer(compressed)
    actual = ctypes.c_ulong()
    status = api.RtlDecompressBufferEx(4, output, size, source, len(compressed), ctypes.byref(actual), workspace)
    if status < 0:
        raise OSError(f"native decompression: {status & 0xffffffff:#x}")
    if actual.value != size:
        raise AssertionError((actual.value, size))
    return output.raw[:actual.value]


class XpressTests(unittest.TestCase):
    def test_literal_roundtrip_multiple_blocks(self):
        rng = random.Random(42)
        for size in (0, 1, 84, 65535, 65536, 65537, 131073):
            data = rng.randbytes(size)
            with self.subTest(size=size):
                self.assertEqual(decompress(encode_literals(data), size), data)

    def test_matches_long_lengths_and_overlap(self):
        for length in (3, 17, 18, 272, 273, 65535, 70000):
            encoder = Encoder()
            encoder.literal(65)
            encoder.match(1, length)
            compressed = encoder.finish()
            expected = b"A" * (length + 1)
            self.assertEqual(decompress(compressed, len(expected)), expected)
            if os.name == "nt":
                self.assertEqual(native_decompress(compressed, len(expected)), expected)

    def test_match_crosses_block_boundary(self):
        encoder = Encoder()
        for value in b"ABC" * 21845:
            encoder.literal(value)
        encoder.match(3, 6)
        expected = b"ABC" * 21847
        compressed = encoder.finish()
        self.assertEqual(decompress(compressed, len(expected)), expected)
        if os.name == "nt":
            self.assertEqual(native_decompress(compressed, len(expected)), expected)

    def test_distance_bits_and_repeated_matches(self):
        encoder = Encoder()
        expected = bytearray(range(256))
        for value in expected:
            encoder.literal(value)
        for distance in (1, 2, 3, 7, 16, 127, 255, 256):
            encoder.match(distance, 42)
            for _ in range(42):
                expected.append(expected[-distance])
        compressed = encoder.finish()
        self.assertEqual(decompress(compressed, len(expected)), expected)
        if os.name == "nt":
            self.assertEqual(native_decompress(compressed, len(expected)), expected)

    def test_bad_table_truncation_and_invalid_offsets(self):
        for payload in (b"", bytes(260), b"\x11" * 260):
            with self.assertRaises(ValueError):
                decompress(payload, 84)
        encoder = Encoder()
        encoder.match(1, 3)
        with self.assertRaises(ValueError):
            decompress(encoder.finish(), 3)
        data = encode_literals(b"test")
        for size in (1, 255, 259, len(data) - 5):
            with self.assertRaises(ValueError):
                decompress(data[:size], 4)
        with self.assertRaises(ValueError):
            decompress(data, 64 * 1024 * 1024 + 1)

    def test_synthetic_mam_prefetch(self):
        data = bytearray(212)
        struct.pack_into("<I4s", data, 0, 30, b"SCCA")
        data[16:30] = "APP.EXE".encode("utf-16-le")
        struct.pack_into("<Q", data, 128, 132537600000000000)
        payload = b"MAM\x04" + struct.pack("<I", len(data)) + encode_literals(data)
        self.assertEqual(decompress_prefetch(payload), data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "APP.pf")
            path.write_bytes(payload)
            events = list(PrefetchParser().parse(path))
            self.assertEqual(events[0].process, "APP.EXE")
        with self.assertRaises(ValueError):
            decompress_prefetch(b"MAM\x84" + payload[4:])

    @unittest.skipUnless(os.name == "nt", "Windows native cross-check")
    def test_windows_literal_crosscheck(self):
        data = bytes(range(256)) * 300
        compressed = encode_literals(data)
        self.assertEqual(native_decompress(compressed, len(data)), decompress(compressed, len(data)))

    @unittest.skipUnless(os.name == "nt", "Windows native encoder")
    def test_windows_generated_variable_tables(self):
        api = ctypes.WinDLL("ntdll", use_last_error=True)
        api.RtlGetCompressionWorkSpaceSize.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
        api.RtlGetCompressionWorkSpaceSize.restype = ctypes.c_long
        api.RtlCompressBuffer.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                        ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        api.RtlCompressBuffer.restype = ctypes.c_long
        workspace_size, fragment = ctypes.c_ulong(), ctypes.c_ulong()
        self.assertGreaterEqual(api.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(workspace_size), ctypes.byref(fragment)), 0)
        workspace = ctypes.create_string_buffer(workspace_size.value)
        rng = random.Random(91)
        for data in (b"A" * 65537, bytes(range(256)) * 300, rng.randbytes(131073), b"ABCD" * 40000):
            source = ctypes.create_string_buffer(data)
            output = ctypes.create_string_buffer(len(data) * 2 + 4096)
            actual = ctypes.c_ulong()
            status = api.RtlCompressBuffer(4, source, len(data), output, len(output), 4096,
                                           ctypes.byref(actual), workspace)
            self.assertGreaterEqual(status, 0)
            compressed = output.raw[:actual.value]
            with self.subTest(size=len(data), prefix=data[:8].hex()):
                self.assertEqual(decompress(compressed, len(data)), data)
