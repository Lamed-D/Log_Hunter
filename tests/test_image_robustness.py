"""Crafted/corrupt disk images must not escape the output folder, loop, or fill the disk."""
import struct
import tempfile
import time
import unittest
from pathlib import Path

from log_hunter.image import extract_artifacts
from log_hunter.image.ewf import RawImage
from log_hunter.image.extract import glob_ntfs
from log_hunter.image.ntfs import NTFSVolume
from test_image import CLUSTER, MFT_LCN, RECORD, NTFSBuilder

PF = b"MAM\x04" + bytes(60)


def _patch_data_attribute(image, record_number, offset, fmt, value):
    """Overwrite a field of the unnamed $DATA attribute of one MFT record (fixup bytes untouched)."""
    data = bytearray(image)
    start = MFT_LCN * CLUSTER + record_number * RECORD
    position, = struct.unpack_from("<H", data, start + 20)
    while True:
        kind, size = struct.unpack_from("<II", data, start + position)
        if kind == 0x80:
            break
        position += size
    struct.pack_into(fmt, data, start + position + offset, value)
    return bytes(data)


class ImageRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _disk(self, builder, name="disk.dd"):
        path = self.root / name
        path.write_bytes(builder if isinstance(builder, bytes) else builder.build())
        return path

    def test_file_names_with_separators_stay_inside_output(self):
        builder = NTFSBuilder()
        prefetch = builder.makedirs("Windows/Prefetch")
        builder.add_file(prefetch, "..\\..\\..\\..\\..\\ESCAPED.EXE-1.pf", PF, mode="resident")
        builder.add_file(prefetch, "../../../../../SLASH.EXE-1.pf", PF, mode="resident")
        output = self.root / "a" / "b" / "out"
        extraction = extract_artifacts(self._disk(builder), output)
        self.assertEqual(len(extraction.files), 2)
        for item in extraction.files:
            extracted = Path(item["extracted"]).resolve()
            self.assertTrue(extracted.is_relative_to(output.resolve()), extracted)
            self.assertTrue(extracted.exists())
        for pattern in ("ESCAPED*", "SLASH*"):
            self.assertTrue(all(p.is_relative_to(output) for p in self.root.rglob(pattern)))

    def test_directory_cycles_are_walked_once(self):
        builder = NTFSBuilder()
        tasks = builder.makedirs("Windows/System32/Tasks")
        for name in "XYZ":
            child = builder.mkdir(tasks, name)
            builder.children[child].append((tasks, "back", True, 0))
        builder.add_file(tasks, "job", b"<Task/>", mode="resident")
        with RawImage(self._disk(builder)) as image:
            volume = NTFSVolume(image, 0)
            started = time.monotonic()
            found = list(glob_ntfs(volume, "Windows/System32/Tasks/**"))
        self.assertEqual([parts[-1] for parts, _e, _p in found], ["job"])
        self.assertLess(time.monotonic() - started, 5)

    def test_name_collision_keeps_both_files(self):
        builder = NTFSBuilder()
        prefetch = builder.makedirs("Windows/Prefetch")
        builder.add_file(prefetch, "A.EXE-1.pf", PF, mode="resident")
        builder.add_file(prefetch, "a.exe-1.pf", PF + b"x", mode="resident")
        extraction = extract_artifacts(self._disk(builder), self.root / "out")
        self.assertEqual(len(extraction.files), 2)
        extracted = [Path(f["extracted"]) for f in extraction.files]
        self.assertEqual(len(set(extracted)), 2)
        self.assertTrue(all(p.exists() for p in extracted))
        self.assertEqual(sorted(p.stat().st_size for p in extracted), [len(PF), len(PF) + 1])

    def test_stream_size_is_bounded_by_allocation(self):
        builder = NTFSBuilder()
        prefetch = builder.makedirs("Windows/Prefetch")
        record = builder.add_file(prefetch, "BIG.EXE-1.pf", b"MAM\x04" + bytes(4000))
        image = _patch_data_attribute(builder.build(), record, 48, "<Q", 1 << 40)  # real size: 1 TiB
        extraction = extract_artifacts(self._disk(image), self.root / "out")
        self.assertEqual(len(extraction.files), 1)
        self.assertLessEqual(extraction.files[0]["size"], CLUSTER)
        self.assertTrue(any("크기" in w for w in extraction.warnings))


if __name__ == "__main__":
    unittest.main()
