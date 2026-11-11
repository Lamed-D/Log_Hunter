"""Recycle companion metadata and complete read-only file/folder export."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from test_image import NTFSBuilder, recycle_record
from log_hunter.core.pipeline import Pipeline
from log_hunter.image.extract import extract_artifacts
from log_hunter.image.recycle import save_recycle_pair, RecyclePairError
from log_hunter.parser.recyclebin import RecycleBinParser

SID = "S-1-5-21-1000-2000-3000-1001"
BASE = "$Recycle.Bin/" + SID
CONTENT = b"synthetic deleted file content"


def pair_volume(unsafe=False, large=False, nonresident=False):
    b = NTFSBuilder()
    recycle = b.makedirs(BASE)
    b.add_file(recycle, "$IFILE.txt", recycle_record(r"C:\Users\alice\Documents\file.txt"), mode="resident")
    b.add_file(recycle, "$RFILE.txt", CONTENT, mode="nonresident" if nonresident else "resident")
    b.add_file(recycle, "$IDIR", recycle_record(r"C:\Users\alice\Documents\folder"), mode="resident")
    folder = b.mkdir(recycle, "$RDIR", large=large)
    number = b.add_file(folder, "one.txt", b"one", mode="resident")
    b.children[folder].append((number, "alias.txt", False, 3))  # A second long name for the same record.
    nested = b.mkdir(folder, "nested")
    b.add_file(nested, "two.bin", b"two", mode="resident")
    b.mkdir(folder, "empty")
    if unsafe:
        b.add_file(folder, "../escape.txt", b"unsafe name", mode="resident")
    b.add_file(recycle, "$IMISSING", recycle_record(r"C:\Users\alice\Documents\missing.txt"), mode="resident")
    return b.build()


class RecyclePairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "synthetic.img"
        self.image.write_bytes(pair_volume())
        self.before = hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.extraction = extract_artifacts(self.image, self.root / "extracted")
        self.result = Pipeline().analyze_image(self.image, self.root / "analysis")

    def tearDown(self):
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), self.before)
        self.temp.cleanup()

    def pair(self, name):
        return next(e.details["recycle_pair"] for e in self.result.events if e.details.get("i_file") == name)

    def test_original_pair_metadata_is_on_event_and_manifest(self):
        pair = self.pair("$IFILE.txt")
        self.assertEqual(pair["state"], "present")
        self.assertTrue(pair["exists"])
        self.assertFalse(pair["directory"])
        self.assertEqual(pair["size"], len(CONTENT))
        self.assertTrue(pair["image_path"].endswith("$RFILE.txt"))
        self.assertIsInstance(pair["mft_record"], int)
        self.assertEqual(pair["mft_sequence"], 1)
        origin = next(f for f in self.extraction.files if f["image_path"].endswith("$IFILE.txt"))
        self.assertEqual(pair["i_sha256"], origin["sha256"])
        self.assertIn("recycle_pair", origin)
        self.assertIsNone(self.pair("$IMISSING")["exists"])
        self.assertFalse(self.pair("$IMISSING")["absence_confirmed"])

    def test_save_file_new_bytes_and_provenance_only(self):
        target = self.root / "saved.txt"
        saved = save_recycle_pair(self.image, 0, BASE + "/$IFILE.txt", target,
                                  expected_pair=self.pair("$IFILE.txt"))
        self.assertEqual(target.read_bytes(), CONTENT)
        self.assertEqual(saved["sha256"], hashlib.sha256(CONTENT).hexdigest())
        self.assertEqual(saved["hash_scope"], "file_bytes")
        self.assertTrue(saved["complete"])
        self.assertFalse(saved["original_content_confirmed"])
        self.assertEqual(json.loads(Path(saved["record"]).read_text(encoding="utf-8")), saved)
        with self.assertRaises(FileExistsError):
            save_recycle_pair(self.image, 0, BASE + "/$IFILE.txt", target,
                              expected_pair=self.pair("$IFILE.txt"))
        self.assertEqual(target.read_bytes(), CONTENT)

    def test_folder_includes_nested_empty_directories_and_both_hardlink_names(self):
        target = self.root / "saved-folder"
        saved = save_recycle_pair(self.image, 0, BASE + "/$IDIR", target,
                                  expected_pair=self.pair("$IDIR"))
        self.assertEqual((target / "one.txt").read_bytes(), b"one")
        self.assertEqual((target / "alias.txt").read_bytes(), b"one")
        self.assertEqual((target / "nested/two.bin").read_bytes(), b"two")
        self.assertTrue((target / "empty").is_dir())
        self.assertEqual(saved["hash_scope"], "directory_manifest_v1")
        self.assertEqual(sum(not item["directory"] for item in saved["files"]), 3)
        self.assertTrue(saved["complete"])

    def test_stale_reference_snapshot_and_limits_fail_before_writing(self):
        original = self.pair("$IFILE.txt")
        for pair in (dict(original, mft_sequence=2), dict(original, i_sha256="0"*64),
                     dict(original, snapshot={"store_id":"synthetic"}), dict(original, snapshot={}),
                     dict(original, volume=1), dict(original, image=r"C:\Evidence\other.img")):
            target = self.root / "must-not-exist"
            with self.assertRaises(RecyclePairError):
                save_recycle_pair(self.image, 0, BASE + "/$IFILE.txt", target, expected_pair=pair)
            self.assertFalse(target.exists())
        with self.assertRaises(RecyclePairError):
            save_recycle_pair(self.image, 0, BASE + "/$IDIR", self.root / "too-large",
                              expected_pair=self.pair("$IDIR"), max_bytes=1)
        self.assertFalse((self.root / "too-large").exists())

    def test_invalid_child_name_cannot_escape_output(self):
        bad = self.root / "unsafe.img"
        bad.write_bytes(pair_volume(unsafe=True))
        extraction = Pipeline().analyze_image(bad, self.root / "bad-analysis")
        pair = next(e.details["recycle_pair"] for e in extraction.events if e.details.get("i_file") == "$IDIR")
        with self.assertRaises(RecyclePairError):
            save_recycle_pair(bad, 0, BASE + "/$IDIR", self.root / "bad-save", expected_pair=pair)
        self.assertFalse((self.root / "bad-save").exists())
        self.assertFalse((self.root / "escape.txt").exists())

    def test_standalone_metadata_does_not_invent_original_image_absence(self):
        source = self.root / "$IFILE.txt"
        source.write_bytes(recycle_record(r"C:\Users\alice\Documents\file.txt"))
        event, = RecycleBinParser().parse(source)
        self.assertIsNone(event.details["recycle_pair"]["exists"])
        directory = self.root / "$RFILE.txt"
        directory.mkdir()
        event, = RecycleBinParser().parse(source)
        self.assertTrue(event.details["recycle_pair"]["directory"])
        self.assertEqual(event.details["recycle_pair"]["scope"], "selected_local_directory")

    def test_directory_listing_suppresses_only_dos_aliases(self):
        from unittest.mock import patch
        from log_hunter.image.browse import ImageBrowser
        from log_hunter.image.ntfs import DirEntry
        browser = ImageBrowser(self.image)
        try:
            ntfs = browser._volume(0)
            entries = [(DirEntry("long.txt", 100, 1, False, 3), 1),
                       (DirEntry("LONG~1.TXT", 100, 1, False, 3), 2),
                       (DirEntry("second.txt", 100, 1, False, 3), 1),
                       (DirEntry("ONLYDOS.TXT", 101, 1, False, 3), 2)]
            with patch("log_hunter.image.ntfs._index_entries", return_value=iter(entries)):
                rows = ntfs.listdir(5)
            self.assertEqual({row.name for row in rows}, {"long.txt", "second.txt", "ONLYDOS.TXT"})
        finally:
            browser.close()

    def test_failed_write_is_marked_incomplete_and_keeps_no_success_claim(self):
        from unittest.mock import patch
        from log_hunter.image.browse import ImageFile
        read = ImageFile.read
        def fail(source, offset, length):
            if source.parts[-1] == "$RFILE.txt":
                raise OSError("synthetic read failure")
            return read(source, offset, length)
        target = self.root / "partial.txt"
        with patch.object(ImageFile, "read", fail), self.assertRaises(OSError):
            save_recycle_pair(self.image, 0, BASE + "/$IFILE.txt", target,
                              expected_pair=self.pair("$IFILE.txt"))
        record = json.loads(target.with_name(target.name + ".log-hunter.json").read_text(encoding="utf-8"))
        self.assertEqual(record["state"], "failed")
        self.assertFalse(record["complete"])
        self.assertNotIn("sha256", record)

    def test_incomplete_directory_index_is_rejected_in_strict_mode(self):
        import struct
        from log_hunter.image.ntfs import _index_entries, NTFSError
        broken = bytearray(32)
        struct.pack_into("<II", broken, 0, 16, 32)
        self.assertEqual(list(_index_entries(broken, 0)), [])
        with self.assertRaises(NTFSError):
            list(_index_entries(broken, 0, strict=True))

    def test_e01_and_live_reader_contract_export_only_synthetic_bytes(self):
        from unittest.mock import patch
        from test_image import write_e01
        from log_hunter.image.ewf import open_image
        segments = write_e01(self.root / "synthetic.E01", self.image.read_bytes())
        before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in segments]
        result = Pipeline().analyze_image(segments[0], self.root / "e01-analysis")
        pair = next(e.details["recycle_pair"] for e in result.events if e.details.get("i_file") == "$IFILE.txt")
        target = self.root / "e01-saved.txt"
        saved = save_recycle_pair(segments[0], 0, BASE + "/$IFILE.txt", target, expected_pair=pair)
        self.assertEqual(target.read_bytes(), CONTENT)
        self.assertEqual(saved["source_method"], "IMAGE")
        self.assertEqual([hashlib.sha256(path.read_bytes()).hexdigest() for path in segments], before)
        live = r"\\.\C:"
        expected = dict(self.pair("$IFILE.txt"), image=live)
        with patch("log_hunter.image.browse.open_image", side_effect=lambda path: open_image(self.image)) as opened:
            saved = save_recycle_pair(live, 0, BASE + "/$IFILE.txt", self.root / "live-contract.txt", expected_pair=expected)
        opened.assert_called_once_with(live)
        self.assertEqual(saved["source_method"], "LIVE")
        self.assertEqual((self.root / "live-contract.txt").read_bytes(), CONTENT)

    def test_unsupported_stream_flags_are_rejected_even_for_resident_data(self):
        from dataclasses import replace
        from unittest.mock import patch
        from log_hunter.image.ntfs import NTFSVolume, FLAG_ENCRYPTED
        fragments = NTFSVolume._fragments
        record_number = self.pair("$IFILE.txt")["mft_record"]
        def encrypted(volume, record, *args):
            result = fragments(volume, record, *args)
            return [replace(a, flags=a.flags | FLAG_ENCRYPTED) for a in result] if record.number == record_number else result
        with patch.object(NTFSVolume, "_fragments", encrypted), self.assertRaises(RecyclePairError):
            save_recycle_pair(self.image, 0, BASE + "/$IFILE.txt", self.root / "encrypted", expected_pair=self.pair("$IFILE.txt"))
        self.assertFalse((self.root / "encrypted").exists())

    def test_folder_allocation_indexes_are_read_completely(self):
        image = self.root / "large-index.img"
        image.write_bytes(pair_volume(large=True))
        result = Pipeline().analyze_image(image, self.root / "large-index-analysis")
        pair = next(e.details["recycle_pair"] for e in result.events if e.details.get("i_file") == "$IDIR")
        target = self.root / "large-index-save"
        saved = save_recycle_pair(image, 0, BASE + "/$IDIR", target, expected_pair=pair)
        self.assertTrue(saved["complete"])
        self.assertEqual(sum(not item["directory"] for item in saved["files"]), 3)
        self.assertEqual((target / "nested/two.bin").read_bytes(), b"two")

    def test_short_image_reads_are_not_silently_padded_as_complete_output(self):
        from unittest.mock import patch
        from log_hunter.image.ewf import RawImage
        read = RawImage.read
        def short(source, offset, length):
            block = read(source, offset, length)
            return block[:-1] if length == 1024 else block
        with patch.object(RawImage, "read", short), self.assertRaises(RecyclePairError):
            save_recycle_pair(self.image, 0, BASE + "/$IFILE.txt", self.root / "short-read",
                              expected_pair=self.pair("$IFILE.txt"))
        self.assertFalse((self.root / "short-read").exists())

    def test_missing_or_outside_runs_are_not_exported_as_zero_filled_content(self):
        from dataclasses import replace
        from unittest.mock import patch
        from log_hunter.image.ntfs import NTFSVolume
        image = self.root / "nonresident.img"
        image.write_bytes(pair_volume(nonresident=True))
        result = Pipeline().analyze_image(image, self.root / "nonresident-analysis")
        pair = next(e.details["recycle_pair"] for e in result.events if e.details.get("i_file") == "$IFILE.txt")
        fragments = NTFSVolume._fragments
        for variant in ("gap", "outside"):
            def broken(volume, record, *args):
                attrs = fragments(volume, record, *args)
                if record.number != pair["mft_record"]:
                    return attrs
                return [replace(a, runs=[(1 if variant == "gap" else 0,
                    a.runs[0][1] if variant == "gap" else image.stat().st_size // volume.cluster_size + 1,
                    a.runs[0][2])]) for a in attrs]
            target = self.root / ("invalid-runs-" + variant)
            with patch.object(NTFSVolume, "_fragments", broken), self.assertRaises(RecyclePairError):
                save_recycle_pair(image, 0, BASE + "/$IFILE.txt", target, expected_pair=pair)
            self.assertFalse(target.exists())
        save_recycle_pair(image, 0, BASE + "/$IFILE.txt", self.root / "valid-runs", expected_pair=pair)
        self.assertEqual((self.root / "valid-runs").read_bytes(), CONTENT)

    def test_many_metadata_files_reuse_one_original_directory_scan(self):
        from unittest.mock import patch
        from log_hunter.image.browse import ImageBrowser
        from log_hunter.image.recycle import describe_recycle_pair
        browser = ImageBrowser(self.image)
        try:
            ntfs = browser._volume(0)
            parent = ntfs.lookup(BASE)
            metadata = [ntfs.lookup(BASE + "/" + name) for name in ("$IFILE.txt", "$IDIR", "$IMISSING")]
            rows = ntfs.listdir(parent.record, strict=True)
            class CountedRows(list):
                passes = 0
                def __iter__(rows):
                    rows.passes += 1
                    return super().__iter__()
            counted, cache = CountedRows(rows), {}
            with patch.object(ntfs, "listdir", return_value=counted):
                states = [describe_recycle_pair(ntfs, [*BASE.split("/"), entry.name], entry, parent.record,
                          directory_cache=cache)["state"] for entry in metadata]
            self.assertEqual(states, ["present", "present", "not_observed"])
            self.assertEqual(counted.passes, 1)
        finally:
            browser.close()
