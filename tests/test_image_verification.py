"""Synthetic image hashes, bounded streaming, and cancellation."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import zlib
import random

from log_hunter.image.verify import verify_image
from log_hunter.core.pipeline import Pipeline
from log_hunter.image.ewf import EWFImage
from test_image import write_e01, _section


class ImageVerificationTests(unittest.TestCase):
    def test_one_changed_media_byte_in_uncompressed_chunk_mismatches(self):
        disk = random.Random(2024).randbytes(8192)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.E01'
            write_e01(path, disk, segments=1)
            with EWFImage(path) as image:
                _, offset, compressed, _ = image.chunks[0]
                self.assertFalse(compressed)
            data = bytearray(path.read_bytes())
            data[offset + 97] ^= 1
            path.write_bytes(data)
            self.assertEqual(verify_image(path)['status'], 'mismatch')

    def test_split_raw_sidecar_must_name_the_selected_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / 'synthetic.001'
            first.write_bytes(b'first')
            (root / 'synthetic.002').write_bytes(b'second')
            digest = hashlib.sha1(b'firstsecond').hexdigest()
            (root / 'synthetic.sha1').write_text(digest + ' *other.001\n', encoding='ascii')
            self.assertEqual(verify_image(first)['status'], 'no_stored_hash')
            (root / 'synthetic.sha1').write_text('SHA1 (synthetic.001) = ' + digest, encoding='ascii')
            result = verify_image(first)
            self.assertEqual(result['status'], 'match')
            self.assertEqual(result['bytes_read'], 11)
            with self.assertRaises(ValueError):
                verify_image(first, block_size=0)

    def test_invalid_image_metadata_is_a_persistable_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'synthetic.E01'
            path.write_bytes(b'EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00')
            self.assertEqual(verify_image(path)['status'], 'read_error')
            result = Pipeline().analyze_image(path, root / 'extracted', verify=True)
            self.assertEqual(result.image['verification']['status'], 'read_error')
            self.assertEqual(result.summaries[0]['state'], 'failed')
            self.assertTrue(any(error.severity == 'error' for error in result.errors))

    def test_sha1_digest_and_pipeline_manifest(self):
        disk = bytes(4096)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'synthetic.E01'
            write_e01(path, disk, segments=1)
            raw = path.read_bytes()
            offset = 13
            while raw[offset:offset + 16].split(b'\0')[0] != b'hash':
                offset = struct.unpack_from('<Q', raw, offset + 16)[0]
            body = hashlib.md5(disk).digest() + hashlib.sha1(disk).digest() + bytes(40)
            body += struct.pack('<I', zlib.adler32(body))
            path.write_bytes(raw[:offset] + _section('digest', offset + 156, 156) + body +
                             _section('done', offset + 156, 76))
            verified = verify_image(path)
            self.assertEqual(verified['status'], 'match')
            self.assertEqual({r['algorithm'] for r in verified['comparisons']}, {'md5', 'sha1'})
            result = Pipeline().analyze_image(path, root / 'extracted', verify=True)
            self.assertEqual(result.image['verification']['status'], 'match')
            self.assertTrue(any(error.locator == 'verification' and error.severity == 'info' for error in result.errors))
            self.assertTrue((root / 'extracted/image_manifest.json').is_file())

    def test_ewf_missing_digest_mismatch_and_bad_digest_metadata(self):
        disk = b'synthetic-sector' * 1024
        disk += bytes((-len(disk)) % 512)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.E01'
            write_e01(path, disk, segments=1)
            original = path.read_bytes()
            offset = 13
            while original[offset:offset + 16].split(b'\0')[0] != b'hash':
                offset = struct.unpack_from('<Q', original, offset + 16)[0]
            missing = bytearray(original)
            missing[offset:offset + 76] = _section('unused', offset + 112, 112)
            path.write_bytes(missing)
            self.assertEqual(verify_image(path)['status'], 'no_stored_hash')
            mismatch = bytearray(original)
            mismatch[offset + 76] ^= 1
            body = mismatch[offset + 76:offset + 108]
            struct.pack_into('<I', mismatch, offset + 108, zlib.adler32(body))
            path.write_bytes(mismatch)
            self.assertEqual(verify_image(path)['status'], 'mismatch')
            mismatch[offset + 108] ^= 1
            path.write_bytes(mismatch)
            self.assertEqual(verify_image(path)['status'], 'metadata_error')

    def test_ewf_compression_error_reports_logical_offset(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.E01'
            write_e01(path, bytes(65536), segments=1)
            raw = bytearray(path.read_bytes())
            offset = 13
            while raw[offset:offset + 16].split(b'\0')[0] != b'sectors':
                offset = struct.unpack_from('<Q', raw, offset + 16)[0]
            raw[offset + 76] = 0  # Invalid zlib header; no source data is used.
            path.write_bytes(raw)
            result = verify_image(path, block_size=512)
        self.assertEqual(result['status'], 'read_error')
        self.assertEqual(result['errors'][0]['offset'], 0)
        self.assertIn('0', result['errors'][0]['message'])
        self.assertEqual(result['computed'], {})

    def test_segmented_ewf_matches_media_not_container(self):
        disk = b'synthetic-sector' * 1024
        disk += bytes((-len(disk)) % 512)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.E01'
            write_e01(path, disk, segments=2)
            calls = []
            result = verify_image(path, progress=lambda done, total: calls.append((done, total)), block_size=512)
        self.assertEqual(result['status'], 'match')
        self.assertEqual(result['computed']['md5'], hashlib.md5(disk).hexdigest())
        self.assertEqual(result['bytes_read'], len(disk))
        self.assertEqual(calls[-1], (len(disk), len(disk)))

    def test_raw_missing_match_mismatch_and_conflicting_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.dd'
            path.write_bytes(b'synthetic disk')
            self.assertEqual(verify_image(path)['status'], 'no_stored_hash')
            sidecar = Path(str(path) + '.md5')
            sidecar.write_text(hashlib.md5(path.read_bytes()).hexdigest() + ' *synthetic.dd\n', encoding='ascii')
            self.assertEqual(verify_image(path)['status'], 'match')
            path.write_bytes(b'Synthetic disk')
            self.assertEqual(verify_image(path)['status'], 'mismatch')
            sidecar.write_text('0' * 32 + '\n' + '1' * 32 + '\n', encoding='ascii')
            self.assertEqual(verify_image(path)['status'], 'mismatch')

    def test_cancelled_partial_digest_is_not_a_complete_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.dd'
            path.write_bytes(bytes(4096))
            steps = []
            result = verify_image(path, block_size=512, progress=lambda done, total: steps.append(done),
                                  cancel=lambda: bool(steps and steps[-1] >= 512))
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['computed'], {})
        self.assertEqual(result['bytes_read'], 512)
