"""SRUM from the original ESE database: OLE-date times in UTC, id map names and binary SIDs, same fields as exports."""
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.pipeline import Pipeline
from log_hunter.parser.srum import id_text, sid_text, srum_time

spec = importlib.util.spec_from_file_location("ese_builder", Path(__file__).parent / "fixtures/ese_builder.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
OLE = 44195.5  # 2020-12-30 12:00:00 UTC as an OLE date
SID = "S-1-5-21-1000-2000-3000-1001"


def sid_bytes(text):
    parts = [int(x) for x in text.split("-")[2:]]
    return bytes([1, len(parts) - 1]) + parts[0].to_bytes(6, "big") + b"".join(p.to_bytes(4, "little") for p in parts[1:])


def make(path, state=3):
    idmap = ("SruDbIdMapTable", {1: ("IdType", B.I32, 0), 2: ("IdIndex", B.I32, 0), 256: ("IdBlob", B.LONG_BINARY, 0)},
             [{1: 0, 2: 10, 256: (0x01, "\\Device\\HarddiskVolume3\\Windows\\tool.exe\x00".encode("utf-16-le"))},
              {1: 3, 2: 11, 256: (0x01, sid_bytes(SID))}])
    network = ("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
               {1: ("AutoIncId", B.I32, 0), 2: ("TimeStamp", B.DATETIME, 0), 3: ("AppId", B.I32, 0), 4: ("UserId", B.I32, 0),
                5: ("BytesSent", B.I64, 0), 6: ("BytesRecvd", B.I64, 0)},
               [{1: 1, 2: OLE, 3: 10, 4: 11, 5: 1234, 6: 5678}])
    B.build(path, [idmap, network], state=state)


class SRUMESETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "SRUDB.dat"
        make(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_native_database_rows(self):
        result = Pipeline().analyze([("srum", self.path)])
        (event,) = [e for e in result.events if e.action == "network_usage"]
        self.assertEqual((event.timestamp, event.time_field), ("2020-12-30T12:00:00+00:00", "srum_timestamp"))
        self.assertEqual(event.process, "\\Device\\HarddiskVolume3\\Windows\\tool.exe")
        self.assertEqual(event.sid, SID)
        self.assertEqual((event.details["bytes_sent"], event.details["bytes_received"]), (1234, 5678))
        self.assertFalse(any("미지원" in e.message for e in result.errors))

    def test_dirty_database_warns_but_reads(self):
        dirty = Path(self.temp.name) / "dirty" / "SRUDB.dat"
        dirty.parent.mkdir()
        make(dirty, state=2)
        result = Pipeline().analyze([("srum", dirty)])
        self.assertTrue(result.events)
        self.assertTrue(any("정상 종료되지 않은" in e.message for e in result.errors))

    def test_time_forms(self):
        self.assertEqual(srum_time(OLE), "2020-12-30T12:00:00+00:00")
        self.assertEqual(srum_time(132537600000000000), "2020-12-30T00:00:00+00:00")  # FILETIME in an export
        self.assertEqual(srum_time("2020-12-30T09:00:00+09:00"), "2020-12-30T00:00:00+00:00")
        self.assertIsNone(srum_time("2020-12-30 00:00:00"))  # no zone: not guessed
        self.assertIsNone(srum_time(0))
        self.assertIsNone(srum_time(-5.0))

    def test_ids(self):
        self.assertEqual(sid_text(sid_bytes(SID)), SID)
        self.assertIsNone(sid_text(b"\x01\x05short"))
        self.assertEqual(id_text(3, sid_bytes(SID)), SID)
        self.assertEqual(id_text(0, "a.exe\x00".encode("utf-16-le")), "a.exe")


if __name__ == "__main__":
    unittest.main()
