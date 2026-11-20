"""Saved e-mail (.eml): header metadata only, times in UTC or kept raw when the zone is unknown."""
import json
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.auto_detect import detect_artifact
from log_hunter.core.pipeline import Pipeline
from log_hunter.core.tree import build_tree
from log_hunter.ui import columns

BODY = "body-text-should-not-be-stored"
MESSAGE = f"""From: Alice <alice@example.com>
To: bob@example.org, Carol <carol@example.org>
Cc: analyst@example.com
Subject: =?utf-8?b?7ZWc6riAIOygnOuqqQ==?=
Date: Wed, 30 Dec 2020 09:00:00 +0900
Message-ID: <1@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain; charset="utf-8"

{BODY}
--b
Content-Type: application/zip
Content-Disposition: attachment; filename="report.zip"
Content-Transfer-Encoding: base64

UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==
--b--
"""


class EmailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "Downloads" / "message.eml"
        self.path.parent.mkdir()
        self.path.write_bytes(MESSAGE.replace("\n", "\r\n").encode("utf-8"))

    def tearDown(self):
        self.temp.cleanup()

    def test_headers_and_attachment_names_without_body(self):
        result = Pipeline().analyze([("email", self.path)])
        (event,) = result.events
        d = event.details
        self.assertEqual(d["email_from"], ["alice@example.com"])
        self.assertEqual(d["email_to"], ["bob@example.org", "carol@example.org"])
        self.assertEqual(d["email_subject"], "한글 제목")
        self.assertEqual(d["email_attachments"], ["report.zip"])
        self.assertEqual(d["email_accounts"], ["alice@example.com", "analyst@example.com", "bob@example.org", "carol@example.org"])
        self.assertEqual((event.timestamp, event.time_field), ("2020-12-30T00:00:00+00:00", "email_sent"))
        self.assertNotIn(BODY, json.dumps(event.to_dict(), ensure_ascii=False))
        self.assertEqual(columns.cell("email_to", event, {}, None), "bob@example.org, carol@example.org")
        nodes = {n.key: n for r in build_tree(result.events) for n in r.walk()}
        self.assertEqual(nodes["art:email"].count, 1)
        self.assertEqual(columns.columns_for(nodes["art:email"]), columns.CATEGORY_COLUMNS["email"])
        self.assertEqual(detect_artifact(str(self.path)), "email")

    def test_date_without_zone_is_not_treated_as_utc(self):
        self.path.write_bytes(MESSAGE.replace("+0900", "-0000").replace("\n", "\r\n").encode("utf-8"))
        result = Pipeline().analyze([("email", self.path)])
        (event,) = result.events
        self.assertIsNone(event.timestamp)
        self.assertEqual(event.details["email_date_basis"], "zone_unknown")
        # the written wall clock is kept and shown as 시간대 미상, never as UTC or converted with the PC's zone
        self.assertEqual(event.details["timestamp_raw_local"], "2020-12-30T09:00:00")
        self.assertFalse(event.details["timezone_known"])
        self.assertEqual(event.time_field, "email_sent")
        from log_hunter.core.timestamp import display_event_time
        self.assertEqual(display_event_time(event), "2020-12-30 09:00:00 (시간대 미상)")
        self.assertIn("Wed, 30 Dec 2020 09:00:00 -0000", event.details["email_date_raw"])
        self.assertEqual(event.status, "partial")

    def test_image_attachment_photo_metadata(self):
        import base64
        import struct
        camera = b"II*\0" + struct.pack("<IHHHI", 8, 1, 0x0110, 2, 4) + b"ABC\0" + bytes(4)
        jpeg = b"\xff\xd8\xff\xe1" + struct.pack(">H", 8 + len(camera)) + b"Exif\0\0" + camera + b"\xff\xd9"
        attachment = base64.b64encode(jpeg).decode()
        mail = MESSAGE.replace("--b--", f"""--b
Content-Type: image/jpeg
Content-Disposition: attachment; filename="photo.jpg"
Content-Transfer-Encoding: base64

{attachment}
--b--""")
        self.path.write_bytes(mail.replace("\n", "\r\n").encode("utf-8"))
        (event,) = Pipeline().analyze([("email", self.path)]).events
        (photo,) = event.details["email_attachment_photos"]
        self.assertEqual((photo["attachment"], photo["camera_model"]), ("photo.jpg", "ABC"))
        self.assertNotIn(attachment, json.dumps(event.to_dict(), ensure_ascii=False))  # the image itself is not kept

    def test_not_a_mail_file(self):
        self.path.write_bytes(b"\x00\x01binary")
        result = Pipeline().analyze([("email", self.path)])
        self.assertEqual((result.events, result.summaries[0]["state"]), ([], "failed"))


if __name__ == "__main__":
    unittest.main()
