"""Saved e-mail messages (.eml, RFC 5322): sender, recipients, subject, times and attachment names.
The message body and attachment contents are not stored or opened."""
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from datetime import timezone

from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent

MAX_EML = 64 * 1024 * 1024


MAX_PHOTOS = 50
MAX_ATTACHMENT = 32 * 1024 * 1024


def _attachment_photo(part, name):
    """Photo metadata (camera, recorded times) of an image attachment, decoded in memory only; None if none."""
    from log_hunter.image.inventory import _photo_metadata, _signature
    try:
        data = part.get_payload(decode=True)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, bytes) or not data or len(data) > MAX_ATTACHMENT:
        return None
    kind, _expected = _signature(data[:4096])
    if kind not in ("jpeg", "tiff"):
        return None
    metadata = _photo_metadata(data[:512 * 1024], kind)
    if not metadata:
        return None
    return {"attachment": str(name or "")[:260] or None, "file_type": kind, **metadata}


def _addresses(message, *headers):
    values = []
    for header in headers:
        values.extend(str(v) for v in message.get_all(header, []) or [])
    return [addr for _name, addr in getaddresses(values) if addr][:500]


def _date(message, header):
    raw = message.get(header)
    if not raw:
        return None, None, None
    try:
        moment = parsedate_to_datetime(str(raw))
    except (TypeError, ValueError, IndexError):
        return None, str(raw), "unparsed"
    if moment is None:
        return None, str(raw), "unparsed"
    if moment.tzinfo is None:  # '-0000' or no zone: the sender's clock zone is unknown
        return moment.isoformat(), str(raw), "zone_unknown"
    return moment.astimezone(timezone.utc).isoformat(), str(raw), "utc"


class EmailParser(ArtifactParser):
    artifact = "email"

    def parse(self, path):
        from pathlib import Path
        path = Path(path)
        if path.stat().st_size > MAX_EML:
            raise ValueError(f"메일 파일이 너무 큽니다 ({path.stat().st_size:,} 바이트)")
        with path.open("rb") as stream:
            message = BytesParser(policy=policy.default).parse(stream, headersonly=False)
        if not (message.get("From") or message.get("To") or message.get("Subject") or message.get("Date")):
            raise ValueError("메일 머리글(From/To/Subject/Date)이 없습니다")
        sent, raw_date, basis = _date(message, "Date")
        attachments, photos = [], []
        for part in message.walk():
            name = part.get_filename()
            if name:
                attachments.append(str(name)[:260])
            if (name or part.get_content_maintype() == "image") and len(photos) < MAX_PHOTOS:
                photo = _attachment_photo(part, name)
                if photo:
                    photos.append(photo)
        sender = _addresses(message, "From")
        recipients = _addresses(message, "To", "Cc", "Bcc")
        details = {
            "email_from": sender, "email_to": _addresses(message, "To"), "email_cc": _addresses(message, "Cc"),
            "email_subject": str(message.get("Subject") or "") or None,
            "email_date_raw": raw_date, "email_date_basis": basis,
            "email_message_id": str(message.get("Message-ID") or "") or None,
            "email_attachments": attachments[:200], "email_has_attachment": bool(attachments),
            "email_attachment_photos": photos,
            "email_accounts": sorted(set(sender + recipients)),
            "body_stored": False,
        }
        status = "ok" if basis in ("utc", None) else "partial"
        if basis == "zone_unknown":
            # Kept as the written wall clock, marked 시간대 미상: it is the sender's clock, so neither UTC nor the
            # analyzed PC's zone may be applied (a naive value is never converted with the evidence's zone).
            self.error(path, "Date", "보낸 시각에 시간대가 없어 UTC로 바꾸지 않았습니다 (원문 보존)", "warning")
            details.update(timezone_known=False, time_basis="시간대 미상 (메일 Date 머리글에 시간대 없음)")
        yield ForensicEvent(self.artifact, str(path), "email_message", sent, "email_sent" if sent else None, self.sid,
                            path=details["email_subject"], locator="headers", status=status, details=details)
