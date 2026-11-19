"""Internet Explorer / legacy Edge web cache database (WebCacheV01.dat, ESE format): visited pages, cookies and
downloads. Cookie values and cached page contents are not read. Times: AccessedTime/LastModified/Expires are UTC
FILETIME; the daily history container's ModifiedTime is a local-clock value and is kept raw, never shown as UTC."""
import re
from pathlib import Path

from .base import ArtifactParser
from .ese import ESEDatabase, ESEError
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime

MAX_DATABASE = 2 * 1024 * 1024 * 1024
BROWSER = "Internet Explorer·Edge (레거시)"
STATES = {1: "just_created", 2: "dirty_shutdown", 3: "clean_shutdown", 4: "being_converted", 5: "force_detach"}
_PREFIX = re.compile(r"^(?:Visited:|:\d{16}:)\s*(?:(?P<user>[^@]*)@)?(?P<url>.*)$", re.DOTALL)


def split_url(text):
    """('user hint', 'url') from 'Visited: alice@https://…' or ':2020123020201231: alice@https://…'."""
    match = _PREFIX.match(text or "")
    if not match:
        return None, text or None
    return (match.group("user") or None), match.group("url") or None


def _time(value):
    return filetime(value) if isinstance(value, int) and value > 0 else None


def _text(value):
    if isinstance(value, bytes):
        value = value.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return value or None


def cookie_domain(reversed_domain):
    """'com.example.www' -> 'www.example.com' (the table keeps the host labels in reverse order)."""
    return ".".join(reversed(reversed_domain.split("."))) if reversed_domain else None


class WebCacheParser(ArtifactParser):
    artifact = "webcache"

    def parse(self, path):
        path = Path(path)
        if path.stat().st_size > MAX_DATABASE:
            raise ValueError("웹 캐시 데이터베이스가 너무 큽니다")
        db = ESEDatabase(path)
        state = STATES.get(db.state, str(db.state))
        if db.state != 3:
            self.error(path, "header", f"정상 종료되지 않은 데이터베이스입니다({state}): 로그 파일 내용은 반영하지 않았습니다", "warning")
        source = str(path)
        try:
            containers = list(db.rows("Containers"))
        except ESEError as exc:
            raise ValueError(f"Containers 테이블을 읽지 못했습니다: {exc}") from exc
        common = {"browser": BROWSER, "database_state": state}
        for container in containers:
            cid, name = container.get("ContainerId"), str(container.get("Name") or "")
            table = f"Container_{cid}"
            kind = ("visit" if name.startswith("MSHist") else "summary" if name == "History" else
                    "download" if name.lower() == "iedownload" else None)
            if kind is None or table not in db.tables:
                continue  # page contents, DOM storage and app caches are not browsing history
            for index, row in enumerate(db.rows(table)):
                user, url = split_url(_text(row.get("Url")))
                accessed = _time(row.get("AccessedTime"))
                details = {"container": name, "container_id": cid, "entry_id": row.get("EntryId"),
                           "url": url, "user_hint": user, "access_count": row.get("AccessCount"),
                           "created": _time(row.get("CreationTime")), "expires": _time(row.get("ExpiryTime")),
                           "synced": _time(row.get("SyncTime")), **common}
                if kind == "visit":
                    # Daily containers: ModifiedTime follows the local clock; without the zone it stays raw.
                    details["modified_time_raw_local"] = row.get("ModifiedTime")
                else:
                    details["modified"] = _time(row.get("ModifiedTime"))
                action = {"visit": "url_visit", "summary": "url_summary", "download": "download"}[kind]
                field = {"visit": "webcache_accessed", "summary": "webcache_last_accessed", "download": "webcache_accessed"}[kind]
                if kind == "download":
                    details.update(download_url=url, final_url=url, download_save_path=_text(row.get("Filename")))
                yield ForensicEvent(self.artifact, source, action, accessed, field if accessed else None, self.sid,
                                    url=url, locator=f"{table}:{row.get('EntryId', index)}", details=details)
        for table in sorted(t for t in db.tables if t.startswith("CookieEntryEx_")):
            for index, row in enumerate(db.rows(table, skip=("Value",))):
                site = cookie_domain(_text(row.get("RDomain")))
                modified = _time(row.get("LastModified"))
                details = {"cookie_site": site, "cookie_name": _text(row.get("Name")), "cookie_path": _text(row.get("Path")),
                           "cookie_last_update": modified, "cookie_expires": _time(row.get("Expires")),
                           "cookie_flags": row.get("Flags"), "value_stored": False, **common}
                yield ForensicEvent(self.artifact, source, "cookie_stored", modified, "cookie_last_update" if modified else None,
                                    self.sid, url=site, locator=f"{table}:{row.get('EntryId', index)}", details=details)
        for warning in db.warnings[:50]:
            self.error(path, "page", warning, "warning")
