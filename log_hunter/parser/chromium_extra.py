"""Chromium profile databases besides History: cookies, site icons and form autofill.
Cookie and autofill values are never read: only names, sites, counts and times are kept."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .base import ArtifactParser
from .history import browser_profile
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import chromium_timestamp


def _open(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _columns(connection, table):
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _tables(connection):
    return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _chromium_time(value):
    return chromium_timestamp(value) if isinstance(value, int) and value > 0 else None


def _unix_time(value):
    if not isinstance(value, int) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


class _ChromiumParser(ArtifactParser):
    table = None

    def parse(self, path, origin=None):
        browser, profile = browser_profile(origin or path)
        self.where = {"browser": browser, "profile": profile}
        connection = _open(path)
        try:
            if self.table not in _tables(connection):
                raise ValueError(f"{self.table} 테이블 없음")
            yield from self.rows(connection, str(path))
        finally:
            connection.close()


class CookiesParser(_ChromiumParser):
    """One record per stored cookie: site, name, path, flags and its times. The value columns are not selected."""
    artifact = "cookies"
    table = "cookies"
    KEEP = ("host_key", "name", "path", "creation_utc", "expires_utc", "last_access_utc", "last_update_utc",
            "is_secure", "secure", "is_httponly", "httponly", "is_persistent", "persistent", "has_expires", "samesite")

    def rows(self, connection, source):
        columns = [c for c in self.KEEP if c in _columns(connection, "cookies")]
        if "host_key" not in columns or "name" not in columns:
            raise ValueError("쿠키 테이블에 사이트·이름 열 없음")
        for index, row in enumerate(connection.execute(f"SELECT rowid AS rid, {', '.join(columns)} FROM cookies")):
            row = dict(row)
            accessed, created = _chromium_time(row.get("last_access_utc")), _chromium_time(row.get("creation_utc"))
            details = {
                "cookie_name": row["name"], "cookie_site": row["host_key"], "cookie_path": row.get("path"),
                "cookie_created": created, "cookie_last_access": accessed,
                "cookie_expires": _chromium_time(row.get("expires_utc")),
                "cookie_last_update": _chromium_time(row.get("last_update_utc")),
                "cookie_secure": bool(row.get("is_secure", row.get("secure"))),
                "cookie_httponly": bool(row.get("is_httponly", row.get("httponly"))),
                "cookie_persistent": bool(row.get("is_persistent", row.get("persistent", row.get("has_expires")))),
                "value_stored": False, **self.where,
            }
            timestamp, field = (accessed, "cookie_last_access") if accessed else (created, "cookie_created")
            yield ForensicEvent(self.artifact, source, "cookie_stored", timestamp, field if timestamp else None, self.sid,
                                url=row["host_key"], locator=f"cookies:{row['rid']}", details=details)


class FaviconsParser(_ChromiumParser):
    """One record per page → icon mapping: the page that showed the icon, the icon address and when it was updated."""
    artifact = "favicons"
    table = "icon_mapping"

    def rows(self, connection, source):
        tables = _tables(connection)
        bitmaps = "favicon_bitmaps" in tables
        requested = bitmaps and "last_requested" in _columns(connection, "favicon_bitmaps")
        sql = ("SELECT m.id AS mid, m.page_url, f.url AS icon_url"
               + (", (SELECT max(b.last_updated) FROM favicon_bitmaps b WHERE b.icon_id=m.icon_id) AS updated" if bitmaps else ", NULL AS updated")
               + (", (SELECT max(b.last_requested) FROM favicon_bitmaps b WHERE b.icon_id=m.icon_id) AS requested" if requested else ", NULL AS requested")
               + " FROM icon_mapping m LEFT JOIN favicons f ON f.id=m.icon_id")
        for row in connection.execute(sql):
            updated = _chromium_time(row["updated"])
            details = {"page_url": row["page_url"], "icon_url": row["icon_url"], "icon_updated": updated,
                       "icon_requested": _chromium_time(row["requested"]), **self.where}
            yield ForensicEvent(self.artifact, source, "site_icon", updated, "icon_updated" if updated else None, self.sid,
                                url=row["page_url"], locator=f"icon_mapping:{row['mid']}", details=details)


class AutofillParser(_ChromiumParser):
    """One record per remembered form entry: the field name, how often it was used and when. The typed value is not read."""
    artifact = "autofill"
    table = "autofill"

    def rows(self, connection, source):
        columns = _columns(connection, "autofill")
        wanted = [c for c in ("name", "count", "date_created", "date_last_used") if c in columns]
        if "name" not in wanted:
            raise ValueError("자동 완성 테이블에 입력 칸 이름 열 없음")
        for row in connection.execute(f"SELECT rowid AS rid, {', '.join(wanted)} FROM autofill"):
            row = dict(row)
            used, created = _unix_time(row.get("date_last_used")), _unix_time(row.get("date_created"))
            details = {"field_name": row["name"], "use_count": row.get("count"), "first_used": created,
                       "last_used": used, "value_stored": False, **self.where}
            timestamp, field = (used, "autofill_last_used") if used else (created, "autofill_created")
            yield ForensicEvent(self.artifact, source, "form_entry", timestamp, field if timestamp else None, self.sid,
                                locator=f"autofill:{row['rid']}", details=details)
