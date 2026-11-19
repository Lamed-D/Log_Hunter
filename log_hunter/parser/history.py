"""Chromium History: page visits and downloads, with each download URL kept in its own role."""
import sqlite3
from pathlib import Path, PureWindowsPath
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import chromium_timestamp

# downloads.state as Chromium stores it; 3 was a retired value and anything else is shown as unknown.
DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 4: "interrupted"}
# Role columns of a download row (shared by the CSV, the result table and the properties dialog).
URL_ROLES = ("download_url", "final_url", "referrer_url", "tab_url", "tab_referrer_url", "site_url")


def _record(row):
    """Keep SQLite binary fields losslessly in a JSON-safe, explicitly typed form."""
    return {key: {'encoding': 'hex', 'value': value.hex()} if isinstance(value, bytes) else value
            for key, value in dict(row).items()}


def browser_profile(path):
    """(browser, profile folder) from '...\\<Vendor>\\<Browser>\\User Data\\<Profile>\\History', else (None, None)."""
    parts = PureWindowsPath(str(path)).parts
    lowered = [p.casefold() for p in parts]
    if "user data" not in lowered:
        return None, None
    index = lowered.index("user data")
    browser = " ".join(parts[max(0, index - 2):index]) if index >= 2 else (parts[index - 1] if index else None)
    profile = parts[index + 1] if index + 1 < len(parts) - 1 else None
    return browser, profile


def _text(value):
    return value if isinstance(value, str) and value else None


def download_fields(record, chain):
    """Download facts in fixed field names. The first URL of the redirect chain is the one requested, the last one
    served the file; referrer, tab and site URLs are what the browser recorded around it, not the file source."""
    fields = {
        "download_save_path": _text(record.get("current_path")) or _text(record.get("target_path")),
        "download_target_path": _text(record.get("target_path")),
        "download_url": chain[0] if chain else _text(record.get("url")),
        "final_url": chain[-1] if chain else _text(record.get("url")),
        "referrer_url": _text(record.get("referrer")),
        "tab_url": _text(record.get("tab_url")),
        "tab_referrer_url": _text(record.get("tab_referrer_url")),
        "site_url": _text(record.get("site_url")),
        "download_start": chromium_timestamp(record["start_time"]) if record.get("start_time") else None,
        "download_end": chromium_timestamp(record["end_time"]) if record.get("end_time") else None,
        "download_size": record.get("total_bytes"),
        "download_received": record.get("received_bytes"),
        "download_state": DOWNLOAD_STATES.get(record.get("state"), "unknown") if record.get("state") is not None else None,
        "download_mime": _text(record.get("mime_type")),
        "url_chain_count": len(chain),
    }
    return fields


class HistoryParser(ArtifactParser):
    artifact = "history"

    def parse(self, path, origin=None):
        # immutable avoids modifying offline evidence; pipeline prepares a WAL-merged
        # working copy before calling this parser when sidecars exist.
        connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        browser, profile = browser_profile(origin or path)
        where = {"browser": browser, "profile": profile}
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "urls" not in tables:
                raise ValueError("Chromium urls 테이블 없음")
            if "visits" in tables:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(visits)")}
                referrer = ("(SELECT ru.url FROM visits rv JOIN urls ru ON rv.url=ru.id WHERE rv.id=v.from_visit) AS referrer_url"
                            if "from_visit" in columns else "NULL AS referrer_url")
                for row in connection.execute(f"SELECT v.id, v.visit_time, v.transition, u.url, u.title, {referrer} "
                                              "FROM visits v JOIN urls u ON v.url=u.id"):
                    details = {**_record(row), **where}
                    if not details.get("referrer_url"):
                        details.pop("referrer_url", None)
                    yield ForensicEvent(self.artifact, str(path), "url_visit", chromium_timestamp(row["visit_time"]),
                                        "visit_time", self.sid, url=row["url"], locator=f"visits:{row['id']}", details=details)
            else:
                for row in connection.execute("SELECT * FROM urls"):
                    yield ForensicEvent(self.artifact, str(path), "url_summary", chromium_timestamp(row["last_visit_time"]),
                                        "last_visit_time", self.sid, url=row["url"], locator=f"urls:{row['id']}",
                                        details={**_record(row), **where})
            if "downloads" in tables:
                for row in connection.execute("SELECT * FROM downloads"):
                    record = _record(row)
                    chain = []
                    if "downloads_url_chains" in tables:
                        chain = [r[0] for r in connection.execute("SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index", (row["id"],))]
                    fields = download_fields(record, chain)
                    yield ForensicEvent(self.artifact, str(path), "download", chromium_timestamp(record.get("start_time", 0)),
                                        "start_time", self.sid, path=fields["download_save_path"] or record.get("full_path"),
                                        url=fields["final_url"], locator=f"downloads:{row['id']}",
                                        details={**record, "url_chain": chain, **fields, **where})
            if "keyword_search_terms" in tables:
                # The browser's own record of words typed into a search engine; its time is the result page's last visit.
                for row in connection.execute("SELECT k.rowid AS rid, k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                                              "LEFT JOIN urls u ON u.id=k.url_id"):
                    visited = chromium_timestamp(row["last_visit_time"]) if row["last_visit_time"] else None
                    yield ForensicEvent(self.artifact, str(path), "web_search", visited, "search_last_visit" if visited else None,
                                        self.sid, url=row["url"], locator=f"keyword_search_terms:{row['rid']}",
                                        details={"search_term": row["term"], "url": row["url"], **where})
        finally:
            connection.close()
