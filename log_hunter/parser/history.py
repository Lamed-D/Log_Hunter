import sqlite3
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import chromium_timestamp


class HistoryParser(ArtifactParser):
    artifact = "history"

    def parse(self, path):
        # immutable avoids modifying offline evidence; pipeline prepares a WAL-merged
        # working copy before calling this parser when sidecars exist.
        connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "urls" not in tables:
                raise ValueError("Chromium urls 테이블 없음")
            if "visits" in tables:
                for row in connection.execute("SELECT v.id, v.visit_time, v.transition, u.url, u.title FROM visits v JOIN urls u ON v.url=u.id"):
                    yield ForensicEvent(self.artifact, str(path), "url_visit", chromium_timestamp(row["visit_time"]),
                                        "visit_time", self.sid, url=row["url"], locator=f"visits:{row['id']}", details=dict(row))
            else:
                for row in connection.execute("SELECT * FROM urls"):
                    yield ForensicEvent(self.artifact, str(path), "url_summary", chromium_timestamp(row["last_visit_time"]),
                                        "last_visit_time", self.sid, url=row["url"], locator=f"urls:{row['id']}", details=dict(row))
            if "downloads" in tables:
                for row in connection.execute("SELECT * FROM downloads"):
                    record = dict(row)
                    chain = []
                    if "downloads_url_chains" in tables:
                        chain = [r[0] for r in connection.execute("SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index", (row["id"],))]
                    yield ForensicEvent(self.artifact, str(path), "download", chromium_timestamp(record.get("start_time", 0)),
                                        "start_time", self.sid, path=record.get("target_path", record.get("full_path")),
                                        url=chain[-1] if chain else record.get("url"), locator=f"downloads:{row['id']}",
                                        details={**record, "url_chain": chain})
        finally:
            connection.close()
