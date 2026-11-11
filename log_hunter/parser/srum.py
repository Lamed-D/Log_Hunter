"""SRUM (System Resource Usage Monitor) parser for SQLite-exported SRUDB data.

Reads SRUM data exported to SQLite (e.g. via srum-dump or similar tools).
Raw ESE SRUDB.dat files are detected but not directly parsed — a warning
is emitted with guidance to use an export tool first.

SRUM tables tracked:
  - NetworkDataUsageMonitor: per-app bytes sent/received
  - NetworkConnectivityUsageMonitor: interface connection durations
  - ApplicationResourceUsageMonitor: foreground/background CPU and I/O
  - EnergyUsageMonitor: battery charge level per app
  - WindowsPushNotificationUsage: push notification stats
"""
import sqlite3
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime

SRUM_TABLES = {
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "network_usage",
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "network_connection",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "app_resource",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "energy_usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "push_notification",
}

ESE_MAGIC = b"\xef\xcd\xab\x89"


def _resolve_id(id_map, raw_id):
    if raw_id is None:
        return None
    resolved = id_map.get(raw_id)
    if resolved is not None:
        return resolved
    if isinstance(raw_id, str):
        return raw_id
    return str(raw_id)


def _safe_int(value):
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _row_timestamp(row, columns):
    for col in ("TimeStamp", "Timestamp", "timestamp", "ConnectStartTime"):
        if col in columns:
            val = row[columns[col]]
            if val is not None:
                ts = _safe_int(val)
                if ts > 0:
                    return filetime(ts)
    return None


def _get_columns(cursor, table):
    try:
        cursor.execute(f"PRAGMA table_info([{table}])")
        info = cursor.fetchall()
        return {row[1]: idx for idx, row in enumerate(info)}
    except sqlite3.Error:
        return {}


def _col(row, columns, name, default=None):
    idx = columns.get(name)
    if idx is None or idx >= len(row):
        return default
    val = row[idx]
    return val if val is not None else default


class SRUMParser(ArtifactParser):
    artifact = "srum"

    def parse(self, path):
        path = Path(path)
        if not path.is_file():
            self.error(path, "file", "파일이 존재하지 않습니다")
            return

        with path.open("rb") as f:
            header = f.read(16)

        if len(header) >= 4 and header[:4] == ESE_MAGIC:
            self.error(path, "format", "ESE 형식의 원본 SRUDB.dat 파일입니다. "
                       "직접 ESE 파싱은 미지원 — srum-dump 등의 도구로 SQLite로 변환 후 분석하세요", "warning")
            yield from self._extract_ese_strings(path)
            return

        if not (len(header) >= 16 and header[:16] == b"SQLite format 3\x00"):
            self.error(path, "format", "SQLite 또는 ESE 형식이 아닙니다")
            return

        if Path(str(path) + "-wal").exists():
            self.error(path, "wal", "보조 기록을 포함하려면 CLI 또는 분석 파이프라인으로 본 파일을 분석하세요.", "warning")

        try:
            # as_uri() escapes '#', '?' and '%' in folder names; immutable=1 stops SQLite from creating
            # -wal/-shm files next to the evidence.
            conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        except sqlite3.Error as exc:
            self.error(path, "sqlite", f"SQLite 열기 실패: {exc}")
            return

        try:
            cursor = conn.cursor()
            id_map = self._load_id_map(cursor, path)
            tables = {row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

            found_any = False
            for table_name, action in SRUM_TABLES.items():
                if table_name not in tables:
                    continue
                found_any = True
                columns = _get_columns(cursor, table_name)
                if not columns:
                    self.error(path, table_name, "테이블 컬럼 정보를 읽을 수 없습니다", "warning")
                    continue
                try:
                    cursor.execute(f"SELECT * FROM [{table_name}]")
                except sqlite3.Error as exc:
                    self.error(path, table_name, f"테이블 읽기 실패: {exc}", "warning")
                    continue

                for row in cursor:
                    try:
                        yield from self._parse_row(row, columns, action, id_map, path, table_name)
                    except Exception as exc:
                        self.error(path, table_name, f"행 파싱 오류: {exc}", "warning")

            if not found_any:
                self.error(path, "tables", "알려진 SRUM 테이블이 없습니다 (SQLite 파일이 SRUM 내보내기가 아닐 수 있음)", "warning")
        finally:
            conn.close()

    def _load_id_map(self, cursor, path):
        id_map = {}
        try:
            cursor.execute("SELECT IdType, IdIndex, IdBlob FROM SruDbIdMapTable")
            for row in cursor:
                id_type, id_index, id_blob = row
                if id_blob is None:
                    continue
                if isinstance(id_blob, bytes):
                    try:
                        value = id_blob.decode("utf-16-le").rstrip("\x00")
                    except UnicodeDecodeError:
                        value = id_blob.hex()
                else:
                    value = str(id_blob)
                id_map[id_index] = value
        except sqlite3.Error:
            self.error(path, "SruDbIdMapTable", "ID 매핑 테이블을 읽을 수 없습니다 — ID가 숫자로 표시됩니다", "warning")
        return id_map

    def _parse_row(self, row, columns, action, id_map, path, table_name):
        app_id = _col(row, columns, "AppId")
        user_id = _col(row, columns, "UserId")
        app_path = _resolve_id(id_map, app_id)
        user_sid = _resolve_id(id_map, user_id)
        timestamp = _row_timestamp(row, columns)

        details = {
            "table": table_name,
            "app_id_raw": app_id,
            "app_path": app_path,
            "user_id_raw": user_id,
        }

        if action == "network_usage":
            details.update(
                bytes_sent=_safe_int(_col(row, columns, "BytesSent")),
                bytes_received=_safe_int(_col(row, columns, "BytesReceived")),
                interface_luid=_col(row, columns, "InterfaceLuid"),
                l2_profile_id=_col(row, columns, "L2ProfileId"),
                l2_profile_flags=_col(row, columns, "L2ProfileFlags"),
            )
        elif action == "network_connection":
            connected_time = _safe_int(_col(row, columns, "ConnectedTime"))
            details.update(
                interface_luid=_col(row, columns, "InterfaceLuid"),
                connected_time_seconds=connected_time,
                l2_profile_id=_col(row, columns, "L2ProfileId"),
                l2_profile_flags=_col(row, columns, "L2ProfileFlags"),
            )
        elif action == "app_resource":
            details.update(
                foreground_cycle_time=_safe_int(_col(row, columns, "ForegroundCycleTime")),
                background_cycle_time=_safe_int(_col(row, columns, "BackgroundCycleTime")),
                face_time=_safe_int(_col(row, columns, "FaceTime")),
                foreground_bytes_read=_safe_int(_col(row, columns, "ForegroundBytesRead")),
                foreground_bytes_written=_safe_int(_col(row, columns, "ForegroundBytesWritten")),
                background_bytes_read=_safe_int(_col(row, columns, "BackgroundBytesRead")),
                background_bytes_written=_safe_int(_col(row, columns, "BackgroundBytesWritten")),
                foreground_context_switches=_safe_int(_col(row, columns, "ForegroundContextSwitches")),
                background_context_switches=_safe_int(_col(row, columns, "BackgroundContextSwitches")),
                foreground_num_read_operations=_safe_int(_col(row, columns, "ForegroundNumberOfReadOperations")),
                foreground_num_write_operations=_safe_int(_col(row, columns, "ForegroundNumberOfWriteOperations")),
            )
        elif action == "energy_usage":
            details.update(
                charge_level=_safe_int(_col(row, columns, "ChargeLevel")),
                designed_capacity=_safe_int(_col(row, columns, "DesignedCapacity")),
                full_charged_capacity=_safe_int(_col(row, columns, "FullChargedCapacity")),
                cycle_count=_safe_int(_col(row, columns, "CycleCount")),
            )
        elif action == "push_notification":
            details.update(
                notification_type=_col(row, columns, "NotificationType"),
                payload_size=_safe_int(_col(row, columns, "PayloadSize")),
                network_type=_col(row, columns, "NetworkType"),
            )

        yield ForensicEvent(
            self.artifact, str(path), action, timestamp, "srum_timestamp",
            sid=user_sid, process=app_path,
            locator=f"{table_name}",
            status="ok" if timestamp else "partial",
            details={k: v for k, v in details.items() if v is not None and v != 0},
        )

    def _extract_ese_strings(self, path):
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.error(path, "ese_read", f"ESE 파일 읽기 실패: {exc}")
            return

        import re
        seen = set()
        for match in re.finditer(rb"(?:[\x20-\x7e]{8,512})", data):
            text = match.group().decode("ascii", errors="replace")
            if text in seen:
                continue
            seen.add(text)
            is_path = "\\" in text and (":" in text or text.startswith("\\"))
            is_sid = text.startswith("S-1-")
            if is_path or is_sid:
                yield ForensicEvent(
                    self.artifact, str(path), "ese_string_candidate",
                    locator=f"byte:{match.start()}",
                    status="partial",
                    sid=text if is_sid else self.sid,
                    path=text if is_path else None,
                    details={
                        "format": "ESE_raw_extraction",
                        "is_path": is_path,
                        "is_sid": is_sid,
                        "format_verified": False,
                    },
                )
