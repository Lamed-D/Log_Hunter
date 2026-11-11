# Teaching copy: runtime tokens are verified by tools/check_annotated.py.
"""Windows Recycle Bin ($I file) parser.

Parses $I files from $Recycle.Bin directories to recover deletion metadata:
  - Original file path and name
  - Deletion timestamp
  - Original file size
  - SID from directory structure

Supports both Vista/7 format (v1, 544 bytes header) and Win10+ format (v2, variable length).
"""
import struct
import ntpath
import stat
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.labels import RECYCLE_PAIR_STATES, RECYCLE_PAIR_REASONS


def parse_dollar_i(data, filename=""):
    if len(data) < 28:
        raise ValueError(f"$I 파일이 너무 작습니다: {len(data)}바이트")
    version, = struct.unpack_from("<Q", data, 0)
    if version == 1:
        if len(data) < 544:
            raise ValueError(f"v1 $I 파일 크기 부족: {len(data)}바이트 (최소 544)")
        file_size, = struct.unpack_from("<Q", data, 8)
        del_time, = struct.unpack_from("<Q", data, 16)
        path_raw = data[24:24 + 520]
        decoding = {}
        try:
            original_path = path_raw.decode("utf-16-le").rstrip("\0")
        except UnicodeDecodeError:
            original_path = path_raw.decode('utf-16-le', errors='replace').rstrip('\0')
            decoding = {'encoding':'utf-16-le', 'decode_error':True, 'inferred':False, 'raw_hex':path_raw.hex()}
        return {
            "version": 1,
            "file_size": file_size,
            "deletion_time": filetime(del_time),
            "deletion_filetime": del_time,
            "original_path": original_path,
            **({'text_decoding':[decoding]} if decoding else {}),
        }
    elif version == 2:
        file_size, = struct.unpack_from("<Q", data, 8)
        del_time, = struct.unpack_from("<Q", data, 16)
        path_len, = struct.unpack_from("<I", data, 24)
        path_offset = 28
        path_bytes = path_len * 2
        if len(data) < path_offset + path_bytes:
            raise ValueError(f"v2 $I 경로 데이터 부족")
        path_raw = data[path_offset:path_offset + path_bytes]
        decoding = {}
        try:
            original_path = path_raw.decode("utf-16-le").rstrip("\0")
        except UnicodeDecodeError:
            original_path = path_raw.decode('utf-16-le', errors='replace').rstrip('\0')
            decoding = {'encoding':'utf-16-le', 'decode_error':True, 'inferred':False, 'raw_hex':path_raw.hex()}
        return {
            "version": 2,
            "file_size": file_size,
            "deletion_time": filetime(del_time),
            "deletion_filetime": del_time,
            "original_path": original_path,
            **({'text_decoding':[decoding]} if decoding else {}),
        }
    else:
        raise ValueError(f"알 수 없는 $I 버전: {version}")


class RecycleBinParser(ArtifactParser):
    artifact = "recyclebin"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            files = sorted(f for f in source.rglob("$I*") if f.is_file())
            if not files:
                files = sorted(f for f in source.rglob("*") if f.is_file() and f.name.startswith("$I"))
        else:
            files = [source]

        for file in files:
            try:
                data = file.read_bytes()
            except OSError as exc:
                self.error(file, "read", exc)
                continue

            if not file.name.upper().startswith("$I"):
                continue

            try:
                info = parse_dollar_i(data, file.name)
            except ValueError as exc:
                self.error(file, "parse", exc)
                continue

            sid_from_path = None
            for parent in file.parents:
                if parent.name.startswith("S-1-"):
                    sid_from_path = parent.name
                    break

            original_name = ntpath.basename(info["original_path"]) if info["original_path"] else file.name
            r_file = file.parent / ("$R" + file.name[2:])
            # Collected metadata may intentionally omit the companion content.
            pair = {"state":"not_observed", "exists":None, "directory":None, "size":None,
                    "scope":"selected_local_directory", "local_path":str(r_file),
                    "image_path":None, "mft_record":None, "mft_sequence":None,
                    "reason":"companion_not_collected", "absence_confirmed":False}
            try:
                observed = r_file.lstat()
                if stat.S_ISLNK(observed.st_mode) or getattr(observed, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                    pair.update(state="unavailable", reason="reparse_point_not_followed")
                elif stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode):
                    directory = stat.S_ISDIR(observed.st_mode)
                    pair.update(state="present", exists=True, directory=directory,
                                size=None if directory else observed.st_size, reason=None)
            except FileNotFoundError:
                pass
            except OSError as exc:
                pair.update(state="unavailable", reason="directory_unreadable", diagnostic=str(exc))
            pair["state_label"] = RECYCLE_PAIR_STATES[pair["state"]]
            pair["reason_label"] = RECYCLE_PAIR_REASONS.get(pair["reason"])
            r_exists = pair["exists"]

            detail = {
                **({'text_decoding':info['text_decoding']} if info.get('text_decoding') else {}),
                "original_path": info["original_path"],
                "original_name": original_name,
                "file_size": info["file_size"],
                "file_size_mb": round(info["file_size"] / (1024 * 1024), 2),
                "deletion_filetime": info["deletion_filetime"],
                "version": info["version"],
                "i_file": file.name,
                "r_file_exists": r_exists,
                "recycle_pair": pair,
            }

            yield ForensicEvent(
                self.artifact, str(file), "파일 삭제",
                info["deletion_time"], "deletion_time",
                sid=sid_from_path or self.sid,
                path=info["original_path"],
                locator=str(file),
                status="ok",
                details=detail,
            )
