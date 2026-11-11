"""Auto-detect forensic artifact types from file paths and content."""
from pathlib import Path
from fnmatch import fnmatchcase
import mmap
import struct
import os
from itertools import islice


HIVE_ARTIFACTS = {
    "ntuser.dat": ("userassist", "mru", "run", "shellbag", "rdp"),
    "system": ("bam", "usb", "services"), "software": ("network", "run", "usb", "taskcache"),
    "usrclass.dat": ("shellbag",), "amcache.hve": ("amcache",),
}


def _sidecar(name):
    return name.lower().endswith((".log1", ".log2", "-wal", "-shm", "-journal"))


def detect_artifact(path_str):
    path = Path(path_str)
    name = path.name
    name_lower = name.lower()
    ext = path.suffix.lower()
    parent = path.parent.name.lower()
    parts_lower = str(path).lower()

    if _sidecar(name):
        return None

    normalized = parts_lower.replace('\\', '/')
    if '/quarantine/resourcedata/' in normalized or '/quarantine/resources/' in normalized:
        return None
    if name_lower.startswith('mplog-') and ext == '.log':
        return 'defender'
    if '/detectionhistory/' in normalized or '/quarantine/entries/' in normalized:
        return 'defender'

    try:
        with path.open("rb") as stream:
            signature = stream.read(8)
        if signature == b"ElfFile\0":
            return "evtx"
    except OSError:
        pass
    if ext == ".evtx":
        return "evtx"
    if ext == ".pf":
        return "prefetch"
    if name_lower == "$mft":
        return "mft"
    if name_lower == "amcache.hve":
        return "amcache"
    if ext == ".lnk":
        return "lnk"
    if ext == '.rdp':
        return 'rdp'
    if name_lower.startswith('thumbcache_') and ext == '.db':
        return 'thumbcache'
    if ext in ('.automaticdestinations-ms', '.customdestinations-ms'):
        return "jumplist"

    if name_lower in ("ntuser.dat", "ntuser.dat.log1", "ntuser.dat.log2"):
        return "userassist"
    if name_lower in ("system", "system.log1", "system.log2") and not ext:
        return "bam"
    if name_lower in ("software", "software.log1", "software.log2") and not ext:
        return "network"
    if name_lower == "sam" and not ext:
        return None

    if "prefetch" in parts_lower and parent == "prefetch":
        return "prefetch"
    if name_lower == "consolehost_history.txt":
        return "psreadline"
    if "psreadline" in parts_lower and name_lower.endswith(".txt"):
        return "psreadline"

    if name_lower == "history" and ("chrome" in parts_lower or "edge" in parts_lower
                                     or "chromium" in parts_lower or "brave" in parts_lower):
        return "history"
    if parent in ("cache", "cache2", "code cache", "gpu cache") or name_lower == "index":
        if _looks_like_cache_dir(path.parent if name_lower == "index" else path):
            return "cache"

    if "srudb" in name_lower or (name_lower.endswith(".dat") and "srum" in parts_lower):
        return "srum"

    if parent == "tasks" or "\\tasks\\" in parts_lower.replace("/", "\\"):
        if _looks_like_task_xml(path):
            return "tasks"

    if ext == ".xml" and "wlansvc" in parts_lower:
        return "wlan"
    if ext == ".xml" and _looks_like_wlan_xml(path):
        return "wlan"

    if name_lower.startswith("$i") and ("$recycle.bin" in parts_lower or "recycl" in parent):
        return "recyclebin"

    if "startup" in parts_lower and ext in (".lnk", ".bat", ".cmd", ".vbs", ".ps1", ".exe"):
        return "startup"

    return None


def _looks_like_cache_dir(dir_path):
    try:
        children = {f.name.lower() for f in Path(dir_path).iterdir() if f.is_file()}
    except OSError:
        return False
    return "index" in children and any(n.startswith("data_") for n in children)


def _looks_like_task_xml(file_path):
    try:
        with Path(file_path).open("rb") as stream:
            data = stream.read(256)
        return b"<Task" in data
    except OSError:
        return False


def _looks_like_wlan_xml(file_path):
    try:
        with Path(file_path).open("rb") as stream:
            data = stream.read(512)
        return b"WLANProfile" in data
    except OSError:
        return False


def detect_artifacts_in_directory(dir_path):
    results = []
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        return results
    for file in sorted(dir_path.rglob("*")):
        if not file.is_file():
            continue
        if _sidecar(file.name):
            continue
        artifact = detect_artifact(file)
        if artifact:
            results.append((artifact, str(file)))
    return results


def _hive_kind(path, header):
    name = path.name.lower()
    if name in HIVE_ARTIFACTS or name in ("sam", "security", "default", "bcd"):
        return name
    if header[:4] != b"regf":
        return None
    embedded = header[0x30:0x70].decode("utf-16-le", errors="replace").split("\0", 1)[0]
    embedded = embedded.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if embedded in HIVE_ARTIFACTS or embedded in ("sam", "security", "default", "bcd"):
        return embedded
    from log_hunter.parser.registry import Hive
    class ProbeHive(Hive):
        def cell(self, relative):
            offset = 4096 + relative
            if offset < 4096 or offset + 4 > len(self.data):
                raise ValueError("하이브 탐색 범위 초과")
            size = struct.unpack_from("<i", self.data, offset)[0]
            if size >= 0 or -size > 1024 * 1024:
                raise ValueError("하이브 탐색 셀 크기 초과")
            return super().cell(relative)
    try:
        with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            hive = ProbeHive.__new__(ProbeHive)
            hive.data = data
            root = hive.key(hive.u32(0x24))
            hive.root = root
            names = {key.name.lower() for key in islice(root.subkeys(), 256)}
            if "select" in names and any(n.startswith("controlset") for n in names):
                return "system"
            if {"microsoft", "classes"} <= names:
                return "software"
            if {"software", "control panel"} <= names:
                return "ntuser.dat"
            if "local settings" in names:
                return "usrclass.dat"
            if "root" in names:
                inventory = hive.open("Root\\InventoryApplicationFile")
                if inventory is not None:
                    return "amcache.hve"
    except (OSError, ValueError, IndexError, KeyError, struct.error):
        pass
    return "unknown"


def _image_kind(path, header):
    if header.startswith(b"EVF2"):
        return None, "Ex01은 아직 지원하지 않습니다. E01 또는 raw 이미지를 선택하세요."
    if header.startswith(b"LVF"):
        return None, "L01은 아직 지원하지 않습니다. E01 또는 raw 이미지를 선택하세요."
    if header.startswith(b"vhdxfile") or path.suffix.lower() == ".vhdx":
        return None, "VHDX는 아직 지원하지 않습니다."
    if header.startswith(b"conectix"):
        return None, "동적 VHD는 아직 지원하지 않습니다. 고정 VHD를 선택하세요."
    if header.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
        if path.suffix.lower() != ".e01":
            first = next((p for p in path.parent.iterdir() if p.stem.casefold() == path.stem.casefold()
                          and p.suffix.lower() == ".e01"), None)
            if first:
                return str(first), "디스크 이미지 시그니처"
            if path.suffix.lower().startswith(".e"):
                return None, "E01 첫 세그먼트를 함께 선택하세요."
        return str(path), "디스크 이미지 시그니처"
    if (header[3:11] == b"NTFS    " or header[512:520] == b"EFI PART"
            or len(header) >= 512 and header[510:512] == b"\x55\xaa"
            and any(header[446 + i * 16 + 4] for i in range(4))):
        return str(path), "디스크 부트 시그니처"
    if path.suffix.lower() == ".vhd":
        with path.open("rb") as stream:
            stream.seek(-512, 2)
            footer = stream.read(512)
        if footer[:8] == b"conectix":
            if int.from_bytes(footer[60:64], "big") == 2:
                return str(path), "고정 VHD 시그니처"
            return None, "동적 VHD는 아직 지원하지 않습니다."
    return None, None


def detect_inputs(paths):
    """Return (artifact, path, owner SID, reason); artifact=None denotes a diagnostic."""
    from log_hunter.image.extract import ARTIFACT_SPECS
    results, seen, emitted = [], set(), set()

    def append(row):
        identity = (row[0], str(Path(row[1]).resolve()).casefold())
        if identity not in emitted:
            emitted.add(identity)
            results.append(row)

    def walk(source):
        def failure(exc):
            append((None, str(exc.filename or source), None, f"폴더를 읽을 수 없습니다: {exc}"))
        for root, dirs, files in os.walk(source, followlinks=False, onerror=failure):
            dirs[:] = sorted(d for d in dirs if not Path(root, d).is_symlink())
            for name in sorted(files):
                yield Path(root, name)

    for source in paths:
        source = Path(source)
        files = walk(source) if source.is_dir() else [source]
        for path in files:
            if path.is_dir():
                continue
            identity = str(path.resolve()).casefold()
            if identity in seen:
                continue
            seen.add(identity)
            reason, kinds = "파일 이름", ()
            if _sidecar(path.name):
                suffix_size = 5 if path.name.lower().endswith((".log1", ".log2")) else 4
                if Path(str(path)[:-suffix_size]).exists():
                    continue
                append((None, str(path), None, "보조 파일입니다. 본 파일을 함께 선택하세요."))
                continue
            try:
                with path.open("rb") as stream:
                    header = stream.read(4096)
                if header[:8] == b"ElfFile\0":
                    append(("evtx", str(path), None, "이벤트 로그 시그니처"))
                    continue
                if header[4:8] == b"LfLe" or path.suffix.lower() == ".evt":
                    append((None, str(path), None, "구형 Windows 이벤트 로그(.evt)는 지원하지 않습니다."))
                    continue
                if not header and path.suffix.lower() == ".evtx":
                    append((None, str(path), None, "빈 파일입니다. 이벤트 로그 헤더가 없습니다."))
                    continue
                from log_hunter.parser.defender_history import is_history
                if is_history(header):
                    append(('defender', str(path), None, '보호 기록 1.2 헤더'))
                    continue
                kind = _hive_kind(path, header)
                if kind:
                    kinds = HIVE_ARTIFACTS.get(kind, ())
                    reason = "하이브 이름 또는 내용"
                    if not kinds:
                        reason = "지원하지 않는 하이브입니다."
                else:
                    image, diagnostic = _image_kind(path, header)
                    if diagnostic:
                        if image:
                            path = Path(image)
                            kinds = ("image",)
                        reason = diagnostic
                        for artifact in kinds or (None,):
                            row = (artifact, str(path), None, reason)
                            append(row)
                        continue
                    normalized = path.as_posix().lower()
                    for pattern, artifacts, _ in ARTIFACT_SPECS:
                        if fnmatchcase(normalized, "*/" + pattern.lower()):
                            kinds, reason = artifacts, "수집 경로 규칙"
                            break
                    if not kinds:
                        artifact = detect_artifact(path)
                        kinds = (artifact,) if artifact else ()
            except (OSError, ValueError) as exc:
                reason = f"입력을 읽을 수 없습니다: {exc}"
            for artifact in kinds or (None,):
                row = (artifact, str(path), None, reason if kinds else reason if reason != "파일 이름" else "기록 종류를 인식하지 못했습니다.")
                append(row)
    return _assign_detected_sids(results)


def _assign_detected_sids(rows):
    from log_hunter.image.extract import ImageExtraction, _assign_sids
    groups = {}
    for row in rows:
        path = Path(row[1])
        parts = path.parts
        lowered = [part.lower() for part in parts]
        index = next((i for i in range(len(parts) - 1, -1, -1)
                      if lowered[i] in ("users", "documents and settings", "$recycle.bin")
                      or lowered[i:i + 2] == ["windows", "system32"]), None)
        if index is None:
            continue
        scope = str(Path(*parts[:index])).casefold()
        extraction = groups.setdefault(scope, ImageExtraction("", ""))
        extraction.files.append({"image_path": "\\" + "\\".join(parts[index:]), "extracted": str(path)})
        extraction.inputs.append([row[0], str(path), None])
    owners = {}
    for extraction in groups.values():
        try:
            _assign_sids(extraction)
        except (OSError, ValueError, KeyError, IndexError):
            continue
        owners.update({path: sid for _, path, sid in extraction.inputs if sid})
    return [(artifact, path, owners.get(path), reason) for artifact, path, _, reason in rows]
