"""Locate and copy Windows forensic artifacts out of a disk image (E01/raw) for offline parsing."""
import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from log_hunter.parser.bam import load_profile_list
from log_hunter.core.labels import IMAGE_VERIFICATION_LABELS
from .ewf import ImageError, open_image
from .live import LIVE_WARNING, is_live_path, live_device
from .ntfs import NTFSError, NTFSVolume
from .volumes import find_volumes

HIVE_SIDECARS = (".LOG1", ".LOG2")
SQLITE_SIDECARS = ("-wal", "-shm", "-journal")
USER_HOMES = ("Users/*", "Documents and Settings/*")

ARTIFACT_SPECS = [
    ('ProgramData/Microsoft/Windows Defender/Support/MPLog-*.log', ('defender',), ()),
    ('ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/*/*', ('defender',), ()),
    ('ProgramData/Microsoft/Windows Defender/Quarantine/Entries/*', ('defender',), ()),
    ("Windows/System32/config/SYSTEM", ("bam", "usb", "services"), HIVE_SIDECARS),
    ("Windows/System32/config/SOFTWARE", ("network", "run", "usb", "taskcache"), HIVE_SIDECARS),
    ("Windows/AppCompat/Programs/Amcache.hve", ("amcache",), HIVE_SIDECARS),
    ("Windows/Prefetch/*.pf", ("prefetch",), ()),
    ("Windows/System32/winevt/Logs/*.evtx", ("evtx",), ()),
    ("Windows/System32/sru/SRUDB.dat", ("srum",), ()),
    ("Windows/System32/Tasks/**", ("tasks",), ()),
    ("ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/*/*.xml", ("wlan",), ()),
    ("ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/*", ("startup",), ()),
    ("$Recycle.Bin/*/$I*", ("recyclebin",), ()),
    *[(home + "/NTUSER.DAT", ("userassist", "mru", "run", "shellbag", "rdp"), HIVE_SIDECARS) for home in USER_HOMES],
    ('Users/*/Documents/Default.rdp', ('rdp',), ()),
    ('Documents and Settings/*/My Documents/Default.rdp', ('rdp',), ()),
    ("Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat", ("shellbag",), HIVE_SIDECARS),
    ("Documents and Settings/*/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat", ("shellbag",), HIVE_SIDECARS),
    ("Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk", ("lnk",), ()),
    ('Users/*/AppData/Local/Microsoft/Windows/Explorer/thumbcache_*.db', ('thumbcache',), ()),
    ("Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms", ("jumplist",), ()),
    ('Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms', ('jumplist',), ()),
    ("Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*", ("startup",), ()),
    ("Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt", ("psreadline",), ()),
    ("Users/*/AppData/Local/Google/Chrome/User Data/*/History", ("history",), SQLITE_SIDECARS),
    ("Users/*/AppData/Local/Microsoft/Edge/User Data/*/History", ("history",), SQLITE_SIDECARS),
]
MFT_SPEC = ("$MFT", ("mft",), ())
_UNSAFE = re.compile(r'[<>:"|?*/\\\x00-\x1f]')


@dataclass
class ImageExtraction:
    image_path: str
    output: str
    image: dict = field(default_factory=dict)
    volumes: list = field(default_factory=list)
    files: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    verification: dict = field(default_factory=dict)

    def to_dict(self):
        return {"image_path": self.image_path, "output": self.output, "image": self.image,
                "volumes": self.volumes, "files": self.files, "warnings": self.warnings,
                "verification": self.verification}

    def file_index(self):
        return {str(Path(f["extracted"]).resolve()).casefold(): f for f in self.files}


def _safe(name):
    cleaned = _UNSAFE.sub("_", name).rstrip(" .")
    if re.match(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", cleaned, re.IGNORECASE):
        cleaned = "_" + cleaned
    return cleaned if cleaned not in ("", ".", "..") else "_"


def glob_ntfs(volume, pattern):
    """Yield (relative parts, entry, parent record) for files matching a '/'-separated pattern."""
    parts = pattern.split("/")
    visited = set()  # (record, pattern index): a crafted index can link a folder back to its ancestor

    def walk(record, index, prefix, depth=0):
        if (record, index) in visited:
            return
        visited.add((record, index))
        part, last = parts[index], index == len(parts) - 1
        try:
            listing = volume.listdir(record)
        except NTFSError:
            return
        for entry in listing:
            if part == "**":
                if entry.directory and depth < 32:
                    yield from walk(entry.record, index, prefix + [entry.name], depth + 1)
                elif not entry.directory:
                    yield prefix + [entry.name], entry, record
            elif fnmatchcase(entry.name.lower(), part.lower()):
                if last and not entry.directory:
                    yield prefix + [entry.name], entry, record
                elif not last and entry.directory:
                    yield from walk(entry.record, index + 1, prefix + [entry.name], depth + 1)

    yield from walk(5, 0, [])


def extract_artifacts(image_path, output_dir, include_mft=False, progress=None,
                      verify=False, verification_progress=None, verification_cancel=None):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FileExistsError(f"추출 폴더가 비어 있지 않습니다: {output}")
    live = is_live_path(image_path)
    source = live_device(image_path) if live else str(Path(image_path).resolve())
    result = ImageExtraction(source, str(output.resolve()))
    specs = ARTIFACT_SPECS + ([MFT_SPEC] if include_mft else [])
    try:
        opened = open_image(image_path)
    except (OSError, ImageError) as exc:
        if not verify:
            raise
        from .verify import open_error
        result.verification = open_error(exc)
        result.warnings.append('이미지 무결성 검증 중 이미지를 열지 못했습니다')
        (output / 'image_manifest.json').write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding='utf-8')
        return result
    with opened as image:
        result.image = image.info()
        if verify:
            if live:
                raise ValueError('실행 중 볼륨 대신 오프라인 이미지에서 무결성을 검증하세요')
            from .verify import verify_open_image
            result.verification = verify_open_image(image, image_path, verification_progress, verification_cancel)
            status = result.verification['status']
            if status in ('mismatch', 'metadata_error', 'read_error', 'cancelled'):
                result.warnings.append('이미지 무결성 검증: ' + IMAGE_VERIFICATION_LABELS[status] + '; 검증 상세값을 확인하세요')
            if status in ('read_error', 'cancelled'):
                (output / 'image_manifest.json').write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding='utf-8')
                return result
        if live:
            result.warnings.append(LIVE_WARNING)
        volumes = find_volumes(image)
        result.volumes = [v.to_dict() for v in volumes]
        if not volumes:
            result.warnings.append("파티션/파일시스템을 찾지 못했습니다")
        for volume in volumes:
            if volume.filesystem == "bitlocker":
                result.warnings.append(f"볼륨 {volume.index}: BitLocker로 암호화되어 있어 분석할 수 없습니다 (복호화된 이미지 필요)")
                continue
            if volume.filesystem != "ntfs":
                continue
            try:
                ntfs = NTFSVolume(image, volume.offset)
            except (NTFSError, ValueError) as exc:
                result.warnings.append(f"볼륨 {volume.index}: NTFS를 열 수 없습니다 ({exc})")
                continue
            _extract_volume(ntfs, volume.index, output / f"volume{volume.index}", specs, result, progress)
    if not result.files:
        result.warnings.append("이미지에서 Windows 아티팩트를 찾지 못했습니다")
    _assign_sids(result)
    (output / "image_manifest.json").write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _extract_volume(ntfs, volume_index, root, specs, result, progress):
    recycle_directories = {}
    for pattern, artifacts, sidecars in specs:
        for parts, entry, parent in glob_ntfs(ntfs, pattern):
            destination = root.joinpath(*[_safe(p) for p in parts])
            if not destination.resolve().is_relative_to(root.resolve()):
                result.warnings.append(f"[볼륨 {volume_index}] {parts}: 출력 폴더 밖을 가리키는 이름이라 건너뜁니다")
                continue
            image_path = "\\" + "\\".join(parts)
            destination = _copy(ntfs, entry, destination, image_path, volume_index, artifacts, result)
            if destination is None:
                continue
            if "recyclebin" in artifacts:
                from .recycle import describe_recycle_pair
                origin = result.files[-1]
                origin["recycle_pair"] = {**describe_recycle_pair(ntfs, parts, entry, parent, origin.get("sha256"), recycle_directories),
                                          "scope":"original_directory_index", "image":result.image_path,
                                          "volume":volume_index}
            if progress:
                progress(len(result.files), image_path)
            for artifact in artifacts:
                result.inputs.append([artifact, str(destination), None])
            if sidecars:
                siblings = {e.name.lower(): e for e in ntfs.listdir(parent)}
                for suffix in sidecars:
                    sibling = siblings.get((entry.name + suffix).lower())
                    if sibling and not sibling.directory:
                        _copy(ntfs, sibling, Path(str(destination) + suffix), image_path + suffix, volume_index, (), result)


def _unique(destination):
    # Case-sensitive NTFS folders can hold "A.pf" and "a.pf"; never overwrite or delete an earlier copy.
    candidate, number = destination, 2
    while candidate.exists():
        candidate = destination.with_name(f"{destination.stem} ({number}){destination.suffix}")
        number += 1
    return candidate


def _copy(ntfs, entry, destination, image_path, volume_index, artifacts, result):
    """Copy one file out of the image; returns the copy's path, or None (with a warning) on failure."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination = _unique(destination)
    try:
        info = ntfs.copy_file(entry, destination)
    except FileExistsError as exc:
        result.warnings.append(f"[볼륨 {volume_index}] {image_path}: 기존 추출 파일을 보존합니다 ({exc})")
        return None
    except (NTFSError, ValueError, OSError) as exc:
        destination.unlink(missing_ok=True)
        result.warnings.append(f"[볼륨 {volume_index}] {image_path}: 추출 실패 ({exc})")
        return None
    note = info.pop("warning", None)
    if note:
        result.warnings.append(f"[볼륨 {volume_index}] {image_path}: {note}")
    result.files.append({"volume": volume_index, "image_path": image_path, "extracted": str(destination),
                         "artifacts": list(artifacts), **info})
    return destination


def _assign_sids(result):
    software = next((f for f in result.files if f["image_path"].lower().endswith("\\system32\\config\\software")), None)
    profiles = load_profile_list(software["extracted"]) if software else {}
    by_user = {name.lower(): sid for sid, name in profiles.items()}
    owners = {}
    for item in result.files:
        parts = item["image_path"].strip("\\").split("\\")
        sid = None
        if len(parts) > 2 and parts[0].lower() in ("users", "documents and settings"):
            sid = by_user.get(parts[1].lower())
        elif len(parts) > 2 and parts[0].lower() == "$recycle.bin" and parts[1].upper().startswith("S-1-"):
            sid = parts[1]
        if sid:
            item["sid"] = sid
            owners[str(Path(item["extracted"]))] = sid
    for entry in result.inputs:
        entry[2] = owners.get(str(Path(entry[1])))
    result.inputs = [tuple(entry) for entry in result.inputs]
