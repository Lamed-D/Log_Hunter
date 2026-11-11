import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from log_hunter.collector.live_collector import sha256, register_evidence
from log_hunter.core.models import ParserError
from .correlation import correlate
from .timeline import timeline
from .labels import IMAGE_VERIFICATION_LABELS
from log_hunter.parser.registry import replay_logs, Hive, current_controlset
from .text import target_acp
from log_hunter.parser.userassist import UserAssistParser
from log_hunter.parser.bam import BAMParser, load_profile_list
from log_hunter.parser.run import RunParser
from log_hunter.parser.mru import MRUParser
from log_hunter.parser.usb import USBParser
from log_hunter.parser.amcache import AmcacheParser
from log_hunter.parser.psreadline import PSReadLineParser
from log_hunter.parser.history import HistoryParser
from log_hunter.parser.cache import CacheParser
from log_hunter.parser.prefetch import PrefetchParser
from log_hunter.parser.evtx import EVTXParser
from log_hunter.parser.mft import MFTParser
from log_hunter.parser.shellbag import ShellBagParser
from log_hunter.parser.srum import SRUMParser
from log_hunter.parser.lnk import LNKParser
from log_hunter.parser.jumplist import JumpListParser
from log_hunter.parser.network import NetworkProfileParser
from log_hunter.parser.tasks import TaskSchedulerParser
from log_hunter.parser.taskcache import TaskCacheParser
from log_hunter.parser.recyclebin import RecycleBinParser
from log_hunter.parser.wlan import WLANParser
from log_hunter.parser.startup import StartupParser
from log_hunter.parser.services import ServicesParser
from log_hunter.parser.mountpoints2 import read_volume_hints, attach_volume_hints
from log_hunter.parser.rdp import RDPParser
from log_hunter.parser.thumbcache import ThumbcacheParser
from log_hunter.parser.defender import DefenderParser

PARSERS = {"userassist": UserAssistParser, "bam": BAMParser, "run": RunParser, "mru": MRUParser,
           "usb": USBParser, "amcache": AmcacheParser, "psreadline": PSReadLineParser, "history": HistoryParser,
           "cache": CacheParser, "prefetch": PrefetchParser, "evtx": EVTXParser, "mft": MFTParser,
           "shellbag": ShellBagParser, "srum": SRUMParser, "lnk": LNKParser, "jumplist": JumpListParser,
           "network": NetworkProfileParser, "taskcache": TaskCacheParser, "tasks": TaskSchedulerParser, "recyclebin": RecycleBinParser,
           "wlan": WLANParser, "startup": StartupParser, "services": ServicesParser,
           "rdp": RDPParser, "thumbcache": ThumbcacheParser,
           "defender": DefenderParser}


@dataclass
class AnalysisResult:
    evidence: list = field(default_factory=list)
    events: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    relations: list = field(default_factory=list)
    summaries: list = field(default_factory=list)
    profiles: dict = field(default_factory=dict)
    image: dict = field(default_factory=dict)
    inputs: list = field(default_factory=list)
    settings: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    sid_names: dict = field(default_factory=dict)


PERMISSION_HINT = ("파일을 열 권한이 없습니다. 실행 중인 Windows의 레지스트리/로그 파일은 잠겨 있어 직접 읽을 수 없습니다. "
                   "'이 PC 직접 분석'(관리자 권한, CLI는 --live)을 사용하거나 디스크 이미지(E01)로 분석하세요.")


def apply_image_metadata(result, extraction):
    """Mark evidence copied out of a disk image with its original location and the image identity."""
    index = extraction.file_index()
    drive = extraction.image.get("drive")
    for item in result.evidence:
        origin = index.get(str(Path(item.source).resolve()).casefold())
        if origin is None:
            continue
        item.method = "LIVE" if drive else "IMAGE"
        item.metadata = {**(item.metadata or {}), "image": extraction.image_path,
                         "image_path": origin["image_path"], "volume": origin["volume"],
                         "mft_record": origin.get("mft_record"), "extracted_sha256": origin.get("sha256")}
        if drive:
            item.metadata["drive"] = drive
        if origin.get('snapshot'):
            item.metadata['snapshot'] = dict(origin['snapshot'])
    for event in result.events:
        if event.artifact != "recyclebin":
            continue
        origin = index.get(str(Path(event.source).resolve()).casefold())
        if origin is not None and origin.get("recycle_pair"):
            pair = dict(origin["recycle_pair"])
            if origin.get("snapshot"):
                pair["snapshot"] = dict(origin["snapshot"])
            event.details["recycle_pair"] = pair
            event.details["r_file_exists"] = pair["exists"]
    result.image = extraction.to_dict()
    for warning in extraction.warnings:
        result.errors.append(ParserError(extraction.image_path, "image", "extract", warning, "warning"))
    return result


def merge_history(source, working_directory):
    """Recover SQLite journals on disposable copies, then SQLite backup to an immutable DB."""
    source = Path(source)
    working = Path(working_directory) / "History"
    shutil.copyfile(source, working)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(source) + suffix)
        if sidecar.exists():
            shutil.copyfile(sidecar, Path(str(working) + suffix))
    normalized = Path(working_directory) / "normalized.sqlite"
    read = sqlite3.connect(working)
    write = sqlite3.connect(normalized)
    try:
        read.backup(write)
    finally:
        write.close()
        read.close()
    return normalized


class Pipeline:
    def analyze_snapshot(self, image_path, workdir, volume_index, store_id, sid=None, environment=None,
                         progress=None, include_mft=False, extract_progress=None,
                         verification_progress=None, verification_cancel=None):
        """선택한 스냅숏의 확인된 저장 범위만 분석하고 증거별 출처를 보존합니다."""
        from log_hunter.image.vss_extract import extract_mapped_snapshot
        extraction = extract_mapped_snapshot(image_path, workdir, volume_index, store_id,
                                             include_mft=include_mft, progress=extract_progress,
                                             verification_progress=verification_progress, verification_cancel=verification_cancel)
        return apply_image_metadata(self.analyze(extraction.inputs, sid, environment, progress), extraction)

    def analyze_image(self, image_path, workdir, sid=None, environment=None, progress=None,
                      include_mft=False, extract_progress=None, verify=False,
                      verification_progress=None, verification_cancel=None):
        from log_hunter.image import extract_artifacts
        extraction = extract_artifacts(image_path, workdir, include_mft=include_mft, progress=extract_progress,
                                       verify=verify, verification_progress=verification_progress,
                                       verification_cancel=verification_cancel)
        result = self.analyze(extraction.inputs, sid, environment, progress)
        result = apply_image_metadata(result, extraction)
        for error in extraction.verification.get('errors', []):
            result.errors.append(ParserError(str(image_path), 'image',
                                             'verification:' + str(error.get('offset')), error['message'], 'error'))
        if extraction.verification.get('status') in ('read_error', 'cancelled'):
            result.summaries = [{'source': str(image_path), 'artifact': 'image', 'events': 0,
                                 'state': 'failed' if extraction.verification['status'] == 'read_error' else 'partial',
                                 'errors': len(extraction.verification.get('errors', []))}]
        if extraction.verification.get('status') in ('match', 'no_stored_hash'):
            result.errors.append(ParserError(str(image_path), 'image', 'verification',
                                             '이미지 무결성 검증: ' + IMAGE_VERIFICATION_LABELS[extraction.verification['status']], 'info'))
        return result

    def analyze(self, inputs, sid=None, environment=None, progress=None):
        # Inputs are (artifact, path) or (artifact, path, owner_sid); the per-input SID wins over `sid`.
        expanded = []
        for artifact, path, *rest in inputs:
            owner = rest[0] if rest and rest[0] else sid
            source = Path(path)
            if source.is_dir() and artifact not in ("cache", "wlan", "recyclebin", "startup", "defender", "tasks"):
                pattern = "*.pf" if artifact == "prefetch" else "*"
                expanded.extend((artifact, file, owner) for file in sorted(source.glob(pattern)) if file.is_file())
            else:
                expanded.append((artifact, source, owner))
        result = AnalysisResult()
        result.inputs = [{'artifact': a, 'path': str(p), 'sid': owner, 'reason': None}
                         for a, p, owner in expanded]
        result.settings = {'sid': sid, 'environment': dict(environment or {})}
        environment = dict(environment or {})
        if target_acp(environment) is None:
            inspected = set()
            for artifact, path, _owner in expanded:
                if artifact not in ('bam', 'usb', 'services') or path in inspected:
                    continue
                inspected.add(path)
                try:
                    hive = Hive(path)
                    if hive.data[4:8] != hive.data[8:12]:
                        continue
                    acp = hive.open(current_controlset(hive) + r'\Control\Nls\CodePage').value('ACP')
                    if target_acp({'ACP':acp}):
                        environment['TARGET_ACP'] = str(acp)
                        break
                except Exception:
                    continue
        profiles = {}
        for art, p, _owner in expanded:
            if art in ("network", "amcache", "bam") or str(p).lower().endswith("software"):
                try:
                    profiles = load_profile_list(p)
                    if profiles:
                        break
                except Exception:
                    continue
        result.profiles = profiles
        result.sid_names = dict(profiles)
        registered = set()
        volume_hints = []
        for index, (artifact, path, owner) in enumerate(expanded, 1):
            if progress:
                progress(index - 1, len(expanded), str(path))
            parser = PARSERS[artifact](sid=owner, environment=environment)
            started, before = time.monotonic(), {}
            event_start = len(result.events)
            failed = False
            original = path
            recovery_dir = None
            try:
                sources = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
                if artifact in ("history", "srum"):
                    sources += [Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal") if Path(str(path) + suffix).exists()]
                if artifact in ("bam", "run", "userassist", "usb", "mru", "amcache", "shellbag", "network", "services", "rdp", "taskcache"):
                    sources += [Path(str(path) + suffix) for suffix in (".LOG1", ".LOG2") if Path(str(path) + suffix).exists()]
                for source in sources:
                    before[source] = sha256(source)
                    key = str(Path(source).resolve()).casefold()
                    if key in registered:
                        continue
                    registered.add(key)
                    item = register_evidence(source, source, "OFFLINE")
                    item.metadata = {"log_replay": False, "source_sidecar": not path.is_dir() and source != path}
                    result.evidence.append(item)
                if artifact in ("bam", "run", "userassist", "usb", "mru", "amcache", "shellbag", "network", "services", "taskcache"):
                    with path.open("rb") as stream:
                        header = stream.read(12)
                    if header[:4] == b"regf" and header[4:8] != header[8:12]:
                        try:
                            recovered_data, recovery_info = replay_logs(path)
                            if recovery_info.get("recovered"):
                                recovery_dir = Path(tempfile.mkdtemp(prefix="log-hunter-reg-"))
                                recovered_path = recovery_dir / path.name
                                recovered_path.write_bytes(recovered_data)
                                parser.error(path, "header", f"dirty hive: LOG 복구 성공 ({recovery_info.get('log_applied', '?')}, {recovery_info.get('pages_applied', 0)}페이지)", "warning")
                                for warning in recovery_info.get("warnings", []):
                                    parser.error(path, "log", warning, "warning")
                                path = recovered_path
                            else:
                                reasons = "; ".join(recovery_info.get("warnings", []))
                                parser.error(path, "header", f"dirty hive: LOG 복구 불가 ({reasons})", "warning")
                        except Exception as exc:
                            parser.error(path, "header", f"dirty hive: LOG 복구 시도 중 오류 ({exc})", "warning")
                sqlite_input = artifact == "history"
                if artifact == "srum":
                    with path.open("rb") as stream:
                        sqlite_input = stream.read(16) == b"SQLite format 3\x00"
                if sqlite_input:
                    with tempfile.TemporaryDirectory(prefix="log-hunter-history-") as temporary:
                        merged = merge_history(path, temporary)
                        for event in parser.parse(merged):
                            event.source = str(path)
                            result.events.append(event)
                        for error in parser.errors:
                            if error.source == str(merged):
                                error.source = str(path)
                elif artifact == "bam" and profiles:
                    result.events.extend(parser.parse(path, profiles=profiles))
                else:
                    result.events.extend(parser.parse(path))
                if artifact == "userassist":
                    hints, errors = read_volume_hints(path, owner, source=str(original))
                    volume_hints.extend(hints)
                    parser.errors.extend(errors)
                if path != original:
                    # Events parsed from the LOG-recovered temp copy still belong to the evidence file.
                    for event in result.events[event_start:]:
                        if event.source == str(path):
                            event.source = str(original)
            except PermissionError:
                failed = True
                parser.error(original, "file", PERMISSION_HINT)
            except Exception as exc:
                failed = True
                parser.error(original, "file", exc)
            finally:
                if recovery_dir is not None:
                    # The recovered copy holds evidence content; don't leave it behind in TEMP.
                    shutil.rmtree(recovery_dir, ignore_errors=True)
                for source, digest in before.items():
                    try:
                        if sha256(source) != digest:
                            parser.error(source, "sha256", "분석 중 원본 무결성 변경 감지")
                            failed = True
                    except PermissionError:
                        parser.error(source, "sha256", PERMISSION_HINT)
                        failed = True
                    except OSError as exc:
                        parser.error(source, "sha256", exc)
                        failed = True
                result.errors.extend(parser.errors)
                count = len(result.events) - event_start
                if failed:
                    for event in result.events[event_start:]:
                        event.status = "partial"
                result.summaries.append({"source": str(original), "artifact": artifact, "events": count,
                                         "state": "failed" if failed else "partial" if any(e.severity in ("warning", "error") for e in parser.errors) else "ok" if count else "no_data",
                                         "elapsed_seconds": round(time.monotonic() - started, 6),
                                         "errors": sum(e.severity == "error" for e in parser.errors),
                                         "warnings": sum(e.severity == "warning" for e in parser.errors)})
        if not expanded:
            result.summaries.append({"state": "no_input", "events": 0})
        attach_volume_hints(result.events, volume_hints)
        from .task_merge import merge_tasks
        result.events = merge_tasks(result.events, result.evidence)
        result.events = timeline(result.events)
        from log_hunter.parser.usb_inventory import usb_device_inventory
        usb_device_inventory(result.events)
        from .wlan_profiles import link_wlan_profiles
        result.events = link_wlan_profiles(result.events)
        from .enrichment import enrich_events
        result.events = enrich_events(result.events)
        result.relations = correlate(result.events)
        if progress:
            progress(len(expanded), len(expanded), "완료")
        return result
