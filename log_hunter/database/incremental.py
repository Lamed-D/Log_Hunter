"""Refresh a saved set of standalone inputs using the recorded evidence fingerprints."""
import re
from datetime import datetime, timezone
from pathlib import Path

from log_hunter.collector.live_collector import sha256
from log_hunter.core.correlation import correlate
from log_hunter.core.enrichment import enrich_events
from log_hunter.core.pipeline import PARSERS, Pipeline, input_sidecars
from log_hunter.core.recent_targets import attach_target_keys
from log_hunter.core.task_merge import TASK_ARTIFACTS
from log_hunter.core.timeline import timeline
from log_hunter.core.timestamp import normalize_event_timestamp
from log_hunter.core.wlan_profiles import link_wlan_profiles
from log_hunter.parser.usb_inventory import usb_device_inventory
from .case_db import load_case
from .source_link import _file_state, _fingerprint_image, _image_sets, _path_key


DEPENDENT_ARTIFACTS = (frozenset(TASK_ARTIFACTS), {"usb", "userassist"}, {"network", "wlan"})
DIRECTORY_ARTIFACTS = {"cache", "wlan", "recyclebin", "startup", "defender", "tasks"}


def _saved_inputs(result, info):
    locations = {}
    expected = {}
    for source in info.sources:
        original = source.get("path")
        resolved = source.get("resolved_path") or original
        digest = source.get("expected_sha256")
        if original and resolved and source.get("kind") == "file":
            locations[_path_key(original)] = Path(resolved)
            if isinstance(digest, str) and re.fullmatch("[0-9a-fA-F]{64}", digest):
                expected[_path_key(resolved)] = digest.lower()
    inputs = []
    for row in result.inputs:
        artifact, path = row.get("artifact"), row.get("path")
        if artifact not in PARSERS or not path or not isinstance(path, str):
            raise ValueError("저장된 입력의 종류 또는 원본 위치를 확인할 수 없습니다")
        original = locations.get(_path_key(path), Path(path))
        folder = original.is_dir() and artifact in DIRECTORY_ARTIFACTS
        if not original.is_absolute() or (not folder and _path_key(original) not in expected):
            raise ValueError("저장된 입력에 확인 가능한 원본 해시가 없습니다")
        if not folder and not original.is_file():
            raise ValueError("저장된 원본 입력을 찾을 수 없습니다")
        inputs.append((artifact, original, row.get("sid")))
    return inputs, expected, locations


def _inspect_inputs(inputs, expected):
    inspected, states, folders, families, changed = {}, {}, {}, [], []
    for artifact, path, _ in inputs:
        family = []
        if path.is_dir():
            paths = sorted(p for p in path.rglob("*") if p.is_file())
            folders[path] = set(paths)
            previous = {Path(key) for key in expected if Path(key).is_relative_to(path)}
            members = sorted(set(paths) | previous)
            family.append(_path_key(path))
        else:
            members = [path, *input_sidecars(artifact, path)]
        for member in members:
            key = _path_key(member)
            family.append(key)
            if key not in inspected:
                if member.is_file():
                    before = _file_state(member)
                    inspected[key] = sha256(member)
                    if _file_state(member) != before:
                        raise ValueError("원본 파일이 해시 확인 중 변경됐습니다")
                    states[member] = before
                else:
                    inspected[key] = None
                    states[member] = None
        families.append(family)
        changed.append(any(inspected.get(key) != expected.get(key) for key in family))
    return changed, families, states, folders


def _selected_inputs(inputs, changed):
    if any(touched and path.name.casefold() in ("system", "software")
           for touched, (_, path, _) in zip(changed, inputs)):
        return list(range(len(inputs)))
    kinds = {artifact for touched, (artifact, _, _) in zip(changed, inputs) if touched}
    affected = set().union(*(group for group in DEPENDENT_ARTIFACTS if kinds & group))
    return [index for index, (artifact, _, _) in enumerate(inputs) if changed[index] or artifact in affected]


def _reanalyze_image(result, info, workdir, progress):
    image = result.image
    original = image.get("image_path")
    if not original or image.get("additional_images"):
        raise ValueError("여러 이미지를 포함한 분석은 원본별로 다시 분석하세요")
    snapshot = (image.get("image") or {}).get("snapshot")
    if snapshot is None and result.settings.get("snapshot_store") is not None:
        raise ValueError("저장된 스냅숏의 원본 범위를 확인할 수 없습니다")
    if snapshot is not None:
        if not isinstance(snapshot, dict):
            raise ValueError("저장된 스냅숏의 원본 범위를 확인할 수 없습니다")
        volume, store = snapshot.get("volume_index"), snapshot.get("store_id")
        if type(volume) is not int or volume < 0 or not isinstance(store, str) or not store:
            raise ValueError("저장된 스냅숏의 볼륨 또는 스토어를 확인할 수 없습니다")
    derived = {_path_key(row["extracted"]) for row in image.get("files", ()) if row.get("extracted")}
    derived.update(_path_key(path) for path in (image.get("cache_paths") or {}))
    if any(_path_key(row["path"]) not in derived for row in result.inputs):
        raise ValueError("이미지와 개별 입력을 함께 사용한 분석은 원본별로 다시 분석하세요")
    expected = _image_sets(image, info.sources)
    if not expected:
        raise ValueError("저장된 이미지 세그먼트의 해시를 모두 확인할 수 없습니다")
    paths, actual, states = _fingerprint_image(original)
    changed = actual not in expected
    counts = {"inputs": 1, "changed": int(changed), "reanalyzed": int(changed), "reused": int(not changed)}
    if not changed:
        return result, counts, info.sources
    if workdir is None:
        raise ValueError("변경된 이미지의 별도 추출 폴더가 필요합니다")
    destination = Path(workdir).resolve()
    if destination.parent in {paths[0].parent, Path(info.path).resolve().parent}:
        raise ValueError("원본 또는 이전 케이스가 있는 폴더와 다른 출력 폴더를 지정하세요")
    include_mft = result.settings.get("include_mft", result.settings.get(
        "with_mft", any(row["artifact"] == "mft" for row in result.inputs)))
    options = dict(sid=result.settings.get("sid"), environment=result.settings.get("environment"),
                   include_mft=include_mft, progress=progress)
    pipeline = Pipeline()
    if snapshot is not None:
        fresh = pipeline.analyze_snapshot(paths[0], destination, volume, store, **options)
        reopened = (fresh.image.get("image") or {}).get("snapshot") or {}
        identity = snapshot.get("snapshot_id")
        if (reopened.get("volume_index") != volume or reopened.get("store_id") != store
                or (identity and reopened.get("snapshot_id") != identity)):
            raise ValueError("변경된 이미지에서 같은 스냅숏을 다시 열 수 없습니다")
    else:
        fresh = pipeline.analyze_image(paths[0], destination, **options)
    if any(_file_state(path) != state for path, state in zip(paths, states)):
        raise ValueError("원본 이미지가 재분석 중 변경됐습니다")
    fresh.tags = result.tags
    sources = [{"kind": "image", "path": str(path), "resolved_path": str(path), "expected_sha256": digest}
               for path, digest in zip(paths, actual)]
    return fresh, counts, sources


def reanalyze_case(path, progress=None, *, workdir=None):
    """Return a refreshed result and counts; the saved case and original files stay read-only."""
    result, info = load_case(path)
    if info.partial or info.verification.get("database", {}).get("status") == "changed":
        raise ValueError("저장 결과를 검증할 수 없어 기존 기록을 재사용할 수 없습니다")
    if result.settings.get("additional_analyses"):
        raise ValueError("여러 분석을 병합한 케이스는 원본별로 다시 분석하세요")
    if result.image:
        return _reanalyze_image(result, info, workdir, progress)
    if not result.inputs:
        raise ValueError("저장된 원본 입력 목록이 없습니다")
    inputs, expected, locations = _saved_inputs(result, info)
    changed, families, states, folders = _inspect_inputs(inputs, expected)
    selection = _selected_inputs(inputs, changed)
    counts = {"inputs": len(inputs), "changed": sum(changed), "reanalyzed": len(selection),
              "reused": len(inputs) - len(selection)}
    if not selection:
        return result, counts, info.sources

    replaced = {(inputs[i][0], path_key) for i in selection for path_key in families[i]}
    replaced_folders = [(inputs[i][0], Path(_path_key(inputs[i][1]))) for i in selection if inputs[i][1] in folders]
    evidence_paths = {path_key for _, path_key in replaced}
    fresh = Pipeline().analyze([inputs[i] for i in selection], sid=result.settings.get("sid"),
                               environment=result.settings.get("environment"), progress=progress,
                               context_inputs=inputs)
    for source, initial in states.items():
        current = _file_state(source) if source.is_file() else None
        if current != initial:
            raise ValueError("원본 또는 보조 파일이 재분석 중 변경됐습니다")
    for directory, members in folders.items():
        if {p for p in directory.rglob("*") if p.is_file()} != members:
            raise ValueError("원본 폴더의 구성 파일이 재분석 중 변경됐습니다")
    if any(error.locator == "sha256" for error in fresh.errors):
        raise ValueError("원본 파일의 무결성을 확인하지 못했습니다")

    def source_key(source):
        key = _path_key(source)
        return _path_key(locations.get(key, source))

    def was_replaced(artifact, source):
        key = source_key(source)
        return (artifact, key) in replaced or any(
            artifact == kind and Path(key).is_relative_to(folder) for kind, folder in replaced_folders)

    result.evidence = [item for item in result.evidence if source_key(item.source) not in evidence_paths] + fresh.evidence
    result.errors = [error for error in result.errors if not was_replaced(error.artifact, error.source)] + fresh.errors
    result.summaries = [row for row in result.summaries
                        if not was_replaced(row.get("artifact"), row.get("source", ""))] + fresh.summaries
    def event_input_artifact(event):
        if event.artifact == "jumplist" and event.details.get("file_parse_state") == "deleted":
            return "mft"
        return event.artifact

    kept = [event for event in result.events if not was_replaced(event_input_artifact(event), event.source)]
    result.events = timeline(normalize_event_timestamp(event) for event in [*kept, *fresh.events])
    result.profiles = fresh.profiles
    result.sid_names = {**result.sid_names, **fresh.sid_names}
    for key in ("windows_time_zone", "windows_time_zones"):
        result.settings.pop(key, None)
    result.settings.update(fresh.settings, analysis_at=datetime.now(timezone.utc).isoformat())
    attach_target_keys(result.events)
    usb_device_inventory(result.events)
    link_wlan_profiles(result.events)
    enrich_events(result.events)
    result.relations = correlate(result.events)
    result.inputs = [{"artifact": artifact, "path": str(path), "sid": sid, "reason": None}
                     for artifact, path, sid in inputs]
    sources = [{"kind": "file", "path": item.source, "resolved_path": str(locations.get(
                    _path_key(item.source), Path(item.source))),
                "expected_sha256": item.sha256} for item in result.evidence]
    return result, counts, sources
