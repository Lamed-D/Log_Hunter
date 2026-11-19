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
from .source_link import _file_state, _path_key


DEPENDENT_ARTIFACTS = (frozenset(TASK_ARTIFACTS), {"usb", "userassist"}, {"network", "wlan"})


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
        if not original.is_absolute() or _path_key(original) not in expected:
            raise ValueError("저장된 입력에 확인 가능한 원본 해시가 없습니다")
        if not original.is_file():
            raise ValueError("저장된 개별 원본 파일을 찾을 수 없습니다")
        inputs.append((artifact, original, row.get("sid")))
    return inputs, expected, locations


def _inspect_inputs(inputs, expected):
    inspected, states, families, changed = {}, {}, [], []
    for artifact, path, _ in inputs:
        family = []
        for member in [path, *input_sidecars(artifact, path)]:
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
        changed.append(any(inspected[key] != expected.get(key) for key in family))
    return changed, families, states


def _selected_inputs(inputs, changed):
    if any(touched and path.name.casefold() in ("system", "software")
           for touched, (_, path, _) in zip(changed, inputs)):
        return list(range(len(inputs)))
    kinds = {artifact for touched, (artifact, _, _) in zip(changed, inputs) if touched}
    affected = set().union(*(group for group in DEPENDENT_ARTIFACTS if kinds & group))
    return [index for index, (artifact, _, _) in enumerate(inputs) if changed[index] or artifact in affected]


def reanalyze_case(path, progress=None):
    """Return a refreshed result and counts; the saved case and original files stay read-only."""
    result, info = load_case(path)
    if result.image or not result.inputs or result.settings.get("additional_analyses"):
        raise ValueError("개별 파일로 저장한 단일 분석에서 변경분 재분석을 실행하세요")
    if info.partial or info.verification.get("database", {}).get("status") == "changed":
        raise ValueError("저장 결과를 검증할 수 없어 기존 기록을 재사용할 수 없습니다")
    inputs, expected, locations = _saved_inputs(result, info)
    changed, families, states = _inspect_inputs(inputs, expected)
    selection = _selected_inputs(inputs, changed)
    counts = {"inputs": len(inputs), "changed": sum(changed), "reanalyzed": len(selection),
              "reused": len(inputs) - len(selection)}
    if not selection:
        return result, counts, info.sources

    replaced = {(inputs[i][0], path_key) for i in selection for path_key in families[i]}
    evidence_paths = {path_key for _, path_key in replaced}
    fresh = Pipeline().analyze([inputs[i] for i in selection], sid=result.settings.get("sid"),
                               environment=result.settings.get("environment"), progress=progress,
                               context_inputs=inputs)
    for source, initial in states.items():
        current = _file_state(source) if source.is_file() else None
        if current != initial:
            raise ValueError("원본 또는 보조 파일이 재분석 중 변경됐습니다")
    if any(error.locator == "sha256" for error in fresh.errors):
        raise ValueError("원본 파일의 무결성을 확인하지 못했습니다")

    def source_key(source):
        key = _path_key(source)
        return _path_key(locations.get(key, source))

    result.evidence = [item for item in result.evidence if source_key(item.source) not in evidence_paths] + fresh.evidence
    result.errors = [error for error in result.errors if (error.artifact, source_key(error.source)) not in replaced] + fresh.errors
    result.summaries = [row for row in result.summaries
                        if (row.get("artifact"), source_key(row.get("source", ""))) not in replaced] + fresh.summaries
    kept = [event for event in result.events if (event.artifact, source_key(event.source)) not in replaced]
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
