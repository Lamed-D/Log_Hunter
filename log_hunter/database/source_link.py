"""Verify an explicitly selected image against the saved image and segment hashes."""
import os
import re
from pathlib import Path

from log_hunter.image.ewf import open_image
from log_hunter.image.live import is_live_path
from .case_db import _hash


def _path_key(path):
    return os.path.normcase(os.path.normpath(str(path)))


def _file_state(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _image_sets(image, sources):
    stored = {}
    for record in sources:
        if not isinstance(record, dict) or record.get("kind") != "image":
            continue
        digest = record.get("expected_sha256")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-fA-F]{64}", digest):
            continue
        for field in ("path", "resolved_path"):
            if record.get(field) and not is_live_path(record[field]):
                stored[_path_key(record[field])] = digest.lower()
    groups = []
    for manifest in [image, *(image.get("additional_images") or [])]:
        if not isinstance(manifest, dict) or not isinstance(manifest.get("image") or {}, dict):
            continue
        paths = (manifest.get("image") or {}).get("segments") or [manifest.get("image_path")]
        if isinstance(paths, list) and paths and all(path and _path_key(path) in stored for path in paths):
            groups.append(tuple(stored[_path_key(path)] for path in paths))
    if not image.get("image_path") and not image.get("additional_images"):
        groups.extend((digest,) for digest in dict.fromkeys(stored.values()))
    return groups


def verify_image_attachment(selected, image, sources):
    """Return the selected image root, complete SHA-256 sequence, expected sequences and match."""
    expected = _image_sets(image or {}, sources)
    if not expected:
        return str(selected), (), (), False
    if is_live_path(selected):
        raise ValueError("원본 파일을 선택하세요")
    chosen = Path(selected).resolve()
    with open_image(chosen) as media:
        paths = tuple(Path(path) for path in media.info().get("segments") or [chosen])
        before = [_file_state(path) for path in paths]
        actual = tuple(_hash(path) for path in paths)
        after = [_file_state(path) for path in paths]
        if before != after:
            raise ValueError("원본 파일이 해시 확인 중 변경됐습니다")
    return str(paths[0]), actual, tuple(expected), actual in expected
