# ▶ 원본: log_hunter/ui/recycle_view.py
# ▶ 휴지통 기록의 짝 파일(원본) 상태 문구와 '원본 파일로 저장' 가능 여부·저장 계획을 만듭니다. 이미지는 읽기만 합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""휴지통 기록: the companion ($R) state as text and the plan for saving the original, without Tk."""
import ntpath
from pathlib import Path

from log_hunter.core.labels import RECYCLE_TEXT as T, RECYCLE_PAIR_REASONS, RECYCLE_PAIR_STATES


def pair_text(details):
    """'짝 파일 확인 (폴더)' / '짝 파일 미관측(부재 확정 아님) — 이유' / '' when the engine gave no pair information."""
    pair = (details or {}).get("recycle_pair")
    if not isinstance(pair, dict):
        return ""
    text = pair.get("state_label") or RECYCLE_PAIR_STATES.get(pair.get("state"), pair.get("state") or "")
    if pair.get("state") == "present" and pair.get("directory"):
        text += " " + T["folder"]
    reason = pair.get("reason_label") or RECYCLE_PAIR_REASONS.get(pair.get("reason"))
    return f"{text} — {reason}" if reason else text


def save_blocker(event):
    """Why '원본 파일로 저장' cannot run for this record, or None when it can."""
    if event is None or event.artifact != "recyclebin":
        return T["not_recycle"]
    pair = (event.details or {}).get("recycle_pair")
    if not isinstance(pair, dict):
        return T["no_pair_info"]
    if pair.get("snapshot") is not None:
        return T["snapshot"]
    if pair.get("state") != "present":
        return pair_text(event.details)
    if not pair.get("image") or pair.get("volume") is None:
        return T["no_pair_info"]
    return None


def save_plan(event, extractions):
    """(image, volume, $I path inside the image, suggested name) for save_recycle_pair; None if not found."""
    pair = (event.details or {}).get("recycle_pair") or {}
    try:
        key = str(Path(event.source).resolve()).casefold()
    except (OSError, ValueError):
        return None
    for extraction in extractions:
        origin = extraction.file_index().get(key)
        if origin and origin.get("image_path"):
            original = (event.details or {}).get("original_path") or ""
            name = ntpath.basename(str(original).rstrip("\\/")) or ntpath.basename(pair.get("image_path") or "") or "recycled"
            return pair.get("image"), pair.get("volume"), origin["image_path"], name
    return None

