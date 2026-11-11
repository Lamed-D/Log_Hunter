# ▶ 원본: log_hunter/core/sid_resolver.py
# ▶ 기록 형식에 맞는 필드와 시각을 읽습니다. 범위 검사와 self.error 호출을 함께 확인하세요.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Resolve SIDs to usernames (ProfileList in SOFTWARE) and name well-known accounts when the evidence does not."""
import re
from pathlib import Path

from log_hunter.core.labels import SID_TEXT, WELL_KNOWN_RIDS, WELL_KNOWN_SID_PREFIXES, WELL_KNOWN_SIDS
from log_hunter.parser.registry import Hive


def resolve_sids(software_hive_path):
    """Read ProfileList from SOFTWARE hive, return {SID: username}."""
    try:
        hive = Hive(software_hive_path)
    except Exception:
        return {}
    try:
        root = hive.open(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
    except KeyError:
        return {}
    mapping = {}
    for subkey in root.subkeys():
        sid = subkey.name
        if not sid.startswith("S-1-5-21-"):
            continue
        for v in subkey.values():
            if v.get("error"):
                continue
            if v["name"] == "ProfileImagePath":
                profile_path = v.get("value", "")
                if profile_path:
                    username = Path(profile_path).name
                    mapping[sid] = username
                break
    return mapping


def resolve_sids_from_sam(sam_hive_path):
    """Read account names from SAM hive, return {account_name: rid_key}."""
    try:
        hive = Hive(sam_hive_path)
    except Exception:
        return {}
    try:
        root = hive.open(r"SAM\Domains\Account\Users\Names")
    except KeyError:
        return {}
    mapping = {}
    for subkey in root.subkeys():
        mapping[subkey.name] = subkey.name
    return mapping


def well_known_sid_name(sid):
    """'시스템 (SYSTEM)' for S-1-5-18 and the other well-known accounts, '로컬 사용자 (RID n)' for unnamed local
    accounts (RID 1000 and up); None for anything else, including malformed values."""
    sid = str(sid or "").strip().upper()
    if not re.fullmatch(r"S-1(-\d+)+", sid):
        return None
    if sid in WELL_KNOWN_SIDS:
        return "{} ({})".format(*WELL_KNOWN_SIDS[sid])
    rid = _local_rid(sid)
    if rid is not None:
        if rid in WELL_KNOWN_RIDS:
            return "{} ({})".format(*WELL_KNOWN_RIDS[rid])
        return SID_TEXT["local_user"].format(rid=rid) if rid >= 1000 else None
    for prefix, name, original in WELL_KNOWN_SID_PREFIXES:
        if sid.startswith(prefix):
            return f"{name} ({original.format(n=sid.rsplit('-', 1)[1])})"
    return None


def _local_rid(sid):
    match = re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-(\d+)", sid)
    return int(match.group(1)) if match else None


def is_service_sid(sid):
    """Built-in/service identities (shown apart from people): well-known and not a machine/domain account."""
    return well_known_sid_name(sid) is not None and _local_rid(str(sid).strip().upper()) is None


def display_name(sid, names=None):
    """Shown user name: the name found in the evidence > the well-known name > ''. A found name for a
    well-known local account keeps its role: 'alice (기본 관리자 계정)'."""
    if not sid:
        return ""
    real = (names or {}).get(sid)
    rid = _local_rid(str(sid).strip().upper())
    if real:
        return SID_TEXT["named"].format(name=real, role=WELL_KNOWN_RIDS[rid][0]) if rid in WELL_KNOWN_RIDS else real
    return well_known_sid_name(sid) or ""

