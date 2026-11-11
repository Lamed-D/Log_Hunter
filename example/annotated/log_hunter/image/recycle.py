# Teaching copy: runtime tokens are verified by tools/check_annotated.py.
"""Resolve and export Recycle Bin companions without altering evidence or overwriting output."""
import hashlib
import json
import os
from pathlib import Path

from .browse import ImageBrowser, ImageFile
from .ntfs import ATTR_DATA, FLAG_COMPRESSED, FLAG_ENCRYPTED, NTFSError
from log_hunter.parser.recyclebin import parse_dollar_i
from log_hunter.core.labels import RECYCLE_PAIR_STATES, RECYCLE_PAIR_REASONS

BLOCK = 1024 * 1024


class RecyclePairError(ValueError):
    pass


class _CompleteReads:
    """A save operation must reject short source reads rather than manufacture bytes."""
    def __init__(self, image):
        self.image = image

    def __getattr__(self, name):
        return getattr(self.image, name)

    def read(self, offset, length):
        block = self.image.read(offset, length)
        if len(block) != length:
            raise RecyclePairError("?? ????? ??? ???? ??? ?? ?????")
        return block


def _parts(path):
    parts = tuple(str(path).replace("/", "\\").strip("\\").split("\\"))
    if (len(parts) != 3 or parts[0].casefold() != "$recycle.bin" or not parts[1].startswith("S-1-")
            or not parts[2].upper().startswith("$I") or len(parts[2]) < 3
            or any(p in ("", ".", "..") or ":" in p or "\0" in p for p in parts)):
        raise RecyclePairError("??? ?????? ??? ? ??? ???? ????")
    return parts


def _checked_record(ntfs, entry):
    record = ntfs.record(entry.record)
    if not record.in_use or entry.sequence and record.sequence != entry.sequence or record.directory != entry.directory:
        raise RecyclePairError("???? ??? MFT ???? ????? ????????")
    return record


def describe_recycle_pair(ntfs, parts, i_entry, parent, i_sha256=None, directory_cache=None):
    """Describe the companion in the original directory, not the extraction folder."""
    result = {"state":"not_observed", "exists":None, "directory":None, "size":None,
              "mft_record":None, "mft_sequence":None, "i_mft_record":i_entry.record,
              "i_mft_sequence":i_entry.sequence, "i_sha256":i_sha256,
              "image_path":"\\" + "\\".join([*parts[:-1], "$R" + parts[-1][2:]]),
              "reason":"no_matching_directory_entry", "absence_confirmed":False}
    try:
        original = _checked_record(ntfs, i_entry)
        result["i_mft_sequence"] = original.sequence
        expected = "$R" + i_entry.name[2:]
        index = directory_cache.get(parent) if directory_cache is not None else None
        if index is None:
            index = {}
            for entry in ntfs.listdir(parent, strict=True):
                index.setdefault(entry.name.casefold(), []).append(entry)
            if directory_cache is not None:
                directory_cache[parent] = index
        entries = index.get(expected.casefold(), [])
        if len(entries) > 1:
            result.update(state="unavailable", reason="ambiguous_companion_names")
        elif entries:
            entry = entries[0]
            record = _checked_record(ntfs, entry)
            fragments = ntfs._fragments(record, ATTR_DATA, "") if not entry.directory else []
            size = (fragments[0].real_size if fragments[0].nonresident else len(fragments[0].value)) if fragments else None
            result.update(state="present", exists=True, directory=entry.directory, size=size,
                          mft_record=entry.record, mft_sequence=record.sequence,
                          image_path="\\" + "\\".join([*parts[:-1], entry.name]), reason=None)
    except (NTFSError, ValueError, OSError) as exc:
        result.update(state="unavailable", reason="directory_or_record_unreadable", diagnostic=str(exc))
    result["state_label"] = RECYCLE_PAIR_STATES[result["state"]]
    result["reason_label"] = RECYCLE_PAIR_REASONS.get(result["reason"])
    return result


def _source(browser, ntfs, index, parts, entry):
    record = _checked_record(ntfs, entry)
    if any(attribute.type == 0xC0 for attribute in record.attributes):
        raise RecyclePairError("??? ??? ???? ????: " + "\\".join(parts))
    if entry.directory:
        return None
    if any(a.flags & (FLAG_COMPRESSED | FLAG_ENCRYPTED) for a in ntfs._fragments(record, ATTR_DATA, "")):
        raise RecyclePairError("암호화 또는 압축된 파일은 원본 내용으로 저장할 수 없습니다")
    source = ImageFile(browser, ntfs, index, tuple(parts), entry.record)
    if source.note:
        raise RecyclePairError("?? ???? ???? ??? ? ????: " + source.note)
    if source.resident is None:
        volume = next(v for v in browser.volumes if v.index == index)
        next_vcn = 0
        for vcn, lcn, count in source.extents:
            if vcn != next_vcn or count <= 0:
                raise RecyclePairError("?? ??? ??? ?? ?? ?? ??? ????")
            next_vcn += count
            if lcn is not None and (lcn < 0 or (lcn + count) * ntfs.cluster_size > volume.size
                                    or ntfs.offset + (lcn + count) * ntfs.cluster_size > browser.image.size):
                raise RecyclePairError("?? ???? ?? ?? ??? ?????")
    return source


def _plan(browser, ntfs, index, parts, root, max_entries, max_bytes, max_depth):
    from .extract import _safe
    stack, seen_dirs, names, plan, total = [((), root)], set(), set(), [], 0
    while stack:
        relative, entry = stack.pop()
        if len(relative) > max_depth or len(plan) >= max_entries:
            raise RecyclePairError("?? ??? ?? ?? ?? ? ??? ?????")
        if any(_safe(name) != name for name in relative):
            raise RecyclePairError("??? ?? ??? ??? ? ?? ?? ?????")
        key = tuple(name.casefold() for name in relative)
        if key in names:
            raise RecyclePairError("?? ?? ??? ?? ?? ??? ??? ? ????")
        names.add(key)
        source = _source(browser, ntfs, index, (*parts, *relative), entry)
        record = _checked_record(ntfs, entry)
        item = {"relative":relative, "entry":entry, "source":source, "sequence":record.sequence,
                "size":source.size if source else None, "directory":entry.directory}
        plan.append(item)
        if entry.directory:
            if entry.record in seen_dirs:
                raise RecyclePairError("?? ??? ????? ?? ??? ?? ?????")
            seen_dirs.add(entry.record)
            children = ntfs.listdir(entry.record, strict=True)
            stack.extend(((*relative, e.name), e) for e in reversed(children))
        else:
            total += source.size
            if total > max_bytes:
                raise RecyclePairError("?? ??? ?? ??? ??? ?????")
    return plan


def _signature(plan):
    return [(p["relative"], p["entry"].record, p["sequence"], p["directory"], p["size"]) for p in plan]


def _write_record(stream, record):
    stream.seek(0)
    json.dump(record, stream, ensure_ascii=False, indent=2)
    stream.truncate()
    stream.flush()
    os.fsync(stream.fileno())


def save_recycle_pair(image_path, volume_index, i_path, destination, *, expected_pair,
                      max_entries=100000, max_bytes=8 * 1024**3, max_depth=64):
    """Export one file or complete folder tree to a new target with a provenance record.

    A failed write keeps only newly created partial output, marked failed in its
    provenance record. It never deletes or replaces an existing file. Live reads
    are observations checked twice, not an atomic snapshot.
    """
    from .extract import _safe
    if not isinstance(expected_pair, dict):
        raise RecyclePairError("?? ??? ? ?? ??? ?????")
    if expected_pair.get("snapshot") is not None:
        raise RecyclePairError("???? ? ??? ?? ???? ?? ??? ? ????")
    if expected_pair.get("state") != "present":
        raise RecyclePairError("??? ??? ? ??? ????")
    if any(not isinstance(n, int) or isinstance(n, bool) or n < 0 for n in (max_entries, max_bytes, max_depth)) or max_entries == 0:
        raise ValueError("?? ??? ???? ????")
    from .live import is_live_path, live_device
    def identity(path):
        return live_device(path).casefold() if is_live_path(path) else os.path.normcase(str(Path(path).resolve()))
    if (expected_pair.get("volume") != volume_index or not expected_pair.get("image")
            or identity(expected_pair["image"]) != identity(image_path)):
        raise RecyclePairError("?? ?? ??? ?? ??? ?? ??? ??????")
    target = Path(destination)
    record_path = target.with_name(target.name + ".log-hunter.json")
    if _safe(target.name) != target.name:
        raise RecyclePairError("??? ? ?? ??? ?????")
    if target.exists() or target.is_symlink() or record_path.exists() or record_path.is_symlink():
        raise FileExistsError("?? ?? ?? ?? ??? ?? ????")
    parts = _parts(i_path)
    browser = ImageBrowser(image_path)
    browser.image = _CompleteReads(browser.image)
    try:
        with browser.lock:
            ntfs, i_entry = browser._entry(volume_index, parts)
            if i_entry is None or i_entry.directory:
                raise RecyclePairError("??? ????? ??? ????")
            i_source = _source(browser, ntfs, volume_index, parts, i_entry)
            if i_source.size > BLOCK:
                raise RecyclePairError("??? ????? ??? ?? ???")
            data = i_source.read(0, i_source.size)
            info = parse_dollar_i(data)
            i_hash = hashlib.sha256(data).hexdigest()
            parent = ntfs.lookup("\\".join(parts[:-1]))
            pair = describe_recycle_pair(ntfs, parts, i_entry, parent.record, i_hash)
            required = ("i_sha256", "i_mft_record", "i_mft_sequence", "mft_record", "mft_sequence", "directory", "image_path", "size")
            if pair["state"] != "present" or any(key not in expected_pair or pair[key] != expected_pair[key] for key in required):
                raise RecyclePairError("?? ?? ????? ?? ? ??? ??? ??? ????")
            r_parts = tuple(pair["image_path"].strip("\\").split("\\"))
            _, root = browser._entry(volume_index, r_parts)
            plan = _plan(browser, ntfs, volume_index, r_parts, root, max_entries, max_bytes, max_depth)
            saved = {"state":"in_progress", "complete":False, "image":str(image_path), "volume":volume_index,
                     "i_path":"\\" + "\\".join(parts), "i_sha256":i_hash, "image_path":pair["image_path"],
                     "original_path":info["original_path"], "directory":pair["directory"],
                     "destination":str(target), "record":str(record_path), "files":[],
                     "original_content_confirmed":False, "consistency":"two_pass_observation",
                     "source_method":"LIVE" if is_live_path(image_path) else "IMAGE"}
            with record_path.open("x+", encoding="utf-8") as provenance:
                _write_record(provenance, saved)
                try:
                    for item in plan:
                        output = target.joinpath(*item["relative"])
                        row = {"relative_path":"/".join(item["relative"]), "directory":item["directory"],
                               "mft_record":item["entry"].record, "mft_sequence":item["sequence"], "size":item["size"]}
                        if item["directory"]:
                            output.mkdir()
                        else:
                            source = item["source"]
                            digest = hashlib.sha256()
                            with output.open("xb") as stream:
                                for offset in range(0, source.size, BLOCK):
                                    block = source.read(offset, min(BLOCK, source.size-offset))
                                    if len(block) != min(BLOCK, source.size-offset):
                                        raise RecyclePairError("?? ???? ??? ?? ?????")
                                    stream.write(block)
                                    digest.update(block)
                                stream.flush()
                                os.fsync(stream.fileno())
                            fresh = _source(browser, ntfs, volume_index, (*r_parts, *item["relative"]), item["entry"])
                            row["sha256"] = digest.hexdigest()
                            if fresh.size != source.size or fresh.sha256() != row["sha256"]:
                                raise RecyclePairError("?? ? ?? ?? ??? ??????")
                        saved["files"].append(row)
                    ntfs._listings.clear()
                    current_plan = _plan(browser, ntfs, volume_index, r_parts, root, max_entries, max_bytes, max_depth)
                    current_i = ntfs.lookup("\\".join(parts))
                    current_parent = ntfs.lookup("\\".join(parts[:-1]))
                    if current_i is None or current_parent is None or current_i.record != i_entry.record:
                        raise RecyclePairError("?? ? ??? ????? ?? ??? ??????")
                    fresh_i = _source(browser, ntfs, volume_index, parts, current_i)
                    current_pair = describe_recycle_pair(ntfs, parts, current_i, current_parent.record, fresh_i.sha256())
                    if (_signature(plan) != _signature(current_plan) or fresh_i.sha256() != i_hash
                            or any(current_pair[key] != pair[key] for key in required)):
                        raise RecyclePairError("?? ? ?? ?? ?? ??? ?????? ??????")
                    canonical = [{k:v for k,v in row.items() if k in ("relative_path","directory","size","sha256")} for row in saved["files"]]
                    tree_hash = hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
                    saved.update(state="complete", complete=True,
                        size=sum(item["size"] or 0 for item in plan),
                        sha256=tree_hash if pair["directory"] else saved["files"][0]["sha256"],
                        hash_scope="directory_manifest_v1" if pair["directory"] else "file_bytes")
                    _write_record(provenance, saved)
                except Exception as exc:
                    saved.update(state="failed", complete=False, error=str(exc))
                    _write_record(provenance, saved)
                    raise
            return saved
    finally:
        browser.close()
