"""File preview cache (thumbcache) columns for the result table and report: what the cache stores, not what it proves."""
from .labels import THUMBCACHE_VALUE_LABELS

COLUMNS = ("cache_id", "image_format", "data_size", "cache_location", "image_sha256", "image_hash_status",
           "stored_checksum", "cache_check")


def _label(value):
    return THUMBCACHE_VALUE_LABELS.get(value, "" if value is None else str(value))


def cell(key, event):
    """Shown value of one thumbcache column. The image itself is never decoded or shown."""
    details = event.details or {}
    if key == "image_format":
        return _label(details.get("image_format"))
    if key == "cache_location":
        entry, data = details.get("entry_offset"), details.get("data_offset")
        if entry is None and data is None:
            return ""
        return f"항목 {_hex(entry)} · 데이터 {_hex(data)}"
    if key == "image_hash_status":
        return _label(details.get("image_hash_status"))
    if key == "stored_checksum":  # stored in the cache, never recomputed: never shown as verified
        return _label("verified" if details.get("checksum_verified") is True else "not_verified")
    if key == "cache_check":
        return _label("identifier_decode_error") if details.get("identifier_decode_error") else ""
    value = details.get(key)
    return "" if value is None else str(value)


def _hex(value):
    return f"0x{value:x}" if isinstance(value, int) and value >= 0 else "알 수 없음"
