# ▶ 원본: log_hunter/core/wifi_view.py
# ▶ 저장된 Wi-Fi 프로필의 결과 표·속성 창·보고서 열 값을 만듭니다. 공유키 표시는 접속 확인이 아닙니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Saved Wi-Fi profile columns for the result table, properties and report: what the profile records, not a connection."""
from .labels import WIFI_TEXT, WLAN_PASSWORD_STATES

COLUMNS = ("ssid_name", "authentication", "encryption", "automatic_connection", "wifi_password", "password_state",
           "password_source", "networklist")


def _ssid(value):
    """SSID with its leading/trailing spaces kept and made visible."""
    if not isinstance(value, str):
        return ""
    return f"“{value}”" if value != value.strip() or not value else value


def _networklist(details):
    candidates = [c for c in details.get("networklist_candidates") or () if isinstance(c, dict)]
    if not candidates:
        return ""
    first = candidates[0]
    text = WIFI_TEXT["candidates"].format(count=len(candidates))
    if first.get("date_last_connected_local"):
        zone = "" if first.get("timezone_known") else WIFI_TEXT["zone_unknown"]
        text += " · " + WIFI_TEXT["last_connected"].format(time=first["date_last_connected_local"], zone=zone)
    if details.get("networklist_link_ambiguous"):
        text += " · " + WIFI_TEXT["ambiguous"]
    return text


def cell(key, event):
    """Shown value of one Wi-Fi column; rows of other records (network list entries) stay empty."""
    if event.artifact != "wlan":
        return ""
    d = event.details or {}
    if key == "ssid_name":
        return _ssid(d.get("ssid_name"))
    if key == "automatic_connection":
        value = d.get("automatic_connection")
        return "" if value is None else WIFI_TEXT["auto" if value else "manual"]
    if key == "wifi_password":
        value = d.get("wifi_password")
        if value is None:
            return ""
        return f"{value} {WIFI_TEXT['candidate']}" if d.get("password_state") == "verified_live_candidate" else str(value)
    if key == "password_state":
        state = d.get("password_state")
        return WLAN_PASSWORD_STATES.get(state, state or "")
    if key == "password_source":
        source = d.get("password_source")
        return WIFI_TEXT["sources"].get(source, source or "")
    if key == "networklist":
        return _networklist(d)
    value = d.get(key)
    return "" if value is None else str(value)
