"""Browser settings files: installed extensions (Preferences / Secure Preferences), profiles (Local State) and bookmarks
(Chromium Bookmarks, Internet Shortcut .url files). Text is evidence: nothing in it is opened or run."""
import json
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from .base import ArtifactParser
from .history import browser_profile
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import chromium_timestamp

MAX_JSON = 64 * 1024 * 1024
MAX_DEPTH = 64


def _load_json(path):
    path = Path(path)
    if path.stat().st_size > MAX_JSON:
        raise ValueError(f"설정 파일이 너무 큽니다 ({path.stat().st_size:,} 바이트)")
    data = json.loads(path.read_bytes().decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("JSON 객체가 아닙니다")
    return data


def _chromium_text_time(value):
    """Chromium keeps these times as decimal text of microseconds since 1601."""
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return chromium_timestamp(number) if number > 0 else None


def _unix_time(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    try:
        return datetime.fromtimestamp(number, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _text(value):
    return value if isinstance(value, str) and value else None


class BrowserExtensionsParser(ArtifactParser):
    """One record per extension listed in a profile's Preferences or Secure Preferences."""
    artifact = "browser_extensions"

    def parse(self, path):
        data = _load_json(path)
        browser, profile = browser_profile(path)
        settings = (data.get("extensions") or {}).get("settings") if isinstance(data.get("extensions"), dict) else None
        if not isinstance(settings, dict):
            return
        # The same extension can be listed in both files of one profile; Secure Preferences is the complete entry,
        # so Preferences only adds the extensions the other file does not have (one record per extension).
        covered = set()
        secure = Path(path).with_name("Secure Preferences")
        if Path(path).name.casefold() == "preferences" and secure.is_file():
            try:
                other = (_load_json(secure).get("extensions") or {}).get("settings") or {}
                covered = set(other) if isinstance(other, dict) else set()
            except (OSError, ValueError, AttributeError):
                covered = set()
        for ext_id, info in settings.items():
            if not isinstance(info, dict) or ext_id in covered:
                continue
            manifest = info.get("manifest") if isinstance(info.get("manifest"), dict) else {}
            permissions = manifest.get("permissions") if isinstance(manifest.get("permissions"), list) else []
            installed = _chromium_text_time(info.get("first_install_time")) or _chromium_text_time(info.get("install_time"))
            name = _text(manifest.get("name"))
            details = {
                "extension_id": ext_id, "extension_name": name,
                "name_localized_key": name if name and name.startswith("__MSG_") else None,
                "extension_version": _text(manifest.get("version")),
                "extension_description": _text(manifest.get("description")),
                "extension_permissions": [str(p) for p in permissions if isinstance(p, (str, int))][:200],
                "extension_enabled": None if info.get("state") is None else info.get("state") == 1,
                "disable_reasons": info.get("disable_reasons"),
                "from_webstore": info.get("from_webstore"), "install_location": info.get("location"),
                "installed": installed, "install_time_kind": "first_install_time" if info.get("first_install_time") else
                ("install_time" if installed else None),
                "settings_file": PureWindowsPath(str(path)).name, "browser": browser, "profile": profile,
            }
            yield ForensicEvent(self.artifact, str(path), "extension_installed", installed,
                                "extension_installed" if installed else None, self.sid, path=name or ext_id,
                                locator=f"extensions.settings.{ext_id}", details=details)


class BrowserProfilesParser(ArtifactParser):
    """One record per profile in Local State (profile folder, shown name, signed-in account name, last active)."""
    artifact = "browser_profiles"

    def parse(self, path):
        data = _load_json(path)
        browser, _ = browser_profile(str(Path(path).parent / "x" / "x"))
        cache = (data.get("profile") or {}).get("info_cache") if isinstance(data.get("profile"), dict) else None
        if not isinstance(cache, dict):
            return
        for folder, info in cache.items():
            if not isinstance(info, dict):
                continue
            active = _unix_time(info.get("active_time"))
            details = {"profile_folder": folder, "profile_name": _text(info.get("name")),
                       "shortcut_name": _text(info.get("shortcut_name")), "account_name": _text(info.get("user_name")),
                       "account_display_name": _text(info.get("gaia_name")), "hosted_domain": _text(info.get("hosted_domain")),
                       "last_active": active, "browser": browser, "profile": folder}
            yield ForensicEvent(self.artifact, str(path), "browser_profile", active, "profile_last_active" if active else None,
                                self.sid, path=folder, locator=f"profile.info_cache.{folder}", details=details)


class BookmarksParser(ArtifactParser):
    """Chromium Bookmarks (JSON tree) and Internet Shortcut files (.url, e.g. Favorites)."""
    artifact = "bookmarks"
    file_times = None  # image MFT times of extracted .url files (created = when the favorite was saved)

    def parse(self, path):
        if str(path).lower().endswith(".url"):
            yield from self._url_file(Path(path))
            return
        data = _load_json(path)
        browser, profile = browser_profile(path)
        roots = data.get("roots") if isinstance(data.get("roots"), dict) else {}
        for root_name, node in roots.items():
            if isinstance(node, dict):
                yield from self._walk(node, [str(node.get("name") or root_name)], str(path), browser, profile, 0)

    def _walk(self, node, folder, source, browser, profile, depth):
        if depth > MAX_DEPTH:
            self.error(source, "/".join(folder), "책갈피 폴더가 너무 깊습니다")
            return
        for child in node.get("children") or ():
            if not isinstance(child, dict):
                continue
            if child.get("type") == "folder":
                yield from self._walk(child, folder + [str(child.get("name") or "")], source, browser, profile, depth + 1)
            elif child.get("type") == "url":
                added = _chromium_text_time(child.get("date_added"))
                details = {"bookmark_title": _text(child.get("name")), "bookmark_folder": "/".join(folder),
                           "bookmark_added": added, "bookmark_last_used": _chromium_text_time(child.get("date_last_used")),
                           "browser": browser, "profile": profile}
                yield ForensicEvent(self.artifact, source, "bookmark_saved", added, "bookmark_added" if added else None,
                                    self.sid, url=_text(child.get("url")), locator=f"roots/{'/'.join(folder)}#{child.get('id')}",
                                    details=details)

    def _url_file(self, path):
        raw = path.read_bytes()[:1024 * 1024]
        text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", errors="replace")
        url = None
        section = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].casefold()
            elif section == "internetshortcut" and line.casefold().startswith("url="):
                url = line[4:].strip() or None
                break
        own = (self.file_times or {}).get(str(path.resolve()).casefold()) or {}
        created = own.get("created")
        details = {"bookmark_title": path.stem, "bookmark_added": created, "bookmark_file_modified": own.get("modified"),
                   "browser": None, "profile": None, "shortcut_file": path.name}
        if url is None:
            self.error(path, "InternetShortcut", "URL 항목이 없습니다", "warning")
        yield ForensicEvent(self.artifact, str(path), "bookmark_saved", created, "bookmark_file_created" if created else None,
                            self.sid, url=url, locator=path.name, status="ok" if url else "partial", details=details)
