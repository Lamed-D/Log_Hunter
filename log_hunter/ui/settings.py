"""The examiner's screen preferences (columns, tag names, recent analyses), kept in the user's own settings folder, never with a case."""
import json
import os
from pathlib import Path

ENV = "LOG_HUNTER_SETTINGS"
RECENT_LIMIT = 10  # saved/opened analyses remembered for the open dialog


def settings_path():
    r"""%APPDATA%\LogHunter\settings.json on Windows, ~/.config/log_hunter/settings.json elsewhere; LOG_HUNTER_SETTINGS overrides."""
    if os.environ.get(ENV):
        return Path(os.environ[ENV])
    base = os.environ.get("APPDATA")
    if base:
        return Path(base) / "LogHunter" / "settings.json"
    return Path.home() / ".config" / "log_hunter" / "settings.json"


class Settings:
    """Small JSON store. A missing, unreadable or damaged file just means default settings."""

    def __init__(self, path=None):
        self.path = Path(path) if path else settings_path()
        self.data = {}
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data = loaded
        except (OSError, ValueError):
            pass

    def _columns_table(self):
        """The saved column sets, or {} when the file holds something else there."""
        table = self.data.get("columns")
        return table if isinstance(table, dict) else {}

    def columns(self, name):
        """(order list, {key: width}) saved for column set `name`; damaged values fall back to defaults."""
        entry = self._columns_table().get(name)
        if not isinstance(entry, dict):
            return [], {}
        order = entry.get("order")
        order = [k for k in order if isinstance(k, str)] if isinstance(order, list) else []
        widths = entry.get("widths")
        widths = {k: int(v) for k, v in widths.items()
                  if isinstance(k, str) and isinstance(v, (int, float)) and not isinstance(v, bool) and 20 <= v <= 3000
                  } if isinstance(widths, dict) else {}
        return order, widths

    def set_columns(self, name, order, widths):
        if not isinstance(self.data.get("columns"), dict):
            self.data["columns"] = {}
        self.data["columns"][name] = {"order": list(order), "widths": dict(widths)}

    def reset_columns(self, name):
        self._columns_table().pop(name, None)

    def tag_preferences(self):
        """Examiner tag colour names and subcategory lists ({"color_names": .., "subcategories": ..})."""
        tags = self.data.get("tags")
        if not isinstance(tags, dict):
            return {}
        names = tags.get("color_names") if isinstance(tags.get("color_names"), dict) else {}
        subs = tags.get("subcategories") if isinstance(tags.get("subcategories"), dict) else {}
        return {"color_names": {k: v for k, v in names.items() if isinstance(v, str)},
                "subcategories": {k: [s for s in v if isinstance(s, str)] for k, v in subs.items() if isinstance(v, list)}}

    def set_tag_preferences(self, preferences):
        self.data["tags"] = preferences

    def recent_cases(self):
        """Saved or opened analyses, newest first: [{path, name, saved_at, events, source_state}] (damaged rows dropped)."""
        rows = self.data.get("recent_cases")
        if not isinstance(rows, list):
            return []
        clean = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not row["path"]:
                continue
            events = row.get("events")
            clean.append({"path": row["path"], "name": row.get("name") if isinstance(row.get("name"), str) else "",
                          "saved_at": row.get("saved_at") if isinstance(row.get("saved_at"), str) else "",
                          "events": events if isinstance(events, int) and not isinstance(events, bool) and events >= 0 else None,
                          "source_state": row.get("source_state") if isinstance(row.get("source_state"), str) else ""})
        return clean[:RECENT_LIMIT]

    def add_recent_case(self, path, name="", saved_at="", events=None, source_state=""):
        """Put a case first in the recent list (same file once, compared case-insensitively), keeping RECENT_LIMIT."""
        key = os.path.normcase(os.path.abspath(str(path)))
        rows = [r for r in self.recent_cases() if os.path.normcase(os.path.abspath(r["path"])) != key]
        rows.insert(0, {"path": str(path), "name": name, "saved_at": saved_at, "events": events, "source_state": source_state})
        self.data["recent_cases"] = rows[:RECENT_LIMIT]

    def remove_recent_case(self, path):
        key = os.path.normcase(os.path.abspath(str(path)))
        self.data["recent_cases"] = [r for r in self.recent_cases() if os.path.normcase(os.path.abspath(r["path"])) != key]

    def save(self):
        """Write atomically; failure (read-only profile, no permission) is ignored and reported as False."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_name(self.path.name + ".tmp")
            temp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(temp, self.path)
            return True
        except OSError:
            return False
