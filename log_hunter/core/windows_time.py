"""Convert Windows evidence wall clocks using the recorded SYSTEM hive rules."""
import calendar
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_hunter.parser.registry import Hive, current_controlset


@dataclass(frozen=True)
class WindowsTimeRules:
    name: str
    registry_key: str
    standard_bias: int
    daylight_bias: int
    standard_date: tuple[int, ...]
    daylight_date: tuple[int, ...]
    annual: dict | None = None

    def metadata(self):
        result = {"name": self.name, "registry_key": self.registry_key,
                  "standard_bias": self.standard_bias, "daylight_bias": self.daylight_bias,
                  "standard_date": list(self.standard_date), "daylight_date": list(self.daylight_date)}
        if self.annual is not None:
            result["annual"] = {str(year): rules.metadata() for year, rules in self.annual.items() if rules is not None}
        return result


def _transition(rule, year):
    absolute, month, weekday, day, hour, minute, second, ms = rule
    if absolute:
        if absolute != year:
            raise ValueError("transition rule does not cover this year")
    else:
        if not 0 <= weekday <= 6 or not 1 <= day <= 5:
            raise ValueError("invalid recurring transition")
        first, length = calendar.monthrange(year, month)
        day = 1 + ((weekday - 1 - first) % 7) + 7 * (day - 1)
        if day > length:
            day -= 7
    return datetime(year, month, day, hour, minute, second, ms * 1000)


def _annual_rules(software, name):
    if not software or not name or "\\" in name:
        return None
    locator = r"Microsoft\Windows NT\CurrentVersion\Time Zones" + "\\" + name + r"\Dynamic DST"
    try:
        hive = Hive(software)
        if hive.data[4:8] != hive.data[8:12]:
            return None
        values = {v["name"].casefold(): v for v in hive.open(locator).values() if "error" not in v}
    except (OSError, ValueError, KeyError):
        return None
    first = values.get("firstentry", {}).get("value")
    last = values.get("lastentry", {}).get("value")
    if not isinstance(first, int) or not isinstance(last, int) or not 1 <= first <= last <= 9999:
        return {}
    result = dict.fromkeys((first, last))
    for year in range(first, last + 1):
        entry = values.get(str(year))
        if entry is None or entry["type"] != 3 or len(entry["raw"]) != 44:
            continue
        raw = struct.unpack("<iii16H", entry["raw"])
        bias, standard, daylight = raw[:3]
        std_date, dst_date = raw[3:11], raw[11:]
        if bool(std_date[1]) != bool(dst_date[1]):
            continue
        standard_bias = bias + standard if std_date[1] else bias
        daylight_bias = bias + daylight if dst_date[1] else bias
        if max(abs(standard_bias), abs(daylight_bias)) < 1440:
            result[year] = WindowsTimeRules(name, f"SOFTWARE\\{locator}\\{year}", standard_bias,
                                           daylight_bias, std_date, dst_date)
    return result


def read_windows_time_rules(path, software=None):
    hive = Hive(path)
    if hive.data[4:8] != hive.data[8:12]:
        return None
    loc = current_controlset(hive) + r"\Control\TimeZoneInformation"
    node = hive.open(loc)
    values = {v["name"].casefold(): v for v in node.values() if "error" not in v}

    def signed(name, default=None):
        value = values.get(name)
        if value is None and default is not None:
            return default
        if value is None or value["type"] != 4 or len(value["raw"]) != 4:
            raise ValueError("invalid time zone bias")
        return struct.unpack("<i", value["raw"])[0]

    def transition(name):
        value = values.get(name)
        if value is None:
            return (0,) * 8
        if value["type"] != 3 or len(value["raw"]) != 16:
            raise ValueError("invalid time zone transition")
        return struct.unpack("<8H", value["raw"])

    bias = signed("bias")
    disabled = signed("dynamicdaylighttimedisabled", 0)
    standard = (0,) * 8 if disabled else transition("standardstart")
    daylight = (0,) * 8 if disabled else transition("daylightstart")
    if bool(standard[1]) != bool(daylight[1]):
        raise ValueError("incomplete time zone transitions")
    standard_bias = bias + signed("standardbias", 0) if standard[1] else bias
    daylight_bias = bias + signed("daylightbias") if daylight[1] else bias
    if max(abs(standard_bias), abs(daylight_bias)) >= 1440:
        raise ValueError("invalid time zone bias")
    name = values.get("timezonekeyname", {}).get("value")
    name = name if isinstance(name, str) else ""
    annual = None if disabled else _annual_rules(software, name)
    return WindowsTimeRules(name, "SYSTEM\\" + loc, standard_bias, daylight_bias, standard, daylight, annual)


def read_evidence_clocks(paths):
    """Index Windows installation clocks using the enclosing volume when identifiable."""
    systems = sorted({Path(path).resolve() for path in paths if Path(path).name.casefold() == "system"})
    software = {Path(path).resolve().parent: Path(path) for path in paths if Path(path).name.casefold() == "software"}
    clocks = {}
    for system in systems:
        installation = tuple(part.casefold() for part in system.parts[-4:-1])
        scope = system.parents[3] if installation == ("windows", "system32", "config") else None
        try:
            rules = read_windows_time_rules(system, software.get(system.parent))
        except (OSError, ValueError, KeyError):
            rules = None
        clocks[system] = (scope, rules)
    return clocks


def clock_for_source(clocks, source):
    if not clocks:
        return None
    path = Path(source).resolve()
    candidates = [rules for scope, rules in clocks.values() if scope is not None and path.is_relative_to(scope)]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates and len(clocks) == 1:
        scope, rules = next(iter(clocks.values()))
        if scope is None:
            return rules
    return None


def local_time_to_utc(raw, rules):
    """Return UTC and provenance; gaps and repeated wall times stay unresolved."""
    details = {"timestamp_raw_local": raw, "timezone_known": False, "time_basis": "시간대 미상"}
    if rules is None:
        return None, details
    try:
        wall = datetime.fromisoformat(raw)
        if wall.tzinfo is not None:
            return None, details
        if rules.annual is not None:
            if not rules.annual:
                return None, details
            year = wall.year
            if year not in rules.annual:
                year = min(max(year, min(rules.annual)), max(rules.annual))
            rules = rules.annual.get(year)
            if rules is None:
                return None, details
        standard = timedelta(minutes=rules.standard_bias)
        daylight = timedelta(minutes=rules.daylight_bias)
        if not rules.standard_date[1] or standard == daylight:
            utc = wall + standard
        else:
            start = _transition(rules.daylight_date, wall.year) + standard
            end = _transition(rules.standard_date, wall.year) + daylight
            if start == end:
                return None, details
            candidates = []
            for shift, expect_daylight in ((standard, False), (daylight, True)):
                candidate = wall + shift
                active = start <= candidate < end if start < end else candidate >= start or candidate < end
                if active == expect_daylight:
                    candidates.append(candidate)
            if len(candidates) != 1:
                return None, details
            utc = candidates[0]
    except (TypeError, ValueError, OverflowError):
        return None, details
    details.update(timezone_known=True,
                   time_basis=f"로컬 기록 → UTC 환산, 시간대 근거: {rules.registry_key}",
                   time_zone_name=rules.name)
    return utc.replace(tzinfo=timezone.utc).isoformat(), details


def resolve_record_clock(raw, rules):
    """Normalize an explicit offset or apply the attributable Windows wall-clock rule."""
    try:
        stamp = datetime.fromisoformat(raw)
        if stamp.utcoffset() is not None:
            return stamp.astimezone(timezone.utc).isoformat(), {
                "time_basis": "원래 시각의 UTC 오프셋", "timezone_known": True}
    except (TypeError, ValueError, OverflowError):
        return None, {"time_basis": "시각 형식 미상"}
    return local_time_to_utc(raw, rules)


def resolve_event_metadata_clock(event, clock):
    """Retain both UTC and raw dates for network observations and task declarations."""
    details = event.details
    if event.artifact == "network" and event.action == "network_profile":
        times = {}
        for field in ("date_last_connected", "date_created"):
            raw = details.get(field)
            if raw:
                times[field] = resolve_record_clock(raw, clock)
                stamp, basis = times[field]
                details[field + "_utc"] = stamp
                basis["time_basis"] = "로컬 SYSTEMTIME (1ms 단위), " + basis["time_basis"]
                details[field + "_basis"] = basis["time_basis"]
        if times:
            field = next(iter(times))
            event.timestamp, provenance = times[field]
            event.time_field = "network_last_connected" if field == "date_last_connected" else "network_profile_created"
            details.update(provenance)
    elif event.artifact == "tasks":
        for target, keys in [(details, ("registration_date",)),
                             *((trigger, ("startboundary", "endboundary")) for trigger in details.get("triggers", ()))]:
            for field in keys:
                if target.get(field):
                    stamp, provenance = resolve_record_clock(target[field], clock)
                    target[field + "_utc"] = stamp
                    target[field + "_basis"] = "예약 작업 XML 날짜, " + provenance["time_basis"]
