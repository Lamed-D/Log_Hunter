"""Convert Windows evidence wall clocks using the recorded SYSTEM hive rules."""
import calendar
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from log_hunter.parser.registry import Hive, current_controlset


@dataclass(frozen=True)
class WindowsTimeRules:
    name: str
    registry_key: str
    standard_bias: int
    daylight_bias: int
    standard_date: tuple[int, ...]
    daylight_date: tuple[int, ...]

    def metadata(self):
        result = asdict(self)
        result["standard_date"] = list(self.standard_date)
        result["daylight_date"] = list(self.daylight_date)
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


def read_windows_time_rules(path):
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
    return WindowsTimeRules(name if isinstance(name, str) else "", "SYSTEM\\" + loc,
                            standard_bias, daylight_bias, standard, daylight)


def local_time_to_utc(raw, rules):
    """Return UTC and provenance; gaps and repeated wall times stay unresolved."""
    details = {"timestamp_raw_local": raw, "timezone_known": False, "time_basis": "시간대 미상"}
    if rules is None:
        return None, details
    try:
        wall = datetime.fromisoformat(raw)
        if wall.tzinfo is not None:
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
