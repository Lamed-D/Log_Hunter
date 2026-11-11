# Runtime source with the same executable tokens.
"""Windows Task Scheduler XML parser.

Parses task definition XML files from C:\\Windows\\System32\\Tasks\\.
Extracts registration info, triggers, actions, principals, and settings.
Flags suspicious patterns for security analysis.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent

NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
NS_MAP = {"t": NS}

SUSPICIOUS_PATH_PATTERNS = re.compile(
    r"(?i)(\\temp\\|\\tmp\\|%temp%|%tmp%|\\appdata\\|\\downloads\\|\\public\\|\\programdata\\.*\\temp)",
)
SUSPICIOUS_CMD_PATTERNS = re.compile(
    r"(?i)(-enc\s|-encodedcommand\s|certutil\s.*-decode|certutil\s.*-urlcache|"
    r"bitsadmin\s.*/transfer|powershell\s.*-nop|mshta\s|regsvr32\s.*/s|"
    r"rundll32\s.*javascript|wscript\s|cscript\s.*//e:)",
)

TRIGGER_TYPES = (
    "TimeTrigger", "CalendarTrigger", "LogonTrigger", "BootTrigger",
    "EventTrigger", "IdleTrigger", "RegistrationTrigger", "SessionStateChangeTrigger",
)


def _find(element, tag):
    return element.find(f"t:{tag}", NS_MAP)


def _text(element, tag, default=None):
    child = _find(element, tag)
    return child.text.strip() if child is not None and child.text else default


def _parse_triggers(triggers_elem):
    results = []
    if triggers_elem is None:
        return results
    for ttype in TRIGGER_TYPES:
        for trigger in triggers_elem.findall(f"t:{ttype}", NS_MAP):
            info = {"type": ttype}
            for field in ("StartBoundary", "EndBoundary", "Enabled", "Delay", "ExecutionTimeLimit"):
                val = _text(trigger, field)
                if val is not None:
                    info[field.lower()] = val
            rep = _find(trigger, "Repetition")
            if rep is not None:
                info["repetition_interval"] = _text(rep, "Interval")
                info["repetition_duration"] = _text(rep, "Duration")
                info["repetition_stop"] = _text(rep, "StopAtDurationEnd")
            if ttype == "EventTrigger":
                sub = _find(trigger, "Subscription")
                if sub is not None and sub.text:
                    info["subscription"] = sub.text.strip()
            if ttype == "CalendarTrigger":
                for schedule in ("ScheduleByDay", "ScheduleByWeek", "ScheduleByMonth", "ScheduleByMonthDayOfWeek"):
                    sched = _find(trigger, schedule)
                    if sched is not None:
                        info["schedule_type"] = schedule
                        interval = _text(sched, "DaysInterval") or _text(sched, "WeeksInterval")
                        if interval:
                            info["schedule_interval"] = interval
            results.append(info)
    return results


def _parse_actions(actions_elem):
    results = []
    if actions_elem is None:
        return results
    for exec_elem in actions_elem.findall(f"t:Exec", NS_MAP):
        action = {"type": "Exec"}
        action["command"] = _text(exec_elem, "Command")
        action["arguments"] = _text(exec_elem, "Arguments")
        action["working_directory"] = _text(exec_elem, "WorkingDirectory")
        results.append(action)
    for com in actions_elem.findall(f"t:ComHandler", NS_MAP):
        action = {"type": "ComHandler"}
        action["class_id"] = _text(com, "ClassId")
        action["data"] = _text(com, "Data")
        results.append(action)
    for send in actions_elem.findall(f"t:SendEmail", NS_MAP):
        action = {"type": "SendEmail"}
        action["to"] = _text(send, "To")
        action["from"] = _text(send, "From")
        action["subject"] = _text(send, "Subject")
        action["server"] = _text(send, "Server")
        results.append(action)
    for msg in actions_elem.findall(f"t:ShowMessage", NS_MAP):
        action = {"type": "ShowMessage"}
        action["title"] = _text(msg, "Title")
        action["body"] = _text(msg, "Body")
        results.append(action)
    return results


def _parse_principal(principals_elem, context=None):
    if principals_elem is None:
        return {}
    principal = next((p for p in principals_elem.findall("t:Principal", NS_MAP)
                      if not context or p.get("id") == context), None)
    if principal is None:
        return {}
    return {
        "principal_id": principal.get("id"),
        "user_id": _text(principal, "UserId"),
        "group_id": _text(principal, "GroupId"),
        "run_level": _text(principal, "RunLevel"),
        "logon_type": _text(principal, "LogonType"),
    }


def _parse_settings(settings_elem):
    if settings_elem is None:
        return {}
    fields = ("Enabled", "Hidden", "RunOnlyIfNetworkAvailable", "AllowStartOnDemand",
              "DisallowStartIfOnBatteries", "StopIfGoingOnBatteries", "AllowHardTerminate",
              "StartWhenAvailable", "RunOnlyIfIdle", "WakeToRun", "ExecutionTimeLimit",
              "DeleteExpiredTaskAfter", "Priority", "MultipleInstancesPolicy")
    result = {}
    for field in fields:
        val = _text(settings_elem, field)
        if val is not None:
            key = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", field).lower()
            if val.lower() in ("true", "false"):
                result[key] = val.lower() == "true"
            else:
                result[key] = val
    idle = _find(settings_elem, "IdleSettings")
    if idle is not None:
        result["idle_duration"] = _text(idle, "Duration")
        result["idle_wait_timeout"] = _text(idle, "WaitTimeout")
        stop = _text(idle, "StopOnIdleEnd")
        if stop is not None:
            result["idle_stop_on_end"] = stop.lower() == "true"
    return result


def _assess_suspicion(actions, principal, settings, triggers):
    flags = []
    run_level = principal.get("run_level", "")
    if run_level and "highest" in run_level.lower():
        flags.append("admin_execution")
    if settings.get("hidden"):
        flags.append("hidden_task")
    for action in actions:
        cmd = (action.get("command") or "") + " " + (action.get("arguments") or "")
        if SUSPICIOUS_CMD_PATTERNS.search(cmd):
            flags.append("suspicious_command")
        full_path = cmd + " " + (action.get("working_directory") or "")
        if SUSPICIOUS_PATH_PATTERNS.search(full_path):
            flags.append("suspicious_path")
    for trigger in triggers:
        sub = trigger.get("subscription", "")
        if "Security" in sub or "4688" in sub or "4624" in sub:
            flags.append("security_log_watcher")
    return list(dict.fromkeys(flags))


def parse_task_xml(data, source_path):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    tag = root.tag
    if not (tag == "Task" or tag.endswith("}Task")):
        return None
    reg = _find(root, "RegistrationInfo")
    if reg is None:
        reg = ET.Element("empty")
    triggers = _parse_triggers(_find(root, "Triggers"))
    actions = _parse_actions(_find(root, "Actions"))
    action_element = _find(root, "Actions")
    context = action_element.get("Context") if action_element is not None else None
    principal = _parse_principal(_find(root, "Principals"), context)
    settings = _parse_settings(_find(root, "Settings"))
    suspicion = _assess_suspicion(actions, principal, settings, triggers)
    return {
        "task_name": Path(source_path).name,
        "author": _text(reg, "Author"),
        "date": _text(reg, "Date"),
        "description": _text(reg, "Description"),
        "uri": _text(reg, "URI"),
        "source": _text(reg, "Source"),
        "triggers": triggers,
        "actions": actions,
        "principal": principal,
        "settings": settings,
        "trigger_count": len(triggers),
        "action_count": len(actions),
        "suspicion_flags": suspicion,
        "risk_level": "high" if suspicion else "low",
    }


class TaskSchedulerParser(ArtifactParser):
    artifact = "tasks"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            files = sorted(f for f in source.rglob("*") if f.is_file())
        else:
            files = [source]
        for file in files:
            try:
                data = file.read_bytes()
            except OSError as exc:
                self.error(file, "read", exc)
                continue
            try:
                text = data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
            except UnicodeDecodeError:
                try:
                    text = data.decode("utf-16")
                except (UnicodeDecodeError, ValueError):
                    self.error(file, "encoding", "인코딩 해석 불가")
                    continue
            parsed = parse_task_xml(text, file)
            if parsed is None:
                self.error(file, "xml", "Task XML 파싱 실패", "warning")
                continue
            action_desc = "task_definition"
            if parsed["suspicion_flags"]:
                action_desc = "suspicious_task"
            for action in parsed["actions"] or [{"type": "none"}]:
                cmd = action.get("command") or action.get("class_id") or ""
                args = action.get("arguments") or ""
                details = {
                    k: v for k, v in {
                        "task_name": parsed["task_name"],
                        "run_user": parsed["principal"].get("user_id") or parsed["principal"].get("group_id"),
                        "author": parsed["author"],
                        "registration_date": parsed["date"],
                        "description": parsed["description"],
                        "uri": parsed["uri"],
                        "action_type": action.get("type"),
                        "command": action.get("command"),
                        "arguments": action.get("arguments"),
                        "working_directory": action.get("working_directory"),
                        "class_id": action.get("class_id"),
                        "trigger_count": parsed["trigger_count"],
                        "triggers": parsed["triggers"] if parsed["triggers"] else None,
                        "principal": parsed["principal"] if parsed["principal"] else None,
                        "settings": parsed["settings"] if parsed["settings"] else None,
                        "suspicion_flags": parsed["suspicion_flags"] if parsed["suspicion_flags"] else None,
                        "risk_level": parsed["risk_level"],
                    }.items() if v is not None
                }
                yield ForensicEvent(
                    self.artifact, str(file), action_desc,
                    None, None,
                    self.sid,
                    process=f"{cmd} {args}".strip() if cmd else None,
                    locator=str(file),
                    status="warning" if parsed["suspicion_flags"] else "ok",
                    details=details,
                )
