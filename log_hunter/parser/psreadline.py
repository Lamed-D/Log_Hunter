import re
from pathlib import Path
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent


CLASSIFICATION_RULES = {
    "DOWNLOAD": r"\b(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|iwr|irm|curl|wget|certutil\s.*urlcache|bitsadmin\s.*/transfer)\b",
    "NETWORK": r"\b(Test-NetConnection|nslookup|ping|tracert|netstat|ipconfig|arp\s|nbtstat|Resolve-DnsName)\b",
    "FILE_DELETE": r"\b(Remove-Item|del\s|erase\s|rm\s|shred|wipe|cipher\s/w)\b",
    "FILE_COPY": r"\b(Copy-Item|cp\s|copy\s|xcopy|robocopy|Move-Item|mv\s|move\s)\b",
    "REGISTRY": r"\b(reg\s|reg\.exe|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Get-ItemProperty)\b",
    "SCHEDULED_TASK": r"\b(schtasks|Register-ScheduledTask|Unregister-ScheduledTask)\b",
    "SERVICE": r"\b(sc\s+create|sc\s+config|sc\s+delete|New-Service|Set-Service|Stop-Service|Start-Service)\b",
    "PROCESS": r"\b(Start-Process|Stop-Process|taskkill|tasklist|Get-Process|Invoke-Expression|iex\s)\b",
    "ENCODING": r"\b(certutil\s.*-encode|certutil\s.*-decode|\[Convert\]::From|base64|ConvertTo-SecureString)\b",
    "CREDENTIAL": r"\b(Get-Credential|mimikatz|sekurlsa|lsadump|net\s+user|cmdkey|runas)\b",
    "RECON": r"\b(whoami|systeminfo|hostname|Get-ComputerInfo|Get-WmiObject|wmic\s|net\s+share|net\s+view|net\s+group|Get-ADUser|Get-ADComputer)\b",
    "FIREWALL": r"\b(netsh\s+advfirewall|New-NetFirewallRule|Set-NetFirewallRule|Disable-NetFirewallRule)\b",
    "POWERSHELL_EVASION": r"(-ExecutionPolicy\s+Bypass|-ep\s+bypass|-nop\b|-w\s+hidden|-WindowStyle\s+Hidden|Set-MpPreference\s.*-DisableRealtimeMonitoring|Add-MpPreference\s.*-ExclusionPath)",
    "ARCHIVE": r"\b(Compress-Archive|Expand-Archive|tar\s|7z\s|zip\s|unzip)\b",
}

RISK_CATEGORIES = {"DOWNLOAD", "CREDENTIAL", "POWERSHELL_EVASION", "ENCODING", "SERVICE", "SCHEDULED_TASK"}


def classify_command(command):
    categories = []
    for label, regex in CLASSIFICATION_RULES.items():
        if re.search(regex, command, re.I):
            categories.append(label)
    return categories or ["OTHER"]


def assess_risk(categories):
    if any(c in RISK_CATEGORIES for c in categories):
        return "high"
    if any(c in ("REGISTRY", "FILE_DELETE", "PROCESS", "FIREWALL") for c in categories):
        return "medium"
    return "low"


class PSReadLineParser(ArtifactParser):
    artifact = "psreadline"

    def parse(self, path):
        command, start = [], 1
        with Path(path).open(encoding="utf-8-sig", errors="replace") as stream:
            for index, line in enumerate(stream, 1):
                if not command:
                    start = index
                text = line.rstrip("\r\n")
                command.append(text[:-1] if text.endswith("`") else text)
                if text.endswith("`"):
                    continue
                result = "\n".join(command)
                command = []
                if result:
                    categories = classify_command(result)
                    risk = assess_risk(categories)
                    yield ForensicEvent(self.artifact, str(path), "command_history", sid=self.sid,
                                        locator=f"line:{start}-{index}",
                                        status="warning" if risk == "high" else "ok",
                                        details={"command": result, "categories": categories,
                                                 "risk_level": risk,
                                                 "timestamp_available": False, "classification_is_heuristic": True})
        if command:
            self.error(path, f"line:{start}", "종료되지 않은 다중행 명령", "warning")
            yield ForensicEvent(self.artifact, str(path), "command_history", sid=self.sid,
                                locator=f"line:{start}", status="partial", details={"command": "\n".join(command)})
