# ▶ 원본: log_hunter/core/process_tree.py
# ▶ 기록 형식에 맞는 필드와 시각을 읽습니다. 범위 검사와 self.error 호출을 함께 확인하세요.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Process tree reconstruction from Sysmon Event ID 1 (Process Create) events."""
from dataclasses import dataclass, field
import ntpath


@dataclass
class ProcessNode:
    pid: int
    ppid: int
    image: str
    commandline: str
    user: str
    timestamp: str
    parent_image: str = ""
    children: list = field(default_factory=list)


LOLBINS = frozenset((
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "msiexec.exe", "cmstp.exe", "wmic.exe", "cscript.exe", "wscript.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "control.exe", "forfiles.exe", "pcalua.exe",
    "eventvwr.exe", "fodhelper.exe", "sdclt.exe",
))

NORMAL_PARENTS = frozenset((
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "wininit.exe", "csrss.exe", "smss.exe",
    "taskhostw.exe", "runtimebroker.exe", "sihost.exe",
    "searchhost.exe", "dllhost.exe",
))


def _safe_int(val):
    if val is None:
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def build_process_tree(events):
    nodes = {}
    for e in events:
        details = e.details or {}
        event_id = details.get("event_id")
        if event_id != 1:
            continue
        ed = details.get("event_data") or details.get("sysmon") or {}
        pid = _safe_int(ed.get("ProcessId"))
        ppid = _safe_int(ed.get("ParentProcessId"))
        if not pid:
            continue
        node = ProcessNode(
            pid=pid,
            ppid=ppid,
            image=ed.get("Image") or e.process or "",
            commandline=ed.get("CommandLine") or "",
            user=ed.get("User") or e.sid or "",
            timestamp=e.timestamp or "",
            parent_image=ed.get("ParentImage") or "",
        )
        nodes[pid] = node

    for node in nodes.values():
        parent = nodes.get(node.ppid)
        if parent is not None and parent is not node:
            parent.children.append(node)

    roots = [n for n in nodes.values() if n.ppid not in nodes or n.ppid == n.pid]
    roots.sort(key=lambda n: n.timestamp)
    return roots


def format_process_tree(roots, indent=0):
    lines = []
    for node in roots:
        prefix = "  " * indent
        exe = ntpath.basename(node.image) or node.image
        cmd = node.commandline
        if cmd and cmd != node.image:
            display = cmd if len(cmd) <= 80 else cmd[:77] + "..."
        else:
            display = exe
        user_part = f" (user: {node.user})" if node.user else ""
        ts_part = f" @{node.timestamp}" if node.timestamp else ""
        lines.append(f"{prefix}[PID:{node.pid}] {display}{user_part}{ts_part}")
        lines.extend(format_process_tree(node.children, indent + 1).splitlines())
    return "\n".join(lines)


def _tree_depth(node, current=1):
    if not node.children:
        return current
    return max(_tree_depth(c, current + 1) for c in node.children)


def _collect_all(node):
    yield node
    for c in node.children:
        yield from _collect_all(c)


def detect_suspicious_trees(roots):
    findings = []
    for root in roots:
        depth = _tree_depth(root)
        if depth > 5:
            findings.append({
                "type": "deep_nesting",
                "description": f"프로세스 트리 깊이 {depth}단계 (PID:{root.pid} {ntpath.basename(root.image)})",
                "severity": "warning" if depth <= 8 else "high",
                "root_pid": root.pid,
            })

        for node in _collect_all(root):
            exe_name = ntpath.basename(node.image).lower()
            parent_name = ntpath.basename(node.parent_image).lower()

            if exe_name in LOLBINS and parent_name and parent_name not in NORMAL_PARENTS:
                findings.append({
                    "type": "lolbin_unusual_parent",
                    "description": f"LOLBin {exe_name} → 비정상 부모: {parent_name} (PID:{node.pid})",
                    "severity": "high",
                    "pid": node.pid,
                    "image": node.image,
                    "parent_image": node.parent_image,
                })

            image_lower = node.image.lower()
            temp_indicators = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                               "\\users\\public\\", "\\downloads\\")
            if any(ind in image_lower for ind in temp_indicators):
                findings.append({
                    "type": "temp_execution",
                    "description": f"임시 경로 실행: {node.image} (PID:{node.pid})",
                    "severity": "warning",
                    "pid": node.pid,
                    "image": node.image,
                })

    return findings
