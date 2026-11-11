"""Left navigation tree: data sources (file tree), artifact categories, analysis results, accounts."""
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from .sid_resolver import display_name
from .task_merge import TASK_ARTIFACTS
from .labels import (DETAIL_LABELS, SID_TEXT, TASK_TEXT, USB_DEVICE_KINDS, USB_GROUP_NODES, action_label, artifact_label, detail_label, relation_label,
                     status_label, time_field_label)

# (key, plain label, artifacts), in the order shown under 찾은 기록.
ARTIFACT_CATEGORIES = [
    ('security_detections', '백신 파일 기록', ('defender',)),
    ("run_programs", "실행한 프로그램", ("prefetch", "bam", "userassist")),
    ("installed_programs", "설치된 프로그램", ("amcache",)),
    ("recent_documents", "최근 문서", ("mru", "lnk", "jumplist")),
    ('thumbnail_cache', '파일 미리 보기 흔적', ('thumbcache',)),
    ("recycle_bin", "휴지통", ("recyclebin",)),
    ("shell_bags", "열어본 폴더", ("shellbag",)),
    ("usb_devices", "USB·외부 장치 연결", ("usb",)),
    ("web_history", "웹 방문 기록", ("history", "cache")),
    ("autostart", "자동 실행 항목", ("run", "startup", "services", "tasks", "taskcache")),
    ("commands", "입력한 명령어", ("psreadline",)),
    ("network", "네트워크·Wi-Fi", ("network", "wlan")),
    ('remote_desktop', '원격 데스크톱 접속 기록', ('rdp',)),
    ("resource_usage", "앱 사용량", ("srum",)),
    ("event_logs", "이벤트 로그", ("evtx",)),
    ("file_system", "파일 시스템 기록", ("mft",)),
]
DIRECT_SOURCE = "직접 추가한 파일"


@dataclass
class TreeNode:
    key: str
    label: str
    kind: str = "group"  # group | all | source | artifacts | device_kind | usb_device | usb_hidden | account | relation | errors | fileview | event_set
    value: object = None
    count: int = 0
    children: list = field(default_factory=list)
    fs: dict = None  # file system item read from the image: {image, volume, parts, directory, browsable, ...}

    @property
    def text(self):
        if self.kind in ("group", "snapshot") or (self.fs is not None and not self.count):
            return self.label  # folders/files without records: no "(0)" noise
        return f"{self.label} ({self.count})"

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


class OriginIndex:
    """Maps an event's evidence path to where it really came from: (data source name, path parts)."""

    def __init__(self, extractions=()):
        self.files = {}
        self.cache = {}
        for extraction in extractions:
            name = source_name(extraction)
            for item in extraction.files:
                parts = (f"볼륨 {item['volume']}", *[p for p in item["image_path"].split("\\") if p])
                self.files[_key(item["extracted"])] = (name, parts)

    def origin(self, source):
        source = str(source or "")
        hit = self.cache.get(source)
        if hit is None:
            hit = self.files.get(_key(source)) if source else None
            if hit is None:
                hit = (DIRECT_SOURCE, PureWindowsPath(source).parts if source else ("(알 수 없음)",))
            self.cache[source] = hit
        return hit

    def text(self, source):
        name, parts = self.origin(source)
        if name == DIRECT_SOURCE:
            return str(source)
        return f"[{name}] " + "\\".join(parts)


def source_name(extraction):
    drive = (extraction.image or {}).get("drive")
    return f"이 PC ({drive})" if drive else PureWindowsPath(extraction.image_path).name


def _key(path):
    return os.path.normcase(os.path.abspath(path))


def category_of(artifact):
    for key, _label, artifacts in ARTIFACT_CATEGORIES:
        if artifact in artifacts:
            return key
    return "other"


def build_tree(events, relations=(), errors=(), sid_map=None, origins=None, sources=()):
    """Return the root nodes. Counts are events, except under 분석 결과 (relations / errors).
    `sources` adds analyzed files that produced no events, so the file tree is complete."""
    origins = origins or OriginIndex()
    sid_map = sid_map or {}
    return [_data_sources(events, origins, sources), _data_artifacts(events), _analysis_results(relations, errors),
            _accounts(events, sid_map)]


def _data_sources(events, origins, sources=()):
    root = TreeNode("src", "데이터 출처", "source", None, len(events))
    per_source = Counter(event.source for event in events)
    for source in sources:
        per_source.setdefault(str(source), 0)
    index = {}
    for source, count in per_source.items():
        name, parts = origins.origin(source)
        path = (name, *parts)
        parent = root
        for depth in range(1, len(path) + 1):
            prefix = path[:depth]
            node = index.get(prefix)
            if node is None:
                node = TreeNode("src:" + "\\".join(prefix), prefix[-1], "source", (prefix[0], tuple(prefix[1:])))
                index[prefix] = node
                parent.children.append(node)
            node.count += count
            parent = node
    _sort(root)
    return root


def _sort(node):
    # Folders first, then files, both by name, like a file explorer.
    node.children.sort(key=lambda n: (not n.children, n.label.casefold()))
    for child in node.children:
        _sort(child)


def _data_artifacts(events):
    counts = Counter(event.artifact for event in events)
    root = TreeNode("art", "찾은 기록", "all", None, len(events))
    known = set()
    for key, label, artifacts in ARTIFACT_CATEGORIES:
        known.update(artifacts)
        present = [a for a in artifacts if counts[a]]
        if not present:
            continue
        category = TreeNode(f"art:{key}", label, "artifacts", tuple(present), sum(counts[a] for a in present))
        groups = _artifact_groups(present)
        if len(groups) > 1:
            category.children = [TreeNode(f"art:{key}:{group[0]}", artifact_label("tasks" if group[0] in TASK_ARTIFACTS
                                                                                  else group[0]), "artifacts", group,
                                          sum(counts[a] for a in group)) for group in groups]
        task_group = next((g for g in groups if g[0] in TASK_ARTIFACTS), None)
        if task_group:  # 의심 신호만 보기: a filter, the signals are leads and not findings
            tasks = next((c for c in category.children if c.value == task_group), category)
            flagged = sum(1 for e in events if e.artifact in TASK_ARTIFACTS and _task_flagged(e))
            if flagged:
                tasks.children = [*tasks.children, TreeNode(f"art:{key}:tasks:signals", TASK_TEXT["signal_node"],
                                                            "task_signals", task_group, flagged)]
        if "usb" in present:  # 장치 종류별: a filter by the engine's recorded-identifier classification
            usb = next((c for c in category.children if c.value == ("usb",)), category)
            usb.children = _device_kind_nodes(key, events)
        root.children.append(category)
    others = sorted(a for a in counts if a not in known)
    if others:
        root.children.append(TreeNode("art:other", "기타 기록", "artifacts", tuple(others), sum(counts[a] for a in others),
                                      [TreeNode(f"art:other:{a}", artifact_label(a), "artifacts", (a,), counts[a]) for a in others]))
    return root


def usb_hidden(details):
    """'system' (hubs, controllers) or 'auxiliary' (service entries) for USB records the engine keeps out of
    the default device list, else None. Records without the engine's inventory fields stay visible."""
    if details.get("device_inventory_visible") is not False:
        return None
    return "system" if details.get("system_device") else "auxiliary"


def _usb_groups(events):
    """{group id: (shown name, representative kind, hidden, record count)} from the engine's inventory fields."""
    groups, counts = {}, Counter()
    for event in events:
        d = event.details or {}
        group = d.get("physical_device_id") if event.artifact == "usb" else None
        if not group:
            continue
        counts[group] += 1
        if d.get("physical_device_representative") or group not in groups:
            name = d.get("friendlyname") or d.get("friendly_name") or d.get("devicedesc") or d.get("device")
            groups[group] = (str(name or USB_GROUP_NODES["unnamed"]), d.get("device_kind") or "unknown", usb_hidden(d))
    return {g: (*info, counts[g]) for g, info in groups.items()}


def _group_nodes(category, groups, wanted):
    return [TreeNode(f"art:{category}:dev:{gid}", f"{name} · {gid}", "usb_device", gid, count)
            for gid, (name, _kind, _hidden, count) in sorted(groups.items(), key=lambda kv: (kv[1][0].casefold(), kv[0]))
            if wanted(groups[gid])]


def _artifact_groups(present):
    """One tree node per artifact, except that scheduled tasks and task registrations share one 예약된 작업 node."""
    tasks = tuple(a for a in TASK_ARTIFACTS if a in present)
    groups = []
    for artifact in present:
        if artifact not in TASK_ARTIFACTS:
            groups.append((artifact,))
        elif tasks and artifact == next(a for a in present if a in TASK_ARTIFACTS):
            groups.append(tasks)
    return groups


def _task_flagged(event):
    details = event.details or {}
    return bool(details.get("task_signals") or details.get("suspicion_flags"))


def _device_kind_nodes(category, events):
    """장치 종류별 filters (visible records only), each with its physical device candidates under it, then the
    hidden system and auxiliary records in their own folded nodes."""
    usb = [e for e in events if e.artifact == "usb"]
    groups = _usb_groups(usb)
    kinds = Counter((e.details or {}).get("device_kind") or "unknown" for e in usb if not usb_hidden(e.details or {}))
    order = list(USB_DEVICE_KINDS)
    nodes = []
    for kind, count in sorted(kinds.items(), key=lambda kv: (kv[0] == "unknown", order.index(kv[0])
                                                               if kv[0] in order else len(order), kv[0])):
        devices = _group_nodes(category, groups, lambda info, k=kind: info[1] == k and info[2] is None)
        label = USB_DEVICE_KINDS.get(kind, kind)
        if devices:
            label += " · " + USB_GROUP_NODES["devices"].format(count=len(devices))
        nodes.append(TreeNode(f"art:{category}:kind:{kind}", label, "device_kind", ("usb", kind), count, devices))
    for hidden in ("system", "auxiliary"):
        count = sum(1 for e in usb if usb_hidden(e.details or {}) == hidden)
        if count:
            devices = _group_nodes(category, groups, lambda info, h=hidden: info[2] == h)
            nodes.append(TreeNode(f"art:{category}:{hidden}", USB_GROUP_NODES[hidden], "usb_hidden", hidden, count, devices))
    return nodes


def _analysis_results(relations, errors):
    root = TreeNode("res", "분석 결과")
    by_type = Counter(r.get("type", "") for r in relations)
    if by_type:
        node = TreeNode("res:rel", "연관 관계", "relation", None, len(relations))
        node.children = [TreeNode(f"res:rel:{t}", relation_label(t), "relation", t, n) for t, n in sorted(by_type.items())]
        root.children.append(node)
    by_severity = Counter(e.severity for e in errors)
    if by_severity:
        node = TreeNode("res:err", "처리 오류·경고", "errors", None, len(errors))
        node.children = [TreeNode(f"res:err:{s}", status_label(s), "errors", s, n) for s, n in sorted(by_severity.items())]
        root.children.append(node)
    return root


def _accounts(events, sid_map):
    counts = Counter(event.sid for event in events if event.sid)
    root = TreeNode("acct", "사용자 계정")
    # People with a name from the evidence first, then other named accounts (well-known), then bare SIDs.
    order = lambda sid: (0 if sid_map.get(sid) else 1 if display_name(sid) else 2, display_name(sid, sid_map).casefold(), sid)
    for sid in sorted(counts, key=order):
        name = display_name(sid, sid_map)
        root.children.append(TreeNode(f"acct:{sid}", SID_TEXT["node"].format(name=name, sid=sid) if name else sid,
                                      "account", sid, counts[sid]))
    return root


def matches(node, event, origins):
    """True if `event` belongs under `node` (only for event-listing node kinds)."""
    if node is None or node.kind == "all" or (node.kind == "source" and node.value is None):
        return True
    if node.kind == "artifacts":
        return event.artifact in node.value
    if node.kind == "device_kind":
        artifact, kind = node.value
        details = event.details or {}
        return (event.artifact == artifact and (details.get("device_kind") or "unknown") == kind
                and not usb_hidden(details))
    if node.kind == "task_signals":
        return event.artifact in TASK_ARTIFACTS and _task_flagged(event)
    if node.kind == "usb_device":  # one physical device candidate: its interfaces, HID children and property times
        return event.artifact == "usb" and (event.details or {}).get("physical_device_id") == node.value
    if node.kind == "usb_hidden":
        return event.artifact == "usb" and usb_hidden(event.details or {}) == node.value
    if node.kind == "account":
        return event.sid == node.value
    if node.kind == "source":
        name, prefix = node.value
        origin_name, parts = origins.origin(event.source)
        # NTFS names are case-insensitive: the image listing may spell a folder differently.
        return (origin_name == name and len(parts) >= len(prefix)
                and all(a.casefold() == b.casefold() for a, b in zip(parts, prefix)))
    if node.kind == "event_set":
        return id(event) in node.value  # records picked from a relation row
    return False


@dataclass
class Property:
    name: str
    value: str = ""
    children: list = field(default_factory=list)


def event_properties(event, origin_text=None, username=None):
    """Item/value rows for one event; nested details become child rows."""
    rows = [
        Property("기록 종류", artifact_label(event.artifact)),
        Property("무슨 일", action_label(event.action)),
        Property("시각 (UTC)", event.timestamp or "알 수 없음"),
        Property("시각의 의미", time_field_label(event.time_field) if event.time_field else ""),
        Property("사용자", f"{username} ({event.sid})" if username and event.sid else event.sid or ""),
        Property("파일/프로그램", event.path or ""),
        Property("실행 파일", event.process or ""),
        Property("주소", event.url or ""),
        Property("상태", status_label(event.status)),
        Property("원본 파일", origin_text or event.source or ""),
        Property("원본 내 위치", event.locator or ""),
    ]
    rows = [row for row in rows if row.value]
    if event.details:
        details = _nested(event.details)
        for row in details:  # top level: explain keys that are easy to over-read
            if row.name in DETAIL_LABELS:
                if row.value == "":
                    row.value = "알 수 없음"
                row.name = detail_label(row.name)
        rows.append(Property("세부 정보", f"{len(event.details)}개 항목", details))
    return rows


def _nested(value, depth=0):
    if depth > 8:
        return [Property("…", repr(value)[:200])]
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple)):
        items = ((f"[{i}]", v) for i, v in enumerate(value))
    else:
        return []
    rows = []
    for key, item in items:
        if isinstance(item, (dict, list, tuple)) and item:
            rows.append(Property(str(key), f"{len(item)}개 항목", _nested(item, depth + 1)))
        else:
            rows.append(Property(str(key), "" if item is None else str(item)))
    return rows
