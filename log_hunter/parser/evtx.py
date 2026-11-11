"""Direct EVTX structural reader with BinXML token decoding and checksum validation.

Reads the EVTX file header, chunk headers, and record structures directly.
BinXML tokens within each record are decoded to extract EventID, EventData,
Provider, Channel, Computer, Security SID, Level, and timestamps.
Chunk header/data CRC32 checksums are verified for integrity.
"""
import struct
import zlib
import ntpath
from pathlib import Path
from .base import ArtifactParser
from .binxml import BinXmlParser, extract_event_fields
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime
from log_hunter.core.labels import action_label


def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
DEFENDER_PROVIDER = 'microsoft-windows-windows defender'
DEFENDER_EVENTS = {1116: 'defender_detection', 1117: 'defender_action'}


def defender_details(event_id, provider, data):
    """Normalize named Defender payload values; an action is not proof of remediation."""
    if (provider or '').casefold() != DEFENDER_PROVIDER or event_id not in DEFENDER_EVENTS:
        return None
    data = data if isinstance(data, dict) else {}
    names = {'Threat Name': 'threat_name', 'Threat ID': 'threat_id', 'Detection ID': 'detection_id',
             'Detection User': 'detection_user', 'Severity Name': 'threat_severity',
             'Category Name': 'threat_category', 'Action Name': 'defender_action_name',
             'Error Code': 'defender_error_code', 'Detection Time': 'defender_detection_time_raw',
             'Path': 'threat_resource', 'Process Name': 'defender_process_name'}
    details = {target: data[source][:4096] for source, target in names.items()
               if isinstance(data.get(source), str) and data[source]}
    for source, target in (('Threat ID', 'threat_id'), ('Detection ID', 'detection_id')):
        value = data.get(source)
        if type(value) is int and 0 <= value <= 0xffffffffffffffff:
            details[target] = str(value)
    details.update(remediation_confirmed=False, threat_execution_confirmed=False)
    return details


def defender_path(resource):
    """Only one plain absolute path or exact file:_ resource can name a file."""
    if any(marker in resource for marker in (';', '->', '|')):
        return None
    path = resource[6:] if resource.startswith('file:_') else resource
    return path if ntpath.isabs(path) else None


KNOWN_SECURITY_EVENTS = {
    4624: "로그온 성공", 4625: "로그온 실패", 4634: "로그오프",
    4648: "명시적 자격 증명 로그온", 4672: "특수 권한 할당",
    4688: "새 프로세스 생성", 4689: "프로세스 종료",
    4697: "서비스 설치", 4698: "예약 작업 생성",
    4720: "사용자 계정 생성", 4722: "사용자 계정 활성화",
    4732: "보안 그룹에 구성원 추가", 4756: "유니버설 그룹에 구성원 추가",
    7034: "서비스 비정상 종료", 7036: "서비스 상태 변경",
    7040: "서비스 시작 유형 변경", 7045: "새 서비스 설치",
    1102: "감사 로그 삭제", 4616: "시스템 시간 변경",
}
SYSMON_EVENTS = {
    1: "프로세스 생성", 2: "파일 생성 시간 변경", 3: "네트워크 연결",
    5: "프로세스 종료", 6: "드라이버 로드", 7: "이미지 로드",
    8: "원격 스레드 생성", 9: "원시 디스크 접근", 10: "프로세스 접근",
    11: "파일 생성", 12: "레지스트리 키/값 생성 또는 삭제",
    13: "레지스트리 값 설정", 14: "레지스트리 키/값 이름 변경",
    15: "파일 스트림 해시", 17: "파이프 생성", 18: "파이프 연결",
    22: "DNS 쿼리", 23: "파일 삭제", 24: "클립보드 변경",
    25: "프로세스 변조", 26: "파일 삭제 기록", 255: "Sysmon 오류",
}
SYSMON_FIELDS = frozenset((
    "Image", "TargetFilename", "User", "SourceIp", "SourcePort",
    "DestinationIp", "DestinationPort", "QueryName", "Hashes",
    "ParentImage", "CommandLine", "OriginalFileName", "ParentCommandLine",
    "CurrentDirectory", "IntegrityLevel", "LogonId", "TerminalSessionId",
    "SourceProcessId", "TargetProcessId", "GrantedAccess", "CallTrace",
    "QueryResults", "QueryStatus",
))
POWERSHELL_EVENTS = {
    4103: "모듈 로깅", 4104: "스크립트 블록 로깅",
    4105: "스크립트 시작", 4106: "스크립트 종료",
    40961: "PowerShell 콘솔 시작", 40962: "PowerShell 콘솔 준비",
    800: "파이프라인 실행 세부정보", 600: "공급자 시작",
}
import re as _re
_PS_SUSPICIOUS = _re.compile(
    r"(?i)(-enc\s|-encodedcommand\s|frombase64string|"
    r"invoke-expression|iex\s|downloadstring|downloadfile|"
    r"net\.webclient|start-bitstransfer|"
    r"amsiutils|amsiinitfailed|"
    r"invoke-mimikatz|invoke-shellcode|invoke-obfuscation|"
    r"set-mppreference\s.*-disablerealtimemonitoring|"
    r"reflection\.assembly|add-type\s.*-typedefinition)",
)


SECURITY_FIELD_MAP = {
    4624: ["LogonType", "TargetUserName", "TargetDomainName", "IpAddress", "IpPort", "WorkstationName", "AuthenticationPackageName"],
    4625: ["LogonType", "TargetUserName", "TargetDomainName", "IpAddress", "IpPort", "WorkstationName", "AuthenticationPackageName"],
    4648: ["TargetUserName", "TargetServerName", "ProcessName"],
    4688: ["NewProcessName", "ParentProcessName", "CommandLine", "TokenElevationType"],
    4689: ["ProcessName"],
    4720: ["TargetUserName", "SubjectUserName"],
    4722: ["TargetUserName", "SubjectUserName"],
    4723: ["TargetUserName", "SubjectUserName"],
    4724: ["TargetUserName", "SubjectUserName"],
    4725: ["TargetUserName", "SubjectUserName"],
    4726: ["TargetUserName", "SubjectUserName"],
    4672: ["SubjectUserName"],
    7045: ["ServiceName", "ImagePath", "ServiceType", "StartType"],
    1102: ["SubjectUserName"],
}


def extract_security_details(event_id, data):
    """Extract forensically-relevant fields for key security event IDs.

    Args:
        event_id: Integer event ID.
        data: Dict of event data fields (e.g. from EventData).

    Returns:
        Dict containing only non-None extracted fields for the given event ID.
        Empty dict if event_id is not in SECURITY_FIELD_MAP or data is empty.
    """
    fields = SECURITY_FIELD_MAP.get(event_id)
    if not fields or not data:
        return {}
    return {k: data[k] for k in fields if data.get(k) is not None}


def known_system_event(event_id, channel, provider):
    """Event IDs are scoped by provider; an unrelated provider can reuse an ID."""
    prov = (provider or "").casefold()
    if event_id in (7034, 7036, 7040, 7045):
        return prov == "service control manager"
    if event_id == 1102 and prov == "microsoft-windows-eventlog":
        return True
    return (prov == "microsoft-windows-security-auditing"
            or (not prov and (channel or "").casefold() == "security"))


def classify_event(event_id, channel, provider):
    categories = []
    known = known_system_event(event_id, channel, provider)
    if known and event_id in KNOWN_SECURITY_EVENTS:
        categories.append("SECURITY")
    if known and event_id in (4688, 4689, 7045, 7034, 7036, 7040):
        categories.append("PROCESS")
    if known and event_id in (4624, 4625, 4634, 4648):
        categories.append("LOGON")
    if known and event_id in (4697, 4698, 7045):
        categories.append("PERSISTENCE")
    if known and event_id in (1102, 4616):
        categories.append("TAMPERING")
    ch = (channel or "").lower()
    prov = (provider or "").lower()
    if "security" in ch:
        categories.append("SECURITY")
    is_sysmon = "sysmon" in prov
    if is_sysmon:
        categories.append("SYSMON")
        if event_id in (1, 5, 10):
            categories.append("PROCESS")
        if event_id in (3, 22):
            categories.append("NETWORK")
        if event_id in (6, 7, 25):
            categories.append("PERSISTENCE")
        if event_id == 8:
            categories.append("LATERAL_MOVEMENT")
        if event_id in (11, 12, 13, 14, 23, 26):
            categories.append("FILE_REGISTRY")
        if event_id == 2:
            categories.append("TIMESTOMP")
    if "powershell" in ch or "powershell" in prov:
        categories.append("POWERSHELL")
        if event_id == 4104:
            categories.append("SCRIPTBLOCK")
        if event_id == 4103:
            categories.append("MODULE_LOG")
    return list(dict.fromkeys(categories)) or ["OTHER"]


class EVTXParser(ArtifactParser):
    artifact = "evtx"

    def parse(self, path):
        with Path(path).open("rb") as stream:
            header = stream.read(4096)
            if len(header) < 4096 or header[:8] != b"ElfFile\0":
                if not header:
                    message = "빈 파일입니다. 이벤트 로그 헤더가 없습니다."
                elif header[4:8] == b"LfLe":
                    message = "구형 Windows 이벤트 로그(.evt)는 지원하지 않습니다."
                elif header[:8] == b"ElfFile\0":
                    message = "이벤트 로그 파일 헤더가 잘렸습니다."
                else:
                    message = "EVTX 이벤트 로그 시그니처가 아닙니다."
                self.error(path, "header", message)
                return
            minor, major = struct.unpack_from("<HH", header, 36)
            chunks, = struct.unpack_from("<H", header, 42)
            flags, = struct.unpack_from("<I", header, 120)
            header_crc_stored, = struct.unpack_from("<I", header, 124)
            header_crc_calc = _crc32(header[:120])
            header_crc_ok = header_crc_stored == header_crc_calc
            if not header_crc_ok:
                self.error(path, "header_crc", f"파일 헤더 CRC32 불일치: 저장={header_crc_stored:#010x} 계산={header_crc_calc:#010x}", "warning")
            if flags & 1:
                self.error(path, "flags", "기록 중 종료된 이벤트 로그입니다. 읽을 수 있는 기록을 계속 읽습니다.", "warning")
            base = 4096
            actual_chunks = 0
            decoded_count = 0
            failed_count = 0
            chunk_ok_count = 0
            chunk_bad_count = 0
            while chunk := stream.read(65536):
                if not any(chunk):
                    base += 65536
                    continue
                truncated = len(chunk) != 65536
                if truncated:
                    self.error(path, base, "마지막 청크가 잘렸습니다. 완전한 레코드만 읽습니다.", "warning")
                if len(chunk) < 512 or chunk[:8] != b"ElfChnk\0":
                    self.error(path, base, "청크 헤더 크기 또는 시그니처 오류")
                    base += 65536
                    continue
                actual_chunks += 1
                header_checksum, = struct.unpack_from("<I", chunk, 124)
                data_checksum, = struct.unpack_from("<I", chunk, 52)
                hdr_verify = _crc32(chunk[:120] + chunk[128:512])
                free, = struct.unpack_from("<I", chunk, 48)
                data_verify = _crc32(chunk[512:free]) if 512 <= free <= len(chunk) else None
                chunk_header_ok = header_checksum == hdr_verify
                chunk_data_ok = data_checksum == data_verify
                if chunk_header_ok and chunk_data_ok:
                    chunk_ok_count += 1
                else:
                    chunk_bad_count += 1
                    if not chunk_header_ok:
                        self.error(path, f"chunk:{base}:header_crc", "청크 헤더 CRC32 불일치", "warning")
                    if not chunk_data_ok:
                        self.error(path, f"chunk:{base}:data_crc", "청크 데이터 CRC32 불일치", "warning")
                free, = struct.unpack_from("<I", chunk, 48)
                if not 512 <= free <= 65536:
                    self.error(path, base + 48, "청크 free-space 범위 오류")
                    base += 65536
                    continue
                free = min(free, len(chunk))
                offset = 512
                scan_end = len(chunk[:free].rstrip(b"\0"))
                record_damage_reported = False
                while offset + 28 <= free and offset < scan_end:
                    signature, size = struct.unpack_from("<II", chunk, offset)
                    if signature != 0x2A2A or size < 28 or size % 8 or offset + size > free:
                        if not record_damage_reported:
                            self.error(path, base + offset, "레코드 시그니처/크기 오류 또는 잘린 레코드; 다음 완전한 기록을 찾습니다.", "warning")
                            record_damage_reported = True
                        offset += 8
                        continue
                    trailing, = struct.unpack_from("<I", chunk, offset + size - 4)
                    if trailing != size:
                        if not record_damage_reported:
                            self.error(path, base + offset, "레코드 후미 크기 불일치", "warning")
                            record_damage_reported = True
                        offset += 8
                        continue
                    record_id, timestamp_raw = struct.unpack_from("<QQ", chunk, offset + 8)
                    fields = {}
                    xml_decoded = False
                    value_warnings = []
                    try:
                        parser = BinXmlParser(chunk, offset + 24, end=offset + size - 4)
                        try:
                            elements = parser.parse()
                        except ValueError:
                            parser = BinXmlParser(chunk, offset + 24, end=offset + size - 4, dependency=False)
                            elements = parser.parse()
                        value_warnings = parser.warnings
                        if value_warnings:
                            self.error(path, base + offset, f"알 수 없는 BinXML 값 형식 {len(value_warnings)}개: 원시 16진수 또는 미해석 값으로 보존했습니다.", "warning")
                        if elements:
                            fields = extract_event_fields(elements)
                            for field in ("provider_name", "channel", "security_user_id"):
                                if fields.get(field) is not None and not isinstance(fields[field], str):
                                    raise ValueError(f"{field}: 문자열 필드가 아닙니다")
                            xml_decoded = bool(fields.get("event_id") is not None or fields.get("provider_name"))
                        if xml_decoded:
                            decoded_count += 1
                        else:
                            failed_count += 1
                    except Exception as exc:
                        fields = {}
                        failed_count += 1
                        self.error(path, base + offset, f"BinXML 디코딩 오류: {exc}", "warning")
                    event_id = fields.get("event_id")
                    channel = fields.get("channel")
                    provider = fields.get("provider_name")
                    security_sid = fields.get("security_user_id")
                    level = fields.get("level")
                    level_name = LEVEL_NAMES.get(level) if isinstance(level, int) else None
                    event_data = fields.get("event_data", {})
                    timestamp_str = filetime(timestamp_raw)
                    is_sysmon = "sysmon" in (provider or "").lower()
                    is_powershell = "powershell" in (provider or "").lower() or "powershell" in (channel or "").lower()
                    action = "event_record"
                    if is_sysmon and event_id in SYSMON_EVENTS:
                        action = SYSMON_EVENTS[event_id]
                    elif is_powershell and event_id in POWERSHELL_EVENTS:
                        action = POWERSHELL_EVENTS[event_id]
                    elif known_system_event(event_id, channel, provider) and event_id in KNOWN_SECURITY_EVENTS:
                        action = KNOWN_SECURITY_EVENTS[event_id]
                    process_name = next((event_data.get(key) for key in ("Image", "NewProcessName", "ProcessName")
                                         if isinstance(event_data.get(key), str) and event_data[key]), None)
                    target_path = next((event_data.get(key) for key in ("TargetFilename", "ImageLoaded")
                                        if isinstance(event_data.get(key), str) and event_data[key]), None)
                    defender = defender_details(event_id, provider, event_data)
                    if defender is not None:
                        action = DEFENDER_EVENTS[event_id]
                        resource = defender.get('threat_resource', '')
                        # Compound resource expressions are not a confirmed single file path.
                        target_path = defender_path(resource) if resource == event_data.get('Path') else None
                        process_name = defender.get('defender_process_name')
                        if (process_name != event_data.get('Process Name')
                                or (process_name or '').casefold() in ('unknown', 'n/a', '-', '')):
                            process_name = None

                    detail = {
                        "record_id": record_id,
                        "event_id": event_id,
                        "version": f"{major}.{minor}",
                        "chunk_count": chunks,
                        "flags": flags,
                        "xml_decoded": xml_decoded,
                        "binxml_value_warnings": value_warnings or None,
                        "checksums_verified": chunk_header_ok and chunk_data_ok,
                        "header_crc_ok": header_crc_ok,
                        "channel": channel,
                        "provider": provider,
                        "time_created": fields.get("time_created"),
                        "computer": fields.get("computer"),
                        "level": level,
                        "level_name": level_name,
                        "task": fields.get("task"),
                        "keywords": fields.get("keywords"),
                        "process_id": fields.get("process_id"),
                        "thread_id": fields.get("thread_id"),
                        "activity_id": fields.get("activity_id"),
                        "event_data": event_data if event_data else None,
                        'user_data': fields.get('user_data'),
                        "categories": classify_event(event_id, channel, provider) if event_id else [],
                        "known_event": (SYSMON_EVENTS.get(event_id) if is_sysmon else
                                        POWERSHELL_EVENTS.get(event_id) if is_powershell else
                                        KNOWN_SECURITY_EVENTS.get(event_id) if known_system_event(event_id, channel, provider) else None) or
                                       (f"기타 이벤트 ({provider or '공급자 미상'}, 이벤트 ID {event_id})"
                                        if xml_decoded else "이벤트 본문 해석 실패 — 원본 파일의 레코드 위치를 확인하세요"),
                    }
                    if is_sysmon:
                        sysmon_detail = {k: event_data[k] for k in SYSMON_FIELDS if k in event_data}
                        if sysmon_detail:
                            detail["sysmon"] = sysmon_detail
                    if defender is not None:
                        detail.update(defender)
                        detail['known_event'] = action_label(DEFENDER_EVENTS[event_id])
                        detail['categories'] = [category for category in detail['categories'] if category != 'OTHER']
                        detail['categories'].append('ANTIVIRUS')
                    if is_powershell:
                        script_block = event_data.get("ScriptBlockText") or event_data.get("Payload")
                        if isinstance(script_block, str) and script_block:
                            detail["script_block"] = script_block[:4096]
                            if _PS_SUSPICIOUS.search(script_block):
                                detail["powershell_suspicious"] = True
                        host_app = event_data.get("HostApplication")
                        if host_app:
                            detail["host_application"] = host_app
                    yield ForensicEvent(
                        self.artifact, str(path), action, timestamp_str, "record_filetime",
                        sid=security_sid,
                        process=process_name,
                        path=target_path,
                        locator=f"byte:{base + offset}",
                        status="ok" if xml_decoded and chunk_header_ok and chunk_data_ok and header_crc_ok and not flags & 1 and not truncated and not value_warnings else "partial",
                        details={k: v for k, v in detail.items() if v is not None},
                    )
                    offset += size
                if offset < scan_end and offset + 28 > free and not record_damage_reported:
                    self.error(path, base + offset, "마지막 레코드가 잘렸습니다.", "warning")
                base += 65536
            if actual_chunks != chunks:
                self.error(path, "chunk_count", f"헤더 청크 수 {chunks}개와 읽은 청크 수 {actual_chunks}개가 다릅니다. 실제 파일 전체를 검사했습니다.", "warning")
            if failed_count:
                self.error(path, "BinXML", f"BinXML 디코딩 실패 {failed_count}건 (성공 {decoded_count}건)", "warning")
            if chunk_bad_count:
                self.error(path, "checksum", f"CRC32 검증 실패 청크 {chunk_bad_count}건 / 전체 {chunk_ok_count + chunk_bad_count}건", "warning")
