"""Plain-language names for artifacts, actions and fields shown to non-specialist users.

Internal keys (e.g. "bam", "prefetch") stay unchanged in data/exports; only the display text changes.
"""

ARTIFACT_LABELS = {
    'defender': '백신 파일 기록',
    'thumbcache': '파일 미리 보기 흔적',
    'rdp': '원격 데스크톱 접속 기록',
    "prefetch": "프로그램 실행 기록",
    "bam": "최근 실행한 프로그램",
    "userassist": "사용자가 직접 실행한 프로그램",
    "amcache": "설치·실행된 프로그램 목록",
    "run": "자동 실행 프로그램",
    "startup": "시작프로그램 폴더",
    "services": "백그라운드 서비스",
    "taskcache": "예약 작업 등록 정보",
    "tasks": "예약된 작업",
    "psreadline": "PowerShell 명령어 기록",
    "evtx": "윈도우 이벤트 로그",
    "mru": "최근 열어본 파일",
    "lnk": "바로가기 파일",
    "jumplist": "최근 사용 항목 (작업 표시줄)",
    "shellbag": "열어본 폴더",
    "recyclebin": "휴지통 (삭제한 파일)",
    "mft": "파일 생성·수정 기록",
    "usb": "USB 장치 연결 기록",
    "history": "웹 방문 기록",
    "cache": "웹 캐시 (임시 파일)",
    "srum": "앱·네트워크 사용량",
    "network": "접속한 네트워크",
    "wlan": "저장된 Wi-Fi",
    "image": "디스크 이미지",
}

ARTIFACT_NAV_STATUS = {
    "not_analyzed": "분석 입력 미확인",
    "no_data": "기록 없음",
    "ok": "분석 완료",
    "partial": "일부 분석",
    "failed": "분석 실패",
    "mixed": "일부 종류만 분석",
}

USB_DEVICE_KINDS = {
    'unknown': '알 수 없는 장치', 'keyboard': '키보드', 'mouse': '마우스',
    'storage': 'USB 저장 장치', 'camera': '카메라', 'audio': '오디오 장치',
    'bluetooth': '블루투스 장치', 'wireless': '무선 장치', 'hub': '허브',
    'hid': '기타 입력 장치', 'gamepad': '게임패드', 'consumer_control': '미디어 제어 입력 장치',
    'communications': '통신 장치', 'printer': '프린터', 'vendor_specific': '제조사 전용 장치',
    'portable': '휴대용 장치',
}
# 장치 종류를 정한 근거(엔진 basis 키): 기록된 식별자일 뿐 실제 장치 확인이 아님
USB_BASIS_LABELS = {
    'compatible_id': '호환 ID', 'hid_hardware_id': '하드웨어 ID', 'class_guid': '설치 클래스 GUID',
    'class_name': '설치 클래스 이름', 'bus': '버스', 'registry_location': '레지스트리 위치',
}
USB_CONFIDENCE_LABELS = {'low': '판정 약함', 'recorded_identifier': '기록된 식별자 기준'}
USB_KIND_CONFLICT = '근거 충돌'
USB_SERIAL_MAY_BE_GENERATED = 'Windows 생성 값일 수 있음'
USB_NO_COMPOSITE_BASIS = '묶음 근거 없음'

AUTO_DETECT_COLUMNS = "기록 종류\t파일\t사용자\t인식 근거"
AUTO_DETECT_UNKNOWN = "인식 안 됨"

ARTIFACT_DESCRIPTIONS = {
    'defender': 'Defender 로그·보호 기록과 격리 항목 파일 정보. 탐지가 실행·조치 성공을 확정하지 않으며 격리 원본은 복원하지 않습니다',
    'thumbcache': '탐색기 미리 보기 캐시 (thumbcache). 캐시가 있다는 것은 그 파일을 실제로 열었거나 지웠다는 확정이 아닙니다. '
                  '원본 파일 경로와 연결하지 않았고, 시각 정보도 없습니다',
    'rdp': '원격 접속 대상 MRU·사용자 힌트·설정 파일 (Terminal Server Client / Default.rdp). 접속 성공을 확정하지 않음',
    "prefetch": "Windows가 프로그램을 빨리 열기 위해 남기는 실행 흔적 (Prefetch)",
    "bam": "백그라운드 활동 관리자가 기록한 사용자별 마지막 실행 시각 (BAM)",
    "userassist": "시작 메뉴·탐색기에서 실행한 프로그램과 실행 횟수 (UserAssist)",
    "amcache": "설치되었거나 실행된 프로그램의 경로와 해시 (Amcache)",
    "run": "로그인할 때 자동으로 실행되도록 등록된 프로그램 (Run/RunOnce)",
    "evtx": "로그인, 프로그램 실행, 서비스 설치 등 시스템 이벤트 (EVTX)",
    "mru": "열기/저장 창과 최근 문서 목록 (MRU)",
    "shellbag": "탐색기로 열어본 폴더 기록 (ShellBag)",
    "mft": "NTFS 파일 시스템의 파일별 생성/수정/접근 시각 ($MFT)",
    "srum": "앱별 실행 시간과 네트워크 사용량 (SRUM)",
    "jumplist": "작업 표시줄·시작 메뉴의 최근 항목 (Jump List)",
    "psreadline": "PowerShell 창에서 입력한 명령어 (PSReadLine)",
    "usb": "USB·저장 장치·입력 장치·블루투스 장치 등록과 속성 시각 (USB/USBSTOR/HID/BTHENUM)",
    "history": "크롬·엣지에서 방문한 주소와 다운로드 (History)",
    "cache": "브라우저가 저장해 둔 웹 페이지 조각과 그 주소 (캐시)",
    "lnk": "파일을 열 때 Windows가 만든 바로가기와 대상 파일의 시각 (LNK)",
    "network": "이 PC가 접속한 네트워크 이름과 처음·마지막 접속 (NetworkList)",
    "taskcache": "TaskCache 레지스트리에 기록된 예약 작업 등록 정보",
    "tasks": "정해진 때 자동으로 실행되도록 등록된 작업 (작업 스케줄러)",
    "recyclebin": "휴지통으로 보낸 파일의 원래 위치·크기·삭제 시각 ($I 파일)",
    "wlan": "저장된 Wi-Fi 이름과 보안 방식 (WLAN 프로필)",
    "startup": "로그인할 때 열리는 시작프로그램 폴더의 파일 (StartUp)",
    "services": "Windows가 백그라운드에서 실행하도록 등록된 서비스 (Services)",
}

ACTION_LABELS = {
    "task_registration": "예약 작업 등록",
    'defender_history_record': '백신 보호 기록',
    'defender_quarantine_metadata': '격리 항목 파일 정보 (내부 형식 미지원)',
    'defender_log_reference': '백신 로그의 문구',
    'defender_exclusion_reference': '백신 제외 관련 문구 (설정 확정 아님)',
    'defender_scan_reference': '백신 검사 관련 문구',
    'defender_detection': '백신 탐지 기록',
    'defender_action': '백신 조치 기록 (조치 내용 확인 필요)',
    'thumbnail_cached': '미리 보기 캐시 항목',
    'rdp_mru': '원격 접속 대상 목록',
    'rdp_server': '원격 서버 사용자 힌트',
    'rdp_settings': '원격 접속 설정',
    "execution_trace": "프로그램 실행",
    "program_execution": "프로그램 실행",
    "file_inventory": "프로그램 파일 확인",
    "program_inventory": "설치된 프로그램",
    "autorun_registration": "자동 실행 등록",
    "startup_entry": "시작프로그램 등록",
    "suspicious_startup": "의심스러운 시작프로그램",
    "service_entry": "서비스 등록",
    "suspicious_service": "의심스러운 서비스",
    "command_history": "입력한 명령어",
    "cleartext_password": "명령어에 비밀번호 노출",
    "event_record": "이벤트 기록",
    "recent_document": "최근 문서 열기",
    "open_save_dialog": "열기/저장 창에서 선택",
    "last_visited_dialog": "열기/저장 창 마지막 폴더",
    "file_metadata": "파일 정보",
    "device_registration": "USB 장치 처음 인식",
    "install": "USB 장치 설치",
    "first_install": "USB 장치 최초 설치",
    "last_arrival": "USB 마지막 연결",
    "last_removal": "USB 마지막 분리",
    "url_visit": "웹사이트 방문",
    "url_summary": "웹사이트 방문 요약",
    "download": "파일 다운로드",
    "activity_update": "앱 사용 기록",
    "network_profile": "네트워크 접속",
    "wlan_profile": "Wi-Fi 저장",
    "deleted_file": "파일 삭제",
    "file_deleted": "파일 삭제",
    "cache_entry": "웹 캐시 항목",
    "cache_url_candidate": "웹 캐시 주소",
    "ese_string_candidate": "사용량 기록 문자열",
    "folder_access": "폴더 열기",
    "network_interface": "네트워크 어댑터",
    "network_signature": "네트워크 식별 정보",
    "recent_file_access": "최근 파일 사용",
    "shortcut_target": "바로가기 대상 파일",
    "network_usage": "네트워크 사용량",
    "network_connection": "네트워크 연결 시간",
    "app_resource": "앱 사용량",
    "energy_usage": "전력 사용량",
    "push_notification": "알림 기록",
}

TIME_FIELD_LABELS = {
    'defender_log_record_time': '백신 로그 기록 시각',
    'lnk_access_time': '바로가기 대상의 접근 시각 (목록 사용 시각 아님)',
    'lnk_write_time': '바로가기 대상의 수정 시각 (목록 사용 시각 아님)',
    'lnk_creation_time': '바로가기 대상의 생성 시각 (목록 사용 시각 아님)',
    "time_created": "이벤트 원본 시각",
    "key_lastwrite": "레지스트리 마지막 변경",
    "key_last_write": "레지스트리 마지막 변경",
    "last_execution": "마지막 실행",
    "last_run_time": "마지막 실행",
    "last_visit_time": "마지막 방문",
    "visit_time": "방문",
    "start_time": "다운로드 시작",
    "creation_time": "생성",
    "deletion_time": "삭제",
    "registration_date": "등록",
    "srum_timestamp": "사용량 기록",
    "activity_update": "사용 기록",
    "destlist_timestamp": "마지막 사용",
    "lnk_timestamp": "바로가기 생성·수정",
    "record_filetime": "이벤트 레코드 기록 시각 (레코드 헤더)",
    "raw_filetime": "기록 시각",
    "modified": "수정",
    "accessed": "접근",
    "mtime": "수정",
    "si_created": "파일 생성",
    "si_modified": "파일 수정",
    "si_accessed": "파일 접근",
    "si_mft_changed": "파일 정보 변경",
    "fn_created": "파일 생성 (이름 기록)",
    "fn_modified": "파일 수정 (이름 기록)",
    "fn_accessed": "파일 접근 (이름 기록)",
    "fn_mft_changed": "파일 정보 변경 (이름 기록)",
    "install": "설치",
    "first_install": "최초 설치",
    "last_arrival": "마지막 연결",
    "last_removal": "마지막 분리",
}

CHART_LABELS = {
    "empty": "표시할 기록이 없습니다", "other": "기타",
    "artifacts": "기록 종류별 기록 수", "actions": "가장 많은 활동",
    "statuses": "처리 상태", "hours": "시간대별 기록 수 (시간대 확인된 기록, UTC)",
    "heatmap": "요일×시간 히트맵 (시간대 확인된 기록, UTC)",
    "weekdays": ("월", "화", "수", "목", "금", "토", "일"),
}


STATUS_LABELS = {"ok": "정상", "partial": "일부 손상", "warning": "주의", "error": "오류",
                 "failed": "실패", "no_data": "데이터 없음", "no_input": "입력 없음", "info": "참고"}

# 파일별 결과: why a file gave no or partial records, in plain words.
DIAGNOSTIC_TEXT = {
    "empty": "정상 (기록 0건)", "empty_note": "정상 (기록 0건 · 참고: {message})", "ok": "정상",
    "header": "형식 미지원 또는 헤더 손상: {message}", "dirty": "기록 중 종료된 로그 (읽을 수 있는 기록은 읽음)",
    "header_crc": "헤더 검사값 불일치", "partial": "부분 읽기: 기록 {events:,}건 읽음, 손상·잘린 위치 {count:,}곳 (첫 위치 {first})",
    "binxml": "본문 해석 실패: {message}", "checksum": "청크 검사값 불일치: {message}", "chunks": "청크 수 불일치: {message}",
    "other": "{message}", "more": "외 {count:,}건", "failed": "읽기 실패: {message}",
    "cause_column": "원인",
    "event": {"provider": "공급자", "event_id": "이벤트 ID", "channel": "채널", "record": "레코드 번호", "where": "원본 위치",
              "meaning": "이벤트 설명", "decode": "본문 해석", "decoded": "해석됨", "not_decoded": "해석 실패 (원시 값만)",
              "value_warnings": "해석하지 못한 값 {count}개 (형식 추정 안 함)", "registered": "등록 여부",
              "known": "알려진 이벤트", "unknown": "미등록 이벤트 (설명 없음)", "computer": "컴퓨터 이름"},
}

RELATION_LABELS = {
    "task_log_correlation": "작업 로그 연결 후보",
    'rdp_session_correlation': '원격 대상·사용자·가까운 시각의 접속 후보',
    "correlation_group": "관계 후보 묶음",
    "path_correlation": "같은 파일 경로·이름",
    "url_correlation": "같은 웹 주소",
    "usb_file_correlation": "USB 기록 시각 전후 5분 안 파일 사용",
    "deletion_correlation": "삭제된 파일의 다른 흔적",
    "execution_chain": "여러 종류의 실행 기록에 나온 같은 프로그램",
    "program_group": "같은 프로그램",
}

CONFIDENCE_LABELS = {
    "path_match": "경로 일치", "filename_only": "이름만 일치", "candidate": "가능성 있음",
    "temporal_proximity": "시간 근접", "url_match": "주소 일치", "drive_match": "드라이브 일치",
    "filename_match": "이름 일치", "corroborated_execution": "여러 실행 기록이 같은 시간대에 일치",
    # Older results only: these levels were too strong for name-based matching.
    "confirmed_execution": "여러 실행 기록 (이름 일치)", "probable_execution": "여러 실행 기록 (이름 일치)",
    "multi_source": "기록 종류 2가지 이상에서 이름만 일치", "single_source": "단일 기록", "program_cluster": "같은 프로그램",
    "volume_match": "볼륨 일치",
}

# 연관 분석 detail pane: why records were put together (engine evidence_details), in plain words.
RELATION_DETAIL_LABELS = {
    "rule": "판단 규칙", "confidence": "신뢰도", "reason": "신뢰도 이유", "compared": "비교한 값",
    "normalized": "비교에 쓴 값", "matched": "일치", "not_matched": "불일치",
    "time": "시각", "time_delta": "시각 차이", "window": "기준", "inside": "안", "outside": "밖",
    "time_not_comparable": "시각 차이 계산 안 함 (시각이 없거나 시각의 기준이 서로 다름)",
    "time_count": "시각 있는 기록 {count:,}건", "span": "처음~마지막", "missing": "시각 없는 기록 {count:,}건",
    "group": "묶인 기록 {events:,}건 · 기록 종류 {artifacts:,}가지 · 출처 파일 {sources:,}개",
    "candidates": "후보 수 {count:,}", "pair_limit": "짝으로 펼치는 상한 {count:,}", "key": "묶은 이름:",
    "sid_conflict": "서로 다른 사용자 SID가 섞여 있음", "more": "{count:,}개 더 (기록 목록 참고)",
    "no_details": "이 결과에는 판단 근거 정보가 없습니다(예전 분석 결과). 다시 분석하면 표시됩니다.",
    "multi_source_note": "같은 실행 파일·같은 실행 건·인과관계를 확인한 것이 아니며, 출처 파일이 여러 개라는 뜻도 아닙니다.",
    "members": "묶인 기록 (두 번 누르면 타임라인에서 그 기록으로)", "show_all": "모든 기록 타임라인에 보기",
    "go_a": "기록 A로", "go_b": "기록 B로", "pick": "위 표에서 관계를 고르면 판단 근거가 여기에 나옵니다.",
    "member_columns": {"role": "구분", "artifact": "기록 종류", "source": "출처 파일", "timestamp": "시각",
                       "time_field": "시각의 의미", "target": "대상"},
    "fields": {"path": "경로", "normalized_path": "정규화한 전체 경로", "process": "프로세스 이름", "filename": "파일 이름", "url": "웹 주소",
               "drive_prefix": "드라이브 문자", "volume_guid": "볼륨 식별자", "drive_letter": "드라이브 문자",
               "host": "원격 대상", "account": "계정", "timestamp_window": "시각", "process_name": "프로그램 이름"},
    "operators": {"equals": "같음", "contained_in": "포함", "member_of": "목록 안", "prefix_in": "앞부분 일치"},
}

# Why two records were put together (relation "basis"), in plain words.
BASIS_LABELS = {
    "same_task_namespace": "같은 수집 Windows의 전체 작업 경로",
    "normalized_path": "같은 전체 경로", "filename_only": "같은 파일 이름만", "same_file": "같은 파일",
    "same_executable": "같은 실행 파일", "process_name": "같은 프로그램 이름", "url_match": "같은 웹 주소",
    "volume_guid_match": "같은 볼륨 식별자",
    "usb_drive_match": "USB 드라이브 일치", "usb_temporal_window": "USB 기록 시각 전후 시간 창",
    "candidate_group": "후보가 많아 묶어서 보관",
}

# Unusual patterns found by statistics and the process tree (anomaly "type").
ANOMALY_LABELS = {
    "burst": "짧은 시간에 몰린 기록", "off_hours": "새벽 시간대 활동(UTC 기준)", "time_gap": "기록이 끊긴 시간",
    "deep_nesting": "프로세스가 깊게 이어짐", "lolbin_unusual_parent": "시스템 도구를 이례적인 부모가 실행",
    "temp_execution": "임시 폴더에서 실행",
}

METHOD_LABELS = {"IMAGE": "디스크 이미지", "OFFLINE": "파일 직접 지정", "LIVE": "이 PC 직접 분석", "VSS": "볼륨 섀도 복사본",
                 "DIRECT_VOLUME": "드라이브 직접 읽기 수집", "RegSaveKeyExW": "레지스트리 저장 수집",
                 "EvtExportLog": "이벤트 로그 내보내기 수집"}
IMAGE_VERIFICATION_LABELS = {
    'match': '저장 해시와 일치', 'mismatch': '저장 해시와 불일치',
    'no_stored_hash': '비교할 저장 해시 없음 (계산값만 기록)',
    'read_error': '이미지 읽기 실패', 'metadata_error': '저장 해시 정보 손상',
    'cancelled': '검증 취소',
}


def image_verification_label(status):
    return IMAGE_VERIFICATION_LABELS.get(status, _fallback(status)) if status else "검증 안 함 (선택하지 않음)"


def image_verification_lines(verification):
    """Plain lines for an image verification result (image['verification']); [] when not requested."""
    if not verification:
        return []
    lines = [f"이미지 무결성 검증: {image_verification_label(verification.get('status'))}"]
    for item in verification.get("comparisons") or []:
        mark = "일치" if item.get("matches") else "불일치"
        lines.append(f"  {str(item.get('algorithm', '')).upper()} {mark} (저장값 출처: {item.get('source', '')})")
    size, done = verification.get("size"), verification.get("bytes_read")
    if size:
        lines.append(f"  읽은 데이터: {done or 0:,} / {size:,}바이트")
    computed = verification.get("computed") or {}
    if computed.get("sha256"):
        lines.append(f"  계산한 SHA-256: {computed['sha256']}")
    for warning in (verification.get("warnings") or [])[:3]:
        lines.append(f"  참고: {warning}")
    for error in (verification.get("errors") or [])[:3]:
        lines.append(f"  오류: {error.get('message', '')}")
    if verification.get("status") == "match":
        lines.append("  저장 해시와 같다는 뜻이며, 저장 해시를 누가 기록했는지(출처의 진위)까지 확인한 것은 아닙니다.")
    return lines


def _fallback(key):
    return (key or "").replace("_", " ")


def artifact_label(key):
    return ARTIFACT_LABELS.get(key, _fallback(key))


def action_label(key):
    return ACTION_LABELS.get(key, _fallback(key))


def time_field_label(key):
    return TIME_FIELD_LABELS.get(key, _fallback(key))


def status_label(key):
    return STATUS_LABELS.get(key, _fallback(key))


def relation_label(key):
    return RELATION_LABELS.get(key, _fallback(key))


def confidence_label(key):
    return CONFIDENCE_LABELS.get(key, _fallback(key))


def basis_label(key):
    return BASIS_LABELS.get(key, _fallback(key))


def anomaly_label(key):
    return ANOMALY_LABELS.get(key, _fallback(key))


def method_label(key):
    return METHOD_LABELS.get(key, key)


def evidence_origin(evidence):
    """Where a piece of evidence really came from: the path inside the image/PC, not the temp copy."""
    meta = evidence.metadata or {}
    if not meta.get("image_path"):
        return str(evidence.source)
    if evidence.method == "LIVE":
        return f"[이 PC {meta.get('drive', '')}] {meta['image_path']}"
    return f"[이미지 볼륨 {meta.get('volume')}] {meta['image_path']}"


def artifact_from_label(text):
    for key, label in ARTIFACT_LABELS.items():
        if text == label:
            return key
    return text


FILE_INFO_LABELS = {
    "path": "파일 위치", "image": "디스크 이미지", "volume": "볼륨", "image_path": "이미지 안 경로",
    "mft_record": "MFT 번호", "mft_sequence": "MFT 순번", "in_use": "상태", "size": "크기",
    "created": "생성 (UTC)", "modified": "수정 (UTC)", "accessed": "접근 (UTC)", "mft_modified": "MFT 변경 (UTC)",
    "sha256": "SHA-256", "note": "참고", "extracted_copy": "분석에 쓴 추출 사본", "extracted_sha256": "추출 사본 SHA-256", "drive": "드라이브",
}


def file_info_label(key):
    return FILE_INFO_LABELS.get(key, _fallback(key))


COLUMN_LABELS = {
    "task_name": "작업 이름(경로)", "task_command": "실행 명령", "run_user": "실행 사용자", "registration_time": "등록 시각",
    "last_run_time": "마지막 실행", "last_completed_time": "마지막 완료", "task_hidden": "숨김", "task_source": "출처",
    "task_signals": "의심 신호",
    "recycle_pair": "짝 파일(원본) 상태",
    "ssid_name": "SSID", "authentication": "인증 방식", "encryption": "암호화", "automatic_connection": "연결 방식",
    "wifi_password": "공유키", "password_state": "공유키 상태", "password_source": "공유키 확인 방법",
    "networklist": "네트워크 목록 후보",
    "threat_name": "위험 이름", "threat_target": "대상(경로)", "defender_result": "조치·결과", "unconfirmed": "확정 안 된 값",
    "artifact": "기록 종류", "timestamp": "시각", "time_field": "시각의 의미", "sid": "사용자 SID", "user": "사용자",
    "action": "무슨 일", "path": "파일/프로그램/주소", "status": "상태", "target": "대상", "origin": "출처 파일",
    "description": "설명", "program": "프로그램", "document": "문서·폴더", "original_path": "원래 위치",
    "file_size": "크기(바이트)", "folder": "폴더", "device": "장치", "serial": "일련번호", "url": "주소",
    "entry": "항목", "command": "명령", "network": "네트워크", "publisher": "게시자", "version": "버전",
    "remote_host": "원격 접속 대상", "username_hint": "사용자 이름 힌트", "rank": "목록 순위",
    "cache_id": "캐시 ID", "image_format": "형식 (시그니처만)", "data_size": "데이터 크기(바이트)",
    "cache_location": "위치 (캐시 파일 안)", "image_sha256": "이미지 데이터 SHA-256", "image_hash_status": "해시 상태",
    "stored_checksum": "저장 체크섬", "cache_check": "확인할 점",
    "device_kind_name": "장치 종류", "device_name": "장치 이름", "vid_pid": "VID/PID",
    "usb_class": "USB 인터페이스 클래스", "install_class": "설치 클래스", "composite": "복합 장치",
    "kind_basis": "종류 판정 근거",
    "physical_group": "물리 장치 묶음", "unknown_reason": "알 수 없는 이유",
}
# 파일 미리 보기 흔적(thumbcache) 열의 값: 형식은 앞부분 시그니처로만 알아본 것, 저장 체크섬은 다시 계산하지 않음
THUMBCACHE_VALUE_LABELS = {
    "png": "PNG", "jpeg": "JPEG", "bmp": "BMP", "unknown": "알 수 없음", "empty": "비어 있음",
    "complete": "완료", "limit": "일부만 (크기 상한)",
    "not_verified": "검증 안 됨", "verified": "검증됨",
    "identifier_decode_error": "식별자 문자 해석 오류",
}


# 백신 파일 기록: result and unconfirmed-value wording (a detection is never shown as executed or removed).
DEFENDER_TEXT = {
    "action_recorded": "조치 기록: {name}", "no_remediation": "제거·격리 완료 확인 안 됨",
    "quarantine_unsupported": "격리 항목 파일 정보만 (내부 형식 미지원, 원본 복원 안 함)",
    "exclusion": "제외 관련 문구 (설정 확정 아님)", "scan": "검사 관련 문구", "reference": "로그 문구 (탐지 확정 아님)",
    "history": "보호 기록 (조치 결과 미기록)",
    "time_zone_unknown": "시각 시간대 미상 (원문 {raw})", "time_invalid": "시각 원문 해석 불가 ({raw})",
    "time_not_verified": "기록 시각의 의미 미확인", "execution_unconfirmed": "위협 실행 확인 안 됨",
    "time_raw": "{unknown} (원문 {raw})", "line": "{where} · {line}번째 줄",
    "partial": "일부만 읽음 (줄 잘림·문자 해석 오류·읽기 상한)", "name_raw": "위험 이름 원문만 ({raw})",
    "fields": {"threat_name": "위험 이름", "target": "대상(경로)", "action": "무슨 일", "time": "시각",
               "result": "조치·결과", "execution": "위협 실행 확인", "remediation": "제거·격리 완료 확인",
               "detection_source": "탐지 출처", "threat_id": "위협 ID", "unconfirmed": "확정 안 된 값",
               "where": "원본 파일·위치", "yes": "확인됨", "no": "확인 안 됨", "log_line": "로그 원문 줄"},
}


def column_label(key):
    return COLUMN_LABELS.get(key, _fallback(key))


# Record properties dialog (double-click a record): field names, title and buttons.
UNKNOWN_VALUE = "알 수 없음"
PROPERTY_TITLE = "속성 — {kind}"
PROPERTY_BUTTONS = {"ok": "확인", "more": "자세히…", "less": "간단히", "copy": "선택 복사", "search": "검색:"}
PROPERTY_LABELS = {
    "artifact": "기록 종류", "action": "무슨 일", "timestamp": "시각", "time_field": "시각의 의미", "user": "사용자",
    "target": "대상", "source": "원본 파일", "raw_json": "원본 JSON",
    "pf_name": "파일 이름", "created": "생성 시각", "modified": "수정 시각", "file_size": "파일 크기",
    "exe_name": "실행 파일 이름", "exe_path": "실행 파일 경로", "run_count": "실행 횟수", "last_run": "마지막 실행 시각",
    "exe_exists": "실행 파일 존재 여부", "exe_present": "있음 (이미지에서 경로 확인)",
    "exe_missing": "없음 (이미지의 현재 파일 시스템에서 경로를 찾지 못함)",
    "exe_unknown": "확인 불가 (디스크 이미지·이 PC 분석에서만 확인)",
    "exe_no_volume": "확인 불가 (실행 파일이 있던 볼륨을 이미지에서 찾지 못함)",
    "exe_no_path": "확인 불가 (Prefetch에 볼륨과 이어진 전체 경로가 없음)",
    "exe_checking": "확인 중...", "exe_error": "확인 불가 (이미지 읽기 오류)",
    "previous_runs": "이전 실행 시각", "references": "참조한 파일", "volumes": "볼륨 정보",
    "serial": "시리얼", "volume_created": "볼륨 생성",
    "device_name": "장치 이름", "device_kind": "종류", "vid_pid": "VID / PID",
    "original_path": "원래 경로", "deleted_at": "삭제 시각", "pair_file": "짝 파일 여부", "pair_where": "짝 파일 위치",
    "pair_yes": "있음", "pair_no": "없음 (내용 파일이 없거나 덮어써짐)",
    "title": "제목", "url": "주소", "visited_at": "방문 시각", "visit_count": "방문 횟수",
}

# File list folder moves (buttons above the file list).
FOLDER_NAV_LABELS = {"back": "◀ 뒤로", "forward": "앞으로 ▶", "up": "▲ 위로"}

# Result table layout: headings can be dragged; the order and widths are remembered per column set.
COLUMN_LAYOUT_HINT = "열 머리를 끌어 순서를 바꾸고 경계를 끌어 너비를 바꿀 수 있습니다(다음 실행에도 유지)"
COLUMN_LAYOUT_RESET = "기본 열 순서·너비로 되돌리기"


FILE_KIND_LABELS = {
    "folder": "폴더", "image": "그림", "video": "동영상", "audio": "음성", "document": "문서", "archive": "압축 파일",
    "executable": "실행 파일", "script": "스크립트", "other": "기타 파일",
}
WLAN_PASSWORD_STATES = {
    'not_in_profile': '이 프로필에 공유키 없음', 'protected': '보호된 공유키 있음',
    'plaintext_in_profile': '프로필 원문에 평문 공유키 있음',
    'decrypted': '공유키 복호화 성공 (접속 성공 확인 아님)',
    'verified_live_candidate': '보호 키 전후 일치로 확인한 현재 프로필 공유키 후보',
    'context_unavailable': '복호화 불가 (대상 키·권한·손상 여부 확인 필요)',
    'platform_unavailable': 'Windows 복호화 API 없음',
    'invalid_or_unsupported_key': '공유키 형식 손상 또는 미지원',
    'unknown_protection': '공유키 보호 형식 미상',
}

# 예약 작업: basic columns, extra tabs and signals (a signal is a lead, never a confirmed finding).
TASK_TEXT = {
    "com": "COM 처리기: {dll} {uuid}", "hidden_yes": "숨겨진 작업 단서 (보안 설명자 없음)", "hidden_no": "아니요",
    "hidden_xml": "작업 파일에 숨김 설정", "source_both": "레지스트리·작업 파일 둘 다",
    "source_registry": "레지스트리만 (작업 파일 없음, 등록만 남음)", "source_xml": "작업 파일",
    "not_confirmed": "(확정 아님)", "signal_node": "의심 신호만 보기", "detail_tab": "예약 작업 상세", "compare_tab": "출처 비교",
    "pick": "예약 작업 기록을 고르면 여기에 보여 줍니다.", "no_compare": "레지스트리와 작업 파일 값이 모두 있는 작업만 나란히 비교합니다.",
    "xml": "작업 파일 정보", "registry": "레지스트리 등록 정보", "no_registry": "레지스트리 등록 정보 없음",
    "conditions": "실행 조건", "execution": "실행 여부", "hashes": "출처 파일과 해시",
    "execution_unconfirmed": "등록 정보만으로 실제 실행을 확정하지 않습니다 (이벤트 로그 실행 이력은 연관 분석의 후보로 표시)",
    "execution_confirmed": "실행 확인됨", "time_unverified": "등록·실행 시각의 의미가 확인되지 않은 값이 있습니다",
    "same": "같음", "different": "다름", "only_registry": "레지스트리에만", "only_xml": "작업 파일에만",
    "compare_columns": {"field": "항목", "registry": "레지스트리 값", "xml": "작업 파일 값", "verdict": "비교"},
    "report_tab": "예약 작업", "report_detail": "상세", "report_note": "등록 정보와 작업 파일에서 읽은 예약 작업입니다. 의심 신호는 확인할 단서이며 확정이 아닙니다.",
    "sd_absent": "보안 설명자 없음", "sd_present": "보안 설명자 있음({size}바이트)",
    "context_note": "(실행 계정 설정을 가리키는 이름이며 사용자 계정으로 단정하지 않음)",
    "not_decoded": "해석하지 못함 ({state})", "meaning_unknown": "어떤 시각인지 확인되지 않음",
    "signals": {"security_descriptor_absent": "보안 설명자 없음 (숨겨진 작업 단서)",
                "actions_disagree": "등록 정보와 작업 파일의 동작이 서로 다름",
                "xml_not_matched": "작업 파일 없음 (이 수집 범위에서 같은 작업 파일을 찾지 못함)",
                "registry_not_matched": "등록 정보 없음 (이 수집 범위에서 같은 등록 정보를 찾지 못함)",
                "registry_identity_incomplete": "등록 정보 연결이 불완전함 (작업 ID와 경로가 하나로 맞지 않음)",
                "com_dll_outside_system_path": "COM 처리기 DLL이 시스템 폴더 밖에 있음 (경험 규칙)",
                "actions_not_decoded": "등록 정보의 동작을 해석하지 못함",
                "hidden_task": "숨겨진 작업", "registry_only": "작업 파일 없음(등록만 남음)", "missing_xml": "작업 파일 없음(등록만 남음)",
                "command_mismatch": "명령이 서로 다름", "nonstandard_dll": "비표준 위치의 DLL",
                "hidden": "숨겨진 작업", "suspicious_path": "의심스러운 경로", "encoded_command": "인코딩된 명령"},
    "kinds": {"registry": "레지스트리", "xml": "작업 파일"},
    "triggers": {"BootTrigger": "부팅 시", "LogonTrigger": "로그온 시", "TimeTrigger": "지정 시각", "CalendarTrigger": "일정",
                 "IdleTrigger": "유휴 시", "EventTrigger": "이벤트 발생 시", "RegistrationTrigger": "등록 시",
                 "SessionStateChangeTrigger": "세션 상태 변경 시"},
    "fields": {"author": "작성자", "description": "설명", "registration_date": "작업 파일의 등록 날짜", "triggers": "트리거",
               "principal": "실행 계정 설정", "settings": "설정", "actions": "동작", "command": "명령", "arguments": "인수",
               "run_user": "실행 사용자", "task_guid": "작업 ID", "task_path": "작업 경로", "sd_present": "보안 설명자",
               "dynamic_info": "동적 정보(원시)", "index": "색인 값", "uri": "작업 경로(URI)", "action_type": "종류", "type": "종류",
               "working_directory": "작업 폴더", "class_id": "COM 클래스 ID", "com_handler_dll": "COM 처리기 DLL",
               "action_n": "동작 {n}", "action_count": "동작 수", "tree": "작업 트리 항목", "key_last_write": "키 마지막 변경",
               "execution_context": "실행 컨텍스트", "dynamic_time": "동적 정보 시각 값(위치 {offset})",
               "launch_catalogs": "시작 목록", "principal_id": "설정 이름", "user_id": "사용자", "group_id": "그룹",
               "run_level": "권한 수준", "logon_type": "로그온 방식"},
}

# Saved Wi-Fi profiles on screen and in the report: profile facts and the shared key state, never a connection.
WIFI_TEXT = {
    "auto": "자동 연결 설정", "manual": "수동 연결 설정", "candidate": "(현재 프로필 후보)",
    "candidates": "이름이 같은 네트워크 목록 후보 {count}개 (같은 프로필로 확정 아님)",
    "last_connected": "마지막 연결 기록 {time}{zone}", "zone_unknown": " (시간대 미상)", "ambiguous": "후보 여러 개",
    "sources": {"input_xml": "프로필 원문의 평문", "dpapi_input_blob": "입력한 보호 키를 복호화",
                "protected_blob_checked_before_after": "현재 로컬 프로필과 보호 키 전후 일치 확인"},
    "tab": "Wi-Fi 프로필",
    "note": "저장된 Wi-Fi 프로필과 공유키 상태입니다. 공유키 표시는 그 네트워크에 접속했다는 뜻이 아니며, "
            "보호된 원문 키 값은 넣지 않습니다.",
    "fields": {"profile_name": "프로필 이름", "interface_guid": "무선 장치 식별자", "connection_type": "연결 종류",
               "password_stored_in_profile": "프로필에 공유키 저장", "password_protected": "원문 공유키 보호",
               "password_decryption_error": "복호화 불가 사유", "yes": "예", "no": "아니요", "none": "해당 없음",
               "no_candidates": "이름이 같은 네트워크 목록 후보 없음"},
}

PREVIEW_KIND_LABELS = {
    'none': '미리보기 없음', 'text': '텍스트', 'image': '이미지',
    'metadata': '문서·이미지 정보', 'hex': '16진수·문자열',
}
PREVIEW_DATA_STATE_LABELS = {
    'actual': '실제 데이터', 'recovery_estimate': '복구 추정 (덮어써졌을 수 있음)',
    'unavailable': '미리보기 데이터 없음',
}

# Existing shadow copies listed from an image: a list only, contents are not read yet.
SNAPSHOT_VERIFY_LABELS = {
    'not_checked': '전체 바이트 검증 전', 'unverified': '검증 진행 중',
    'limit': '검증 처리 상한 초과', 'unmapped': '저장 위치를 확인하지 못한 영역 있음',
    'invalid_mapping': '저장 위치 범위 오류', 'cancelled': '스냅숏 검증 취소',
    'read_error': '스냅숏 바이트 읽기 실패', 'verified': '전체 저장 범위와 SHA-256 확인',
}
SNAPSHOT_VERIFY_PHASES = {'mapping': '스냅숏 저장 범위 확인', 'hashing': '스냅숏 전체 바이트 검증'}

SNAPSHOT_TEXT = {
    "group": "볼륨 {volume} 섀도 복사본 ({count}개)", "no_time": "생성 시각 알 수 없음", "store": "스토어 {id}",
    "ambiguous": "목록 항목이 모호함", "incomplete": "목록 불완전", "errors": "목록 진단: 문제 {count}건",
    "failed": "섀도 복사본 목록을 읽지 못했습니다: {error}",
    "message": "섀도 복사본 목록만 표시합니다. 이 복사본의 내용 열기·분석은 아직 지원하지 않습니다.",
    "info": {"volume": "볼륨", "created": "스냅숏 생성 시각", "time_note": "시각의 의미", "store_id": "스토어 식별자",
             "store_note": "스토어 식별자 설명", "raw": "생성 시각 원시 값(FILETIME)", "volume_size": "볼륨 크기",
             "entry": "카탈로그 항목 위치", "complete": "목록 상태", "ambiguous": "모호함", "readable": "내용 읽기",
             "error": "진단"},
    "time_note": "스냅숏(섀도 복사본)을 만든 시각입니다. 파일 생성·실행 시각이 아닙니다.",
    "store_note": "스토어를 가리키는 식별자이며 섀도 복사본 GUID로 단정하지 않습니다.",
    "complete": "완전", "not_complete": "불완전 또는 검증 실패", "yes": "예", "no": "아니요",
    "not_readable": "아직 지원 안 함 (목록만)",
}

# 미리 보기 tab: summary lines above the preview itself.
PREVIEW_TEXT = {
    "tab": "미리 보기", "kind": "미리보기 종류", "state": "데이터 상태", "name": "이름", "size": "크기",
    "format": "내용으로 본 형식", "extension": "확장자", "reason": "미리보기 없는 이유", "truncated": "앞부분만 읽었습니다",
    "mismatch": "확장자와 실제 내용 형식이 다릅니다 (확장자 위장 가능성: .{extension} ↔ {format})",
    "warning": "주의", "error": "읽기 오류", "metadata": "정보", "failed": "미리보기를 만들지 못했습니다: {error}",
    "no_image": "이미지를 화면에 그리지 못했습니다: {error}",
}

FILE_VIEW_LABELS = {
    "file_views": "파일 보기", "by_kind": "종류별", "deleted": "삭제된 파일", "by_size": "크기별",
    "size_50_200": "50MB ~ 200MB", "size_200_1g": "200MB ~ 1GB", "size_1g": "1GB 이상",
}
FILE_TABLE_LABELS = {
    "name": "이름", "kind": "종류", "size": "크기", "modified": "수정 (UTC)", "created": "생성 (UTC)",
    "accessed": "접근 (UTC)", "mft_modified": "MFT 변경 (UTC)", "state": "상태", "records": "기록 수", "path": "이미지 안 경로",
}


def file_kind_label(key):
    return FILE_KIND_LABELS.get(key, _fallback(key))


def file_view_label(key):
    return FILE_VIEW_LABELS.get(key, file_kind_label(key))


def file_table_label(key):
    return FILE_TABLE_LABELS.get(key, _fallback(key))


# Detail keys whose raw name could be read as a stronger claim than the evidence supports.
DETAIL_LABELS = {
    "task_name": "작업 이름", "task_path": "전체 작업 경로", "task_guid": "등록 GUID",
    "task_sources": "작업 출처", "registry_details": "레지스트리 원시 관측", "xml_details": "XML 원시 관측",
    "task_signals": "작업 검토 신호", "task_match_basis": "작업 병합 근거",
    "registration_time": "확인된 등록 시각", "last_run_time": "확인된 마지막 실행 시각",
    "last_completed_time": "확인된 마지막 완료 시각", "time_semantics_verified": "시각 의미 확인 여부",
    "hidden_indicator": "SD 누락 신호", "xml_hidden": "XML 숨김 설정",
    "com_handler_uuid": "COM 처리기 UUID", "com_handler_dll": "등록된 COM DLL",
    "run_user": "XML 실행 사용자", "launch_catalogs": "등록된 실행 조건 목록",
    'log_line': '로그 원문', 'line_number': '줄 번호', 'log_marker': '인식한 문구',
    'log_time_raw': '원문 기록 시각', 'log_time_invalid': '잘못된 기록 시각',
    'history_file_guid': '보호 기록 식별자', 'history_format': '보호 기록 형식',
    'resource_type': '대상 종류', 'resource_location': '기록된 대상 위치',
    'resource_decode_error': '대상 문자 해석 오류', 'threat_id': '위협 식별 번호',
    'threat_category_raw': '기록된 위협 분류 값', 'threat_values': '위협 구역 원시 값',
    'threat_name_raw': '위협 이름 문구 원문', 'threat_name_decode_error': '위협 이름 해석 오류',
    'history_values': '대상 구역 원시 값', 'history_values_truncated': '대상 값 표시 제한 적용',
    'time_meaning_verified': '시각 의미 확인 여부',
    'quarantine_entry_file_id': '격리 항목 파일 식별자',
    'metadata_file_size_read': '읽은 항목 파일 크기', 'metadata_file_sha256': '항목 파일 SHA-256',
    'metadata_format_supported': '항목 내부 형식 지원 여부',
    'quarantine_payload_recovered': '격리 원본 복원 여부',
    'threat_execution_confirmed': '위협 실행 확인 여부', 'remediation_confirmed': '조치 완료 확인 여부',
    'wifi_password': '저장된 Wi-Fi 공유키 (복호화·평문 값)',
    'password_stored_in_profile': '이 프로필에 공유키 저장됨',
    'password_protected': '프로필 원문의 공유키가 보호됨',
    'password_state': '공유키 표시·복호화 상태',
    'password_source': '공유키 값의 확인 방법',
    'password_decryption_error': '공유키 복호화 불가 사유',
    'automatic_connection': '자동 연결',
    'networklist_candidates': '같은 이름의 NetworkList 후보 (동일 프로필 확정 아님)',
    'networklist_link_ambiguous': '이름 일치 네트워크 후보가 여러 개',
    'networklist_candidates_truncated': '네트워크 후보 목록 상한 적용',
    'identity_confirmed': '동일 대상임이 확인됨',
    'date_created_local': 'NetworkList 후보의 생성 시각 (로컬 원문)',
    'date_last_connected_local': 'NetworkList 후보의 마지막 연결 시각 (로컬 원문)',
    'device_kind': '장치 종류 (내부 분류)',
    'device_kind_name': '장치 종류',
    'device_classification_basis': '장치 종류 판정 근거',
    'classification_conflict': '종류 판정 근거 불일치',
    'classification_confidence': '장치 종류 판정 신뢰도',
    'usb_interfaces': 'USB 클래스·하위 클래스·프로토콜',
    'is_storage_device': '저장 장치로 판정됨',
    'serial_is_hardware_confirmed': '하드웨어 시리얼 확인 여부',
    'serial_may_be_generated': 'Windows 생성 인스턴스 값 가능성',
    'composite_group': '복합 장치 묶음 (기록된 컨테이너)',
    'composite_group_basis': '복합 장치 묶음 근거',
    'text_decoding': '문자 해석 근거·추정 여부·손상 원시 바이트',
    'id_list_decoding': '바로가기 셸 항목 이름 복원 근거',
    'pidl_has_unknown_items': '해석하지 못한 셸 항목 포함 여부',
    'encoding': '문자 인코딩',
    'inferred': '문자 인코딩 추정 여부',
    'decode_error': '문자 해석 오류 여부',
    'raw_hex': '해석 전 원시 바이트 (16진수)',
    'threat_name': '백신이 기록한 위협 이름',
    'threat_id': '백신 위협 ID',
    'detection_id': '백신 탐지 ID',
    'detection_user': '탐지 기록의 사용자 (이벤트 작성 계정과 다를 수 있음)',
    'threat_severity': '백신이 기록한 심각도',
    'threat_category': '백신이 기록한 위협 분류',
    'threat_resource': '백신이 기록한 대상 표현 (단일 파일 경로가 아닐 수 있음)',
    'defender_action_name': '백신에 기록된 조치 이름 (허용 포함)',
    'defender_error_code': '백신 조치 오류 코드',
    'defender_detection_time_raw': '탐지 시각 원문 (시간대 미검증)',
    'defender_process_name': '백신 기록의 프로세스 이름',
    'remediation_confirmed': '제거·격리 완료 확인 여부',
    'threat_execution_confirmed': '위협 실행 확인 여부',
    'entry_aux_28': '항목 헤더 +28 원시 값 (의미 미검증)',
    'entry_aux_32': '항목 헤더 +32 원시 값 (의미 미검증)',
    'identifier_decode_error': '캐시 식별자 문자 해석 오류 여부',
    'cache_version': '캐시 형식 버전',
    'cache_type': '캐시 종류 번호',
    'cache_id': '캐시 항목 ID (원본 파일 경로 아님)',
    'cache_identifier': '캐시에 저장된 식별 문자열',
    'entry_offset': '캐시 파일 안의 항목 위치',
    'entry_size': '캐시 항목 전체 크기',
    'data_offset': '캐시 파일 안의 이미지 데이터 위치',
    'data_size': '캐시 이미지 데이터 크기',
    'image_format': '이미지 시그니처 형식 (내용 유효성 미검증)',
    'image_sha256': '캐시 이미지 데이터 SHA-256',
    'image_hash_status': '이미지 해시 계산 상태',
    'stored_data_checksum': '저장된 데이터 체크섬 (검증하지 않음)',
    'stored_header_checksum': '저장된 헤더 체크섬 (검증하지 않음)',
    'checksum_verified': '저장 체크섬 검증 여부',
    'original_path_confirmed': '원본 파일 경로 확인 여부',
    'view_confirmed': '실제 열람 확인 여부',
    'signed_delta_seconds': '파일 시각 − USB 기록 시각 (초, 음수는 기록 전)',
    'direction': 'USB 기록 시각에 대한 파일 시각의 전후',
    'signed_window_seconds': 'USB 기록 전후 후보 범위 (초)',
    'signed_delta_basis': '부호 있는 시각 차이의 계산 기준',
    'remote_host': '원격 접속 대상',
    'remote_port': '원격 접속 포트 (기록에 있을 때)',
    'username_hint': '원격 사용자 이름 힌트',
    'connection_confirmed': '접속 성공 확인 여부',
    'time_is_connection_time': '해당 시각이 실제 접속 시각인지 여부',
    'pinned_status': '고정 여부 (확인되지 않으면 unknown)',
    'time_is_recent_access_time': '목록에서 최근 사용한 시각인지 여부',
    'verification': '이미지 무결성 검증',
    "time_created": "XML TimeCreated (이벤트에 적힌 발생 시각, 레코드 기록 시각과 다를 수 있음)",
    "access_count": "사용 횟수 (확정 안 됨)",
    "access_count_raw": "사용 횟수 후보 원시 값 (4바이트, 의미 미상)",
}


def detail_label(key):
    """Label for a top-level details key in the record view; the raw key stays visible in brackets."""
    label = DETAIL_LABELS.get(key)
    return f"{label} [{key}]" if label else key


# Examiner tags (the examiner's own judgement, not something found in the evidence).
TAG_LABELS = {"notable": "빨강 · 중요·확인 필요", "follow_up": "노랑 · 검토 필요", "benign": "초록 · 확인 완료",
              "note": "메모 있음"}
# Examiner tag colours: the colour word stays, the name after it can be changed by the examiner.
TAG_COLOR_WORDS = {"red": "빨강", "yellow": "노랑", "green": "초록"}
TAG_COLOR_DEFAULT_NAMES = {"red": "중요·확인 필요", "yellow": "검토 필요", "green": "확인 완료"}
TAG_MENU = {"subcategories": "{color} 하위 분류", "new_subcategory": "새 하위 분류...", "rename": "색 이름 바꾸기",
            "rename_prompt": "{color} 태그의 새 이름:", "new_prompt": "{color} 아래에 만들 하위 분류 이름 (예: 유출 의심):",
            "rename_sub": "하위 분류 이름 바꾸기", "delete_sub": "하위 분류 지우기",
            "rename_sub_prompt": "'{name}'의 새 이름:",
            "delete_sub_confirm": "'{name}' 하위 분류를 지울까요?\n이 하위 분류가 붙은 기록·파일에서도 떼어 냅니다(색 태그는 그대로).",
            "save": "태그 저장", "save_done": "태그·메모 {count:,}건과 색상·하위 분류 설정을 저장했습니다.",
            "save_error": "태그를 저장하지 못했습니다: {error}", "file_type": "분석자 태그 JSON",
            "load": "태그 불러오기", "load_none": "이 파일에는 저장된 분석자 태그가 없습니다.",
            "load_done": "태그·메모 {count:,}건을 불러왔습니다. 예전 '주목/추적 필요/정상으로 확인'은 빨강/노랑/초록으로 바뀌었습니다.",
            "load_error": "태그를 읽지 못했습니다: {error}\n태그 저장으로 만든 JSON 또는 기존 case.sqlite를 고르세요.",
            "file_load_done": "태그·메모 {count:,}건과 색상·하위 분류 설정을 불러왔습니다. 같은 항목의 태그·메모는 불러온 값으로 바뀝니다."}
# 태그한 파일의 이미지가 태그할 때와 크기·수정 시각이 다를 때 (같은 경로에 다른 이미지일 수 있음)
TAGGED_IMAGE_CHANGED = "이미지 바뀜 · 확인 필요"
TAGGED_IMAGE_CHANGED_NOTE = "태그한 뒤 이미지 파일의 크기나 수정 시각이 바뀐 파일이 있습니다. 같은 파일인지 확인하세요"


def tag_label(key):
    """Shown name of a saved tag with the default colour names ('red/유출 의심' -> '빨강 › 유출 의심')."""
    color, _, sub = str(key).partition("/")
    if color in TAG_COLOR_WORDS:
        return f"{TAG_COLOR_WORDS[color]} › {sub}" if sub else f"{TAG_COLOR_WORDS[color]} · {TAG_COLOR_DEFAULT_NAMES[color]}"
    return TAG_LABELS.get(key, _fallback(key))


RELATION_REASON_LABELS = {
    "normalized_path": "정규화한 전체 경로 문자열이 같습니다. 같은 파일 실체나 실행을 확인한 것은 아닙니다.",
    "filename_only": "파일 이름만 같습니다. 경로가 다르거나 전체 경로를 알 수 없습니다.",
    "same_file": "삭제 기록과 다른 기록의 파일 이름이 같습니다. 같은 파일 실체는 미확인입니다.",
    "url_match": "웹 주소의 도메인과 경로가 같습니다. 질의 문자열은 비교에서 제외합니다.",
    "usb_temporal": "USB 기록 시각과 파일 기록 시각이 5분 이내입니다. 장치 사용을 확인한 것은 아닙니다.",
    "usb_drive_match": "USB 기록 전후 5분 안에 같은 드라이브 문자로 시작하는 파일 경로가 있습니다.",
    "rdp_host_user_time": "원격 대상·사용자 단서가 일치하고 키 수정·이벤트 시각이 5분 이내입니다. 접속 확정은 아닙니다.",
    "volume_guid_match": "기록된 볼륨 식별자 문자열이 같습니다. 실제 연결 시각은 미확인입니다.",
    "drive_letter_match": "드라이브 문자가 같습니다. 문자는 재사용될 수 있으므로 같은 장치 확정은 아닙니다.",
    "same_executable": "정규화한 실행 파일 이름이 같습니다. 전체 경로와 실행 건의 동일성은 미확인입니다.",
    "multi_source": "실행 관련 기록 종류 두 가지 이상에서 프로그램 이름이 같습니다. 같은 파일·실행 건·출처 파일의 다양성을 보장하지 않습니다.",
    "corroborated_execution": "현재 규칙의 실행 관련 기록 종류·알려진 사용자·5분 시간 창 조건을 충족한 후보입니다. 실행 건의 동일성은 미확인입니다.",
    "candidate_group": "개별 관계 후보 수가 펼치기 상한을 넘어 기록 목록과 묶음 조건으로 보관했습니다.",
}


# USB physical device candidates (engine inventory): tree nodes and why records were put together.
USB_GROUP_NODES = {"system": "시스템 장치 (허브·컨트롤러)", "auxiliary": "보조 항목 (이름만 남은 기록·블루투스 서비스 등)",
                   "devices": "장치 {count}개", "unnamed": "이름 없는 장치"}
USB_GROUP_BASIS_LABELS = {
    "recorded_instance": "같은 기록 인스턴스", "container_id": "같은 컨테이너 ID", "vid_pid_serial": "같은 VID·PID·시리얼",
    "recorded_parent": "기록된 부모 장치", "unique_parent_prefix": "유일한 부모 접두사", "single_observation": "단독 기록",
}
USB_GROUP_NOT_CONFIRMED = "물리 장치 후보(같은 장치로 확정 아님)"
USB_GROUP_AUXILIARY = "보조 항목(별도 물리 장치 아님)"
# Report tab: the same columns as the result table, grouped like the tree; times are key/property times only.
USB_REPORT_TEXT = {
    "tab": "USB·외부 장치", "section": "구분", "candidate": "물리 장치 후보",
    "system": "시스템 장치 (허브·컨트롤러)", "auxiliary": "보조 항목 (별도 물리 장치 아님)",
    "summary": "물리 장치 후보 {devices}개 (기록 {records}건) · 시스템 장치 기록 {system}건 · 보조 항목 기록 {auxiliary}건. "
               "시스템 장치와 보조 항목은 장치 수에 넣지 않습니다.",
    "note": "같은 묶음 번호는 기록된 식별자로 묶은 물리 장치 후보이며 같은 장치로 확정한 것이 아닙니다. "
            "시각은 레지스트리 키·속성 시각이며 연결 시각으로 확정하지 않습니다.",
    "limit": " 표시 상한 {limit:,}건 — 전체 {total:,}건은 report.json·timeline.csv에 있습니다.",
}

USB_UNKNOWN_REASON_LABELS = {
    "metadata_only": "장치 이름만 남은 메타데이터 관측(별도 물리 장치 아님)",
    "parent_device_unknown": "HID 자식 기록만 있어 부모 물리 장치를 확인할 수 없음",
    "description_missing": "장치 이름·설명 기록 없음",
    "classification_missing": "장치 종류를 판단할 클래스·식별자 없음",
    "identifier_unsupported": "기록된 식별자로 장치 종류를 판단할 수 없음",
    "classification_conflict": "기록된 장치 종류가 서로 다름",
}


UUID_NODE_LABELS = {
    "mac_candidate": "랜카드 주소 형식 후보(실제 장치 확인 안 됨)",
    "no_adapter_placeholder": "실제 랜카드 주소 아님(랜카드 없음 표시값)",
    "random_node": "실제 랜카드 주소 아님(무작위 값)",
    "zero_node": "실제 랜카드 주소 아님(비어 있는 값)",
    "not_v1": "랜카드 주소 해석 불가(지원하지 않는 식별자 형식)",
    "invalid_uuid": "랜카드 주소 해석 불가(잘못된 식별자)",
}


ACTION_LABELS.update({"bluetooth_last_seen": "블루투스 마지막 관측 기록",
                      "bluetooth_last_connected": "블루투스 마지막 연결 기록"})
TIME_FIELD_LABELS.update({"bluetooth_last_seen": "블루투스에 기록된 마지막 관측 시각",
                          "bluetooth_last_connected": "블루투스에 기록된 마지막 연결 시각"})


# 휴지통: saving the original ($R) as a new file; the image is only read.
RECYCLE_TEXT = {
    "save": "원본 파일로 저장...", "folder": "(폴더)", "column": "짝 파일(원본) 상태",
    "pick": "원본 파일을 저장할 폴더 (원본 이미지는 바뀌지 않습니다)", "title": "원본 파일로 저장",
    "not_recycle": "휴지통 기록을 고르세요", "no_pair_info": "짝 파일 정보가 없습니다 (디스크 이미지·이 PC에서 꺼낸 휴지통 기록만 저장할 수 있음)",
    "snapshot": "섀도 복사본에서 꺼낸 기록은 아직 저장할 수 없습니다", "no_source": "이 기록의 이미지 안 위치를 찾지 못했습니다",
    "saving": "원본 파일을 저장하는 중...", "unavailable": "저장할 수 없음: {reason}",
    "saved": "새 파일로 저장했습니다: {target}\n원래 경로: {original}\nSHA-256: {sha256}\n출처 기록: {record}\n"
             "(삭제 당시 내용과 같은지는 확인하지 않았습니다)",
    "failed": "저장하지 못했습니다: {error}",
}
RECYCLE_PAIR_STATES = {"present":"짝 파일 확인", "not_observed":"짝 파일 미관측(부재 확정 아님)",
                       "unavailable":"짝 파일 확인 불가"}
RECYCLE_PAIR_REASONS = {
    "no_matching_directory_entry":"원래 디렉터리에서 일치하는 항목을 찾지 못함",
    "ambiguous_companion_names":"일치하는 이름이 여러 개라 선택할 수 없음",
    "directory_or_record_unreadable":"디렉터리 또는 MFT 기록을 확인할 수 없음",
    "companion_not_collected":"선택한 폴더에 짝 파일이 수집되지 않았을 수 있음",
    "reparse_point_not_followed":"링크·재분석 지점을 따라가지 않음",
    "directory_unreadable":"선택한 폴더의 짝 파일 정보를 읽을 수 없음",
}
DETAIL_LABELS.update({"recycle_pair":"휴지통 짝 원본 정보", "i_sha256":"휴지통 메타데이터 SHA-256",
                     "i_mft_record":"휴지통 메타데이터 MFT 번호", "i_mft_sequence":"휴지통 메타데이터 MFT 순번",
                     "absence_confirmed":"원본 부재 확인 여부", "original_content_confirmed":"삭제 당시 내용의 동일성 확인 여부",
                     "reason_label":"확인 상태의 이유", "hash_scope":"해시 계산 범위"})


# Well-known Windows accounts (public well-known SID list): easy name (original name). A name found in the
# evidence (ProfileList, SAM) always comes first; these only fill in what the evidence does not name.
WELL_KNOWN_SIDS = {
    "S-1-0-0": ("아무도 아님", "NULL SID"), "S-1-1-0": ("모든 사람", "Everyone"), "S-1-2-0": ("로컬", "LOCAL"),
    "S-1-3-0": ("작성자 소유자", "CREATOR OWNER"), "S-1-3-1": ("작성자 그룹", "CREATOR GROUP"),
    "S-1-5-2": ("네트워크", "NETWORK"), "S-1-5-4": ("대화형 사용자", "INTERACTIVE"), "S-1-5-6": ("서비스", "SERVICE"),
    "S-1-5-7": ("익명", "ANONYMOUS LOGON"), "S-1-5-10": ("자신", "SELF"), "S-1-5-11": ("인증된 사용자", "Authenticated Users"),
    "S-1-5-18": ("시스템", "SYSTEM"), "S-1-5-19": ("로컬 서비스", "LOCAL SERVICE"), "S-1-5-20": ("네트워크 서비스", "NETWORK SERVICE"),
    "S-1-5-32-544": ("관리자 그룹", "Administrators"), "S-1-5-32-545": ("사용자 그룹", "Users"),
    "S-1-5-32-546": ("게스트 그룹", "Guests"), "S-1-5-32-547": ("고급 사용자 그룹", "Power Users"),
    "S-1-5-32-551": ("백업 운영자 그룹", "Backup Operators"), "S-1-5-32-555": ("원격 데스크톱 사용자 그룹", "Remote Desktop Users"),
    "S-1-5-32-562": ("분산 COM 사용자 그룹", "Distributed COM Users"), "S-1-5-32-568": ("IIS 사용자 그룹", "IIS_IUSRS"),
    "S-1-5-32-573": ("이벤트 로그 읽기 그룹", "Event Log Readers"), "S-1-5-32-578": ("Hyper-V 관리자 그룹", "Hyper-V Administrators"),
    "S-1-5-32-580": ("원격 관리 사용자 그룹", "Remote Management Users"), "S-1-5-80-0": ("모든 서비스", "ALL SERVICES"),
}
WELL_KNOWN_RIDS = {  # S-1-5-21-<machine or domain>-<RID>
    500: ("기본 관리자 계정", "Administrator"), 501: ("게스트", "Guest"), 503: ("기본 계정", "DefaultAccount"),
    504: ("보호된 실행 계정", "WDAGUtilityAccount"), 512: ("도메인 관리자 그룹", "Domain Admins"), 513: ("도메인 사용자 그룹", "Domain Users"),
}
WELL_KNOWN_SID_PREFIXES = (  # (prefix, easy name, original name; {n} = last number)
    ("S-1-5-90-0-", "창 관리자", "DWM-{n}"), ("S-1-5-96-0-", "글꼴 드라이버 호스트", "UMFD-{n}"),
    ("S-1-5-80-", "서비스 계정", "NT SERVICE"), ("S-1-5-83-", "가상 머신 계정", "NT VIRTUAL MACHINE"),
    ("S-1-5-82-", "IIS 앱 풀", "IIS APPPOOL"),
)
SID_TEXT = {"local_user": "로컬 사용자 (RID {rid})", "named": "{name} ({role})", "node": "{name} — {sid}",
            "filter": "사용자(이름·SID)로 거르기:"}


# Left tree tools: find by name, back/forward over selections, the selected path and the right-click menu.
NAV_TEXT = {"back": "◀", "forward": "▶", "find": "트리에서 찾기", "find_hint": "이름 일부 입력 후 Enter",
            "not_found": "트리에 '{text}'이(가) 든 항목이 없습니다 (아직 펼치지 않은 이미지 폴더는 찾지 않습니다)",
            "found": "찾음: {path}", "expand_all": "모두 펼치기", "collapse_all": "모두 접기",
            "copy_path": "경로 복사", "copy_name": "이름 복사"}


# Saved analyses (case.sqlite): open again without re-analysing, save, and the link back to the original evidence.
CASE_TEXT = {
    "open_button": "저장한 분석 열기", "save_button": "분석 저장", "new_button": "새 분석",
    "open_title": "저장한 분석 열기", "recent": "최근 분석 (최근 {n}개)", "browse": "다른 파일 찾기…", "open": "열기",
    "remove": "목록에서 빼기", "close": "닫기", "empty": "최근에 저장하거나 연 분석이 없습니다. [다른 파일 찾기…]로 case.sqlite를 고르세요.",
    "columns": {"name": "케이스 이름", "saved_at": "저장 시각", "events": "기록 수", "source_state": "원본 연결", "path": "위치"},
    "missing": "파일 없음", "pick_file": "저장한 분석(case.sqlite) 고르기", "file_types": "저장한 분석",
    "not_case_file": "case.sqlite 파일을 고르세요",
    "engine_pending": "저장한 분석을 불러오는 기능은 아직 준비 중입니다. 지금은 최근 목록과 파일 선택만 됩니다.",
    "source_states": {"match": "원본 있음 (해시 일치)", "present_unverified": "원본 있음 (해시 확인 안 함)",
                      "saved": "저장 직후", "linked": "원본 연결됨", "missing": "원본 없음", "changed": "원본 해시 다름",
                      "unavailable": "원본 확인 불가", "not_checked": "확인 안 함", "": "알 수 없음",
                      "live_unverified": "이 PC에서 수집 (현재 드라이브 연결·해시 미확인)"},
    "relink_button": "원본 위치 다시 지정", "relink_pick": "저장할 때 쓴 디스크 이미지(E01 등) 고르기",
    "relink_checking": "고른 이미지의 해시를 확인하는 중… (이미지는 읽기만 합니다)",
    "relink_done": "원본 이미지를 연결했습니다 (해시 일치). 왼쪽 데이터 출처에서 이미지 안 파일을 볼 수 있습니다.",
    "relink_mismatch": "고른 파일의 SHA-256이 저장된 원본과 다릅니다. 연결하지 않았습니다.\n저장된 값: {expected}\n고른 파일: {actual}",
    "relink_no_image": "이 분석에는 저장된 디스크 이미지 원본 정보가 없습니다.",
    "relink_unknown": "저장된 원본 해시가 없어 같은 이미지인지 확인할 수 없습니다. 연결하지 않았습니다.",
    "content_unavailable": "저장한 분석이라 이 기록의 원본 파일 사본이 없어 내용을 보여 줄 수 없습니다. {how}",
    "content_how_relink": "[원본 위치 다시 지정]으로 이미지를 연결하면 데이터 출처에서 이미지 안 파일을 볼 수 있습니다.",
    "content_how_linked": "연결한 이미지의 데이터 출처에서 같은 파일을 고르세요.",
    "recycle_unavailable": "저장한 분석에서는 휴지통 원본 추출을 할 수 없습니다. 이미지를 다시 열어 분석하면 추출할 수 있습니다.",
    "same_as_evidence": "원본 증거가 있는 폴더에는 분석을 저장할 수 없습니다. 다른 폴더를 고르세요.",
    "loading": "저장한 분석을 불러오는 중… (다시 분석하지 않습니다)", "load_error": "저장한 분석을 열지 못했습니다: {error}",
    "loaded": "저장한 분석 '{name}' · 저장 {saved} · 도구 {version} · 기록 {events:,}건", "title": "Log Hunter - {name} (저장한 분석)",
    "warnings_title": "저장한 분석 확인 필요", "partial": "일부만 불러왔습니다 (예전·새 형식이거나 손상된 부분이 있음)",
    "missing_fields": "저장 당시 없던 정보: {fields}", "source_problem": "원본 연결 문제: {items}",
    "save_name": "케이스 이름", "save_name_prompt": "저장할 분석의 이름:", "save_pick": "분석을 저장할 빈 폴더",
    "save_exists": "이 폴더에 이미 저장한 분석(case.sqlite)이 있습니다. 덮어쓰지 않으니 빈 폴더를 고르세요.",
    "saved": "분석을 저장했습니다: {path}", "save_error": "분석을 저장하지 못했습니다: {error}",
    "new_confirm": "지금 화면의 분석(입력·결과·태그)을 비우고 새로 시작할까요? 저장하지 않은 태그·메모는 사라집니다.",
    "unsaved_title": "저장하지 않은 태그·메모", "unsaved": "태그·메모를 바꾼 뒤 분석을 저장하지 않았습니다. 지금 저장할까요? (아니요: 저장하지 않고 계속)",
}

# 저장한 분석을 여는 엔진과 CLI 안내. 상태 키는 내보내기용 내부 값입니다.
CASE_DB_TEXT = {
    'incomplete': '저장이 완료되지 않은 빈 케이스 DB입니다. 이 파일에는 복원할 분석 기록이 없습니다. 원본을 다시 분석한 뒤 새 폴더에 저장하세요',
    'invalid': '케이스 DB 파일을 읽을 수 없습니다: {detail}',
    'legacy': '이전 형식의 케이스입니다. 저장되지 않은 정보는 빈 값으로 복원합니다',
    'future': '지원 버전보다 새로운 케이스입니다. 읽을 수 있는 정보만 복원합니다',
    'multiple': '여러 분석이 들어 있어 마지막 분석을 열었습니다. case_id로 선택할 수 있습니다',
    'damaged': '케이스 DB의 일부 정보를 복원하지 못했습니다: {detail}',
    'missing': '저장되지 않은 정보: {field}',
    'integrity_missing': '저장 당시 무결성 목록이 없어 변경 여부를 확인할 수 없습니다',
    'integrity_changed': '케이스 DB 또는 표별 개수가 저장 후 바뀌었습니다',
    'integrity_invalid': '무결성 목록을 읽을 수 없습니다',
    'source_missing': '원본을 찾을 수 없습니다. 저장된 목록은 열 수 있으나 원본 내용 보기·추출은 제한됩니다: {path}',
    'source_changed': '원본 해시가 저장된 값과 다릅니다: {path}',
    'source_unreadable': '원본 연결을 확인하지 못했습니다: {path}',
    'limit': '안전 상한으로 일부 정보를 읽지 않았습니다: {detail}',
    'output_exists': '기존 케이스를 덮어쓰지 않습니다. 새 경로를 고르세요',
}

CASE_QUERY_TEXT = {
    'invalid': 'DB 조회 입력을 확인하세요: {detail}',
    'legacy': '조회 색인이 없어 읽기 전용 호환 경로를 사용합니다. 큰 결과에서는 느릴 수 있습니다',
    'search_fallback': '검색 색인을 사용할 수 없어 정확한 부분 문자열 검색으로 읽습니다',
    'index_changed': '조회 색인을 신뢰할 수 없어 저장된 원래 행으로 조회합니다',
    'changed': '케이스 DB가 바뀌었습니다. 다시 열어 조회하세요',
    'unavailable': '케이스 DB를 더 이상 읽을 수 없습니다',
    'closed': '닫힌 DB 조회입니다. 다시 열어 주세요',
    'cursor': '다른 케이스·필터·정렬의 커서이거나 저장 파일이 바뀌었습니다',
}
