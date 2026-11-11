# 요구사항과 구현 대응

기준 문서는 팀의 개발 요구사항 문서(Word)와 요구사항 명세(Excel)입니다.
원문에는 팀원 개인정보(담당자 이름)가 있어 저장소에 두지 않고, 이 문서에 기능별 대응만 정리합니다.
원문 안의 담당자 배정과 프로토타입 제안은 개발 참고자료로 취급했으며 별도의 작업 지시로 실행하지 않았습니다.

## 우선순위와 충돌

수집은 Python 표준 라이브러리 ctypes로 Windows API를 직접 호출하고 오프라인 분석은 순수 Python으로 실행합니다.
Word의 diskshadow 프로토타입은 사용하지 않습니다. Word에는 python-evtx가
있으나 Excel EVTX 시트 21행의 직접 구현 제약을 적용해 외부 EVTX 라이브러리를
사용하지 않습니다. Word에서 생략된 Amcache는 Excel의 실행 흔적 분석 시트를
근거로 추가했습니다. Excel 시트 5의 세 아티팩트 범위는 실행 흔적 분석 모듈에
적용하고 프로젝트 전체에는 Word의 다른 아티팩트도 포함합니다.

## 구현 상태

아래의 구현은 실제 코드가 있다는 뜻입니다. 합성 fixture 테스트를 실 증거 검증과
동일하게 취급하지 않습니다. 부분 항목에는 미완료 범위를 명시합니다.

| 요구사항 | 코드 | 상태와 남은 범위 |
| --- | --- | --- |
| Word 1 공통 구조 | core/models.py, pipeline.py | 구현: Collector/Parser Protocol, Evidence/Event/Error, 배치 처리, 21개 파서 등록 |
| Word 2 수집 | collector/ | 공유 읽기/API 저장/직접 NTFS 볼륨 읽기/SHA-256/원본 경로; 시스템 시간대/프로필 metadata 통합 미완료 |
| Word 3 UserAssist, Excel 실행 FR-12~17 | parser/userassist.py | **v0.7.0 업그레이드**: ROT13, 72/16바이트, 횟수/focus/FILETIME, **20개 GUID 폴더 경로 해석** |
| Word 4 USB | parser/usb.py | **v0.4.0 업그레이드**: VID/PID, serial, USBSTOR vendor/product 파싱, MountedDevices 드라이브 매칭, FriendlyName, DeviceDesc 추출; live 연결 감지 미완료 |
| Word 5 MRU | parser/mru.py | 부분: MRUListEx/rank/RecentDocs 이름, PIDL 원문; 전체 PIDL 경로 미완료 |
| Word 6 BAM, BAM-FR-01~19 | parser/bam.py | **v0.6.0 업그레이드**: 두 BAM 경로, ControlSet/SID/원문/유형/활동 갱신/LastWrite, SOFTWARE ProfileList SID→사용자명 매핑, NT 경로→DOS 경로 변환 |
| Word 7 Run, RUN-FR-01~20 | parser/run.py | 부분: Run/RunOnce/native/Wow6432Node/scope/flags/환경변수/명령 분리; 조사 규칙/실행 조건 안내 상세 UI 미완료 |
| Word 8 PSReadLine | parser/psreadline.py | **v0.2.0 업그레이드**: 14개 분류 카테고리, 위험도 평가(high/medium/low), POWERSHELL_EVASION/CREDENTIAL/ENCODING 등 보안 분류; 자동 live 경로 탐색 미완료 |
| Word 9 VSS | collector/windows.py | 스냅샷 대신 직접 NTFS 볼륨 읽기. 실행 중 원본의 시점 일관성은 보장하지 않음; 관리자 실제 테스트 미실행 |
| Word 10 History | parser/history.py, collector/browser_collector.py | 프로필 탐색/단일 볼륨 세션 DB+WAL+SHM 수집, 시점 일관성 보장 없음, urls/visits/downloads/chains; 프로필 자동 수집 UI 미완료 |
| Word 11 Cache | parser/cache.py | **v0.3.0 업그레이드**: Chromium Blockfile 캐시 형식 디코더 (index/block file, HTTP 헤더 추출, Content-Type/ETag/Last-Modified/Cache-Control 등), URL 매칭 |
| Word 12 Prefetch, Excel 실행 FR-01/06~11 | parser/prefetch.py, parser/xpress.py | 17/23/26/30 이름/hash/count/times/references, 순수 Python XPRESS Huffman MAM 해제, 볼륨 정보, 파일명 해시 검증; CRC MAM 미지원 |
| Word 13 EVTX, Excel EVTX FR-01~13 | parser/evtx.py, parser/binxml.py | **v0.7.0 업그레이드**: BinXML 토큰 스트림 디코더, EventID/EventData/Provider/Channel/SID/Level 추출, 보안 이벤트 분류, 청크 CRC32 체크섬 검증, **Sysmon 22개 이벤트 분류** (PROCESS/NETWORK/PERSISTENCE/LATERAL_MOVEMENT/FILE_REGISTRY/TIMESTOMP), **PowerShell 8개 이벤트** (ScriptBlock/Module 로깅, 의심 패턴 탐지) |
| Word 14 MFT | parser/mft.py | **v0.4.0 업그레이드**: non-resident data run 디코딩, attribute type 이름, data 크기 추적, 전체 속성 메타데이터; DATA 내용 추출/live raw volume 미완료 |
| Excel 실행 FR-18~22 Amcache | parser/amcache.py | **v0.2.0 업그레이드**: InventoryApplicationFile/Root File/Programs 파싱, 15+ 필드 매핑, SHA-1 추출 |
| Word 15 timeline, Excel 실행 FR-30~37 | core/timeline.py, ui/app.py | **v0.3.0 업그레이드**: 날짜 범위 필터, SID 필터, 상태 필터, 정렬 가능한 컬럼, GUI 기간 필터 |
| Word 16 correlation, Excel 실행 FR-23~29 | core/correlation.py | **v0.7.0 업그레이드**: URL 도메인+경로 매칭, 프로그램 그룹 집계, USB 드라이브 매칭, 시간 근접 매칭, **실행 체인 분석** (prefetch+BAM+EVTX 교차 검증), 연관 요약 통계 |
| Word 17 SQLite | database/repository.py | **v0.3.0 업그레이드**: 엔티티 중복 통합(정규화 키, 이벤트 연결), 엔티티 요약 통계, entity_events 연결 테이블 |
| Word 18 Report, Excel 실행 FR-38~41 | core/report.py | **v0.2.0 업그레이드**: 인터랙티브 다크 테마 HTML 보고서, 통계 대시보드, 차트, 검색/필터, 페이지네이션, 연관 분석 요약 |
| Word 19 UI, Excel 실행 NFR-07 | ui/app.py | **v0.3.0 업그레이드**: 날짜 범위/SID/상태 필터, 정렬 가능 컬럼, 탭별 구조(타임라인/진단/연관/증거), 통계 바, 파일 제거; live 수집 화면/시각화 미완료 |
| 레지스트리 무결성 | parser/registry.py, core/pipeline.py | **v0.3.0+v0.4.0 업그레이드**: LOG1/LOG2 트랜잭션 로그 재적용, big-data (db cell) 값 지원, 더티 하이브 자동 복구 |
| ShellBag | parser/shellbag.py | **v0.2.0 신규**: BagMRU 트리 구조 파싱, 5개 루트 경로, 폴더 접근 이력 복구 |
| SRUM | parser/srum.py | **v0.4.0 신규**: SQLite 내보내기 파싱 (네트워크/앱/에너지/알림), ID 매핑, ESE 감지 |
| LNK 파일 | parser/lnk.py | **v0.5.0 신규**: Windows Shell Link 파싱, 타임스탬프/대상 경로/볼륨/네트워크 추출 |
| Jump List | parser/jumplist.py | **v0.5.0 신규**: AutomaticDestinations/CustomDestinations 파싱, 앱 ID 매핑 |
| 네트워크 프로필 | parser/network.py | **v0.6.0 신규**: SOFTWARE NetworkList 프로필/시그니처/인터페이스 파싱, DHCP/DNS/게이트웨이 MAC 추출, 연결 이력 |
| 예약 작업 | parser/tasks.py | **v0.6.0 신규**: Task Scheduler XML 파싱, 트리거/액션/설정 추출, 의심 패턴 탐지 (인코딩 명령/temp 경로/숨김 작업), 위험도 평가 |
| 타임라인 내보내기 | core/export.py | **v0.7.0 신규**: CSV/JSON/JSONL 내보내기, ForensicEvent 직렬화, None 안전 처리 |
| 포렌식 통계 | core/stats.py | **v0.7.0 신규**: 아티팩트/동작/SID/시간대별 통계, 위험도 요약, 이상 탐지 (새벽 활동/버스트/시간 공백) |
| 아티팩트 자동 감지 | core/auto_detect.py | **v0.7.0 신규**: 디렉토리 스캔으로 아티팩트 유형 자동 식별 |
| SID 해석 | core/sid_resolver.py | **v0.7.0 신규**: SOFTWARE ProfileList 기반 SID→사용자명 매핑 |
| BAM 프로필 매핑 | parser/bam.py | **v0.7.0 업그레이드**: ProfileList SID→사용자명 매핑, NT 디바이스 경로→DOS 경로 변환 |
| GUI 시각화 | ui/app.py | **v0.7.0 업그레이드**: 통계/시각화 탭 (파이 차트, 막대 차트, 시간대별 분포), CSV/JSON 내보내기 버튼, 이상 탐지 결과 표시, 아티팩트 자동 감지 |
| 휴지통 | parser/recyclebin.py | **v0.8.0 신규**: $I 파일 파싱 (v1/v2), 삭제 시각/원본 경로/파일 크기, SID 디렉토리 추출, $R 존재 확인 |
| HTML 보고서 | core/report.py | **v0.8.0 업그레이드**: 통계/이상탐지 탭, 시간대별 분포 차트, 이상 패턴 표시, 키보드 페이지네이션 |
| WLAN 프로필 | parser/wlan.py | **v0.9.0 신규**: Wi-Fi 프로필 XML 파싱, SSID/인증/암호화 추출, 평문 비밀번호 감지 (보안 경고), 인터페이스 GUID 추출 |
| 삭제 연관 분석 | core/correlation.py | **v0.9.0 업그레이드**: 휴지통 삭제 이벤트와 다른 아티팩트(prefetch/bam/mft) 파일명 매칭, 시간 근접성 분석, SID 교차 검증 |
| GUI 히트맵 | ui/app.py | **v0.9.0 업그레이드**: 요일×시간 히트맵 시각화, 새벽 시간대 강조, 활동 패턴 분석 |
| HTML 보고서 히트맵 | core/report.py | **v0.9.0 업그레이드**: 요일×시간 히트맵 Canvas 차트, 새벽 시간대 적색 강조, 삭제 연관 관계 표시 |
| Bodyfile 내보내기 | core/export.py | **v0.10.0 신규**: mactime 호환 Bodyfile 형식, time_field→atime/mtime/ctime/crtime 매핑, SID→UID 매핑 |
| 프로세스 트리 | core/process_tree.py | **v0.10.0 신규**: Sysmon Event ID 1 기반 프로세스 트리 재구성, 부모-자식 관계, LOLBin 탐지, 깊이 분석 (5단계+), 임시 경로 실행 탐지 |
| 시작 프로그램 | parser/startup.py | **v0.10.0 신규**: Startup 폴더 지속성 탐지, 스크립트/실행파일 분류, 의심 패턴 분석 (인코딩 명령/hidden), LNK 타겟 추출 |
| BAM 파이프라인 통합 | core/pipeline.py | **v0.10.0 업그레이드**: SOFTWARE 하이브 자동 감지, ProfileList SID→사용자명 매핑 자동 로딩, BAMParser에 프로필 전달 |
| 이벤트 중복 탐지 | core/stats.py | **v0.10.0 업그레이드**: find_duplicates() 함수, 아티팩트+타임스탬프+대상 기준 중복 감지 |
| 프로세스 트리 보고서 | core/report.py | **v1.0.0 업그레이드**: 프로세스 트리 탭 (트리 시각화, 의심 프로세스 탐지, 삭제 연관 요약), 연관 분석 탭 삭제 매칭 표시 |
| 삭제 연관 표시 | core/report.py | **v1.0.0 업그레이드**: 연관 분석 탭에 삭제 매칭 건수 및 삭제 파일 목록 표시 |

## 테스트 현황

- 전체 테스트: 순수 Python 분석·XPRESS 및 Windows ctypes 공유 읽기 검증; 최신 수치는 PR 검증 결과 참조.
- BinXML 디코딩, 엔티티 중복 통합, CRC32 검증, data run 디코딩, URL 정규화, 프로그램 그룹, SRUM, Sysmon 분류, PowerShell 분류, GUID 경로 해석, 실행 체인 분석, 네트워크 프로필, 예약 작업, CSV/JSON/JSONL/Bodyfile 내보내기, 포렌식 통계, 이상 탐지, BAM NT경로 변환, 휴지통 $I v1/v2 파싱, WLAN 프로필 파싱/보안 경고, 삭제 연관 분석/SID 충돌/요약, 프로세스 트리 구축/LOLBin 탐지, 시작 프로그램 파싱/의심 패턴, BAM 파이프라인 프로필 통합, 이벤트 중복 탐지, 보안 세부 추출 등 개별 유닛 테스트 포함

## WinAPI 설계 근거

* [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges): 백업 권한을 활성화한 뒤 이전 상태로 복원합니다.
* [EvtExportLog](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtexportlog): 새 대상 파일로 export합니다.
* [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew): 공유 읽기/쓰기/삭제 요청은 다른 프로세스의 잠금을 강제로 무시하지 않습니다.

## 검증 한계

실제 관리자 NTFS raw-volume 수집과 다양한 실제 아티팩트 버전은 별도 실환경 검증이 필요합니다.
미지원 형식/필드는 추측하지 않고 오류 또는 partial로 기록합니다.
