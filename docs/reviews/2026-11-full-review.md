# 전체 코드 리뷰 (2026-11)

`log_hunter/` 전체와 `tests/`, `techs/*.c`를 [코드 리뷰 규칙](../dev/code-review.md)의 순서
(증거 무결성 → 해석 → 보안 → 표시 문구 → 테스트 → 품질)로 리뷰한 결과입니다.

- 기준: `feat/navigation-tree`(= `main` + 탐색 트리). 기준선 테스트 121개 통과(1개 skip).
- 방법: 코드 읽기 + 합성 입력으로 재현. "확인"은 재현 스크립트나 실패 테스트로 직접 본 것, "코드로 확인"은 코드 경로만 따라간 것입니다.
- 담당 구분: 파서(`parser/*`), 이미지 엔진(`image/*`), 자동 인식, 대용량 성능은 Codex 담당입니다. 그쪽 지적은
  이 브랜치에서 고치지 않고 **Codex 이관**으로 표시했습니다. 재현 테스트가 붙은 수정 커밋은 로컬 브랜치
  `feat/parser-image-fixes`에 있습니다(push 안 함, 같은 저장소 worktree에서 볼 수 있음).

상태: **수정됨**(이 브랜치 커밋) / **Codex 이관**(수정 커밋은 `feat/parser-image-fixes`) / **이관**(수정 커밋 없음) / **미해결**.

## 1. 증거 무결성

| # | 등급 | 위치 | 문제와 재현 | 수정 방안 | 상태 |
| --- | --- | --- | --- | --- | --- |
| 1 | [차단] | `image/extract.py` `_safe` | 이미지 안 파일 이름의 `\`·`/`를 그대로 경로로 씀. 이름이 `..\..\..\..\..\ESCAPED.pf`인 Prefetch가 추출 폴더 **밖**에 써짐(확인) | 구분자 치환 + 결과 경로가 출력 폴더 안인지 확인 | Codex 이관 (`6eb745b`) |
| 2 | [차단] | `image/ntfs.py` `copy_file` | 실제 크기 필드를 할당된 클러스터와 대조하지 않음. 4KB 파일의 크기를 1TiB로 바꾼 이미지에서 디스크가 찰 때까지 0을 씀(50MB로 확인) | 크기를 run 목록 범위로 제한하고 경고 | Codex 이관 (`c350b04`) |
| 3 | [차단] | `image/extract.py` `_copy` | 대소문자만 다른 두 파일(`A.pf`, `a.pf`): 두 번째가 `FileExistsError` → 오류 처리에서 **먼저 꺼낸 사본을 삭제**. manifest에는 남아 있음(확인) | 빈 이름을 골라 둘 다 보존 | Codex 이관 (`d292b48`) |
| 4 | [차단] | `main.py` `save_result` | 증거와 겹치는지 검사하는 출력 파일이 7개 중 4개뿐. 출력 폴더 안의 증거 `timeline.json`이 덮어써짐. 같은 폴더에 두 번 저장하면 `case.sqlite`에 사건 2개가 섞임(확인) | 출력 7개 모두 검사, 이전 결과가 있는 폴더 거부 | 수정됨 |
| 5 | [차단] | `parser/srum.py:103` | `mode=ro`로 WAL SQLite를 열면 증거 폴더에 `-wal`/`-shm`이 생김. 폴더 이름에 `#`이 있으면 다른 경로를 엶(확인) | `as_uri()` + `immutable=1` | Codex 이관 (`334f475`) |
| 6 | [제안] | `core/pipeline.py` | LOG로 복구한 하이브 사본(증거 내용 전체)을 TEMP에 남기고 지우지 않음(확인) | 파싱 후 삭제 | 수정됨 |
| 7 | [제안] | `pipeline.analyze_image` | 이미지(E01) 자체는 분석 전후 해시를 비교하지 않고, E01에 저장된 MD5도 검증하지 않음 | 선택 옵션으로 전체 해시·저장 MD5 검증 | 미해결 |
| 8 | [사소] | `collector/live_collector.py:23`, `main.py:96` | manifest를 `exists()` 확인 뒤 `write_text`로 씀(경쟁 상태) | `"x"` 모드 | 미해결 |

## 2. 해석의 정확성

| # | 등급 | 위치 | 문제와 재현 | 수정 방안 | 상태 |
| --- | --- | --- | --- | --- | --- |
| 9 | [차단] | `core/correlation.py` 실행 연쇄 | 파일 이름만 같으면(폴더·사용자·시각 무관, 공급자 확인 없는 이벤트 ID 1 포함) "실행 확실"로 표시. 2020/2023/2024년 서로 다른 폴더의 `evil.exe`가 "실행 확실"(확인) | Prefetch + BAM/UserAssist/Amcache + 4688/Sysmon 1이 5분 안, SID 충돌 없음일 때만 "여러 실행 기록이 같은 시간대에 일치". 나머지는 "이름만 일치" | 수정됨 |
| 10 | [차단] | `core/correlation.py:66` | 이름만 같은 경로 관계가 "같은 파일"로 보임(신뢰도가 `filename_only`가 아님) | 신뢰도 `filename_only`, 관계 라벨 "같은 파일 경로·이름" | 수정됨 |
| 11 | [제안] | `core/correlation.py:22` | `lstrip("www.")`가 접두어가 아니라 문자를 지움: `web.com`→`eb.com`, 서로 다른 사이트가 "주소 일치"(확인) | `removeprefix` | 수정됨 |
| 12 | [차단] | `parser/registry.py` `replay_logs` | LOG1/LOG2를 실제 Windows 형식과 다르게 읽음(4096부터 offset/size/data). 실제 LOG에서는 엉뚱한 데이터를 적용하고도 "복구 성공"이라고 할 수 있음. 조작한 offset 하나로 복구본이 약 268MB(확인) | Windows 8.1+ HvLE 항목, Marvin32 해시 두 개 검증, 연속 시퀀스, 하이브 크기 + 64MB 제한. 이전 형식(DIRT)은 "지원 안 함" 경고 | Codex 이관 (`e25c1e7`) |
| 13 | [차단] | `parser/jumplist.py:223` | AutomaticDestinations 스트림 이름(16진수)을 10진수로 짝지음. 항목 10의 시각과 경로가 스트림 `"10"`(= 항목 16)에 붙음 | `int(name, 16)` | 이관 |
| 14 | [차단] | `parser/jumplist.py:185` | 4KB 미만 스트림(mini stream)을 지원하지 않음. 대부분의 실제 LNK 스트림이 오류 없이 사라짐 | MiniFAT 구현 | 이관 |
| 15 | [차단] | `parser/jumplist.py:91` | DestList version 3/4(Win10+) 레이아웃을 무시하고 Win7 오프셋을 씀 | 버전별 오프셋 | 이관 |
| 16 | [차단] | `parser/binxml.py` | fragment header(0x0F), 템플릿, 청크 기준 이름 오프셋을 스펙대로 처리하지 않음. 스펙대로 만든 4624 레코드에서 `event_id=None` | 청크 버퍼와 템플릿 캐시를 스펙대로 구현 | 이관 (Codex EVTX 작업) |
| 17 | [차단] | `parser/evtx.py:173` | 청크 CRC를 `chunk[512:]` 전체로 계산(스펙: free space 오프셋까지). 정상 파일의 모든 청크에 "CRC 불일치" | 범위 수정 | 이관 |
| 18 | [차단] | `parser/wlan.py` | `keyMaterial`만 있으면 "평문 비밀번호". Windows는 DPAPI로 암호화하고 `<protected>true</protected>`로 저장 | `protected == false`일 때만 | Codex 이관 (`55f4a53`) |
| 19 | [차단] | `parser/services.py:38` | `%SystemRoot%\System32\svchost.exe`, 따옴표 친 Program Files 경로, `\??\C:\...`가 모두 "시스템 폴더 밖 자동 시작" | 따옴표·환경 변수·NT 경로 정규화 | Codex 이관 (`55f4a53`) |
| 20 | [차단] | `parser/network.py:18` | NetworkList 시각은 로컬 SYSTEMTIME인데 `+00:00`(UTC)을 붙임 | local로 표시하거나 시간대 정보로 변환 | 이관 |
| 21 | [차단] | `parser/tasks.py:212` | UTF-16 작업 파일(실제 형식)을 오류 없이 건너뜀. `RegistrationInfo/Date`(로컬·조작 가능)를 그대로 시각으로 씀 | 디코딩 후 검사, Date는 세부 정보로 | 이관 |
| 22 | [차단] | `parser/startup.py:63,77` | 이미지 분석에서 `st_mtime`이 **추출한 시점**. `parse_lnk` 인자 오류(TypeError)를 `except: pass`로 삼켜 LNK 대상이 한 번도 나오지 않음 | 원래 $SI 시각 사용 또는 None, 호출 수정 | 이관 |
| 23 | [차단] | `parser/shellbag.py:391` | 모든 항목에 `deleted_folder_evidence: True`. 키 LastWrite를 형제 값 모두에 붙임 | 플래그 제거, MRU 0번에만 시각 | 이관 |
| 24 | [차단] | `parser/userassist.py:266` | 폴더 GUID 매핑 오류(Programs→%APPDATA%, SystemX86→System32, CommonPrograms→CommonProgramFiles) | 매핑 수정 | 이관 |
| 25 | [차단] | `parser/mru.py:387` | LastVisited 값을 홀수 위치 `\0\0`에서 잘라 문자가 깨지고, PIDL 바이너리를 경로 문자열로 저장 | 2바이트 정렬, PIDL은 hex만 | 이관 |
| 26 | [차단] | `core/export.py` Bodyfile | 매핑에 없는 `time_field`(`si_created`, `key_lastwrite`, `last_execution` 등)는 한 시각을 M·A·C·B 네 칸 모두에 씀. `|`·줄바꿈이 든 경로가 가짜 줄을 만듦 | 필드별 한 칸만, 이스케이프 | 수정됨 |
| 27 | [제안] | `parser/mru.py`, `parser/shellbag.py` | 키 LastWrite를 모든 순위 값의 시각으로 씀(관련 있는 것은 0번) | 0번에만 시각 | 이관 |
| 28 | [제안] | `parser/recyclebin.py:357` | 이미지 분석은 `$I`만 꺼내므로 `r_file_exists`가 항상 False | 이미지 모드에서는 None | 이관 |
| 29 | [제안] | `core/enrichment.py:63`, `stats.py`, 보고서 히트맵 | "새벽(00~05시)"이 UTC 기준(한국 09~14시). 보고서 히트맵은 브라우저 로컬 시각이라 표와 다름 | UTC 명시 또는 사건 시간대 적용 | 미해결 |
| 30 | [제안] | `labels.py` "USB 연결 직후" | 실제 조건은 ±300초(연결 전 포함) | 중립 문구 | 미해결 |
| 31 | [제안] | `core/enrichment.py:73` | 위험 키워드를 `action`(고정 값)에만 대조해서 절대 맞지 않음 | 명령행·세부 정보에 대조 | 미해결 |

## 3. 손상 입력·멈춤

| # | 등급 | 위치 | 문제와 재현 | 상태 |
| --- | --- | --- | --- | --- |
| 32 | [차단] | `parser/registry.py` `walk`, `shellbag._walk_bagmru` | 하위 키 목록이 같은 자식을 두 번 가리키는 9KB 하이브에서 2^40단계 → Amcache·MRU·USB·ShellBag이 멈춤. 파이프라인에 시간 제한이 없어 전체 분석이 멈춤(확인) | Codex 이관 (`32da309`) |
| 33 | [차단] | `image/extract.py` `glob_ntfs` | 폴더가 조상을 가리키는 `$I30` 3개로 같은 파일이 수백만 번 추출(13초에 717만 건, 확인) | Codex 이관 (`52070a1`) |
| 34 | [차단] | `database/repository.py:99` | 실행 연쇄 관계에는 left/right가 없어 `KeyError: 'left'` → 같은 프로그램이 두 기록에 나오면 **보고서가 하나도 저장되지 않음**(CLI·GUI, 확인) | 수정됨 |
| 35 | [제안] | `core/process_tree.py:75` | 1,200단계 부모-자식 체인에서 RecursionError → 보고서 생성 실패(확인). PID만 키로 써서 PID 재사용 시 잘못 연결 | 미해결 |
| 36 | [제안] | `parser/registry.py:376` `Hive.open` | 경로 위 형제 키 하나가 손상되면 정상 키 조회도 전체 실패 | 이관 |
| 37 | [제안] | `parser/mft.py:359` | 짝 없는 서로게이트가 든 파일 이름이면 레코드 전체(시각 8개)가 사라짐 | 이관 |
| 38 | [제안] | `image/ntfs.py` `_read_extents` | 이미지 끝을 넘는 run에서 짧게 읽힌 만큼 뒤 데이터가 당겨짐 | Codex 이관 (`c350b04`에 포함) |
| 39 | [제안] | `image/ewf.py:169` | header 섹션 크기가 손상되면 세그먼트 끝까지 메모리로 읽음 | 이관 |

## 4. 보안

| # | 등급 | 위치 | 문제와 재현 | 상태 |
| --- | --- | --- | --- | --- |
| 40 | [차단] | `main.py:26`, `core/export.py` | 보호된 `timeline.csv`를 보호 없는 `export_csv`가 다시 덮어씀. GUI CSV 내보내기도 보호 없음. `=HYPERLINK(...)`, `=cmd|...`가 그대로 남음(확인) | 수정됨 (`csv_safe`, 공백·탭·줄바꿈 뒤 수식도 처리) |
| 41 | [차단] | `core/export.py` Bodyfile | `|`·줄바꿈 미처리로 가짜 줄 삽입 가능 | 수정됨 (퍼센트 인코딩) |
| 42 | [사소] | `core/report.py:125` | 스크립트 안 JSON에 U+2028 그대로(현재 브라우저에서는 무해) | 미해결 |

HTML 보고서 이스케이프(`</script>`, `<!--`, `<img onerror>`), SQL(바인딩 사용), `techs/*.c`(읽기 전용 공유 모드, `CREATE_NEW`, 권한 복원, VSS 정리)는 문제를 찾지 못했습니다.

## 5. GUI·표시 문구

| # | 등급 | 위치 | 문제 | 상태 |
| --- | --- | --- | --- | --- |
| 43 | [제안] | `ui/app.py` 날짜 필터 | 종료일 `2024-01-01`이 `2024-01-01T00:00:00`이 되어 그날 기록이 모두 빠짐 | 수정됨 |
| 44 | [제안] | `ui/app.py` SID 칸 | SID를 입력해도 표가 갱신되지 않음(trace 없음). 같은 칸이 "분석 시 소유자 SID"로도 쓰임 | 갱신은 수정됨, 두 가지 용도는 미해결 |
| 45 | [제안] | `ui/app.py` 내보내기 | 필터 결과가 0건이면 **전체** 기록을 내보냄 | 수정됨 |
| 46 | [제안] | `ui/app.py` 작업 스레드 | 스레드 안에서 `include_mft.get()`(Tk 변수) 호출 | 수정됨 |
| 47 | [제안] | `ui/app.py` 결과 표 | 표시 개수 제한 없음 — $MFT 수백만 건이면 Treeview가 멈춤 | 미해결 (백로그 C-7) |
| 48 | [사소] | `ui/app.py` `ARTIFACT_COLORS` | `startup`·`services`·`mountpoints2` 빠짐, 없는 `registry` 있음 | 수정됨 (`feat/ui-refactor`) |
| 49 | [사소] | `labels.py` | `date_last_connected`·`date_created` 시각 라벨, 10개 아티팩트 설명, `SHARED_READ` 등 수집 방식 라벨 없음 | 설명 10개는 수정됨(`feat/viewer-upgrade`), 시각·수집 방식 라벨은 미해결 |

## 6. 성능 (Codex 담당: 대용량 성능)

| # | 위치 | 측정 | 상태 |
| --- | --- | --- | --- |
| 50 | `core/correlation.py` | 같은 이름 4,000건 → 관계 400만 개, 9.3초. 이름·URL 그룹마다 O(n²), USB×파일 곱 | 이관 |
| 51 | `core/stats.py:134` 폭주 탐지 | 2만 건 136초, 기록마다 이상 1건 | 이관 |
| 52 | `database/repository.py:178` | 같은 SID 2만 건 14초(엔티티 목록 매번 다시 직렬화) | 이관 |
| 53 | `core/report.py` | 전체 JSON을 메모리에 여러 벌, HTML에 모든 기록 포함 | 미해결 (백로그 D) |

## 7. 기능 검증표

| 기능 | 방법 | 결과 | 근거 |
| --- | --- | --- | --- |
| E01 다중 세그먼트, raw, MBR/GPT, BitLocker 경고 | 합성 이미지 테스트 | 통과 | `tests/test_image.py` |
| `analyze --image` (CLI) | 합성 raw | 통과 | `test_cli_image_option` |
| `analyze --live` 관리자 아님 → 안내 | 테스트(관리자 확인 mock) | 통과 | `test_requires_admin` |
| 손상 이미지(경로 탈출·순환·이름 충돌·크기 조작) | 실패 테스트 → 수정 | Codex 이관 브랜치에서 통과 | `feat/parser-image-fixes`의 `tests/test_image_robustness.py` |
| 결과 저장(sqlite/html/json/csv/bodyfile) | 실행 연쇄가 있는 결과 저장 | 수정 후 통과 | `tests/test_outputs.py` |
| GUI 실행 | 창을 띄웠다 1.5초 뒤 닫는 스크립트 | 오류 없음 | `outputs/gui-check/tree_dump.py` |
| 왼쪽 트리 라벨 | 합성 E01 분석 결과로 트리 덤프 | 한국어 라벨, 기록 수 표시 | `outputs/gui-check/tree_dump.txt` |
| `--input`으로 모든 아티팩트 | — | **검증 안 됨**(파서는 기존 단위 테스트만) | — |
| 분할 `.001`, 고정 VHD, `--with-mft` | — | **검증 안 됨** | — |
| GUI SID·종료일 필터 | 실제 창에 결과를 넣고 입력칸에 입력하는 스크립트 | 수정 전 3행/0행 → 수정 후 1행/2행 | `outputs/gui-check/filter_check.py` |
| GUI 탭 5개·보고서 저장·내보내기 버튼 | — | **검증 안 됨**(코드 리뷰만) | — |
| 실제 E01, 관리자 권한 이 PC 분석 | — | **검증 안 됨** | — |

## 8. 요약

### 브랜치

| 브랜치 | base | 내용 | push |
| --- | --- | --- | --- |
| `feat/navigation-tree` | `main` | 탐색 트리, LOG 복구 경로 수정, 외부 도구 이름 정리·재유입 방지 | 됨 |
| `feat/review-fixes` | `feat/navigation-tree` | 이 문서 + 수정 10건(#4, #6, #9~11, #26, #34, #40, #41, #43~46) | 됨 |
| `feat/parser-image-fixes` (로컬) | `feat/navigation-tree` 계열 | Codex 담당 파일 수정 8건 + 테스트 | 안 함 (Codex 참고용) |

병합 순서: `navigation-tree → review-fixes → ui-refactor → viewer-upgrade → tree-polish`.

### 다음 작업

1. #35 프로세스 트리 재귀, #29~31 표시 문구(내 담당).
2. `feat/ui-refactor`: `ui/app.py` 분리, `ARTIFACT_COLORS`·레지스트리 목록 중복 정리(#48).
3. Codex에 넘길 이슈: #12~25, #27~28, #32~33, #36~39, #50~52.
