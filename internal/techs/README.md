# techs 기술 기록 — 과거 네이티브 구현

순수 Python 전환 전 `main`의 `techs/`를 기록용으로 보관합니다.
현재 수집·압축 해제는 Python 표준 라이브러리 구현을 사용하며, 이 보관본을 불러오지 않습니다.

## 출처와 보존 범위

- 기준 커밋: `3ec9763735e40c9370b75318425dc698f02f671e`
- 기준 시점: 순수 Python 전환 PR #16의 main 병합 커밋 `97e48e8`의 첫 번째 부모.
- 원래 위치: `techs/`. 기록 위치: `internal/techs/`.
- C 소스 5개, 헤더 1개, CMake 파일 1개와 당시 README를 Git blob 그대로 복원했습니다.
- 당시 README는 현재 안내와 혼동하지 않도록 [README.legacy.md](README.legacy.md)라는 이름으로 보관합니다.
  그 파일의 DLL·스냅샷·빌드 설명은 당시 구현에 대한 기록이며 현재 설치 지침이 아닙니다.
- [provenance.json](provenance.json)에 원래 경로, Git blob ID, SHA-256과 바이트 수를 기록했습니다.

실제 증거·수집 결과·개인 정보·빌드된 DLL은 포함하지 않습니다. 저장소에 있던 자체 구현의 소스 기록입니다.

## 파일별 기술 설명

| 파일 | 당시 역할 | 현재 구현과의 관계 |
| --- | --- | --- |
| [native.h](native.h) | Windows 타입을 쓰는 C ABI와 `cdecl` 내보내기 선언. C++에서 컴파일할 때도 C 심볼로 노출 | 현재 Python 수집 API의 전신을 살펴보는 자료 |
| [shared_read.c](shared_read.c) | `CreateFileW` 공유 읽기, 반복 `ReadFile`/`WriteFile`, 새 목적지만 생성, 실패 시 자신이 만든 불완전 사본 정리 | [windows.py](../../log_hunter/collector/windows.py)의 `copy_shared` 경로 |
| [registry_save.c](registry_save.c) | 백업 권한을 활성화해 `RegSaveKeyExW`로 저장하고 이전 권한 상태 복구 | 같은 Python 모듈의 `save_registry` 경로 |
| [eventlog_export.c](eventlog_export.c) | `EvtExportLog`로 채널을 파일에 내보내고 Windows 오류 코드 반환 | 같은 Python 모듈의 `export_eventlog` 경로 |
| [prefetch_decompress.c](prefetch_decompress.c) | 시스템 압축 해제 함수 주소를 구하고 작업 버퍼를 준비해 XPRESS Huffman 해제 | 현재는 [xpress.py](../../log_hunter/parser/xpress.py)의 순수 Python 구현 |
| [vss_requester.c](vss_requester.c) | COM/VSS 백업 객체·비동기 작업·스냅샷 컨텍스트를 생성·정리 | 현재 실행 경로에서는 스냅샷을 생성하지 않음 |
| [CMakeLists.txt](CMakeLists.txt) | Windows SDK/MSVC, C/C++ 및 라이브러리 연결을 정의한 당시 DLL 빌드 명세 | 현재 설치·빌드와 연결하지 않은 보존용 파일 |

`vss_requester.c`는 확장자가 `.c`이지만 CMake에서 C++로 컴파일하도록 지정돼 있습니다.
공개 함수의 ABI는 C이며, 내부에서는 Windows SDK의 C++ COM 인터페이스를 사용합니다.
이는 당시 `native.h`의 `extern "C"` 분기와 함께 읽으면 됩니다.

## 현재 실행·빌드와의 경계

현재 패키지 검색은 `log_hunter*`에 한정되고, `tools/build_pyz.py`는 `log_hunter/`만 복사합니다.
이 기록을 위해 `pyproject.toml`, 런타임 의존성, CLI, Python 수집기 또는 빌드 진입점을 변경하지 않았습니다.
이 폴더의 CMake 파일은 당시 구조를 설명하기 위해 보존하며 이번 복구 작업에서 컴파일하거나 실행하지 않았습니다.

현재 사용법은 [루트 README](../../README.md)를 따릅니다.

## 보존 상태 확인

`provenance.json`의 각 `git_blob`에 대해 `git cat-file blob <git_blob>` 결과와 보관 파일을 바이트 단위로 비교할 수 있습니다.
SHA-256도 같은 파일에 기록돼 있습니다. 이 설명과 manifest를 제외한 보관 원본 8개는 수정하지 않았습니다.

이 자료는 과거 설계의 기록입니다. 현재 기능이나 유지 보수 상태를 보장하는 구현으로 해석하지 않습니다.
