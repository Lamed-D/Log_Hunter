# WinAPI 기술 원본

이 폴더의 소스가 Python 수집 기능의 실제 DLL 구현입니다.
`native.h`는 cdecl C ABI, `collector/winapi.py`는 일치하는 ctypes 선언입니다.

VSS requester는 `.c` 파일을 C++로 컴파일합니다. Windows SDK의 공식
IVssBackupComponents 헤더를 사용하기 위한 선택입니다. 손으로 COM vtable
배치를 복제하지 않습니다. COM은 Python VSSManager의 한 전용 스레드가 소유합니다.

수집 순서: dedicated registry/event API → 공유 읽기 → 접근 실패 시 VSS.
동일 볼륨 스냅샷을 여러 요청이 공유합니다. 다른 드라이브 문자를 노출하지 않고
GLOBALROOT shadow device path를 사용합니다. 정리는 생성한 snapshot set에만 적용됩니다.

네이티브 코드는 MSVC `/W4`로 빌드합니다. 대상 플랫폼은 Windows x64입니다.
빌드 명령과 API 문서 링크는 루트 README와 docs/requirements.md에 있습니다.
