# 자동 인식 엔진 검증

- 브랜치: `feat/auto-detect`
- START: `3c0e1c5add7b8f2974b7691d1a1039ce9208298a`
- 전체 테스트: 138개 실행, 137개 통과, 1개 건너뜀.
- CLI: `python -m log_hunter analyze --auto outputs/codex/cli-input --output outputs/codex/cli-auto-validation`
- 합성 입력 결과: 이벤트 1개, 오류 0개, JSON/CSV/SQLite/HTML 생성.
- 원본 해시 보존, 중복 입력, 하이브 다중 연결, 헤더·루트 키 판별, E01 묶기, 손상 입력, SID 연결을 검사했다.
- 새 파서 등록은 없으며 tree.py와 GUI는 변경하지 않았다.
- 테스트와 엔진이 함께 검증하는 하나의 공개 API 변경이라 단일 PR로 유지한다.
- 실제 수집 폴더·실제 E01·관리자 환경은 검증하지 않았다.

## push 전 검토

2026-11-04: 새 파일 경로와 추가 줄, 새 커밋 메시지에서 외부 참고 자료·개인 경로·증거 데이터 유입 없음.
런타임 의존성 추가 없음. 출력 폴더는 추적하지 않는다. 원본 입력을 읽기 모드로만 열며 실행하지 않는다.
