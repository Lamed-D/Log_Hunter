# Jump List 스트림·버전 검증 (#7)

- START: `b8be7cbec79bd4aaf0e20a86ab74d68abdfb52b8`
- 로컬 `issue/7-jumplist-streams`, feat 전용 게시 `feat/issue-7-jumplist-streams`.
- 기존 실패를 합성 파일로 먼저 확인했다: 16진수 ID·MiniFAT·버전 정렬 테스트에서 2개 실패·3개 오류.
- 전체 테스트: 167개 실행, 166개 통과·1개 skip.
- CLI: `python -m log_hunter analyze --input jumplist outputs/codex/jumplist7/synthetic.automaticDestinations-ms --output outputs/codex/jumplist7/cli-result`
- 결과: 이벤트 2개, 오류 0개. a(10), 10(16)의 서로 다른 대상과 시각이 올바르게 연결된다.

## 변경

MS-CFB 구조에 따라 FAT/DIFAT·MiniFAT·루트 mini stream, 512/4096바이트 섹터와 디렉터리 연결을 읽는다.
스트림 번호는 16진수로 연결하고 DestList 1/3/4의 경로 길이·레코드 끝 위치를 구분한다.
DIFAT 확장이 있어야 접근되는 높은 번호의 합성 섹터까지 검증했다. 중복 ID는 임의의 시각을 선택하지 않는다.
순환·범위·잘린 레코드는 진단 후 가능한 정상 스트림을 계속 읽으며, LNK가 손상돼도 DestList 경로를 partial로 보존한다.
원시 4바이트 카운터의 의미를 확정할 수 없어 access_count는 None으로 두고 access_count_raw에 원시 바이트를 보존한다.
이 해석 변경은 기존 잘못된 숫자를 사실로 내보내지 않기 위한 것이다. 기존 시각·경로·내보내기 구조는 유지한다.
입력 파일과 디코딩한 스트림 총량은 각각 128MiB 상한이다. 할당표·체인·중복 확장에도 범위와 개수 상한을 적용한다.
실제 Jump List·모든 Windows 변형은 검증하지 않았다. CustomDestinations의 기존 시그니처 스캔 경로는 그대로 유지한다.
GUI·트리·보고서 변경 없음. 새 파서는 아니므로 등록·추출 규칙은 변경하지 않는다.

## push 전 검토

2026-11-04: 새 파일·추가 줄·커밋 메시지에 외부 참고 도구 이름/코드/데이터·개인 경로·실제 증거 없음. 전체 테스트 통과.
