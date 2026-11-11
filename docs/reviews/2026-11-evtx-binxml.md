# EVTX BinXML·청크 검증 (#8)

- START: `b8be7cbec79bd4aaf0e20a86ab74d68abdfb52b8`
- 로컬 `issue/8-evtx-binxml-chunks`, feat 전용 게시 `feat/issue-8-evtx-binxml`.
- 정상 이름/템플릿 참조와 CRC를 갖춘 합성 EVTX의 기존 실패를 먼저 확인했다(테스트 3개 오류).
- 전체 테스트: 169개 실행, 168개 통과·1개 skip.
- 실제 CLI: `python -m log_hunter analyze --input evtx outputs/codex/evtx8/synthetic.evtx --output outputs/codex/evtx8/cli-final`
- 결과: 이벤트 2개, 오류 0개. EventID 4624/4625, Provider, TimeCreated, EventData 사용자, SID, 검증된 CRC 확인.

## 구조와 경계

레코드를 잘라 청크 주소를 잃던 경로를 바꿔 전체 청크와 레코드 경계를 함께 전달한다.
fragment·이름 오프셋·요소/속성 길이·UTF-16 코드 단위·템플릿 정의/재사용·3바이트 치환 필드·선택적 NULL을 해석한다.
숫자/문자열 배열·FILETIME/SYSTEMTIME·SID·GUID·바이너리 값은 기존 값 디코더를 사용하며 중첩 BinXML을 요소로 연결한다.
의존성 필드가 있는/생략된 fragment를 모두 검증한다. 중첩/확장 트리/치환 개수 상한과 순환 템플릿 검사를 적용한다.
청크 데이터 CRC는 오프셋 52의 값을 512..free 범위로 검증한다. 보관 로그의 사용 영역 끝 0 패딩을 잘못된 레코드로 보고하지 않는다.
CRC 실패·알 수 없는 토큰·손상 참조는 레코드를 partial로 보존하고 진단한다. 손상 청크 뒤의 정상 청크도 계속 읽는다.
TimeCreated는 원본 필드로 details에 보존하고 기존 timestamp/time_field 키는 유지한다.

실제 EVTX·모든 공급자 변형은 검증하지 않았다. 처리하지 않는 XML 토큰은 조용히 성공하지 않고 partial/진단으로 남는다.
핵심 이벤트별 필드 정규화 확장은 백로그 B의 후속 작업이다. 원본 쓰기·증거 명령 실행·GUI/보고서 수정은 없다.
파서 구현·경계·독립 합성 바이너리 생성기를 함께 검토해야 하므로 변경량을 고려한 뒤 단일 PR로 유지했다.

## push 전 검토

2026-11-04: 새 파일·추가 줄·새 커밋 메시지에 외부 참고 도구 이름/코드/데이터·개인 경로·실제 증거 유입 없음. 전체 테스트 통과.
