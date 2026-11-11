# NTFS 파일 식별 검증 (#25)

- START: `b8be7cbec79bd4aaf0e20a86ab74d68abdfb52b8`
- 로컬 `issue/25-ntfs-case-identity`, feat 전용 게시 `feat/issue-25-ntfs-identity`.
- PR #19 a2109c9 교차 리뷰에서 합성 A.bin=UPPER/a.bin=lower 중 a.bin을 열어 UPPER가 나오는 것을 재현했다.
- 실패 테스트 먼저: 정확한 이름의 내용·모호한 대소문자 무시 일치·동일 이름 중복에서 3개 실패.
- 전체 테스트: 161개 실행, 160개 통과·1개 skip.
- 정확한 이름 일치를 먼저 사용한다. 정확한 일치가 없을 때만 유일한 대소문자 무시 일치를 사용한다. 모호하거나 동일한 이름이 중복이면 명시적 NTFSError를 반환한다.
- 실제 합성 이미지 CLI: `analyze --image <합성 이미지> --output <새 출력>` → 이벤트 1개, 오류 0개.
- PR #19 고정 소비자 코드에 새 메서드만 프로세스 안에서 적용해 `selected=\Data\a.bin bytes=b'lower'`, 모호한 A.BIN 거부를 확인했다. 다른 PR 소스는 변경하지 않았다.
- 실제 이미지·이 PC 볼륨은 검증하지 않았다. 반환 DirEntry/기존 유일한 대소문자 무시 조회는 호환된다.

## push 전 검토

2026-11-04: 추가 줄·새 경로·커밋 메시지에 외부 참고 코드/문구·개인 경로·실제 증거 없음. 전체 테스트 통과.
