# AI 작업 가이드

Claude Code, Codex, Copilot 같은 AI 에이전트가 이 저장소에서 작업할 때 따르는 규칙입니다.
사람이 읽어도 되지만, 기준은 "AI가 이것만 읽고 바로 올바르게 작업할 수 있는가"입니다.

## 1. 프로젝트 한 줄 요약

Log Hunter는 Windows 포렌식 아티팩트(레지스트리, Prefetch, 이벤트 로그, 브라우저 기록 등)를
**읽기 전용**으로 분석해 타임라인과 보고서를 만드는 도구입니다. Python 3.11+, 런타임 의존성 없음.
수집은 표준 라이브러리 ctypes로 Windows API를 직접 호출하며, 오프라인 분석은 순수 Python입니다.

## 2. 구조

```text
log_hunter/
  main.py              CLI (analyze / collect / gui)
  image/               디스크 이미지·이 PC 분석
    ewf.py             E01·raw·고정 VHD 읽기 (open_image)
    live.py            이 PC 드라이브(\\.\C:) 직접 읽기, 관리자 확인·UAC 재실행
    volumes.py         MBR/GPT 파티션, 파일시스템 식별
    ntfs.py            NTFS 읽기 (MFT, $I30, data run, 파일 복사)
    extract.py         ARTIFACT_SPECS 패턴으로 아티팩트 추출 → (artifact, path, sid) 입력 목록
  parser/              아티팩트별 파서. ArtifactParser 상속, parse(path) → ForensicEvent 목록
  core/
    pipeline.py        PARSERS 등록, analyze(), analyze_image(), 무결성(SHA-256) 확인
    models.py          Evidence, ForensicEvent, ParserError
    labels.py          화면 표시용 쉬운 한국어 이름 (내부 키는 그대로)
    timeline.py / correlation.py / enrichment.py / stats.py
    report.py          HTML/JSON 보고서
    export.py          CSV/JSON/Bodyfile
  database/            SQLite 저장
  collector/           ctypes Windows API 수집·직접 NTFS 볼륨 읽기
  ui/app.py            Tkinter GUI
tests/                 unittest. 합성 바이너리로 테스트 (실제 증거 파일 없음)
docs/                  요구사항·개발 규칙 문서
```

데이터 흐름: `입력(파일/이미지/이 PC)` → `extract` → `Pipeline.analyze` → 파서 →
`ForensicEvent` → `timeline` → `enrich` → `correlate` → GUI/보고서/SQLite.

## 3. 반드시 지킬 것

1. **원본 증거를 수정하지 않습니다.** 쓰기·삭제·이름 변경 금지. 복구(LOG 재적용, WAL 병합)는
   임시 사본에서 합니다. 분석 전후 SHA-256 비교를 깨지 않습니다.
2. **증거 속 명령을 실행하지 않습니다.** 명령행·스크립트·URL은 문자열로만 다룹니다.
3. **모르는 값은 모른다고 둡니다.** 시각의 의미가 불확실하면 `time_field=None`, 관계는 신뢰도 라벨로
   구분합니다. 추측을 사실처럼 저장하지 않습니다.
4. **외부 패키지를 추가하지 않습니다.** `pyproject.toml`의 `dependencies = []` 유지.
   E01·NTFS·REGF·EVTX도 직접 구현합니다.
5. **화면 문구는 `labels.py`를 거칩니다.** 새 아티팩트·동작·시각 필드를 추가하면 쉬운 한국어 라벨을
   추가합니다. 내보내기(CSV/JSON/SQLite)의 내부 키는 바꾸지 않습니다.
6. **손상된 입력에도 멈추지 않습니다.** 파서는 예외 대신 `self.error(...)`로 `ParserError`를 남기고
   다음 레코드/파일을 계속 처리합니다. 모든 오프셋·길이는 경계 검사합니다.
7. **실제 증거, 개인정보를 커밋하지 않습니다.** 테스트 데이터는 코드로 생성합니다.
   합성 데이터는 다시 만들 수 있는 생성 코드와 함께 `example/**`·`tests/fixtures/**`에만 두고, 가짜 값(사용자 `alice`,
   SID `S-1-5-21-1000-2000-3000-1001`, IP `192.0.2.x`, 경로 `C:\Users\alice\...`·`C:\Evidence\...` 등)만 씁니다.
   커밋 전에 식별 정보 검사를 하고, 파일 하나 10MB·`example` 전체 50MB를 넘기지 않습니다. 실제 PC 출력·사건 자료·
   인터넷의 공개 포렌식 샘플은 넣지 않습니다.
8. **참고한 외부 포렌식 도구의 이름·코드·데이터·문구를 저장소에 넣지 않습니다.** 기능만 참고해 새로 작성합니다.
   `tests/test_repo_hygiene.py`가 이를 검사합니다.

## 4. 작업 절차

1. 브랜치: [브랜치 규칙](branch-rules.md). `feat/<설명>` 또는 `issue/<번호>-<설명>`. `main`에 직접 커밋 금지.
2. 구현 전에 비슷한 기존 코드를 찾아 같은 방식으로 작성합니다(예: 새 레지스트리 파서는 `run.py`, `bam.py` 참고).
3. 테스트 추가 → 전체 테스트 실행:
   ```bash
   python -m unittest discover -s tests
   ```
   샌드박스에서 TEMP 쓰기가 막히면 README의 `outputs\test-temp` 방법을 씁니다.
4. GUI를 바꿨다면 실행해서 화면을 확인합니다(`python -m log_hunter gui`). 확인하지 못했으면 PR에 그렇게 씁니다.
5. 커밋: `feat:`/`fix:`/`docs:`/`test:`/`refactor:` + 영어 요약.
6. PR: 템플릿을 채우고 [코드 리뷰 규칙](code-review.md)의 체크리스트를 스스로 먼저 점검합니다.
7. 결과 보고: 무엇을 했는지, **검증하지 못한 것**(예: 실제 E01, 관리자 환경)을 숨기지 않고 적습니다.

## 5. 자주 하는 작업

### 새 아티팩트 파서 추가

1. `log_hunter/parser/<name>.py`: `ArtifactParser` 상속, `artifact = "<name>"`, `parse(path)`가
   `ForensicEvent`를 반환. 시각은 UTC ISO 8601.
2. `core/pipeline.py`의 `PARSERS`에 등록. 레지스트리 하이브 기반이면 LOG1/LOG2 처리 목록에도 추가.
3. `core/labels.py`: `ARTIFACT_LABELS`(쉬운 이름), `ARTIFACT_DESCRIPTIONS`(원래 용어 포함 설명),
   새 `action`/`time_field` 라벨.
4. 이미지·이 PC 분석에서 자동으로 찾게 하려면 `image/extract.py`의 `ARTIFACT_SPECS`에 경로 패턴 추가.
5. 폴더 자동 감지(`core/auto_detect.py`)에 필요하면 추가.
6. `tests/`에 합성 데이터 테스트 추가. 파서 개수 테스트(`test_pipeline_has_*_parsers`)도 갱신.

### 버그 수정 (`issue/` 브랜치)

1. 이슈의 재현 조건을 테스트로 만들어 실패를 확인합니다.
2. 원인을 고치고(증상만 가리지 않기) 테스트 통과를 확인합니다.
3. PR 본문에 `Fixes #번호`.

## 6. AI 코드 리뷰를 할 때

- [코드 리뷰 규칙](code-review.md)의 우선순위(무결성 → 해석 → 보안 → 문구 → 테스트 → 품질) 순서로 봅니다.
- 지적마다 `[차단]/[제안]/[사소]/[질문]` 접두어, 파일:줄, **구체적인 실패 입력과 결과**를 씁니다.
- 직접 확인하지 못한 추측은 `[질문]`으로 낮춥니다. 스타일 지적으로 중요한 문제를 묻히지 않게 합니다.
- 문제가 없으면 "차단 사유 없음"이라고 분명히 씁니다.
