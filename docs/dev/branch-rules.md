# 브랜치 규칙

브랜치는 **`feat`** 와 **`issue`** 두 종류만 씁니다. `main`에 직접 커밋하지 않고
항상 브랜치 → Pull Request(PR) → 리뷰 → `main` 병합 순서로 진행합니다.

## 종류

| 종류 | 이름 형식 | 언제 | 예시 |
| --- | --- | --- | --- |
| `feat` | `feat/<짧은-설명>` | 새 기능, 기능 개선, 문서, 리팩터링, 테스트 추가 | `feat/tree-view`, `feat/evtx-binxml` |
| `issue` | `issue/<이슈번호>-<짧은-설명>` | GitHub 이슈로 등록된 버그·오류 수정 | `issue/12-permission-error`, `issue/7-e01-chunk-crash` |

- 설명은 **영어 소문자 + 하이픈(kebab-case)**, 3~5단어 이내로 씁니다.
- `issue` 브랜치는 반드시 이슈 번호로 시작합니다. 이슈가 없으면 먼저 이슈를 만듭니다
  ([이슈 규칙](issue-rules.md)).
- 버그가 아니어도 이슈로 관리하고 싶은 기능 요청은 이슈를 만든 뒤 `feat/` 브랜치에서
  작업하고, PR 본문에 `Closes #번호`를 적습니다.

## 흐름

```text
main ──┬── feat/tree-view ──── PR ── 리뷰 ── squash merge ──> main
       └── issue/12-permission-error ── PR ── 리뷰 ── squash merge ──> main
```

1. 최신 `main`에서 분기합니다.
   ```bash
   git switch main
   git pull
   git switch -c feat/<짧은-설명>
   ```
2. 작업 단위마다 커밋합니다 (아래 커밋 메시지 규칙).
3. 푸시하고 PR을 엽니다. PR 템플릿(`.github/pull_request_template.md`)을 채웁니다.
4. [코드 리뷰 규칙](code-review.md)에 따라 다른 에이전트의 리뷰를 받고 수정합니다.
5. 상대 에이전트의 승인과 검사 통과 등 [병합 조건](agents.md#6-서로-리뷰하고-스스로-병합)을 채우면 PR 작성자가 **squash merge** 하고 브랜치를 삭제합니다
   (`gh pr merge <번호> --squash --delete-branch`). 단독 모드에서는 [10절](agents.md#10-단독-모드-solo)의 자체 리뷰로 대신합니다.

- **PR base는 항상 `main`** 입니다. 다른 작업 브랜치 위에 쌓은 PR을 만들지 않습니다(앞 PR이 필요하면 병합을 기다립니다).

- 한 브랜치에는 한 가지 주제만 담습니다. 서로 관계없는 수정은 브랜치를 나눕니다.
- 오래 걸리는 브랜치는 `main`을 주기적으로 병합(merge)해서 충돌을 미리 해소합니다.
  이미 푸시한 브랜치는 rebase/force-push 하지 않습니다.

## 커밋 메시지

```text
<type>: <한국어 요약, 50자 안팎>

<본문(한국어): 무엇을, 왜 바꿨는지>

Agent: <claude1|codex1>
```

- 제목의 `type`은 영어(아래 표), 요약과 본문은 **한국어**로 씁니다. 제목만 있는 커밋은 만들지 않습니다.
- 본문 마지막 줄에 작업한 에이전트 이름 `Agent: <이름>`을 적습니다(사람이 직접 커밋하면 생략).
- 커밋 메시지에도 참고 도구 이름·개인정보를 쓰지 않습니다(커밋 훅이 검사, [비공개 자료 규칙](confidentiality.md)).

| type | 용도 | 브랜치 |
| --- | --- | --- |
| `feat` | 새 기능·개선 | `feat/` |
| `fix` | 버그 수정 | `issue/` (또는 `feat/` 작업 중 발견한 버그) |
| `docs` | 문서만 변경 | `feat/` |
| `test` | 테스트만 추가·수정 | `feat/`, `issue/` |
| `refactor` | 동작 변화 없는 구조 변경 | `feat/` |
| `chore` | 설정·도구·정리 | `feat/` |

- `issue/` 브랜치의 마지막 커밋이나 PR 본문에는 `Fixes #번호`를 넣어 병합 시 이슈가 닫히게 합니다.
- 실제 증거 파일, 개인 정보, 케이스 번호, 계정 정보는 커밋하지 않습니다.
  `outputs/`는 `.gitignore`에 들어 있습니다.
