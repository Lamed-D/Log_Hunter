"""커밋에 비공개 낱말·참고 자료 흔적이 들어가는 것을 막는 검사.

낱말 목록은 저장소에 올리지 않는 `.confidential-terms`(한 줄에 하나, `#`은 주석)에서 읽는다.
목록 자체가 비밀이므로 이 스크립트에는 낱말을 적지 않는다.

사용:
    python tools/check_confidential.py staged          # 스테이징된 변경의 추가 줄과 파일 경로 검사
    python tools/check_confidential.py message FILE    # 커밋 메시지 파일 검사
    python tools/check_confidential.py range A..B      # 커밋 범위의 메시지·변경 검사 (푸시 전 확인용)
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TERMS_FILE = ROOT / ".confidential-terms"


def load_terms():
    if not TERMS_FILE.exists():
        print("[check_confidential] .confidential-terms 가 없습니다. 검사를 건너뜁니다 "
              "(docs/dev/confidentiality.md 참고).", file=sys.stderr)
        return []
    terms = []
    for line in TERMS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line.lower())
    return terms


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout


def find_hits(text, terms, where):
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for term in terms:
            if term in low:
                hits.append(f"{where}:{number}: 비공개 낱말 발견 (목록의 '{term[:2]}…')")
    return hits


def added_lines(diff_text):
    return "\n".join(line[1:] for line in diff_text.splitlines()
                     if line.startswith("+") and not line.startswith("+++"))


def check_staged(terms):
    hits = []
    names = git("diff", "--cached", "--name-only")
    hits += find_hits(names, terms, "파일 경로")
    hits += find_hits(added_lines(git("diff", "--cached", "-U0")), terms, "추가된 내용")
    return hits


def check_message(path, terms):
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    text = "\n".join(l for l in text.splitlines() if not l.startswith("#"))
    return find_hits(text, terms, "커밋 메시지")


def check_range(spec, terms):
    hits = []
    hits += find_hits(git("log", "--format=%B", spec), terms, f"{spec} 커밋 메시지")
    hits += find_hits(git("diff", "--name-only", spec.replace("..", "...", 1)), terms, f"{spec} 파일 경로")
    hits += find_hits(added_lines(git("log", "-p", "--format=", spec)), terms, f"{spec} 추가된 내용")
    return hits


def main(argv):
    terms = load_terms()
    if not terms:
        return 0
    mode = argv[1] if len(argv) > 1 else "staged"
    if mode == "staged":
        hits = check_staged(terms)
    elif mode == "message" and len(argv) > 2:
        hits = check_message(argv[2], terms)
    elif mode == "range" and len(argv) > 2:
        hits = check_range(argv[2], terms)
    else:
        print(__doc__)
        return 2
    if hits:
        print("[check_confidential] 커밋을 막았습니다. 비공개 참고 자료·개인정보 흔적을 지우고 다시 시도하세요.",
              file=sys.stderr)
        for hit in hits:
            print("  " + hit, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
