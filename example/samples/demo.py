"""Log Hunter 학습용 데모 — 가짜(합성) 증거 파일을 만들고 실제 분석 파이프라인을 돌려 본다.

실행 (저장소 루트에서):
    python example/samples/demo.py

하는 일
  1) example/samples/evidence/ 에 "가상의 사건" 증거 파일 4종을 만든다.
       - History               : Chrome 방문/다운로드 기록 (SQLite DB)
       - SETUP.EXE-1A2B3C4D.pf : Windows Prefetch (실행 흔적, 바이너리)
       - NTUSER.DAT            : 사용자 레지스트리 하이브 (Run 키 + UserAssist, 바이너리)
       - ConsoleHost_history.txt : PowerShell 명령 기록 (텍스트)
  2) log_hunter 의 Pipeline 으로 4개를 한꺼번에 분석한다.
  3) example/samples/output/ 에 case.sqlite / report.json / timeline.csv / report.html 을 저장한다.

가상의 사건 시나리오 (모든 시각은 UTC)
  09:58  사용자가 Chrome 으로 https://example.com/tools 방문
  09:59  setup.exe 다운로드 (리다이렉트 체인 2단계)
  10:00  PowerShell 에서 같은 파일을 다시 받으려는 명령 입력 (시각은 기록되지 않음)
  10:01  setup.exe 실행 → Prefetch / UserAssist 에 흔적
  10:02  setup.exe 가 자기 자신을 Run 키에 등록 (재부팅 시 자동 실행)

TS 개발자를 위한 비유
  - 이 스크립트는 "테스트 픽스처(fixture) 생성기 + 통합 테스트 실행기" 이다.
    Jest 의 beforeAll 에서 가짜 DB 를 만들고, 실제 서비스 코드를 호출하는 것과 같다.
  - struct.pack_into(...) 는 DataView.setUint32(offset, value, true) 처럼
    바이트 배열의 특정 위치에 숫자를 '리틀 엔디언'으로 써 넣는 함수다.
"""
import shutil
import sqlite3
import struct
import sys
import hashlib
import json
from dataclasses import fields, is_dataclass
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path

# ── 저장소 루트를 import 경로에 추가 ─────────────────────────────────────────
# TS 로 치면 tsconfig 의 "baseUrl" 을 잡아 주는 것. 이 파일은 example/samples/ 에 있으므로
# parents[2] 가 저장소 루트(Log_Hunter/)다.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from log_hunter.core.pipeline import Pipeline  # noqa: E402  (경로 추가 후 import)
from log_hunter.main import save_result  # noqa: E402

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"
OUTPUT = HERE / "output"
SID = "S-1-5-21-1000-2000-3000-1001"  # 가상의 사용자 SID
EXE = r"C:\Users\alice\Downloads\setup.exe"


# ── 시간 변환 도우미 ──────────────────────────────────────────────────────────
def utc(hour, minute):
    """2026-03-14 hh:mm UTC 를 datetime 으로."""
    return datetime(2026, 3, 14, hour, minute, tzinfo=timezone.utc)


EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(moment):
    """Windows FILETIME = 1601-01-01 부터 흐른 100나노초(=0.1µs) 단위 개수.

    JS 의 Date.getTime() 이 '1970 부터 밀리초' 인 것과 기준점/단위만 다르다.
    """
    delta = moment - EPOCH_1601
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def to_chromium(moment):
    """Chromium 시각 = 1601-01-01 부터 흐른 마이크로초. FILETIME 의 1/10."""
    return to_filetime(moment) // 10


# ── 1) Chrome History (SQLite) ───────────────────────────────────────────────
def make_history(path):
    # 실제 Chrome DB 의 일부 테이블/컬럼만 흉내 낸다. 파서가 읽는 컬럼만 있으면 충분하다.
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER,
                               end_time INTEGER, total_bytes INTEGER, mime_type TEXT);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
    """)
    db.execute("INSERT INTO urls VALUES(1, 'https://example.com/tools', 'Free Tools', ?)", (to_chromium(utc(9, 58)),))
    db.execute("INSERT INTO visits VALUES(1, 1, ?, 805306368)", (to_chromium(utc(9, 58)),))
    db.execute("INSERT INTO downloads VALUES(1, ?, ?, ?, 482304, 'application/x-msdownload')",
               (EXE, to_chromium(utc(9, 59)), to_chromium(utc(9, 59))))
    # 다운로드 리다이렉트 체인: 마지막 원소가 실제 파일을 내려준 최종 URL
    db.execute("INSERT INTO downloads_url_chains VALUES(1, 0, 'https://example.com/dl?id=1')")
    db.execute("INSERT INTO downloads_url_chains VALUES(1, 1, 'https://example.com/setup.exe')")
    db.commit()
    db.close()


# ── 2) Prefetch v30 (바이너리) ───────────────────────────────────────────────
def make_prefetch(path):
    # 압축되지 않은 SCCA 형식. 오프셋은 log_hunter/parser/prefetch.py 가 읽는 위치와 같다.
    #   0   : version (30 = Windows 10/11)
    #   4   : "SCCA" 시그니처
    #   16  : 실행 파일 이름 (UTF-16LE, 최대 60바이트)
    #   76  : Prefetch 해시 (파일 이름 끝의 16진수와 같음)
    #   100 : 참조 파일 문자열 영역 offset / size
    #   128 : 마지막 실행 시각 FILETIME × 8개
    #   208 : 실행 횟수
    data = bytearray(400)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    name = "SETUP.EXE\0".encode("utf-16-le")
    data[16:16 + len(name)] = name
    struct.pack_into("<I", data, 76, 0x1A2B3C4D)
    refs = ("\\VOLUME{01d9a1b2c3d4e5f6-12345678}\\USERS\\ALICE\\DOWNLOADS\\SETUP.EXE\0"
            "\\VOLUME{01d9a1b2c3d4e5f6-12345678}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL\0").encode("utf-16-le")
    struct.pack_into("<II", data, 100, 240, len(refs))
    data[240:240 + len(refs)] = refs
    struct.pack_into("<Q", data, 128, to_filetime(utc(10, 1)))  # 가장 최근 실행
    struct.pack_into("<Q", data, 136, to_filetime(utc(10, 0)))  # 그 이전 실행
    struct.pack_into("<I", data, 208, 2)                         # 총 2회 실행
    path.write_bytes(data)


# ── 3) 레지스트리 하이브 (REGF 바이너리) ─────────────────────────────────────
class HiveBuilder:
    """아주 작은 REGF 하이브를 바이트 단위로 직접 조립한다.

    구조 (log_hunter/parser/registry.py 가 읽는 것과 동일)
      [0     .. 4096) base block : "regf", 시퀀스 번호 2개, 루트 nk cell offset(0x24)
      [4096  .. )     hbin       : "hbin" 헤더 32바이트 + cell 들
      cell = int32(음수 크기 = 사용 중) + payload, 8바이트 정렬
      nk cell = 키(폴더), vk cell = 값(파일), li cell = 하위 키 offset 목록
    모든 offset 은 hbin 시작(파일 4096 위치) 기준 상대값이다.
    """

    def __init__(self):
        self.cells = bytearray(b"hbin" + b"\0" * 28)

    def cell(self, payload):
        offset = len(self.cells)
        size = (len(payload) + 4 + 7) & ~7  # 8바이트 배수로 올림
        self.cells += struct.pack("<i", -size) + payload + b"\0" * (size - 4 - len(payload))
        return offset

    def value(self, name, kind, raw):
        # 데이터 블록 cell → vk cell 순서로 만든다 (vk 가 데이터 위치를 가리켜야 하므로)
        block = self.cell(raw)
        vk = bytearray(20)
        vk[:2] = b"vk"
        #                name_len   data_len  data_off  type  flags(1=ASCII 이름)
        struct.pack_into("<HIIIH", vk, 2, len(name), len(raw), block, kind, 1)
        return self.cell(bytes(vk) + name.encode("ascii"))

    def key(self, name, lastwrite, values=(), children=()):
        # values  : [(이름, 타입, raw bytes)]
        # children: 이미 만든 하위 nk cell 의 offset 목록
        value_list = self.cell(b"".join(struct.pack("<I", self.value(*v)) for v in values)) if values else 0
        sub_list = self.cell(b"li" + struct.pack("<H", len(children)) +
                             b"".join(struct.pack("<I", c) for c in children)) if children else 0
        nk = bytearray(76)
        nk[:2] = b"nk"
        struct.pack_into("<H", nk, 2, 0x20)              # flags: 이름이 ASCII
        struct.pack_into("<Q", nk, 4, lastwrite)         # 키 마지막 수정 시각
        struct.pack_into("<I", nk, 20, len(children))    # 하위 키 개수
        struct.pack_into("<I", nk, 28, sub_list)         # 하위 키 목록 offset
        struct.pack_into("<II", nk, 36, len(values), value_list)  # 값 개수 / 값 목록 offset
        struct.pack_into("<H", nk, 72, len(name))        # 이름 길이
        return self.cell(bytes(nk) + name.encode("ascii"))

    def path(self, names, lastwrite, values=(), siblings=()):
        """'A\\B\\C' 처럼 중첩된 경로를 아래(C)부터 위(A)로 만들어 A 의 offset 을 돌려준다."""
        child = self.key(names[-1], lastwrite, values, siblings)
        for name in reversed(names[:-1]):
            child = self.key(name, lastwrite, children=[child])
        return child

    def build(self, root_offset):
        header = bytearray(4096)
        header[:4] = b"regf"
        struct.pack_into("<II", header, 4, 1, 1)  # 두 시퀀스 번호가 같으면 'clean' 하이브
        struct.pack_into("<I", header, 0x24, root_offset)
        return bytes(header + self.cells)


def rot13(text):
    import codecs
    return codecs.encode(text, "rot_13")


def make_ntuser(path):
    b = HiveBuilder()
    # UserAssist: 값 이름은 ROT13 으로 가려져 있고, 값 데이터는 72바이트 구조체
    ua = bytearray(72)
    struct.pack_into("<III", ua, 4, 2, 3, 15000)                # 실행 2회, 포커스 3회, 포커스 15초
    struct.pack_into("<Q", ua, 60, to_filetime(utc(10, 1)))     # 마지막 실행 시각
    count = b.key("Count", to_filetime(utc(10, 1)), values=[(rot13(EXE), 3, bytes(ua))])
    guid = b.key("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", to_filetime(utc(10, 1)), children=[count])
    userassist = b.key("UserAssist", to_filetime(utc(10, 1)), children=[guid])
    explorer = b.key("Explorer", to_filetime(utc(10, 1)), children=[userassist])
    # Run: 로그온 시 자동 실행 등록. REG_SZ(1) 문자열은 UTF-16LE + NUL 종료
    command = f'"{EXE}" -silent\0'.encode("utf-16-le")
    run = b.key("Run", to_filetime(utc(10, 2)), values=[("Updater", 1, command)])
    current = b.key("CurrentVersion", to_filetime(utc(10, 2)), children=[explorer, run])
    root = b.path(["ROOT", "Software", "Microsoft", "Windows"], to_filetime(utc(10, 2)), siblings=[current])
    path.write_bytes(b.build(root))


# ── 4) PowerShell PSReadLine 기록 (텍스트) ───────────────────────────────────
def make_psreadline(path):
    path.write_text(
        "Get-ChildItem $env:USERPROFILE\\Downloads\n"
        "Invoke-WebRequest https://cdn.example.com/setup.exe -OutFile setup.exe\n"
        "Start-Process .\\setup.exe `\n"          # 백틱(`)으로 끝나면 다음 줄과 한 명령
        "  -ArgumentList '-silent'\n"
        "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "Remove-Item .\\setup.exe\n",
        encoding="utf-8")


def make_thumbcache(path):
    """Create one synthetic 1x1 red BMP in a version-32 cache; no real image input."""
    image = (struct.pack('<2sIHHI', b'BM', 58, 0, 0, 54)
             + struct.pack('<IiiHHIIiiII', 40, 1, 1, 1, 24, 0, 4, 0, 0, 0, 0) + b'\0\0\xff\0')
    identifier = 'synthetic-1'.encode('utf-16-le')
    entry_size = 56 + len(identifier) + len(image)
    entry = struct.pack('<4sIQIIIIIIQQ', b'CMMM', entry_size, 0x1001001, len(identifier),
                        0, len(image), 1, 1, 0, 0, 0)
    header = struct.pack('<4sIIIII', b'CMMM', 32, 4, 0, 24, 24 + entry_size)
    path.write_bytes(header + entry + identifier + image)


def normalize_generated_result(value, directory):
    """Only generated demo results use this stable, fictional display root."""
    if isinstance(value, str):
        for prefix in (str(directory), directory.as_posix()):
            value = value.replace(prefix, r"C:\Evidence\synthetic")
        return value
    if isinstance(value, list):
        return [normalize_generated_result(item, directory) for item in value]
    if isinstance(value, dict):
        return {key: normalize_generated_result(item, directory) for key, item in value.items()}
    if is_dataclass(value):
        for field in fields(value):
            setattr(value, field.name, normalize_generated_result(getattr(value, field.name), directory))
    return value


def main(destination=HERE):
    destination = Path(destination).resolve()
    evidence, output = destination / "evidence", destination / "output"
    # Only these two generated subfolders of the explicitly chosen destination are replaced.
    for folder in (evidence, output):
        if folder.resolve().parent != destination or folder.is_symlink():
            raise ValueError("합성 자료 출력 폴더 경계 오류")
    EVIDENCE, OUTPUT = evidence, output
    # 이전 실행 결과를 지우고 새로 만든다 (example/samples 아래만 건드림)
    for folder in (EVIDENCE, OUTPUT):
        if folder.exists():
            shutil.rmtree(folder)
    EVIDENCE.mkdir(parents=True)

    make_history(EVIDENCE / "History")
    make_prefetch(EVIDENCE / "SETUP.EXE-1A2B3C4D.pf")
    make_ntuser(EVIDENCE / "NTUSER.DAT")
    make_psreadline(EVIDENCE / "ConsoleHost_history.txt")
    make_thumbcache(EVIDENCE / 'thumbcache_256.db')
    (EVIDENCE / 'MPLog-synthetic.log').write_text(
        '2026-03-14T10:02:00Z DETECTIONEVENT MPSOURCE_REALTIME Test:Win32/Synthetic file:C:\\Evidence\\fake.exe;\n',
        encoding='utf-8')

    # CLI 로 치면:
    #   python -m log_hunter analyze --sid S-1-... \
    #     --input history evidence/History --input prefetch evidence/SETUP.EXE-1A2B3C4D.pf \
    #     --input userassist evidence/NTUSER.DAT --input run evidence/NTUSER.DAT \
    #     --input psreadline evidence/ConsoleHost_history.txt --output output
    inputs = [("history", EVIDENCE / "History"),
              ("prefetch", EVIDENCE / "SETUP.EXE-1A2B3C4D.pf"),
              ("userassist", EVIDENCE / "NTUSER.DAT"),
              ("run", EVIDENCE / "NTUSER.DAT"),
              ("psreadline", EVIDENCE / "ConsoleHost_history.txt"),
              ('thumbcache', EVIDENCE / 'thumbcache_256.db'),
              ('defender', EVIDENCE / 'MPLog-synthetic.log')]
    result = Pipeline().analyze(inputs, sid=SID,
                                progress=lambda done, total, path: print(f"  [{done}/{total}] {Path(path).name}"))
    normalize_generated_result(result, destination)
    result.settings['analysis_at'] = utc(10, 3).isoformat()
    for item in result.evidence:
        item.collected_at = utc(10, 3).isoformat()
    for summary in result.summaries:
        summary["elapsed_seconds"] = 0.0  # Reproducible teaching output, not a benchmark.
    with patch("log_hunter.core.report._now", return_value="2026-03-14 10:03:00 UTC"):
        save_result(result, OUTPUT)
    generated = {}
    for folder in (EVIDENCE, OUTPUT):
        for file in sorted(folder.rglob("*")):
            if file.is_file():
                generated[file.relative_to(destination).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    (destination / "generated.json").write_text(json.dumps({
        "generator": "example/samples/demo.py", "synthetic": True,
        "files": generated,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("\n== 타임라인 (UTC 오름차순, 시각 미상은 맨 뒤) ==")
    for e in result.events:
        what = (e.path or e.process or e.url or e.details.get('cache_id')
                or next(iter(e.details.get("command", "").splitlines()), ''))
        print(f"  {e.timestamp or '미상':<26} {e.artifact:<10} {e.action:<22} {what}")
    print("\n== 연관 후보 (실행 확정 아님) ==")
    for r in result.relations:
        if "left" not in r or "right" not in r:
            print(f"  {r['type']}: {len(r.get('event_indices', []))}개 기록의 후보 묶음")
            continue
        left, right = result.events[r["left"]], result.events[r["right"]]
        print(f"  {left.artifact:<10} ↔ {right.artifact:<10} {r['basis']:<16} {r['confidence']}")
    print(f"\n이벤트 {len(result.events)}개, 오류/경고 {len(result.errors)}개 → {OUTPUT}")


if __name__ == "__main__":
    main()
