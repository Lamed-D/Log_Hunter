# ▶ 원본: log_hunter/main.py
# ▶ CLI 인자를 입력 목록으로 바꾸고 분석 결과를 SQLite·보고서로 저장합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
import argparse
import json
import logging
import sys
from pathlib import Path
from .core.pipeline import Pipeline, PARSERS
from .core.report import export_reports
from .core.labels import SNAPSHOT_VERIFY_PHASES
from .database.case_db import save_case, load_case


OUTPUT_FILES = ("case.sqlite", "case.sqlite.integrity.json", "report.json", "timeline.csv", "report.html", "image_manifest.json",
                "timeline.json", "timeline.bodyfile")


def save_result(result, output, tags=None, sid_names=None):
    """Write case.sqlite, reports and timelines. `tags`: the examiner's tag rows (core.tags.TagBook.rows()),
    `sid_names`: {SID: user name found in the evidence} for the report's user column (exports keep the SID)."""
    output = Path(output)
    targets = {str((output / name).resolve()).casefold(): output / name for name in OUTPUT_FILES}
    if any(str(Path(e.source).resolve()).casefold() in targets for e in result.evidence):
        raise ValueError("보고서 파일 이름이 원본 증거 파일과 겹칩니다. 다른 저장 폴더를 고르세요")
    existing = [path.name for path in targets.values() if path.exists()]
    if existing:
        raise FileExistsError(f"저장 폴더에 이전 결과가 있습니다({', '.join(existing)}). 빈 폴더를 고르세요")
    output.mkdir(parents=True, exist_ok=True)
    tags = result.tags if tags is None else tags
    sid_names = (result.sid_names or result.profiles) if sid_names is None else sid_names
    save_case(output / "case.sqlite", result, name=output.name, tags=list(tags), sid_names=sid_names)
    export_reports(output, result.evidence, result.events, result.errors, result.relations, result.summaries, tags,
                   image=getattr(result, "image", None), sid_names=sid_names)
    if getattr(result, "image", None):
        (output / "image_manifest.json").write_text(json.dumps(result.image, ensure_ascii=False, indent=2), encoding="utf-8")
    # timeline.csv is written by export_reports (with time_field); don't overwrite it here.
    from .core.export import export_json, export_bodyfile
    export_json(result.events, output / "timeline.json")
    export_bodyfile(result.events, output / "timeline.bodyfile")


def main(argv=None):
    from .core.text import configure_console
    configure_console()
    parser = argparse.ArgumentParser(description="Log Hunter Windows 포렌식 분석")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="오프라인 아티팩트 분석")
    analyze.add_argument("--input", action="append", nargs=2, metavar=("ARTIFACT", "PATH"))
    analyze.add_argument("--auto", nargs="+", metavar="PATH", help="파일 또는 폴더의 기록 종류 자동 인식")
    analyze.add_argument("--image", help="디스크 이미지(E01/raw dd) — 내부 Windows 아티팩트를 자동 추출해 분석")
    analyze.add_argument("--live", nargs="?", const="", metavar="DRIVE",
                         help="이 PC의 드라이브(기본: 시스템 드라이브)에서 잠긴 파일까지 직접 읽어 분석 (관리자 권한 필요)")
    analyze.add_argument("--with-mft", action="store_true", help="이미지 분석 시 $MFT(파일 시스템 기록)도 포함 (대용량)")
    analyze.add_argument('--verify-image', action='store_true', help='오프라인 이미지 미디어 해시를 스트리밍 계산하고 저장값과 비교')
    analyze.add_argument('--snapshot-store', help='선택한 기존 스토어 ID의 확인된 저장 범위만 부분 분석')
    analyze.add_argument('--snapshot-volume', type=int, help='--snapshot-store와 함께 선택할 NTFS 볼륨 번호')
    analyze.add_argument("--output", required=True)
    analyze.add_argument("--sid")
    analyze.add_argument("--environment", help="수집 대상 환경변수 JSON 파일")
    collect = sub.add_parser("collect", help="WinAPI로 지정 증거 수집")
    collect.add_argument("kind", choices=("file", "registry", "eventlog", "browser"))
    collect.add_argument("source")
    collect.add_argument("destination")
    gui = sub.add_parser("gui", help="파일 선택/분석/조회 GUI")
    gui.add_argument("--live", metavar="DRIVE", help=argparse.SUPPRESS)
    snapshots = sub.add_parser('snapshots', help='오프라인 이미지의 기존 섀도 복사본 목록 (내용 읽기는 후속 지원)')
    snapshots.add_argument('image', help='E01/raw/고정 VHD 이미지')
    reopen = sub.add_parser('open', help='저장한 분석 결과 열기 (원본 재분석 없음)')
    reopen.add_argument('case_db')
    reopen.add_argument('--verify', action='store_true', help='케이스와 원본 파일 무결성 확인')
    regenerate = sub.add_parser('report', help='저장한 분석으로 보고서와 타임라인 다시 만들기')
    regenerate.add_argument('--from', dest='case_db', required=True)
    regenerate.add_argument('--output', required=True)
    regenerate.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.command in ('open', 'report'):
        try:
            result, info = load_case(args.case_db, verify=args.verify)
            if args.command == 'report':
                if info.created_at:
                    result.settings.setdefault('analysis_at', info.created_at)
                save_result(result, args.output)
            print(json.dumps({'events': len(result.events), 'errors': len(result.errors),
                              'case': info.to_dict()}, ensure_ascii=False))
            return 0
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    if args.command == 'snapshots':
        from .image.ewf import ImageError
        from .image.vss import list_snapshots
        try:
            result = list_snapshots(args.image)
        except (ImageError, OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if any(row['errors'] for row in result) else 0
    if args.command == "gui":
        from .ui.app import run
        run(live=args.live)
        return
    if args.command == "analyze":
        if (args.snapshot_store is None) != (args.snapshot_volume is None):
            parser.error('--snapshot-store와 --snapshot-volume은 함께 지정하세요')
        if args.snapshot_store is not None and (not args.image or args.input or args.auto
                                                or args.live is not None or args.verify_image):
            parser.error('스냅숏 부분 분석은 명시적인 --image에서만 지원하며 --verify-image와 함께 사용할 수 없습니다')
        if args.snapshot_store is not None:
            from .image.live import is_live_path
            if is_live_path(args.image) or str(args.image).startswith(('\\\\.\\', '\\\\?\\')):
                parser.error('스냅숏 부분 분석에는 라이브 장치 대신 오프라인 이미지를 선택하세요')
        if args.auto:
            if args.input or args.image or args.live is not None:
                parser.error("--auto는 --input/--image/--live와 함께 사용할 수 없습니다")
            from .core.auto_detect import detect_inputs
            from .core.labels import ARTIFACT_LABELS, AUTO_DETECT_COLUMNS, AUTO_DETECT_UNKNOWN
            rows = detect_inputs(args.auto)
            print(AUTO_DETECT_COLUMNS)
            for artifact, path, sid, reason in rows:
                print(f"{ARTIFACT_LABELS.get(artifact, AUTO_DETECT_UNKNOWN)}\t{path}\t{sid or ''}\t{reason}")
            images = [path for artifact, path, _, _ in rows if artifact == "image"]
            inputs = [(artifact, path, sid) for artifact, path, sid, _ in rows if artifact and artifact != "image"]
            if images:
                if len(images) != 1 or inputs:
                    parser.error("이미지는 한 번에 하나씩 별도로 분석하세요")
                args.image = images[0]
            else:
                args.input = inputs
        if args.live is not None:
            from .image import live
            if args.image or args.input:
                parser.error("--live는 --image/--input과 함께 사용할 수 없습니다")
            args.image = live.live_device(args.live or live.system_drive())
            if args.image is None:
                parser.error(f"드라이브 이름이 아닙니다: {args.live} (예: C:)")
            if not live.is_admin():
                parser.error(live.ADMIN_REQUIRED)
        if not args.input and not args.image:
            parser.error("--input, --image, --live 중 하나는 필요합니다")
        if args.verify_image and (not args.image or args.live is not None):
            parser.error('--verify-image는 오프라인 --image 또는 자동 인식한 이미지에서만 사용하세요')
        for kind, *_ in args.input or []:
            if kind not in PARSERS:
                parser.error(f"지원 아티팩트: {', '.join(PARSERS)}")
        environment = json.loads(Path(args.environment).read_text(encoding="utf-8")) if args.environment else {}
        report = lambda done, total, path: logging.info("%s/%s %s", done, total, path)
        if args.image:
            if args.input:
                parser.error("--image와 --input은 함께 사용할 수 없습니다")
            if args.snapshot_store is not None:
                result = Pipeline().analyze_snapshot(args.image, Path(args.output) / 'extracted',
                                                     args.snapshot_volume, args.snapshot_store, args.sid, environment,
                                                     report, include_mft=args.with_mft,
                                                     verification_progress=lambda done, total, phase: logging.info(
                                                         '%s %s/%s 바이트', SNAPSHOT_VERIFY_PHASES[phase], done, total),
                                                     extract_progress=lambda count, path: logging.info('추출 %s: %s', count, path))
            else:
                result = Pipeline().analyze_image(args.image, Path(args.output) / "extracted", args.sid, environment, report,
                                                  include_mft=args.with_mft,
                                                  verify=args.verify_image,
                                                  verification_progress=lambda done, total: logging.info('이미지 검증 %s/%s 바이트', done, total),
                                                  extract_progress=lambda count, path: logging.info("추출 %s: %s", count, path))
        else:
            result = Pipeline().analyze(args.input, args.sid, environment, report)
        result.settings.update({'sid': args.sid, 'with_mft': args.with_mft,
                                'verify_image': args.verify_image,
                                'snapshot_store': args.snapshot_store, 'snapshot_volume': args.snapshot_volume})
        if args.auto:
            result.inputs = [{'artifact': a, 'path': str(p), 'sid': owner, 'reason': reason}
                             for a, p, owner, reason in rows]
        save_result(result, args.output)
        print(json.dumps({"events": len(result.events), "errors": len(result.errors), "output": str(Path(args.output).resolve())}, ensure_ascii=False))
        return 1 if any(e.severity == "error" for e in result.errors) else 0
    from .collector.winapi import NativeAPI
    from .collector.live_collector import LiveCollector, write_manifest
    from .collector.registry_collector import RegistryCollector
    from .collector.eventlog_collector import EventLogCollector
    from .collector.browser_collector import BrowserCollector
    api = NativeAPI()
    manifest = Path(args.destination) / "manifest.json" if args.kind == "browser" else Path(args.destination + ".manifest.json")
    if manifest.exists():
        raise FileExistsError(manifest)
    collector = {"file": LiveCollector(api=api), "registry": RegistryCollector(api),
                 "eventlog": EventLogCollector(api), "browser": BrowserCollector(api=api)}[args.kind]
    evidence = collector.collect(args.source, args.destination)
    items = evidence if isinstance(evidence, list) else [evidence]
    write_manifest(items, manifest)
    print(str(manifest.resolve()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
