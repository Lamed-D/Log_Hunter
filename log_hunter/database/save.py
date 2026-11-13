"""Transactional analysis exports shared by CLI and GUI."""
import copy
import errno
import json
import os
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from .case_db import save_case, _hash, _counts, _readonly
from log_hunter.core.report import export_reports
from log_hunter.core.export import export_json, export_bodyfile

OUTPUT_FILES = ('case.sqlite', 'case.sqlite.integrity.json', 'report.json', 'timeline.csv',
                'report.html', 'image_manifest.json', 'timeline.json', 'timeline.bodyfile')


class SaveError(OSError):
    pass


class SaveExistsError(FileExistsError, SaveError):
    def __init__(self, files):
        self.files = tuple(files)
        super().__init__('이전 결과가 있습니다(' + ', '.join(self.files) + '). 새 하위 폴더를 고르세요')


class SaveCancelled(SaveError):
    def __init__(self):
        super().__init__('저장을 취소했습니다. 새로 만든 결과 파일은 정리했습니다')


class SaveSourceError(ValueError):
    pass


class SavePermissionError(SaveError):
    pass


class SaveLockedError(SaveError):
    pass


class SaveSpaceError(SaveError):
    pass


class SavePathError(SaveError):
    pass


@dataclass
class SaveReport:
    folder: Path
    files: tuple
    case: object


def suggest_save_folder(folder):
    folder = Path(folder)
    for i in range(1, 100000):
        candidate = folder / f'analysis-{i:03d}'
        if not candidate.exists():
            return candidate
    raise SaveError('새 저장 폴더 이름을 지정하세요')


def save_analysis(folder, result, *, name=None, tags=None, sid_names=None, inputs=None,
                  settings=None, sources=None, progress=None, cancel=None):
    folder = Path(folder).resolve()
    tags = result.tags if tags is None else list(tags)
    sid_names = (result.sid_names or result.profiles) if sid_names is None else dict(sid_names)
    source_paths = [Path(e.source).resolve() for e in result.evidence]
    # Extracted files can legitimately live below output/extracted; never write beside an input.
    source_paths += [Path(row['path']).resolve() for row in (result.inputs or []) if row.get('path')]
    images = [result.image or {}, *((result.image or {}).get('additional_images') or [])]
    for image in images:
        paths = (image.get('image') or {}).get('segments') or [image.get('image_path')]
        source_paths += [Path(p).resolve() for p in paths if p and not str(p).startswith(('\\\\.\\', '\\\\?\\'))]
    if any(source.parent == folder for source in source_paths):
        raise SaveSourceError('원본 증거와 같은 폴더에는 저장할 수 없습니다. 다른 폴더를 고르세요')
    original_events = result.events
    class CheckedEvents:
        def __len__(self):
            return len(original_events)

        def __getitem__(self, key):
            return original_events[key]

        def __iter__(self):
            for index, event in enumerate(original_events):
                if index % 256 == 0 and cancel and cancel():
                    raise SaveCancelled()
                yield event

    result = copy.copy(result)
    result.events = CheckedEvents()
    temporary = None
    published = []
    created = not folder.exists()

    def checkpoint(stage, ratio):
        if cancel and cancel():
            raise SaveCancelled()
        if progress:
            progress(stage, ratio)

    try:
        checkpoint('저장 준비', 0)
        existing = [n for n in OUTPUT_FILES if os.path.lexists(folder / n)]
        if existing:
            raise SaveExistsError(existing)
        folder.parent.mkdir(parents=True, exist_ok=True)
        # Published files must inherit the selected location's permissions, not
        # mkdtemp's private Windows ACL. Stage inside an existing destination so
        # hard-linked files inherit that directory's ACL as well.
        staging_parent = folder.parent if created else folder
        while True:
            candidate = staging_parent / ('.saving-' + uuid.uuid4().hex)
            try:
                candidate.mkdir(mode=0o777)
            except FileExistsError:
                continue
            temporary = candidate
            break
        checkpoint('분석 데이터 저장', .1)
        info = save_case(temporary / 'case.sqlite', result, name=name or folder.name,
                         tags=tags, sid_names=sid_names, inputs=inputs, settings=settings, sources=sources, cancel=cancel)
        checkpoint('보고서 저장', .4)
        export_reports(temporary, result.evidence, result.events, result.errors, result.relations,
                       result.summaries, tags, image=result.image, sid_names=sid_names)
        checkpoint('타임라인 저장', .65)
        export_json(result.events, temporary / 'timeline.json')
        export_bodyfile(result.events, temporary / 'timeline.bodyfile')
        if result.image:
            with (temporary / 'image_manifest.json').open('x', encoding='utf-8') as stream:
                json.dump(result.image, stream, ensure_ascii=False, indent=2)
        checkpoint('무결성 확인', .85)
        manifest = json.loads((temporary / 'case.sqlite.integrity.json').read_text(encoding='utf-8'))
        with _readonly((temporary / 'case.sqlite').resolve()) as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or _counts(db) != manifest['table_counts'] or manifest['table_counts']['events'] != len(result.events):
                raise SaveError('저장 검증에 실패했습니다. 새 폴더에 다시 저장하세요')
        if _hash(temporary / 'case.sqlite') != manifest['sha256']:
            raise SaveError('저장 파일 해시가 다릅니다. 새 폴더에 다시 저장하세요')
        checkpoint('저장 마무리', .95)
        if created:
            # A complete bundle appears with one directory rename on a fresh destination.
            if folder.exists():
                raise SaveExistsError([folder.name])
            temporary.rename(folder)
            temporary = None
            info.path = str(folder / 'case.sqlite')
            return SaveReport(folder, tuple(p.name for p in folder.iterdir()), info)
        # Hard links reserve each name exclusively, including against a competing save.
        # Roll back only the names this transaction created; never touch preexisting files.
        for source in temporary.iterdir():
            target = folder / source.name
            try:
                os.link(source, target)
            except FileExistsError:
                raise SaveExistsError([source.name]) from None
            published.append(target)
        info.path = str(folder / 'case.sqlite')
        return SaveReport(folder, tuple(p.name for p in published), info)
    except BaseException as exc:
        for target in reversed(published):
            target.unlink()
        if cancel and cancel():
            raise SaveCancelled() from exc
        if isinstance(exc, (SaveError, SaveSourceError)):
            raise
        if isinstance(exc, sqlite3.OperationalError) and 'full' in str(exc).lower():
            raise SaveSpaceError('저장 공간이 부족합니다. 공간을 확보하거나 다른 드라이브를 고르세요') from exc
        if isinstance(exc, OSError):
            if getattr(exc, 'winerror', None) in (32, 33):
                raise SaveLockedError('파일이 사용 중입니다. 파일을 연 프로그램을 닫고 다시 저장하세요') from exc
            if exc.errno == errno.ENOSPC:
                raise SaveSpaceError('저장 공간이 부족합니다. 공간을 확보하거나 다른 드라이브를 고르세요') from exc
            if exc.errno == errno.ENAMETOOLONG or getattr(exc, 'winerror', None) == 206:
                raise SavePathError('경로가 너무 깁니다. 더 짧은 저장 경로를 고르세요') from exc
            if isinstance(exc, PermissionError):
                raise SavePermissionError('저장 권한이 없습니다. 쓰기 가능한 다른 폴더를 고르세요') from exc
        raise
    finally:
        if temporary is not None:
            shutil.rmtree(temporary)
