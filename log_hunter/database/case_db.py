"""Complete case persistence and read-only, versioned restoration of saved analysis."""
import copy
import hashlib
import json
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path

from log_hunter import __version__
from log_hunter.core.labels import CASE_DB_TEXT as T
from log_hunter.core.models import Evidence, ForensicEvent, ParserError
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.tags import event_key, migrate_row
from .repository import Repository, ENTITY_TABLES

SCHEMA_VERSION = 2
MAX_ROWS = 1000000
MAX_JSON = 64 * 1024 * 1024
TABLES = ('cases', 'evidence_files', 'events', 'parser_errors', 'relations',
          *ENTITY_TABLES, 'entity_events', 'meta', 'case_state', 'examiner_tags',
          'event_query', 'event_query_tags', 'relation_query_members', 'relation_query_summaries', 'case_query_meta')
STATE_FIELDS = ('summaries', 'profiles', 'image', 'inputs', 'settings', 'tags', 'sid_names')


@dataclass
class CaseInfo:
    path: str = ''
    case_id: int | None = None
    name: str = ''
    created_at: str | None = None
    tool_version: str | None = None
    schema_version: int = 0
    inputs: list = field(default_factory=list)
    settings: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    sid_names: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
    verification: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    missing_fields: list = field(default_factory=list)
    partial: bool = False

    def to_dict(self):
        return asdict(self)


def _hash(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def _warn(info, message, partial=False):
    if len(info.warnings) < 256:
        info.warnings.append(message)
    info.partial |= partial


def _json(data):
    if len(data) > MAX_JSON:
        raise ValueError('JSON row exceeds safety limit')
    return json.loads(data)


def _tables(db):
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _counts(db):
    names = _tables(db)
    return {name: db.execute('SELECT COUNT(*) FROM ' + name).fetchone()[0]
            for name in TABLES if name in names}


def _sidecar(path):
    return Path(str(path) + '.integrity.json')


@contextmanager
def _readonly(path):
    """WAL snapshots are copied before opening; the original gets no shared-memory writes."""
    wal = Path(str(path) + '-wal')
    with tempfile.TemporaryDirectory() as temporary:
        selected = path
        if wal.exists() and wal.stat().st_size:
            import shutil
            selected = Path(temporary) / 'case.sqlite'
            shutil.copyfile(path, selected)
            shutil.copyfile(wal, str(selected) + '-wal')
            uri = selected.as_uri() + '?mode=ro'
        else:
            uri = path.as_uri() + '?mode=ro&immutable=1'
        db = sqlite3.connect(uri, uri=True)
        try:
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            yield db
        finally:
            db.close()


def _sources(result):
    sources = {}
    for item in result.evidence:
        sources[(item.source, 'file')] = {'path': item.source, 'resolved_path': str(Path(item.source).resolve()),
                                               'kind': 'file', 'expected_sha256': item.sha256 or None}
    images = [result.image or {}, *(result.image.get('additional_images') or [])]
    for image in images:
        details = image.get('image') or {}
        paths = details.get('segments') or ([image['image_path']] if image.get('image_path') else [])
        for path in paths:
            key = (str(path), 'image')
            if key in sources:
                continue
            digest = None
            try:
                if not str(path).startswith(('\\\\.\\', '\\\\?\\')) and Path(path).is_file():
                    digest = _hash(path)
            except (OSError, ValueError):
                pass
            sources[key] = {'path': str(path), 'resolved_path': str(Path(path).resolve()),
                            'kind': 'image', 'expected_sha256': digest}
    return list(sources.values())


def save_case(path, result, *, name=None, tags=None, inputs=None, settings=None, sid_names=None):
    """Save a new case in one data transaction, then record its closed-file digest and counts."""
    path = Path(path)
    if path.exists() or _sidecar(path).exists():
        raise FileExistsError(T['output_exists'])
    path.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the path exclusively before SQLite opens it; never replace an existing evidence file.
    with path.open('xb'):
        pass
    state = {key: copy.deepcopy(getattr(result, key)) for key in STATE_FIELDS}
    for key, value in (('tags', tags), ('inputs', inputs), ('settings', settings), ('sid_names', sid_names)):
        if value is not None:
            state[key] = copy.deepcopy(value)
    state.update(created_at=state['settings'].get('analysis_at') or datetime.now(timezone.utc).isoformat(),
                 tool_version=__version__, sources=_sources(result))
    repository = Repository(path)
    try:
        case_id = repository.save(name or path.stem, result.evidence, result.events, result.errors,
                                  result.relations, state=state, tags=state['tags'])
        counts = _counts(repository.connection)
    finally:
        repository.close()
    manifest = {'schema_version': SCHEMA_VERSION, 'sha256': _hash(path), 'table_counts': counts}
    with _sidecar(path).open('x', encoding='utf-8') as stream:
        json.dump(manifest, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')
    return CaseInfo(str(path.resolve()), case_id, name or path.stem, state['created_at'], __version__,
                    SCHEMA_VERSION, state['inputs'], state['settings'], state['tags'], state['sid_names'],
                    state['sources'], {'database': {'status': 'saved', **manifest}})


def _rows(db, table, info, case_id=None):
    if table not in _tables(db):
        return
    try:
        sql = 'SELECT data FROM ' + table
        params = ()
        if case_id is not None:
            sql += ' WHERE case_id=?'
            params = (case_id,)
        cursor = db.execute(sql + ' ORDER BY id', params)
        for index, (data,) in enumerate(cursor):
            if index >= MAX_ROWS:
                _warn(info, T['limit'].format(detail=table), True)
                return
            try:
                value = _json(data)
                if not isinstance(value, dict):
                    raise ValueError('expected object')
                yield index, value
            except (ValueError, TypeError) as exc:
                _warn(info, T['damaged'].format(detail=f'{table}[{index}]: {exc}'), True)
    except sqlite3.DatabaseError as exc:
        _warn(info, T['damaged'].format(detail=f'{table}: {exc}'), True)


def _construct(cls, data, info):
    allowed = {f.name for f in fields(cls)}
    unknown = data.keys() - allowed
    if unknown:
        _warn(info, T['damaged'].format(detail='unknown fields: ' + ', '.join(sorted(unknown))), True)
    result = cls(**{key: value for key, value in data.items() if key in allowed})
    required_strings = {Evidence: ('source', 'collected', 'sha256', 'method'),
                        ForensicEvent: ('artifact', 'source', 'action', 'status'),
                        ParserError: ('source', 'artifact', 'locator', 'message', 'severity')}[cls]
    if any(not isinstance(getattr(result, key), str) for key in required_strings):
        raise ValueError('record identity fields must be strings')
    optional_strings = ('timestamp', 'time_field', 'sid', 'path', 'process', 'url', 'locator') if cls is ForensicEvent else ()
    if any(getattr(result, key) is not None and not isinstance(getattr(result, key), str) for key in optional_strings):
        raise ValueError('record text fields must be strings or null')
    if hasattr(result, 'details') and not isinstance(result.details, dict):
        raise ValueError('event details must be an object')
    if hasattr(result, 'metadata') and not isinstance(result.metadata, dict):
        raise ValueError('evidence metadata must be an object')
    return result


def _remap(relation, mapping):
    result = copy.deepcopy(relation)
    for key in ('left', 'right'):
        if key in result:
            if type(result[key]) is not int or result[key] not in mapping:
                return None
            result[key] = mapping[result[key]]
    for key in ('event_indices', 'left_event_indices', 'right_event_indices'):
        if key in result:
            if not isinstance(result[key], list) or any(type(i) is not int or i not in mapping for i in result[key]):
                return None
            result[key] = list(dict.fromkeys(mapping[i] for i in result[key]))
    details = result.get('evidence_details')
    if isinstance(details, dict):
        for key in ('event_refs', 'comparisons'):
            for ref in details.get(key, []):
                if isinstance(ref, dict) and 'event_index' in ref:
                    if type(ref['event_index']) is not int or ref['event_index'] not in mapping:
                        return None
                    ref['event_index'] = mapping[ref['event_index']]
        criteria = details.get('grouping', {}).get('criteria', {})
        if isinstance(criteria, dict) and 'left_event_indices' in criteria:
            indices = criteria['left_event_indices']
            if any(type(i) is not int or i not in mapping for i in indices):
                return None
            criteria['left_event_indices'] = [mapping[i] for i in indices]
    return result


def _verify(db, path, info, verify):
    actual = {'sha256': _hash(path)}
    try:
        actual['table_counts'] = _counts(db)
        check = db.execute('PRAGMA quick_check(1)').fetchone()[0] if verify else 'not_checked'
        actual['sqlite_check'] = check
        if check not in ('ok', 'not_checked'):
            _warn(info, T['damaged'].format(detail=check), True)
    except sqlite3.DatabaseError as exc:
        actual['sqlite_check'] = str(exc)
        _warn(info, T['damaged'].format(detail=str(exc)), True)
    status, expected = 'unknown', None
    try:
        sidecar = _sidecar(path)
        if sidecar.exists():
            if sidecar.stat().st_size > 4 * 1024 * 1024:
                raise ValueError('oversized manifest')
            expected = json.loads(sidecar.read_text(encoding='utf-8'))
            status = 'match' if (actual.get('sha256') == expected['sha256'] and
                                actual.get('table_counts') == expected['table_counts']) else 'changed'
            if status == 'changed':
                _warn(info, T['integrity_changed'])
        else:
            _warn(info, T['integrity_missing'])
    except (OSError, ValueError, TypeError, KeyError):
        status = 'invalid_manifest'
        _warn(info, T['integrity_invalid'])
    info.verification = {'database': {'status': status, 'actual': actual, 'expected': expected}}


def _check_sources(info, verify):
    for source in info.sources:
        path = source.get('resolved_path') or source.get('path')
        source.update(status='not_checked', actual_sha256=None)
        try:
            if not isinstance(path, str) or path.startswith(('\\\\.\\', '\\\\?\\')):
                source['status'] = 'unavailable'
                continue
            if not Path(path).is_absolute():
                source['status'] = 'unavailable'
                _warn(info, T['source_unreadable'].format(path=path))
            elif not Path(path).is_file():
                source['status'] = 'missing'
                _warn(info, T['source_missing'].format(path=path))
            elif verify and source.get('expected_sha256'):
                source['actual_sha256'] = _hash(path)
                source['status'] = 'match' if source['actual_sha256'] == source['expected_sha256'] else 'changed'
                if source['status'] == 'changed':
                    _warn(info, T['source_changed'].format(path=path))
            else:
                source['status'] = 'present_unverified'
        except (OSError, ValueError):
            source['status'] = 'unavailable'
            _warn(info, T['source_unreadable'].format(path=path))


def load_case(path, *, verify=False, case_id=None):
    """Restore rows in memory only; unsupported or damaged information never becomes a false result."""
    path = Path(path).resolve()
    try:
        with path.open('rb') as stream:
            if stream.read(16) != b'SQLite format 3\0':
                raise ValueError('not a SQLite case')
    except (OSError, ValueError) as exc:
        raise ValueError(T['invalid'].format(detail=str(exc))) from exc
    if case_id is not None and type(case_id) is not int:
        raise ValueError(T['invalid'].format(detail='case_id must be an integer'))
    result, info = AnalysisResult(), CaseInfo(path=str(path))
    try:
        with _readonly(path) as db:
            names = _tables(db)
            if 'cases' not in names:
                raise ValueError(T['invalid'].format(detail='missing cases table'))
            cases = db.execute('SELECT id,name FROM cases ORDER BY id DESC').fetchall()
            selected = next((r for r in cases if case_id is None or r[0] == case_id), None)
            if selected is None:
                raise ValueError(T['invalid'].format(detail='case not found'))
            info.case_id, info.name = selected
            if case_id is None and len(cases) > 1:
                _warn(info, T['multiple'])
            if 'meta' in names:
                version = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                try:
                    info.schema_version = int(version[0]) if version else 0
                except (ValueError, TypeError):
                    _warn(info, T['damaged'].format(detail='invalid schema version'), True)
            if info.schema_version == 0:
                _warn(info, T['legacy'])
            elif info.schema_version > SCHEMA_VERSION:
                _warn(info, T['future'], True)
            state = {}
            if 'case_state' in names:
                row = db.execute('SELECT data FROM case_state WHERE case_id=?', (info.case_id,)).fetchone()
                if row:
                    try:
                        state = _json(row[0])
                        if not isinstance(state, dict):
                            raise ValueError('case state must be an object')
                    except (ValueError, TypeError) as exc:
                        state = {}
                        _warn(info, T['damaged'].format(detail=str(exc)), True)
            for key in STATE_FIELDS:
                if key in state and isinstance(state[key], type(getattr(result, key))):
                    setattr(result, key, state[key])
                else:
                    info.missing_fields.append(key)
                    _warn(info, T['missing'].format(field=key), key in state)
            if result.image and (not isinstance(result.image.get('image', {}), dict) or
                                 not isinstance(result.image.get('files', []), list) or
                                 any(not isinstance(f, dict) for f in result.image.get('files', []))):
                result.image = {}
                _warn(info, T['damaged'].format(detail='invalid image manifest'), True)
            info.created_at, info.tool_version = state.get('created_at'), state.get('tool_version')
            saved_sources = state.get('sources', [])
            info.sources = [s for s in saved_sources if isinstance(s, dict)] if isinstance(saved_sources, list) else []
            event_mapping = {}
            for table, cls, target in (('evidence_files', Evidence, result.evidence),
                                       ('events', ForensicEvent, result.events),
                                       ('parser_errors', ParserError, result.errors)):
                for old_index, data in _rows(db, table, info, info.case_id):
                    try:
                        value = _construct(cls, data, info)
                        if table == 'events':
                            event_mapping[old_index] = len(target)
                        target.append(value)
                    except (TypeError, ValueError) as exc:
                        _warn(info, T['damaged'].format(detail=f'{table}[{old_index}]: {exc}'), True)
            for _, relation in _rows(db, 'relations', info, info.case_id):
                try:
                    remapped = _remap(relation, event_mapping)
                    if remapped is None:
                        raise ValueError('relation references an unavailable event')
                    result.relations.append(remapped)
                except (TypeError, ValueError, AttributeError) as exc:
                    _warn(info, T['damaged'].format(detail=str(exc)), True)
            if 'examiner_tags' in names:
                result.tags = []
                for _, row in _rows(db, 'examiner_tags', info):
                    try:
                        if not isinstance(row.get('key'), str) or not isinstance(row.get('tags', []), list):
                            raise ValueError('invalid tag identity or list')
                        result.tags.append(migrate_row(row))
                    except (ValueError, TypeError) as exc:
                        _warn(info, T['damaged'].format(detail=str(exc)), True)
            if not info.sources:
                # A legacy DB has evidence file hashes, but never invent an absent image digest.
                info.sources = [{'path': e.source, 'kind': 'file', 'expected_sha256': e.sha256 or None}
                                for e in result.evidence]
            _verify(db, path, info, verify)
    except (sqlite3.DatabaseError, OSError, TypeError) as exc:
        _warn(info, T['damaged'].format(detail=str(exc)), True)
    info.inputs, info.settings, info.tags, info.sid_names = result.inputs, result.settings, result.tags, result.sid_names
    _check_sources(info, verify)
    return result, info


def merge_results(existing, additional):
    """Merge without mutating either run; record identity is the existing content fingerprint contract."""
    merged = copy.deepcopy(existing)
    evidence_keys = {(e.source, e.sha256, json.dumps(e.metadata.get('snapshot'), sort_keys=True)) for e in merged.evidence}
    for e in additional.evidence:
        key = (e.source, e.sha256, json.dumps(e.metadata.get('snapshot'), sort_keys=True))
        if key not in evidence_keys:
            merged.evidence.append(copy.deepcopy(e))
            evidence_keys.add(key)
    event_keys = {event_key(e): i for i, e in enumerate(merged.events)}
    mapping = {}
    for i, event in enumerate(additional.events):
        key = event_key(event)
        if key not in event_keys:
            event_keys[key] = len(merged.events)
            merged.events.append(copy.deepcopy(event))
        mapping[i] = event_keys[key]
    seen_relations = {json.dumps(r, sort_keys=True) for r in merged.relations}
    for relation in additional.relations:
        value = _remap(relation, mapping)
        if value is None:
            raise ValueError('additional relation references an unavailable event')
        key = json.dumps(value, sort_keys=True)
        if key not in seen_relations:
            merged.relations.append(value)
            seen_relations.add(key)
    for key in ('errors', 'summaries', 'inputs'):
        values = getattr(merged, key)
        seen = {json.dumps(asdict(v) if hasattr(v, '__dataclass_fields__') else v, sort_keys=True) for v in values}
        for value in getattr(additional, key):
            encoded = json.dumps(asdict(value) if hasattr(value, '__dataclass_fields__') else value, sort_keys=True)
            if encoded not in seen:
                values.append(copy.deepcopy(value))
                seen.add(encoded)
    merged.profiles.update(additional.profiles)
    merged.sid_names.update(additional.sid_names)
    if additional.image and additional.image != merged.image:
        images = merged.image.setdefault('additional_images', [])
        if additional.image not in images:
            images.append(copy.deepcopy(additional.image))
    for key, value in additional.settings.items():
        if key not in merged.settings:
            merged.settings[key] = copy.deepcopy(value)
    if any(existing.settings.get(k) != v for k, v in additional.settings.items()):
        runs = merged.settings.setdefault('additional_analyses', [])
        if additional.settings not in runs:
            runs.append(copy.deepcopy(additional.settings))
    tags = {r['key']: copy.deepcopy(r) for r in merged.tags}
    for row in additional.tags:
        if row['key'] not in tags:
            tags[row['key']] = copy.deepcopy(row)
        else:
            target = tags[row['key']]
            labels = dict(zip(target.get('tags', []), target.get('tag_labels', [])))
            labels.update(zip(row.get('tags', []), row.get('tag_labels', [])))
            target['tags'] = sorted(set(target.get('tags', [])) | set(row.get('tags', [])))
            target['tag_labels'] = [labels.get(tag, tag) for tag in target['tags']]
            target['updated_at'] = max(target.get('updated_at', ''), row.get('updated_at', ''))
            notes = list(dict.fromkeys(n for n in (target.get('note'), row.get('note')) if n))
            target['note'] = '\n\n'.join(notes)
    merged.tags = list(tags.values())
    return merged
