# ▶ DB 조회: 원본 증거를 열지 않고 저장된 기록을 필요한 범위만 읽습니다.
"""Write disposable query projections without changing original event payloads."""
import json
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

from log_hunter.core.labels import action_label, artifact_label, status_label, time_field_label
from log_hunter.core.models import ForensicEvent
from log_hunter.core.sid_resolver import display_name
from log_hunter.core.tags import event_key, migrate_row
from log_hunter.core.tree import OriginIndex, usb_hidden

QUERY_VERSION = 1
COLUMNS = ('event_id', 'case_id', 'event_index', 'artifact', 'source', 'locator', 'sid', 'status',
           'timestamp', 'clock_kind', 'clock_value', 'path', 'process', 'url', 'user_name',
           'origin_name', 'origin_path', 'origin_parts', 'query_text', 'quick_text',
           'has_note', 'device_kind', 'physical_group', 'physical_rep', 'physical_aux', 'usb_hidden', 'task_signals', 'search_safe')


def clock_value(text):
    if text is None:
        return 3, ''
    if not isinstance(text, str) or not text or len(text) > 128:
        return 2, ''
    try:
        value = datetime.fromisoformat(text)
        aware = value.tzinfo is not None
        if aware:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return (0 if aware else 1), value.isoformat(timespec='microseconds')
    except (ValueError, OverflowError):
        return 2, ''


def quick_fields(event, user):
    target = event.path or event.process or event.url or event.details.get('command') or ''
    return tuple(str(f).lower() for f in (event.artifact, event.timestamp or '', event.action, target,
        event.sid or '', user, artifact_label(event.artifact), action_label(event.action),
        time_field_label(event.time_field) if event.time_field else '', status_label(event.status)))


def context(state):
    image = state.get('image') or {}
    image = image if isinstance(image, dict) else {}
    manifests = [image, *(image.get('additional_images') or [])]
    extractions = []
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        files = [f for f in manifest.get('files') or [] if isinstance(f, dict) and
                 isinstance(f.get('extracted'), str) and isinstance(f.get('image_path'), str) and 'volume' in f]
        extractions.append(SimpleNamespace(files=files, image=manifest.get('image') or {},
                                           image_path=manifest.get('image_path') or ''))
    names = {**(state.get('profiles') or {}), **(state.get('sid_names') or {})}
    tags = {}
    for row in state.get('tags') or []:
        try:
            tags[row['key']] = migrate_row(row)
        except (ValueError, TypeError, KeyError):
            continue
    return names, OriginIndex(extractions), tags


def projection(event_id, case_id, event_index, event, state_context):
    names, origins, tags = state_context
    category, clock = clock_value(event.timestamp)
    user = str(display_name(event.sid, names) or '')
    origin_name, parts = origins.origin(event.source)
    tag = tags.get(event_key(event), {})
    details = event.details
    quick = '\n'.join(quick_fields(event, user))
    values = (event_id, case_id, event_index, event.artifact, event.source, event.locator or '', event.sid,
              event.status, event.timestamp, category, clock, event.path or '', event.process or '', event.url or '',
              user, origin_name, '\\'.join(p.casefold() for p in parts), json.dumps(list(parts), ensure_ascii=False),
              str(event.to_dict()).casefold(), quick, int(bool(tag.get('note'))),
              str(details.get('device_kind') or 'unknown'),
              str(details['physical_device_id']) if details.get('physical_device_id') is not None else None,
              int(bool(details.get('physical_device_representative'))), int(bool(details.get('auxiliary_device'))), usb_hidden(details),
              int(bool(details.get('task_signals') or details.get('suspicion_flags'))), int('\0' not in quick))
    return values, tag.get('tags') or []



def relation_summary(relation, raw_size):
    if raw_size <= 256 * 1024:
        return relation, False
    result = dict(relation)
    result['member_counts'] = {}
    for key in ('event_indices', 'left_event_indices', 'right_event_indices'):
        values = result.pop(key, None)
        if isinstance(values, list):
            result['member_counts'][key] = len(values)
    evidence = relation.get('evidence_details')
    if isinstance(evidence, dict):
        evidence = dict(evidence)
        refs = evidence.pop('event_refs', [])
        evidence['event_ref_count'] = len(refs) if isinstance(refs, list) else None
        comparisons = evidence.get('comparisons')
        if isinstance(comparisons, list) and len(comparisons) > 20:
            evidence['comparisons'] = comparisons[:20]
            evidence['comparisons_truncated'] = True
            evidence['comparison_count'] = len(comparisons)
        grouping = evidence.get('grouping')
        if isinstance(grouping, dict) and isinstance(grouping.get('criteria'), dict):
            grouping = dict(grouping)
            criteria = dict(grouping['criteria'])
            for key in ('left_event_indices', 'right_event_indices'):
                values = criteria.pop(key, None)
                if isinstance(values, list):
                    criteria[key + '_count'] = len(values)
            grouping['criteria'] = criteria
            evidence['grouping'] = grouping
        result['evidence_details'] = evidence
    return result, True

def schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS event_query(
        event_id INTEGER PRIMARY KEY REFERENCES events(id), case_id INTEGER NOT NULL, event_index INTEGER NOT NULL,
        artifact TEXT NOT NULL, source TEXT NOT NULL, locator TEXT NOT NULL, sid TEXT, status TEXT NOT NULL,
        timestamp TEXT, clock_kind INTEGER NOT NULL, clock_value TEXT NOT NULL,
        path TEXT NOT NULL, process TEXT NOT NULL, url TEXT NOT NULL, user_name TEXT NOT NULL,
        origin_name TEXT NOT NULL, origin_path TEXT NOT NULL, origin_parts TEXT NOT NULL,
        query_text TEXT NOT NULL, quick_text TEXT NOT NULL, has_note INTEGER NOT NULL,
        device_kind TEXT NOT NULL, physical_group TEXT, physical_rep INTEGER NOT NULL, physical_aux INTEGER NOT NULL,
        usb_hidden TEXT, task_signals INTEGER NOT NULL,
        search_safe INTEGER NOT NULL)''')
    for name, columns in (('timeline', 'case_id,clock_kind,clock_value,artifact,source,locator,event_id'),
                          ('artifact', 'case_id,artifact,event_id'), ('sid', 'case_id,sid,event_id'),
                          ('status', 'case_id,status,event_id'), ('source', 'case_id,source,event_id'),
                          ('origin', 'case_id,origin_name,origin_path,event_id'),
                          ('ordinal', 'case_id,event_index')):
        db.execute(f'CREATE INDEX IF NOT EXISTS query_{name} ON event_query({columns})')
    db.execute('''CREATE TABLE IF NOT EXISTS event_query_tags(
        case_id INTEGER NOT NULL, event_id INTEGER NOT NULL REFERENCES events(id), tag TEXT NOT NULL,
        color TEXT NOT NULL, PRIMARY KEY(case_id,event_id,tag))''')
    db.execute('CREATE INDEX IF NOT EXISTS query_tag_color ON event_query_tags(case_id,color,event_id)')
    db.execute('CREATE INDEX IF NOT EXISTS query_tag ON event_query_tags(case_id,tag,event_id)')
    db.execute('''CREATE TABLE IF NOT EXISTS relation_query_members(
        relation_id INTEGER NOT NULL REFERENCES relations(id), case_id INTEGER NOT NULL,
        event_id INTEGER NOT NULL REFERENCES events(id), position INTEGER NOT NULL, role TEXT NOT NULL,
        PRIMARY KEY(relation_id,event_id,role))''')
    db.execute('CREATE INDEX IF NOT EXISTS query_member_event ON relation_query_members(case_id,event_id,relation_id)')
    db.execute('''CREATE TABLE IF NOT EXISTS relation_query_summaries(
        relation_id INTEGER PRIMARY KEY REFERENCES relations(id), case_id INTEGER NOT NULL,
        data TEXT NOT NULL, is_summary INTEGER NOT NULL, stored_bytes INTEGER NOT NULL, member_count INTEGER NOT NULL)''')
    db.execute('CREATE INDEX IF NOT EXISTS query_relation_case ON relation_query_summaries(case_id,relation_id)')
    db.execute('''CREATE TABLE IF NOT EXISTS case_query_meta(
        case_id INTEGER PRIMARY KEY, version INTEGER NOT NULL, raw_events INTEGER NOT NULL,
        indexed_events INTEGER NOT NULL, rejected_relations INTEGER NOT NULL, fts INTEGER NOT NULL, tag_rows INTEGER NOT NULL)''')
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ('events', 'relations', 'case_state', 'event_query', 'event_query_tags', 'examiner_tags'):
        if table not in names:
            continue
        for operation in ('INSERT', 'UPDATE', 'DELETE'):
            if table == 'examiner_tags':
                condition = ''
            elif operation == 'INSERT':
                condition = ' WHERE case_id=NEW.case_id'
            elif operation == 'DELETE':
                condition = ' WHERE case_id=OLD.case_id'
            else:
                condition = ' WHERE case_id IN (OLD.case_id,NEW.case_id)'
            db.execute(f'CREATE TRIGGER IF NOT EXISTS query_dirty_{table}_{operation} AFTER {operation} ON {table} '
                       'BEGIN UPDATE case_query_meta SET version=0' + condition + '; END')
    fts = False
    db.execute('SAVEPOINT optional_search')
    try:
        db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS event_search USING fts5(
            query_text,quick_text,content='event_query',content_rowid='event_id',tokenize='trigram',detail=none)""")
        fts = True
    except sqlite3.OperationalError:
        db.execute('ROLLBACK TO optional_search')
    finally:
        db.execute('RELEASE optional_search')
    return fts


def build_case_index(db, case_id, state, source_relations=None):
    """Called inside the case save transaction. Events and relation JSON are not rewritten."""
    from .case_db import CaseInfo, _construct, _json
    fts = schema(db)
    state = dict(state)
    if 'examiner_tags' in {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
        state['tags'] = [json.loads(r[0]) for r in db.execute('SELECT data FROM examiner_tags ORDER BY id')]
    ctx = context(state)
    raw_count, indexed_count, rejected = 0, 0, 0
    insert = 'INSERT INTO event_query(' + ','.join(COLUMNS) + ') VALUES(' + ','.join('?' for _ in COLUMNS) + ')'
    for event_index, (event_id, data) in enumerate(db.execute('SELECT id,data FROM events WHERE case_id=? ORDER BY id', (case_id,))):
        raw_count += 1
        try:
            event = _construct(ForensicEvent, _json(data), CaseInfo())
            values, tags = projection(event_id, case_id, event_index, event, ctx)
            db.execute(insert, values)
        except (ValueError, TypeError, AttributeError, sqlite3.InterfaceError):
            continue
        indexed_count += 1
        db.executemany('INSERT OR IGNORE INTO event_query_tags VALUES(?,?,?,?)',
                       ((case_id, event_id, tag, tag.partition('/')[0]) for tag in tags))
        if fts:
            db.execute('INSERT INTO event_search(rowid,query_text,quick_text) VALUES(?,?,?)',
                       (event_id, values[COLUMNS.index('query_text')], values[COLUMNS.index('quick_text')]))
    source = iter(source_relations) if isinstance(source_relations, (list, tuple)) else None
    for relation_id, raw_size in db.execute('SELECT id,length(CAST(data AS BLOB)) FROM relations WHERE case_id=? ORDER BY id', (case_id,)):
        try:
            relation = next(source) if source is not None else _json(db.execute('SELECT data FROM relations WHERE id=?', (relation_id,)).fetchone()[0])
            position = 0
            for key, role in (('left', 'left'), ('right', 'right'), ('event_indices', 'member'),
                              ('left_event_indices', 'anchor'), ('right_event_indices', 'right')):
                if key not in relation:
                    continue
                indices = relation[key] if isinstance(relation[key], list) else [relation[key]]
                for index in indices:
                    row = db.execute('SELECT event_id FROM event_query WHERE case_id=? AND event_index=?',
                                     (case_id, index)).fetchone() if type(index) is int else None
                    if row is None:
                        rejected += 1
                        continue
                    db.execute('INSERT OR IGNORE INTO relation_query_members VALUES(?,?,?,?,?)',
                               (relation_id, case_id, row[0], position, role))
                    position += 1
            summary, is_summary = relation_summary(relation, raw_size)
            count = db.execute('SELECT COUNT(DISTINCT event_id) FROM relation_query_members WHERE relation_id=?', (relation_id,)).fetchone()[0]
            db.execute('INSERT INTO relation_query_summaries VALUES(?,?,?,?,?,?)',
                       (relation_id, case_id, json.dumps(summary, ensure_ascii=False, sort_keys=True), int(is_summary), raw_size, count))
        except (TypeError, ValueError, AttributeError, StopIteration):
            rejected += 1
    tag_rows = db.execute('SELECT COUNT(*) FROM examiner_tags').fetchone()[0] if 'examiner_tags' in {
        r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} else 0
    db.execute('INSERT INTO case_query_meta VALUES(?,?,?,?,?,?,?)',
               (case_id, QUERY_VERSION, raw_count, indexed_count, rejected, int(fts), tag_rows))
    db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version','2')")
