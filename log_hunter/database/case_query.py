"""Read-only pages, relations and aggregates from saved case rows, never original evidence."""
import base64
import binascii
import copy
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from log_hunter.core.labels import CASE_DB_TEXT as T, CASE_QUERY_TEXT as Q
from log_hunter.core.models import ForensicEvent
from log_hunter.core.tree import ARTIFACT_CATEGORIES
from .case_db import SCHEMA_VERSION, CaseInfo, _construct, _json, _readonly, _tables, _verify
from .query_index import COLUMNS, QUERY_VERSION, context, projection, quick_fields
from . import query_filters as filters_sql
from .query_common import QueryInputError
from .query_details import QueryDetails

MAX_PAGE = 5000
MAX_PAGE_BYTES = 16 * 1024 * 1024


@dataclass
class EventPage:
    events: list = field(default_factory=list)
    event_ids: list = field(default_factory=list)
    next_cursor: str | None = None
    warnings: list = field(default_factory=list)
    partial: bool = False
    member_roles: dict = field(default_factory=dict)


def _bounds(offset, limit):
    if type(offset) is not int or not 0 <= offset < 2**63 or type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise QueryInputError('offset must be nonnegative; limit must be between 1 and 5000')


class CaseQuery(QueryDetails):
    _bounds = staticmethod(_bounds)
    def __init__(self, path, *, case_id=None):
        self.path = Path(path).resolve()
        self.warnings, self.partial = [], False
        self._warning_set = set()
        self._cache_data, self._cache_event, self._cache_projection = None, None, None
        self._state_context = None
        self.indexed, self.fts, self.case_id, self.name = False, False, None, ''
        self._manager, self.db = None, None
        self._closed = False
        self.schema_version = 0
        if case_id is not None and type(case_id) is not int:
            raise QueryInputError('case_id must be an integer')
        try:
            with self.path.open('rb') as stream:
                if stream.read(16) != b'SQLite format 3\0':
                    raise QueryInputError('not a SQLite case')
            stat = self.path.stat()
            wal = Path(str(self.path) + '-wal')
            wal_stat = wal.stat() if wal.exists() else None
            self._identity = [str(self.path), stat.st_size, stat.st_mtime_ns,
                              [wal_stat.st_size, wal_stat.st_mtime_ns] if wal_stat else None]
            self._manager = _readonly(self.path)
            self.db = self._manager.__enter__()
            self.db.execute('PRAGMA cache_size=-8192')
            self.db.execute('PRAGMA temp_store=FILE')
            self.db.create_function('lh_fold', 1, lambda s: str(s or '').casefold(), deterministic=True)
            self.db.create_function('lh_valid', 1, lambda data: int(self._decode(data) is not None))
            self.db.create_function('lh_qcol', 4, self._column)
            self.db.create_function('lh_quick', 3, self._quick)
            self.db.create_function('lh_tag', 2, self._tag)
            self.db.create_function('lh_parts_len', 1, lambda text: len(json.loads(text)))
            self.db.create_function('lh_child', 2, lambda text, depth: json.dumps(json.loads(text)[:depth + 1], ensure_ascii=False))
            names = _tables(self.db)
            selected = self.db.execute('SELECT id,name FROM cases ' + ('WHERE id=? ' if case_id is not None else '') +
                                       'ORDER BY id DESC LIMIT 1', (case_id,) if case_id is not None else ()).fetchone()
            if not selected:
                raise QueryInputError('case not found')
            self.case_id, self.name = selected
            if case_id is None and self.db.execute('SELECT COUNT(*) FROM cases').fetchone()[0] > 1:
                self._warn(T['multiple'])
            if 'meta' in names:
                v = self.db.execute("SELECT substr(value,1,32) FROM meta WHERE key='schema_version'").fetchone()
                try:
                    self.schema_version = int(v[0]) if v else 0
                except (ValueError, TypeError):
                    self._warn(T['damaged'].format(detail='schema version'), True)
                if self.schema_version > SCHEMA_VERSION:
                    self._warn(T['future'], True)
            if {'case_query_meta', 'event_query', 'event_query_tags', 'relation_query_members', 'relation_query_summaries'} <= names and self.schema_version <= SCHEMA_VERSION:
                row = self.db.execute('SELECT version,raw_events,indexed_events,rejected_relations,fts,tag_rows '
                                      'FROM case_query_meta WHERE case_id=?', (self.case_id,)).fetchone()
                if row and row[0] == QUERY_VERSION:
                    raw = self.db.execute('SELECT COUNT(*) FROM events WHERE case_id=?', (self.case_id,)).fetchone()[0]
                    count = self.db.execute('SELECT COUNT(*) FROM event_query WHERE case_id=?', (self.case_id,)).fetchone()[0]
                    tag_count = self.db.execute('SELECT COUNT(*) FROM examiner_tags').fetchone()[0] if 'examiner_tags' in names else 0
                    self.indexed = raw == count == row[1] == row[2] and tag_count == row[5]
                    self.fts = self.indexed and bool(row[4]) and 'event_search' in names
                    if row[3]:
                        self._warn(T['damaged'].format(detail='unavailable relation members'), True)
            if self.fts:
                try:
                    self.db.execute("SELECT rowid FROM event_search WHERE query_text LIKE '%LHFTSREADPROBE%' LIMIT 1").fetchone()
                except sqlite3.DatabaseError:
                    self.fts = False
                    self._warn(Q['search_fallback'])
            if not self.indexed:
                self._warn(Q['legacy'])
        except (OSError, ValueError) as exc:
            self.close()
            raise QueryInputError(T['invalid'].format(detail=str(exc))) from exc
        except sqlite3.DatabaseError as exc:
            self._warn(T['damaged'].format(detail=str(exc)), True)

    def _warn(self, message, partial=False):
        if len(self.warnings) < 256 and message not in self._warning_set:
            self.warnings.append(message)
            self._warning_set.add(message)
        self.partial |= partial

    def _check(self):
        if self._closed:
            raise QueryInputError(Q['closed'])
        try:
            stat = self.path.stat()
            wal = Path(str(self.path) + '-wal')
            w = wal.stat() if wal.exists() else None
            current = [str(self.path), stat.st_size, stat.st_mtime_ns, [w.st_size, w.st_mtime_ns] if w else None]
            if current != self._identity:
                raise QueryInputError(Q['changed'])
        except OSError as exc:
            raise QueryInputError(Q['unavailable']) from exc

    def _decode(self, data):
        if data == self._cache_data:
            return self._cache_event
        self._cache_data, self._cache_event, self._cache_projection = data, None, None
        try:
            info = CaseInfo()
            event = _construct(ForensicEvent, _json(data), info)
            for message in info.warnings:
                self._warn(message, info.partial)
            self._cache_event = event
        except (ValueError, TypeError, AttributeError) as exc:
            self._warn(T['damaged'].format(detail=str(exc)), True)
        return self._cache_event

    def _context(self):
        if self._state_context is None:
            state = {}
            if 'case_state' in _tables(self.db):
                row = self.db.execute('SELECT data FROM case_state WHERE case_id=?', (self.case_id,)).fetchone()
                if row:
                    try:
                        state = _json(row[0])
                    except (ValueError, TypeError):
                        self._warn(T['damaged'].format(detail='case state'), True)
            if not isinstance(state, dict):
                state = {}
            if 'examiner_tags' in _tables(self.db):
                state['tags'] = []
                for data, in self.db.execute('SELECT data FROM examiner_tags ORDER BY id'):
                    try:
                        state['tags'].append(_json(data))
                    except (ValueError, TypeError):
                        self._warn(T['damaged'].format(detail='tag'), True)
            try:
                self._state_context = context(state)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                self._warn(T['damaged'].format(detail=str(exc)), True)
                self._state_context = context({})
        return self._state_context

    def _column(self, event_id, case_id, data, key):
        event = self._decode(data)
        if event is None:
            return None
        if self._cache_projection is None or self._cache_projection[0][0] != event_id:
            self._cache_projection = projection(event_id, case_id, 0, event, self._context())
        return self._cache_projection[0][COLUMNS.index(key)]

    def _quick(self, data, user, needle):
        event = self._decode(data)
        return int(event is not None and any(needle in field for field in quick_fields(event, user)))

    def _tag(self, event_id, tag):
        row = self.db.execute('SELECT data,length(CAST(data AS BLOB)) FROM events WHERE id=? AND case_id=?', (event_id, self.case_id)).fetchone()
        if not row or self._column(event_id, self.case_id, row[0], 'event_id') is None:
            return 0
        tags = self._cache_projection[1]
        return int(any(t == tag or tag in ('red', 'yellow', 'green') and t.startswith(tag + '/') for t in tags))

    def _base(self):
        self._check()
        if self.indexed:
            return 'event_query q', 'q.case_id=?', [self.case_id]
        columns = ['e.id AS event_id', 'e.case_id AS case_id', '0 AS event_index']
        columns += ["lh_qcol(e.id,e.case_id,e.data,'" + key + "') AS " + key for key in COLUMNS[3:]]
        return ('(SELECT ' + ','.join(columns) + ' FROM events e WHERE e.case_id=? AND lh_valid(e.data)=1) q',
                '1', [self.case_id])

    def _selection(self, filters, extra='1', extra_params=()):
        base, initial, params = self._base()
        condition, values = filters_sql.where(filters, indexed=self.indexed, fts=self.fts)
        return base, '(' + initial + ') AND (' + condition + ') AND (' + extra + ')', params + values + list(extra_params)

    def _execute(self, sql, params):
        try:
            return self.db.execute(sql, params)
        except (sqlite3.DatabaseError, AttributeError) as exc:
            self._warn(T['damaged'].format(detail=str(exc)), True)
            return None

    def _fetch(self, cursor, limit):
        result = []
        if cursor is not None:
            try:
                for _ in range(limit):
                    row = cursor.fetchone()
                    if row is None:
                        break
                    result.append(row)
            except sqlite3.DatabaseError as exc:
                self._warn(T['damaged'].format(detail=str(exc)), True)
        return result

    def _ids_page(self, ids):
        page, total = EventPage(), 0
        for event_id in ids:
            rows = self._fetch(self._execute('SELECT data,length(CAST(data AS BLOB)) FROM events WHERE id=? AND case_id=?', [event_id, self.case_id]), 1)
            if not rows:
                self._warn(T['damaged'].format(detail='event payload unavailable'), True)
                continue
            data = rows[0][0]
            if total + rows[0][1] > MAX_PAGE_BYTES:
                self._warn(T['limit'].format(detail='page payload bytes'), True)
                break
            event = self._decode(data)
            if event is not None:
                page.events.append(copy.deepcopy(event))
                page.event_ids.append(event_id)
                total += rows[0][1]
        page.warnings, page.partial = list(self.warnings), self.partial
        return page

    def _cursor(self, sort, filters, values):
        data = json.dumps({'case': self.case_id, 'identity': self._identity, 'sort': sort,
                           'filters': filters_sql.fingerprint(filters), 'values': values}, ensure_ascii=False).encode('utf-8')
        if len(data) > 48000:
            self._warn(T['limit'].format(detail='cursor size'), True)
            return None
        return base64.urlsafe_b64encode(data).decode('ascii')

    def _after(self, token, sort, filters):
        try:
            if not isinstance(token, str) or len(token) > 65536:
                raise QueryInputError('cursor size')
            data = json.loads(base64.b64decode(token, altchars=b'-_', validate=True))
            if (data['case'] != self.case_id or data['identity'] != self._identity or data['sort'] != sort or
                    data['filters'] != filters_sql.fingerprint(filters)):
                raise QueryInputError('cursor belongs to another query or saved database')
            return filters_sql.seek(sort, data['values'])
        except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error) as exc:
            raise QueryInputError(Q['cursor']) from exc

    def query_events(self, filters=None, sort='timeline', offset=0, limit=500, *, after=None):
        _bounds(offset, limit)
        filters = filters_sql.normalize(filters)
        order = filters_sql.order(sort)
        extra, extra_params = self._after(after, sort, filters) if after is not None else ('1', [])
        if after is not None and offset:
            raise QueryInputError('use either after or offset')
        base, where, params = self._selection(filters, extra, extra_params)
        keys = ','.join(filters_sql.atom(key) for key, _ in filters_sql.SORTS[sort])
        rows = self._execute('SELECT q.event_id,' + keys + ' FROM ' + base + ' WHERE ' + where +
                             ' ORDER BY ' + order + ' LIMIT ? OFFSET ?', params + [limit + 1, offset])
        if rows is None:
            return EventPage(warnings=list(self.warnings), partial=True)
        selected = self._fetch(rows, limit + 1)
        page, bytes_read, last = EventPage(), 0, None
        more = len(selected) > limit
        for row in selected[:limit]:
            event_id = row[0]
            data = self._fetch(self._execute('SELECT data,length(CAST(data AS BLOB)) FROM events WHERE id=? AND case_id=?', [event_id, self.case_id]), 1)
            if not data:
                last = row[1:]
                self._warn(T['damaged'].format(detail='event payload unavailable'), True)
                continue
            if bytes_read + data[0][1] > MAX_PAGE_BYTES:
                self._warn(T['limit'].format(detail='page payload bytes; use a smaller page or get_event'), True)
                if not page.events:
                    last = row[1:]
                more = True
                break
            last = row[1:]
            event = self._decode(data[0][0])
            if event is not None:
                page.events.append(copy.deepcopy(event))
                page.event_ids.append(event_id)
                bytes_read += data[0][1]
        if more and last is not None:
            page.next_cursor = self._cursor(sort, filters, list(last))
        page.warnings, page.partial = list(self.warnings), self.partial
        return page

    def count_events(self, filters=None):
        base, where, params = self._selection(filters_sql.normalize(filters))
        rows = self._execute('SELECT COUNT(*) FROM ' + base + ' WHERE ' + where, params)
        values = self._fetch(rows, 1)
        return values[0][0] if values else None

    def get_event(self, event_id):
        self._check()
        if type(event_id) is not int:
            raise QueryInputError('event_id must be a database ID')
        row = self._execute('SELECT data,length(CAST(data AS BLOB)) FROM events WHERE id=? AND case_id=?', [event_id, self.case_id])
        rows = self._fetch(row, 1)
        return copy.deepcopy(self._decode(rows[0][0])) if rows else None

    def verify_integrity(self):
        self._check()
        if self.db is None:
            return {'database': {'status': 'unavailable'}}
        info = CaseInfo()
        _verify(self.db, self.path, info, True)
        for message in info.warnings:
            self._warn(message, info.partial)
        if info.verification.get('database', {}).get('status') in ('changed', 'invalid_manifest'):
            self.indexed = self.fts = False
            self._warn(Q['index_changed'], True)
        return info.verification

    def close(self):
        if not self._closed:
            self._closed = True
            if self._manager is not None and self.db is not None:
                self._manager.__exit__(None, None, None)
            self.db = None

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_args):
        self.close()


def open_case_query(path, *, case_id=None):
    return CaseQuery(path, case_id=case_id)
