# ▶ DB 조회: 원본 증거를 열지 않고 저장된 기록을 필요한 범위만 읽습니다.
"""Translate existing display-filter semantics to bound SQLite predicates."""
import hashlib
import json
from dataclasses import asdict, is_dataclass

from log_hunter.core.labels import artifact_from_label, STATUS_LABELS
from log_hunter.core.timeline import parse_filter_date
from .query_index import clock_value
from .query_common import QueryInputError

FILTER_KEYS = {'artifact', 'start', 'end', 'sid', 'query', 'search', 'status', 'node', 'tag', 'event_ids'}
SORTS = {'timeline': (('clock_kind', False), ('clock_value', False), ('artifact', False),
                      ('source', False), ('locator', False), ('event_id', False)),
         '-timeline': (('clock_kind', False), ('clock_value', True), ('artifact', False),
                       ('source', False), ('locator', False), ('event_id', False))}
for _key in ('artifact', 'source', 'sid', 'status'):
    SORTS[_key] = ((_key, False), ('event_id', False))
    SORTS['-' + _key] = ((_key, True), ('event_id', False))


def normalize(filters):
    if filters is None:
        return {}
    filters = asdict(filters) if is_dataclass(filters) else dict(filters)
    if filters.keys() - FILTER_KEYS:
        raise QueryInputError('unsupported filters: ' + ', '.join(sorted(filters.keys() - FILTER_KEYS)))
    filters = {k: v for k, v in filters.items() if v is not None and v != ''}
    for key in ('artifact', 'start', 'end', 'sid', 'query', 'search', 'status', 'tag'):
        if key in filters and not isinstance(filters[key], str):
            raise QueryInputError('filter must be text: ' + key)
    if filters.get('artifact') == '\uc804\uccb4':
        filters.pop('artifact')
    if filters.get('status') == '\uc804\uccb4':
        filters.pop('status')
    if 'node' in filters:
        node = filters['node']
        if is_dataclass(node):
            node = {'kind': node.kind, 'value': node.value}
        if not isinstance(node, dict) or node.keys() - {'kind', 'value'}:
            raise QueryInputError('node requires kind/value')
        filters['node'] = node
    if 'event_ids' in filters:
        ids = filters['event_ids']
        if not isinstance(ids, (list, tuple)) or len(ids) > 10000 or any(
                type(i) is not int or not -2**63 <= i < 2**63 for i in ids):
            raise QueryInputError('event_ids requires up to 10000 database IDs')
        filters['event_ids'] = list(ids)
    return filters


def fingerprint(filters):
    return hashlib.sha256(json.dumps(filters, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


def atom(key):
    return "COALESCE(q.sid,'')" if key == 'sid' else 'q.' + key


def order(sort):
    if sort not in SORTS:
        raise QueryInputError('unsupported sort')
    return ','.join(atom(key) + (' DESC' if descending else ' ASC') for key, descending in SORTS[sort])


def seek(sort, values):
    if len(values) != len(SORTS[sort]):
        raise QueryInputError('invalid cursor keys')
    for value, (key, _) in zip(values, SORTS[sort]):
        if key in ('event_id', 'clock_kind'):
            if type(value) is not int or not -2**63 <= value < 2**63 or key == 'clock_kind' and value not in (0, 1, 2, 3):
                raise QueryInputError('invalid integer cursor key')
        elif not isinstance(value, str):
            raise QueryInputError('invalid text cursor key')
    clauses, params = [], []
    for i, (key, descending) in enumerate(SORTS[sort]):
        prefix = []
        for previous, (name, _) in enumerate(SORTS[sort][:i]):
            prefix.append(atom(name) + '=?')
            params.append(values[previous])
        prefix.append(atom(key) + ('<?' if descending else '>?'))
        params.append(values[i])
        clauses.append('(' + ' AND '.join(prefix) + ')')
    return '(' + ' OR '.join(clauses) + ')', params


def where(filters, *, indexed, fts=False, tag_match=None):
    clauses, params = [], []
    def add(sql, *values):
        clauses.append(sql)
        params.extend(values)
    artifact = filters.get('artifact')
    if artifact:
        add('q.artifact=?', artifact_from_label(artifact))
    sid = filters.get('sid', '').strip()
    if sid:
        add('q.sid=?', sid) if sid.upper().startswith('S-1-') else add('instr(lh_fold(q.user_name),?)>0', sid.casefold())
    status = filters.get('status')
    if status:
        internal = [k for k, v in STATUS_LABELS.items() if v == status]
        values = internal or [status]
        add('q.status IN (' + ','.join('?' for _ in values) + ')', *values)
    for key, operator in (('start', '>='), ('end', '<=')):
        if filters.get(key):
            category, value = clock_value(parse_filter_date(filters[key], end=key == 'end'))
            if category >= 2:
                add('0')
            else:
                add('q.clock_kind=?' if category == 0 else 'q.clock_kind<2', *([0] if category == 0 else []))
                add('q.clock_value' + operator + '?', value)
    for key, column in (('query', 'query_text'), ('search', 'quick_text')):
        if not filters.get(key):
            continue
        needle = filters[key].casefold() if key == 'query' else filters[key].lower()
        if fts and len(needle) >= 3 and '\0' not in needle:
            add('(q.search_safe=0 OR q.event_id IN (SELECT rowid FROM event_search WHERE ' + column + ' LIKE ?))',
                '%' + needle + '%')
        if key == 'query':
            add('instr(q.query_text,?)>0', needle)
        else:
            add('lh_quick((SELECT data FROM events WHERE id=q.event_id),q.user_name,?)=1', needle)
    if 'event_ids' in filters:
        add('q.event_id IN (' + ','.join(str(i) for i in filters['event_ids']) + ')' if filters['event_ids'] else '0')
    node = filters.get('node')
    if node:
        kind, value = node.get('kind'), node.get('value')
        if kind == 'all' or (kind == 'source' and value is None):
            pass
        elif kind == 'artifacts':
            if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
                raise QueryInputError('artifact node requires artifact keys')
            add('q.artifact IN (' + ','.join('?' for _ in value) + ')' if value else '0', *value)
        elif kind == 'account':
            if value is not None and not isinstance(value, str):
                raise QueryInputError('account node requires a SID')
            add('q.sid IS NULL') if value is None else add('q.sid=?', value)
        elif kind == 'source':
            if not isinstance(value, (list, tuple)) or len(value) != 2 or not isinstance(value[0], str) or not isinstance(value[1], (list, tuple)):
                raise QueryInputError('source node requires name and path parts')
            if not all(isinstance(p, str) for p in value[1]):
                raise QueryInputError('source path parts must be strings')
            prefix = '\\'.join(p.casefold() for p in value[1])
            add('q.origin_name=?', value[0])
            if prefix:
                add('(q.origin_path=? OR instr(q.origin_path,?)=1)', prefix, prefix + '\\')
        elif kind == 'device_kind':
            if not isinstance(value, (list, tuple)) or len(value) != 2 or not all(isinstance(v, str) for v in value):
                raise QueryInputError('device node requires artifact and kind')
            add('q.artifact=? AND q.device_kind=? AND q.usb_hidden IS NULL', *value)
        elif kind == 'usb_device':
            if not isinstance(value, str):
                raise QueryInputError('USB group requires a recorded group ID')
            add("q.artifact='usb' AND q.physical_group=?", value)
        elif kind == 'usb_hidden':
            if value is not None and not isinstance(value, str):
                raise QueryInputError('USB hidden category must be text')
            add("q.artifact='usb' AND q.usb_hidden IS NULL") if value is None else add("q.artifact='usb' AND q.usb_hidden=?", value)
        elif kind == 'task_signals':
            add("q.artifact IN ('tasks','taskcache') AND q.task_signals=1")
        else:
            raise QueryInputError('unsupported tree node; event_set requires database event_ids')
    tag = filters.get('tag')
    if tag:
        if tag == 'note':
            add('q.has_note=1')
        elif indexed:
            field = 'color' if tag in ('red', 'yellow', 'green') else 'tag'
            add('EXISTS(SELECT 1 FROM event_query_tags t WHERE t.case_id=q.case_id AND t.event_id=q.event_id AND t.' + field + '=?)', tag)
        else:
            add('lh_tag(q.event_id,?)=1', tag)
    return (' AND '.join(clauses) or '1'), params
