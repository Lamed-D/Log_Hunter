# ▶ DB 조회: 원본 증거를 열지 않고 저장된 기록을 필요한 범위만 읽습니다.
"""Bounded relation membership, tree counts and statistics for CaseQuery."""
import json

from log_hunter.core.labels import CASE_DB_TEXT as T
from log_hunter.core.tree import ARTIFACT_CATEGORIES
from .case_db import _json
from .query_index import relation_summary
from . import query_filters as filters_sql
from .query_common import QueryInputError


def indices(relation):
    for key in ('left', 'right', 'event_indices', 'left_event_indices', 'right_event_indices'):
        if key in relation:
            values = relation[key] if isinstance(relation[key], list) else [relation[key]]
            for value in values:
                if type(value) is int and value >= 0:
                    yield value


class QueryDetails:
    def get_relations(self, event_id=None, *, offset=0, limit=500):
        self._check()
        self._bounds(offset, limit)
        condition, params = 'r.case_id=?', [self.case_id]
        table = 'relation_query_summaries' if self.indexed else 'relations'
        identity = 'r.relation_id' if self.indexed else 'r.id'
        if event_id is not None:
            if type(event_id) is not int:
                raise QueryInputError('event_id must be a database ID')
            if self.indexed:
                condition += ' AND EXISTS(SELECT 1 FROM relation_query_members m WHERE m.relation_id=r.relation_id AND m.case_id=r.case_id AND m.event_id=?)'
                params.append(event_id)
            else:
                row = self._fetch(self._execute('SELECT id FROM events WHERE id=? AND case_id=?', [event_id, self.case_id]), 1)
                if not row:
                    return []
                ordinal = self._fetch(self._execute('SELECT COUNT(*) FROM events WHERE case_id=? AND id<?', [self.case_id, event_id]), 1)
                if not ordinal:
                    return []
                def has_member(text, index):
                    try:
                        return int(index in indices(_json(text)))
                    except (TypeError, ValueError):
                        self._warn(T['damaged'].format(detail='relation membership'), True)
                        return 0
                self.db.create_function('lh_rel_has', 2, has_member)
                condition += ' AND lh_rel_has(r.data,?)=1'
                params.append(ordinal[0][0])
        extras = ',r.is_summary,r.stored_bytes,r.member_count' if self.indexed else ',0,length(CAST(r.data AS BLOB)),NULL'
        cursor = self._execute('SELECT ' + identity + ',r.data' + extras + ' FROM ' + table + ' r WHERE ' + condition +
                               ' ORDER BY ' + identity + ' LIMIT ? OFFSET ?', params + [limit, offset])
        result, size = [], 0
        for _ in range(limit):
            rows = self._fetch(cursor, 1)
            if not rows:
                break
            relation_id, text, is_summary, raw_size, member_count = rows[0]
            try:
                value = _json(text)
                if not isinstance(value, dict):
                    raise QueryInputError('relation must be an object')
                if not self.indexed:
                    member_count = len(set(indices(value)))
                    value, is_summary = relation_summary(value, raw_size)
                size += len(json.dumps(value, ensure_ascii=False).encode('utf-8'))
                if size > 16 * 1024 * 1024:
                    self._warn(T['limit'].format(detail='relation page bytes'), True)
                    break
                result.append({'relation_id': relation_id, 'data': value, 'data_is_summary': bool(is_summary),
                               'stored_bytes': raw_size, 'member_count': member_count})
            except (TypeError, ValueError) as exc:
                self._warn(T['damaged'].format(detail=str(exc)), True)
        return result

    def get_relation(self, relation_id, *, include_members=False):
        self._check()
        if type(relation_id) is not int:
            raise QueryInputError('relation_id must be a database ID')
        if include_members or not self.indexed:
            rows = self._fetch(self._execute('SELECT data,length(CAST(data AS BLOB)) FROM relations WHERE id=? AND case_id=?',
                                            [relation_id, self.case_id]), 1)
        else:
            rows = self._fetch(self._execute('SELECT data,stored_bytes,is_summary,member_count FROM relation_query_summaries '
                                            'WHERE relation_id=? AND case_id=?', [relation_id, self.case_id]), 1)
        if not rows:
            return None
        try:
            value = _json(rows[0][0])
            if not isinstance(value, dict):
                raise QueryInputError('relation must be an object')
            raw_size = rows[0][1]
            if not include_members and self.indexed:
                is_summary, member_count = bool(rows[0][2]), rows[0][3]
            else:
                member_count = len(set(indices(value)))
                is_summary = False
                if not include_members:
                    value, is_summary = relation_summary(value, raw_size)
            return {'relation_id': relation_id, 'data': value, 'data_is_summary': is_summary,
                    'stored_bytes': raw_size, 'member_count': member_count}
        except (TypeError, ValueError) as exc:
            self._warn(T['damaged'].format(detail=str(exc)), True)
            return None

    def relation_members(self, relation_id, *, offset=0, limit=500):
        self._check()
        self._bounds(offset, limit)
        if type(relation_id) is not int:
            raise QueryInputError('relation_id must be a database ID')
        if self.indexed:
            rows = self._fetch(self._execute('''SELECT event_id,MIN(position) FROM relation_query_members
                WHERE case_id=? AND relation_id=? GROUP BY event_id ORDER BY MIN(position),event_id LIMIT ? OFFSET ?''',
                [self.case_id, relation_id, limit, offset]), limit)
            page = self._ids_page([r[0] for r in rows])
            if page.event_ids:
                allowed = ','.join(str(i) for i in page.event_ids)
                roles = self._fetch(self._execute('SELECT event_id,role FROM relation_query_members WHERE case_id=? AND relation_id=? '
                                                 'AND event_id IN (' + allowed + ') ORDER BY event_id,role',
                                                 [self.case_id, relation_id]), len(page.event_ids) * 4)
                for event_id, role in roles:
                    page.member_roles.setdefault(event_id, []).append(role)
            return page
        raw = self._fetch(self._execute('SELECT data FROM relations WHERE id=? AND case_id=?', [relation_id, self.case_id]), 1)
        if not raw:
            return self._ids_page([])
        try:
            selected = list(dict.fromkeys(indices(_json(raw[0][0]))))[offset:offset + limit]
        except (TypeError, ValueError) as exc:
            self._warn(T['damaged'].format(detail=str(exc)), True)
            return self._ids_page([])
        if not selected:
            return self._ids_page([])
        sql = '''WITH numbered AS(SELECT id,ROW_NUMBER() OVER(ORDER BY id)-1 AS n FROM events WHERE case_id=?)
                 SELECT id,n FROM numbered WHERE n IN (''' + ','.join(str(i) for i in selected) + ')'
        rows = self._fetch(self._execute(sql, [self.case_id]), limit)
        mapping = {ordinal: event_id for event_id, ordinal in rows}
        if any(i not in mapping for i in selected):
            self._warn(T['damaged'].format(detail='relation references unavailable events'), True)
        return self._ids_page([mapping[i] for i in selected if i in mapping])

    def _groups(self, filters, select, group, *, maximum=1000, extra='1', extra_params=()):
        self._bounds(0, maximum)
        base, where, params = self._selection(filters, extra, extra_params)
        rows = self._fetch(self._execute('SELECT ' + select + ',COUNT(*) FROM ' + base + ' WHERE ' + where +
                          ' GROUP BY ' + group + ' ORDER BY ' + group + ' LIMIT ?', params + [maximum + 1]), maximum + 1)
        if len(rows) > maximum:
            self._warn(T['limit'].format(detail='aggregate groups'), True)
        return rows[:maximum]

    def _count_extra(self, filters, extra, params=()):
        base, where, values = self._selection(filters, extra, params)
        rows = self._fetch(self._execute('SELECT COUNT(*) FROM ' + base + ' WHERE ' + where, values), 1)
        return rows[0][0] if rows else None

    def tree_counts(self, filters=None, *, source_prefix=None, max_groups=1000):
        filters = filters_sql.normalize(filters)
        artifacts = self._groups(filters, 'q.artifact', 'q.artifact', maximum=max_groups)
        categories = {}
        for artifact, count in artifacts:
            key = next((key for key, _label, kinds in ARTIFACT_CATEGORIES if artifact in kinds), 'other')
            categories[key] = categories.get(key, 0) + count
        source_extra, source_params, depth = '1', [], 0
        if source_prefix is not None:
            source_extra, source_params = filters_sql.where({'node': {'kind': 'source', 'value': source_prefix}}, indexed=self.indexed)
            depth = len(source_prefix[1])
        self_records = self._count_extra(filters, '(' + source_extra + ') AND lh_parts_len(q.origin_parts)=' + str(depth), source_params)
        source_extra = '(' + source_extra + ') AND lh_parts_len(q.origin_parts)>' + str(depth)
        child = f'lh_child(q.origin_parts,{depth})'
        sources = self._groups(filters, 'q.origin_name,MIN(' + child + ')', 'q.origin_name,lh_fold(' + child + ')',
                               maximum=max_groups, extra=source_extra, extra_params=source_params)
        sids = self._groups(filters, 'q.sid,q.user_name', 'q.sid,q.user_name', maximum=max_groups,
                           extra="q.sid IS NOT NULL AND q.sid!=''")
        tags = {}
        for color in ('red', 'yellow', 'green'):
            clause, values = filters_sql.where({'tag': color}, indexed=self.indexed)
            tags[color] = self._count_extra(filters, clause, values)
        usb_records = self._groups(filters, 'q.device_kind,q.usb_hidden', 'q.device_kind,q.usb_hidden',
                                   maximum=max_groups, extra="q.artifact='usb'")
        base, where, params = self._selection(filters, "q.artifact='usb' AND q.physical_group IS NOT NULL AND q.physical_group!=''")
        sql = '''SELECT device_kind,usb_hidden,COUNT(*),SUM(physical_aux=0) FROM (
            SELECT c.*,ROW_NUMBER() OVER(PARTITION BY physical_group ORDER BY physical_rep DESC,
                   CASE WHEN physical_rep THEN event_id END DESC,event_id ASC) AS representative
            FROM (SELECT q.event_id,q.device_kind,q.usb_hidden,q.physical_group,q.physical_rep,q.physical_aux FROM ''' + base + ' WHERE ' + where + ''') c)
            WHERE representative=1 GROUP BY device_kind,usb_hidden ORDER BY device_kind,usb_hidden LIMIT ?'''
        group_cursor = self._execute(sql, params + [max_groups + 1])
        physical = self._fetch(group_cursor, max_groups + 1)
        if len(physical) > max_groups:
            self._warn(T['limit'].format(detail='USB kind groups'), True)
        return {'records': self.count_events(filters), 'artifacts': dict(artifacts), 'categories': categories,
                'source_self_records': self_records,
                'sources': [{'name': name, 'parts': json.loads(parts), 'records': count} for name, parts, count in sources],
                'users': [{'sid': sid, 'name': name, 'records': count} for sid, name, count in sids],
                'tag_colors': tags,
                'usb': {'records': [{'kind': kind, 'hidden': hidden, 'records': count} for kind, hidden, count in usb_records],
                        'groups': ([{'kind': kind, 'hidden': hidden, 'groups': count, 'physical_candidates': candidates}
                                    for kind, hidden, count, candidates in physical[:max_groups]] if group_cursor is not None else None)},
                'warnings': list(self.warnings), 'partial': self.partial}

    def statistics(self, filters=None):
        filters = filters_sql.normalize(filters)
        base, where, params = self._selection(filters)
        rows = self._fetch(self._execute("SELECT COUNT(*),COUNT(DISTINCT NULLIF(q.sid,'')),COUNT(DISTINCT NULLIF(q.process,'')),"
                           "COUNT(DISTINCT NULLIF(q.path,'')),COUNT(DISTINCT NULLIF(q.url,'')) FROM " + base + ' WHERE ' + where, params), 1)
        totals = rows[0] if rows else (None,) * 5
        artifacts = self._groups(filters, 'q.artifact', 'q.artifact')
        statuses = self._groups(filters, 'q.status', 'q.status')
        hours = self._groups(filters, 'q.clock_kind,substr(q.clock_value,12,2)', 'q.clock_kind,substr(q.clock_value,12,2)', extra='q.clock_kind<2')
        return {**dict(zip(('records', 'users', 'processes', 'files', 'urls'), totals)),
                'artifacts': dict(artifacts), 'statuses': dict(statuses),
                'hours': [{'clock_kind': clock, 'hour': hour, 'records': count} for clock, hour, count in hours],
                'warnings': list(self.warnings), 'partial': self.partial}
