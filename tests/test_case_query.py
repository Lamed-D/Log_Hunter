"""Database queries match loaded GUI filters without materializing a whole analysis."""
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from log_hunter.core.labels import artifact_label, status_label
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.tags import TagBook, event_key, event_ref, save_to_sqlite
from log_hunter.core.timeline import timeline
from log_hunter.core.tree import TreeNode, OriginIndex
from log_hunter.database.case_db import save_case, load_case
from log_hunter.database.case_query import open_case_query
from log_hunter.database.repository import Repository
from log_hunter.ui.view_model import Filters, filter_events, matches_search

SID = 'S-1-5-21-1000-2000-3000-1001'


def result_fixture():
    source = r'C:\Evidence\extracted\a.dat'
    clocks = ('2024-01-01T00:00:00+00:00', '2024-01-01T10:00:00+09:00',
              '2024-01-01T00:00:00', '2024-01-02T00:00:00Z', 'bad', '', None)
    events = [ForensicEvent('psreadline', source, 'command_history', timestamp=t,
        time_field='last_execution' if t else None, sid=SID, locator=f'line:{i}',
        status=('ok','warning','partial')[i % 3], details={'command': f'Write-Output example-{i}'})
        for i, t in enumerate(clocks)]
    events += [
        ForensicEvent('test', source, 'test', path=r'C:\Users\alice\Straße.exe', sid=SID),
        ForensicEvent('test', source, 'test', path='abc\0hiddenNeedle'),
        ForensicEvent('test', source, 'test', path='100% and a_b literal'),
        ForensicEvent('test', source, 'test', path='100X and acb different'),
        ForensicEvent('usb', r'C:\Evidence\USB.dat', 'device_registration',
            details={'device_kind': 'keyboard', 'physical_device_id': 'usb:0', 'physical_device_representative': True}),
        ForensicEvent('usb', r'C:\Evidence\USB.dat', 'last_arrival',
            details={'device_kind': 'keyboard', 'physical_device_id': 'usb:0'}),
        ForensicEvent('usb', r'C:\Evidence\USB.dat', 'device_registration', details={'device_kind': 'unknown',
            'physical_device_id': 'usb:1', 'auxiliary_device': True, 'device_inventory_visible': False}),
        ForensicEvent('taskcache', source, 'task_registration', sid='S-1-5-18',
            details={'task_signals': [{'code': 'xml_not_matched'}]}),
        ForensicEvent('tasks', source, 'task_registration'),
    ]
    book = TagBook()
    for index, color in ((0, 'red'), (1, 'red/sub'), (2, 'green')):
        event = events[index]
        book.toggle(event_key(event), 'event', event_ref(event), color)
    book.set_note(event_key(events[3]), 'event', event_ref(events[3]), 'generated note')
    image = {'image_path': r'C:\Evidence\fictional.img', 'image': {}, 'files': [
        {'extracted': source, 'image_path': r'\Users\alice\A.dat', 'volume': 0}]}
    return AnalysisResult(events=events, profiles={SID: 'StraßeUser'}, sid_names={SID: 'StraßeUser'},
        image=image, tags=book.rows(), settings={'analysis_at': '2026-01-01T00:00:00+00:00'},
        relations=[{'type': 'pair', 'left': 0, 'right': 1},
                   {'type': 'correlation_group', 'event_indices': list(range(len(events))), 'left_event_indices': [0, 5]}])


class CaseQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'case.sqlite'
        self.original = result_fixture()
        save_case(self.path, self.original)
        self.loaded, _ = load_case(self.path)
        self.origins = OriginIndex([SimpleNamespace(**self.original.image)])

    def snapshot(self):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.iterdir() if p.is_file()}

    def test_default_timeline_and_counts_equal_loaded_results(self):
        with open_case_query(self.path) as query:
            self.assertTrue(query.indexed)
            self.assertEqual(query.query_events().events, timeline(self.loaded.events))
            self.assertEqual(query.count_events(), len(self.loaded.events))
            self.assertEqual(query.query_events().event_ids, query.query_events().event_ids)
            self.assertFalse(query.partial)

    def test_gui_date_user_artifact_status_and_raw_query_equivalence(self):
        choices = [Filters(), Filters(artifact=artifact_label('psreadline')),
            Filters(start='2024-01-01', end='2024-01-01'),
            Filters(start='2024-01-01T00:00:00+09:00'), Filters(end='2024-01-01 00:00'),
            Filters(start='invalid'), Filters(sid=SID), Filters(sid='STRASSE'), Filters(sid='시스템'),
            Filters(query='straße'), Filters(query='100%'), Filters(status=status_label('warning'))]
        with open_case_query(self.path) as query:
            for filters in choices:
                with self.subTest(filters=filters):
                    expected = filter_events(self.loaded.events, filters, names=self.loaded.sid_names)
                    self.assertEqual(query.query_events(filters).events, expected)
                    self.assertEqual(query.count_events(filters), len(expected))

    def test_tree_filters_and_case_insensitive_original_path(self):
        nodes = [TreeNode('x', 'x', 'artifacts', ('tasks','taskcache')),
            TreeNode('x','x','account',SID), TreeNode('x','x','task_signals'),
            TreeNode('x','x','device_kind',('usb','keyboard')), TreeNode('x','x','usb_hidden','auxiliary'),
            TreeNode('x','x','usb_device','usb:0'),
            TreeNode('x','x','source',('fictional.img', ('볼륨 0','users','ALICE')))]
        with open_case_query(self.path) as query:
            for node in nodes:
                with self.subTest(node=node.kind):
                    expected = filter_events(self.loaded.events, Filters(), node, self.origins, self.loaded.sid_names)
                    self.assertEqual(query.query_events({'node':node}).events, expected)

    def test_quick_search_has_exact_label_unicode_literal_and_nul_semantics(self):
        with open_case_query(self.path) as query:
            backend = query.fts
            for text in ('시스템', 'STRASSE', 'straße', 'hiddenNeedle', '100%', 'a_b',
                         "x' OR 1=1 --", 'psreadline\n2024', 'example-1'):
                expected = [e for e in timeline(self.loaded.events)
                            if matches_search(e, text.lower(), self.loaded.sid_names)]
                with self.subTest(text=text):
                    query.fts = backend
                    self.assertEqual(query.query_events({'search':text}).events, expected)
                    query.fts = False
                    self.assertEqual(query.query_events({'search':text}).events, expected)

    def test_keyset_pages_are_stable_for_each_sort_and_reject_other_queries(self):
        with open_case_query(self.path) as query:
            for sort in ('timeline','-timeline','artifact','-artifact','source','-source','sid','-sid','status','-status'):
                expected = query.query_events(sort=sort).event_ids
                actual, cursor = [], None
                while True:
                    page = query.query_events(sort=sort, limit=3, after=cursor)
                    actual += page.event_ids
                    cursor = page.next_cursor
                    if cursor is None:
                        break
                self.assertEqual(actual, expected)
                self.assertEqual(len(actual), len(set(actual)))
            cursor = query.query_events(limit=2).next_cursor
            with self.assertRaises(ValueError):
                query.query_events({'query':'different'}, after=cursor)
            with self.assertRaises(ValueError):
                query.query_events(sort='source', after=cursor)
            with self.assertRaises(ValueError):
                query.query_events(after='not base64')

    def test_page_and_single_events_do_not_share_mutable_cached_objects(self):
        with open_case_query(self.path) as query:
            first = query.query_events(limit=1)
            first.events[0].details['injected'] = True
            self.assertNotIn('injected', query.get_event(first.event_ids[0]).details)
            one = query.get_event(first.event_ids[0])
            one.details['again'] = True
            self.assertNotIn('again', query.get_event(first.event_ids[0]).details)

    def test_counts_and_statistics_do_not_construct_event_models(self):
        with open_case_query(self.path) as query, patch.object(query,'_decode',wraps=query._decode) as decode:
            self.assertEqual(query.count_events(), len(self.loaded.events))
            stats = query.statistics()
            self.assertEqual(stats['records'], len(self.loaded.events))
            self.assertEqual(stats['users'], len({e.sid for e in self.loaded.events if e.sid}))
            self.assertEqual(decode.call_count, 0)
            page = query.query_events(limit=3)
            self.assertEqual(len(page.events), 3)
            self.assertEqual(decode.call_count, 3)

    def test_tag_colors_subcategories_and_notes(self):
        book = TagBook();book.load_rows(self.loaded.tags)
        with open_case_query(self.path) as query:
            for tag in ('red','red/sub','green','note'):
                expected = [e for e in timeline(self.loaded.events) if event_key(e) in book.keys_with(tag)]
                self.assertEqual(query.query_events({'tag':tag}).events, expected)
            counts = query.tree_counts()
            self.assertEqual(counts['tag_colors'], {'red':2,'yellow':0,'green':1})
            self.assertEqual(sum(r['physical_candidates'] for r in counts['usb']['groups']), 1)
            self.assertEqual(sum(r['records'] for r in counts['usb']['records']), 3)

    def test_source_tree_children_do_not_repeat_leaf_and_physical_counts_differ_from_records(self):
        with open_case_query(self.path) as query:
            counts = query.tree_counts(source_prefix=('fictional.img', ('볼륨 0','Users','alice')))
            self.assertEqual(counts['sources'], [{'name':'fictional.img','parts':['볼륨 0','Users','alice','A.dat'], 'records':13}])
            leaf = query.tree_counts(source_prefix=('fictional.img', ('볼륨 0','Users','alice','A.dat')))
            self.assertEqual(leaf['sources'], [])
            self.assertEqual(leaf['source_self_records'],13)

    def test_relation_pages_resolve_database_ids_without_loading_the_whole_group(self):
        with open_case_query(self.path) as query:
            rows = query.get_relations()
            self.assertEqual(len(rows),2)
            with patch('log_hunter.database.query_details._json',side_effect=AssertionError('must use membership index')):
                members = query.relation_members(rows[1]['relation_id'], offset=3, limit=4)
            self.assertEqual(members.events, self.loaded.events[3:7])
            self.assertEqual(len(query.get_relations(members.event_ids[0])),1)
            self.assertEqual(query.relation_members(999999).events,[])

    def test_query_never_loads_analysis_or_opens_original_evidence_and_does_not_write_db(self):
        before = self.snapshot()
        with patch('log_hunter.database.case_db.load_case', side_effect=AssertionError('no full load')), \
             patch('log_hunter.database.case_db._check_sources', side_effect=AssertionError('no original checks')), \
             patch('log_hunter.database.case_db._hash', side_effect=AssertionError('no original hashes')):
            with open_case_query(self.path) as query:
                self.assertEqual(len(query.query_events(limit=2).events),2)
                query.count_events();query.tree_counts();query.statistics()
        self.assertEqual(before,self.snapshot())

    def test_legacy_schema1_and_no_fts_compatibility_are_readonly(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            for name in ('event_search','event_query_tags','relation_query_members','relation_query_summaries','event_query','case_query_meta'):
                db.execute('DROP TABLE '+name)
            db.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
        before=self.snapshot()
        with open_case_query(self.path) as query:
            self.assertFalse(query.indexed)
            self.assertEqual(query.query_events().events,timeline(self.loaded.events))
            self.assertEqual(query.count_events({'tag':'red'}),2)
            self.assertEqual(query.relation_members(2,limit=3).events,self.loaded.events[:3])
        self.assertEqual(before,self.snapshot())

    def test_changes_invalidate_saved_projection_and_active_cursors(self):
        query = open_case_query(self.path)
        self.addCleanup(query.close)
        cursor=query.query_events(limit=2).next_cursor
        with closing(sqlite3.connect(self.path)) as db, db:
            data=json.loads(db.execute('SELECT data FROM events WHERE id=1').fetchone()[0])
            data['path']='new-query-target'
            db.execute('UPDATE events SET data=? WHERE id=1',(json.dumps(data),))
        with self.assertRaises(ValueError):query.query_events(after=cursor)
        query.close()
        with open_case_query(self.path) as query:
            self.assertFalse(query.indexed)
            self.assertEqual(query.count_events({'search':'new-query-target'}),1)

    def test_new_tag_table_and_changed_notes_use_latest_rows(self):
        result=AnalysisResult(events=[ForensicEvent('test','generated','act')])
        path=self.root/'empty-tags.sqlite';save_case(path,result)
        book=TagBook();event=result.events[0]
        book.set_note(event_key(event),'event',event_ref(event),'added later')
        save_to_sqlite(path,book.rows())
        with open_case_query(path) as query:
            self.assertFalse(query.indexed)
            self.assertEqual(query.count_events({'tag':'note'}),1)

    def test_large_relation_uses_summary_and_member_pages_keep_roles(self):
        path=self.root/'large.sqlite'
        events=[ForensicEvent('test','generated','act',locator=str(i)) for i in range(2000)]
        relation={'type':'correlation_group','event_indices':list(range(2000)), 'left_event_indices':[0,10],
                  'candidate_count':1000000, 'evidence_details':{'rule':'generated rule',
                    'event_refs':[{'event_index':i,'source':'generated'+('x'*200)} for i in range(2000)]}}
        save_case(path,AnalysisResult(events=events,relations=[relation]))
        with open_case_query(path) as query:
            row=query.get_relations()[0]
            self.assertTrue(row['data_is_summary'])
            self.assertEqual(row['member_count'],2000)
            self.assertEqual(row['data']['evidence_details']['event_ref_count'],2000)
            self.assertEqual(row['data']['candidate_count'],1000000)
            self.assertNotIn('event_indices',row['data'])
            self.assertEqual(query.get_relation(row['relation_id'],include_members=True)['data'],relation)
            page=query.relation_members(row['relation_id'],limit=2)
            self.assertEqual(page.events,events[:2])
            self.assertEqual(set(page.member_roles[page.event_ids[0]]),{'member','anchor'})
            self.assertEqual(query.relation_members(row['relation_id'],offset=1990,limit=10).events,events[1990:])

    def test_readonly_wal_snapshot_does_not_change_original_sidecars(self):
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute("INSERT INTO parser_errors(case_id,data) VALUES(1,?)",(json.dumps({
            'source':'generated','artifact':'test','locator':'1','message':'test','severity':'warning'}),))
        db.commit();before=self.snapshot()
        with open_case_query(self.path) as query:
            self.assertEqual(query.count_events(),len(self.loaded.events))
            self.assertEqual(query.query_events().events,timeline(self.loaded.events))
            with self.assertRaises(sqlite3.OperationalError):
                query.db.execute('DELETE FROM events')
        self.assertEqual(before,self.snapshot())

    def test_legacy_zero_future_and_damaged_rows_remain_explicit(self):
        legacy=self.root/'legacy.sqlite';repo=Repository(legacy)
        repo.save('legacy',[],self.loaded.events,[],[]);repo.close()
        with open_case_query(legacy) as query:
            self.assertEqual(query.schema_version,0)
            self.assertFalse(query.indexed)
            self.assertEqual(query.query_events().events,timeline(self.loaded.events))
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
            db.execute("UPDATE events SET data='broken JSON' WHERE id=1")
        with open_case_query(self.path) as query:
            self.assertTrue(query.partial)
            self.assertFalse(query.indexed)
            self.assertEqual(query.count_events(),len(self.loaded.events)-1)
            self.assertTrue(query.query_events().warnings)

    def test_no_fts_table_has_exact_search_fallback(self):
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('DROP TABLE IF EXISTS event_search')
        with open_case_query(self.path) as query:
            self.assertTrue(query.indexed)
            self.assertFalse(query.fts)
            expected=[e for e in timeline(self.loaded.events) if matches_search(e,'hiddenneedle',self.loaded.sid_names)]
            self.assertEqual(query.query_events({'search':'hiddenneedle'}).events,expected)

    def test_case_ids_cannot_cross_case_or_cursor_boundaries(self):
        repo=Repository(self.path)
        second=repo.save('second',[],[ForensicEvent('test','generated','second')],[],[],state={
            'tool_version':'test','created_at':'2026-01-01T00:00:00+00:00'})
        repo.close()
        with open_case_query(self.path,case_id=1) as first,open_case_query(self.path,case_id=second) as other:
            cursor=first.query_events(limit=2).next_cursor
            self.assertEqual(other.count_events(),1)
            self.assertIsNone(other.get_event(1))
            self.assertEqual(other.get_relations(1),[])
            with self.assertRaises(ValueError):other.query_events(after=cursor)

    def test_native_timeline_index_is_used_and_extreme_cursor_values_are_rejected(self):
        import base64
        from log_hunter.database.query_filters import order
        with open_case_query(self.path) as query:
            base,where,params=query._selection({})
            plan=query.db.execute('EXPLAIN QUERY PLAN SELECT q.event_id FROM '+base+' WHERE '+where+
                                   ' ORDER BY '+order('timeline')+' LIMIT 5',params).fetchall()
            self.assertTrue(any('query_timeline' in row[-1] for row in plan))
            token=query.query_events(limit=1).next_cursor
            data=json.loads(base64.urlsafe_b64decode(token))
            data['values'][-1]=2**100
            token=base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
            with self.assertRaises(ValueError):query.query_events(after=token)

    def test_integrity_check_does_not_trust_changed_projection(self):
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute("UPDATE event_query SET query_text='not original' WHERE event_id=1")
        with open_case_query(self.path) as query:
            verification=query.verify_integrity()
            self.assertEqual(verification['database']['status'],'changed')
            self.assertFalse(query.indexed)
            self.assertTrue(query.partial)
            self.assertEqual(query.count_events(),len(self.loaded.events))

    def test_corrupt_database_has_unknown_count_instead_of_false_zero(self):
        path=self.root/'truncated.sqlite';path.write_bytes(b'SQLite format 3\0'+bytes(200))
        with open_case_query(path) as query:
            self.assertIsNone(query.count_events())
            self.assertTrue(query.query_events().partial)
            self.assertTrue(query.warnings)
            query.verify_integrity()

    def test_invalid_inputs_are_not_interpreted_as_sql(self):
        with open_case_query(self.path) as query:
            for kwargs in ({'sort':'source;DROP TABLE events'}, {'limit':5001}, {'offset':-1},
                           {'filters':{'unknown':'x'}}, {'filters':{'event_ids':['1 OR 1=1']}},
                           {'filters':{'node':{'kind':'event_set','value':[1]}}}):
                with self.assertRaises(ValueError):query.query_events(**kwargs)
            self.assertEqual(query.count_events(),len(self.loaded.events))
        with self.assertRaises(ValueError):query.query_events()

    def test_page_byte_budget_still_advances_without_duplicate_ids(self):
        with open_case_query(self.path) as query:
            expected=query.query_events().event_ids
            sizes=[len(r[0]) for r in query.db.execute('SELECT data FROM events')]
            actual=[];cursor=None
            with patch('log_hunter.database.case_query.MAX_PAGE_BYTES',max(sizes)*2):
                for _ in range(len(expected)+1):
                    page=query.query_events(limit=5,after=cursor);actual+=page.event_ids;cursor=page.next_cursor
                    if cursor is None:break
            self.assertEqual(actual,expected)
