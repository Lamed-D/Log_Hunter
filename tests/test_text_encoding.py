import csv
import io
import json
from pathlib import Path
import struct
import subprocess
import os
from contextlib import closing
import tempfile
import unittest

from log_hunter.parser.lnk import parse_lnk, LNK_HEADER_SIZE, LNK_CLSID
from log_hunter.parser.shellbag import _extract_shell_item_name
from log_hunter.core.export import export_csv, export_json, export_jsonl, export_bodyfile
from log_hunter.core.models import ForensicEvent
from log_hunter.image.extract import _safe
from log_hunter.core.text import decode_ansi, decode_text
from test_example_samples import load_demo

NAMES = ['보고서.hwp', '한글 문서.docx', '사진 2024.jpg', '사진😀e\u0301.txt']


def link_string(name, unicode=False):
    data=bytearray(LNK_HEADER_SIZE)
    struct.pack_into('<I',data,0,LNK_HEADER_SIZE)
    data[4:20]=LNK_CLSID
    struct.pack_into('<I',data,20,0x08 | (0x80 if unicode else 0))
    raw=name.encode('utf-16-le' if unicode else 'cp949')
    return bytes(data)+struct.pack('<H',len(raw)//2 if unicode else len(raw))+raw+bytes(4)


def link_info(name):
    data=bytearray(LNK_HEADER_SIZE)
    struct.pack_into('<I',data,0,LNK_HEADER_SIZE);data[4:20]=LNK_CLSID
    struct.pack_into('<I',data,20,2)
    ansi=('C:\\Evidence\\'+name).encode('cp949')+b'\0'
    unicode=('C:\\Evidence\\'+name+'\0').encode('utf-16-le')
    volume=struct.pack('<IIII',17,3,1,16)+b'\0'
    local=36+len(volume);suffix=local+len(ansi);uni=suffix+1;usuffix=uni+len(unicode)
    info=struct.pack('<9I',usuffix+2,36,1,36,local,0,suffix,uni,usuffix)
    return bytes(data)+info+volume+ansi+b'\0'+unicode+b'\0\0'+bytes(4)


def shell_item(name, extension=False):
    short=b'REPORT~1.HWP' if extension else name.encode('cp949')
    data=bytearray(14)+short+b'\0'
    data[2]=0x31
    if extension:
        if len(data)%2: data+=b'\0'
        ext=len(data)
        block=bytearray(46)+(name+'\0').encode('utf-16-le')+struct.pack('<H',ext)
        struct.pack_into('<HHI',block,0,len(block),9,0xBEEF0004)
        struct.pack_into('<H',block,16,46)
        data+=block
    struct.pack_into('<H',data,0,len(data))
    return bytes(data)


class EncodingMatrixTests(unittest.TestCase):
    def test_teaching_copy_line_endings_follow_python_newline_rules(self):
        from tools.check_annotated import code_tokens
        with tempfile.TemporaryDirectory() as folder:
            a,b=[Path(folder)/name for name in ('원본.py','해설.py')]
            source='"""한글\n설명"""\nvalue = "사진😀"\n'
            a.write_bytes(source.encode('utf-8'))
            b.write_bytes(source.replace('\n','\r\n').encode('utf-8'))
            self.assertEqual(code_tokens(a),code_tokens(b))
    def hive(self, entries):
        b=load_demo().HiveBuilder(); tree={}
        for path, values in entries:
            node=tree
            for part in path.split('\\'): node=node.setdefault(part,{})
            node[':values']=values
        def emit(name,node):
            return b.key(name,133485408000000000,values=node.get(':values',[]),
                         children=[emit(n,v) for n,v in node.items() if n!=':values'])
        return b.build(emit('ROOT',tree))

    def test_ansi_lnk_known_codepage_and_inferred_raw_bytes(self):
        for name in NAMES[:3]:
            with self.subTest(name=name):
                result=parse_lnk(link_string(name))
                self.assertEqual(result['relative_path'],name)
                self.assertTrue(result['text_decoding'][0]['inferred'])
                self.assertEqual(result['text_decoding'][0]['raw_hex'],name.encode('cp949').hex())

    def test_unicode_lnk_and_linkinfo_correct_offsets(self):
        for name in NAMES:
            self.assertEqual(parse_lnk(link_string(name,True))['relative_path'],name)
        result=parse_lnk(link_info(NAMES[0]))
        self.assertEqual(result['target_path'],'C:\\Evidence\\'+NAMES[0])

    def test_shell_item_cp949_and_unicode_extension_priority(self):
        for name in NAMES[:3]:
            value,detail=_extract_shell_item_name(shell_item(name))
            self.assertEqual(value,name)
            self.assertTrue(detail['text_decoding'][0]['inferred'])
        for name in NAMES:
            value,detail=_extract_shell_item_name(shell_item(name,True))
            self.assertEqual(value,name)

    def test_unicode_primary_shell_name_and_pidl_in_mru_and_lnk(self):
        from log_hunter.parser.mru import MRUParser
        from log_hunter.parser.shellbag import decode_id_list
        for name in NAMES:
            item=bytearray(14)+(name+'\0').encode('utf-16-le')
            item[2]=0x35;struct.pack_into('<H',item,0,len(item))
            self.assertEqual(_extract_shell_item_name(item)[0],name)
            pidl=shell_item(name,True)+bytes(2)
            self.assertEqual(decode_id_list(pidl)[0],name)
            header=bytearray(LNK_HEADER_SIZE);struct.pack_into('<I',header,0,LNK_HEADER_SIZE)
            header[4:20]=LNK_CLSID;struct.pack_into('<I',header,20,1)
            parsed=parse_lnk(bytes(header)+struct.pack('<H',len(pidl))+pidl+bytes(4))
            self.assertEqual(parsed['target_path'],name)
            self.assertFalse(parsed['id_list_decoding']['full_path_confirmed'])
            with tempfile.TemporaryDirectory() as folder:
                p=Path(folder)/'NTUSER.DAT'
                p.write_bytes(self.hive([(r'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
                    [('MRUListEx',3,struct.pack('<II',0,0xffffffff)),('0',3,pidl)])]))
                event=list(MRUParser().parse(p))[0]
                self.assertEqual(event.path,name)
                self.assertTrue(event.details['pidl_decoded'])
    def test_export_and_extraction_keep_unicode(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in NAMES:
                self.assertEqual(_safe(name),name)
                events=[ForensicEvent('mft','generated','file_created','2024-01-01T00:00:00+00:00',
                                      'created',path='C:\\Evidence\\'+name)]
                export_csv(events,root/'a.csv');export_json(events,root/'a.json')
                export_jsonl(events,root/'a.jsonl');export_bodyfile(events,root/'a.body')
                self.assertTrue((root/'a.csv').read_bytes().startswith(b'\xef\xbb\xbf'))
                row=next(csv.DictReader(io.StringIO((root/'a.csv').read_text(encoding='utf-8-sig'))))
                self.assertEqual(row['path'],events[0].path)
                self.assertEqual(json.loads((root/'a.json').read_text(encoding='utf-8'))[0]['path'],events[0].path)
                self.assertIn(name,(root/'a.jsonl').read_text(encoding='utf-8'))
                self.assertIn(name,(root/'a.body').read_text(encoding='utf-8'))

    def test_known_acp_and_raw_damage_metadata(self):
        for name in NAMES[:3]:
            result=parse_lnk(link_string(name),codepage='cp949')
            self.assertEqual(result['relative_path'],name)
            self.assertNotIn('text_decoding',result)
        damaged=decode_ansi(b'\xff',949)
        self.assertTrue(damaged['decode_error'])
        self.assertEqual(damaged['raw_hex'],'ff')
        self.assertFalse(damaged['inferred'])
        for encoding in ('utf-8','utf-8-sig','utf-16','utf-16-be','cp949'):
            name=NAMES[1]
            result=decode_text(name.encode(encoding))
            self.assertEqual(result['text'],name)

    def test_mru_recentdocs_amcache_and_system_acp_pipeline(self):
        from log_hunter.parser.mru import MRUParser
        from log_hunter.parser.amcache import AmcacheParser
        from log_hunter.core.pipeline import Pipeline
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in NAMES:
                path='C:\\Evidence\\'+name
                user=root/'NTUSER.DAT'
                user.write_bytes(self.hive([(r'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                    [('MRUListEx',3,struct.pack('<II',0,0xffffffff)),('0',3,(name+'\0').encode('utf-16-le'))])]))
                self.assertEqual(list(MRUParser().parse(user))[0].path,name)
                amcache=root/'Amcache.hve'
                amcache.write_bytes(self.hive([(r'Root\InventoryApplicationFile\TEST',
                    [('LowerCaseLongPath',1,(path+'\0').encode('utf-16-le'))])]))
                self.assertEqual(list(AmcacheParser().parse(amcache))[0].path,path)
            system=root/'SYSTEM'
            system.write_bytes(self.hive([('Select',[('Current',4,struct.pack('<I',1))]),
                (r'ControlSet001\Control\Nls\CodePage',[('ACP',1,'949\0'.encode('utf-16-le'))])]))
            link=root/'synthetic.lnk';link.write_bytes(link_string(NAMES[0]))
            result=Pipeline().analyze([('lnk',link),('usb',system)])
            event=next(e for e in result.events if e.artifact=='lnk')
            self.assertEqual(event.path,NAMES[0])
            self.assertNotIn('text_decoding',event.details)

    def test_jumplist_and_recyclebin_unicode_and_damage(self):
        from log_hunter.parser.jumplist import JumpListParser
        from log_hunter.parser.recyclebin import parse_dollar_i
        from log_hunter.image.ntfs import parse_file_name
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'0000000000000000.customDestinations-ms'
            for name in NAMES:
                p.write_bytes(link_string(name,True))
                self.assertEqual(list(JumpListParser().parse(p))[0].path,name)
                raw=(name+'\0').encode('utf-16-le')
                data=struct.pack('<QQQI',2,10,133485408000000000,len(raw)//2)+raw
                self.assertEqual(parse_dollar_i(data)['original_path'],name)
            raw=b'\x00\xd8\0\0'
            result=parse_dollar_i(struct.pack('<QQQI',2,1,133485408000000000,2)+raw)
            self.assertTrue(result['text_decoding'][0]['decode_error'])
            fn=bytearray(68);fn[64]=1;fn[66:68]=raw[:2]
            self.assertEqual(parse_file_name(fn)['name_raw_hex'],'00d8')

    def test_ntfs_unicode_file_tree_and_content(self):
        from test_image import NTFSBuilder
        from log_hunter.image import open_image
        from log_hunter.image.ntfs import NTFSVolume
        builder=NTFSBuilder();parent=builder.makedirs('Evidence')
        for name in NAMES: builder.add_file(parent,name,b'synthetic',mode='resident')
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'synthetic.dd';p.write_bytes(builder.build())
            with open_image(p) as image:
                volume=NTFSVolume(image)
                entries=volume.listdir(parent)
                self.assertTrue(set(NAMES)<={e.name for e in entries})

    def test_prefetch_and_evtx_unicode_strings(self):
        from test_prefetch_v31 import fixture
        from test_evtx_chunks import ChunkWriter
        from log_hunter.parser.prefetch import PrefetchParser
        from log_hunter.parser.evtx import EVTXParser
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            for name in NAMES:
                raw=bytearray(fixture());raw[16:76]=bytes(60)
                encoded=name.encode('utf-16-le');raw[16:16+len(encoded)]=encoded
                pf=p/'synthetic.pf';pf.write_bytes(raw)
                self.assertEqual(list(PrefetchParser().parse(pf))[0].process,name)
                writer=ChunkWriter();start=writer.begin()
                writer.element('Event',children=[dict(name='System',children=[dict(name='EventID',text=1)]),
                    dict(name='EventData',children=[dict(name='Data',attrs=[('Name','ObjectName')],text=name)])])
                writer.finish(start)
                evtx=p/'synthetic.evtx';evtx.write_bytes(writer.file())
                self.assertEqual(list(EVTXParser().parse(evtx))[0].details['event_data']['ObjectName'],name)

    def test_sqlite_and_html_preserve_names(self):
        import sqlite3
        from log_hunter.main import save_result
        from log_hunter.core.pipeline import AnalysisResult
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            events=[ForensicEvent('mft','generated','created',path='C:\\Evidence\\'+name) for name in NAMES]
            save_result(AnalysisResult(events=events),p)
            with closing(sqlite3.connect(p/'case.sqlite')) as connection:
                self.assertEqual({json.loads(row[0])['path'] for row in connection.execute('SELECT data FROM events')},{e.path for e in events})
            html=(p/'report.html').read_text(encoding='utf-8')
            self.assertIn('charset="utf-8"',html.lower())
            for name in NAMES: self.assertIn(name,html)

    @unittest.skipUnless(os.name=='nt','Windows cmd 출력 검사')
    def test_cmd_utf8_output_for_korean_and_emoji_paths(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);source=p/'한글😀.txt';source.write_text('Write-Output synthetic\n',encoding='utf-8')
            command='cmd /d /s /c ""'+str(root/'run.bat')+'" analyze --input psreadline "'+str(source)+'" --output "'+str(p/'결과😀')+'""'
            result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('결과😀',result.stdout.decode('utf-8'))
