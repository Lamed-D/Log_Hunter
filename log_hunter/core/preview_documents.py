"""문서·압축 파일의 제한된 메타데이터와 텍스트만 읽습니다."""
import io
import re
import struct
import time
import zipfile
import xml.etree.ElementTree as ET

from .text import decode_text, decode_ansi

MAX_XML = 1024 * 1024
MAX_EXPANDED = 8 * MAX_XML


def _check(deadline):
    if time.monotonic() >= deadline:
        raise ValueError('문서 미리보기 시간 상한 초과')


def _zip_directory(data):
    end=data.rfind(b'PK\x05\x06',max(0,len(data)-65557))
    if end<0 or end+22>len(data): raise ValueError('ZIP 중앙 디렉터리 종료 표시가 없습니다')
    disk,start_disk,on_disk,count,size,offset,comment=struct.unpack_from('<4H2IH',data,end+4)
    if disk or start_disk or on_disk!=count or count>512 or size>MAX_XML or offset+size>end or end+22+comment!=len(data):
        raise ValueError('ZIP 항목·디렉터리 상한 또는 범위 오류')
    cursor,actual=offset,0
    while cursor<offset+size:
        actual+=1
        if actual>512 or cursor+46>offset+size or data[cursor:cursor+4]!=b'PK\x01\x02':
            raise ValueError('ZIP 중앙 디렉터리 항목 오류')
        name,extra,notes=struct.unpack_from('<3H',data,cursor+28)
        cursor+=46+name+extra+notes
    if cursor!=offset+size or actual!=count:
        raise ValueError('ZIP 중앙 디렉터리 개수 불일치')


def _zip(data, deadline, complete):
    if not complete:
        return {'format':'zip','extensions':('.zip',),'metadata':{},'warnings':['읽기 상한으로 ZIP 전체를 확인하지 못했습니다.']}
    _zip_directory(data)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos=archive.infolist();total=0
        for info in infos:
            _check(deadline);total+=info.file_size
            if total>MAX_EXPANDED or info.file_size>MAX_EXPANDED or info.file_size>100*max(1,info.compress_size):
                raise ValueError('ZIP 압축 해제 크기 또는 비율 상한 초과')
        names=[i.filename for i in infos]
        format='docx' if 'word/document.xml' in names else 'xlsx' if 'xl/workbook.xml' in names else 'pptx' if 'ppt/presentation.xml' in names else 'zip'
        meta={'files':names,'file_count':len(names),'uncompressed_size':total}
        text,warnings=[],[]
        if len(set(names))!=len(names): warnings.append('중복된 ZIP 항목 이름이 있습니다.')
        expanded,text_size=0,0
        for info in infos:
            _check(deadline)
            name=info.filename
            wanted=(name in ('docProps/core.xml','docProps/app.xml','word/document.xml','xl/sharedStrings.xml')
                    or name.startswith('ppt/slides/slide') and name.endswith('.xml'))
            if not wanted or info.is_dir(): continue
            if info.flag_bits&1:
                warnings.append('암호화된 문서 항목은 읽지 않았습니다.');continue
            if info.file_size>MAX_XML:
                warnings.append('XML 항목의 읽기 상한을 초과했습니다.');continue
            with archive.open(info) as stream: raw=stream.read(MAX_XML+1)
            expanded+=len(raw)
            if len(raw)>MAX_XML or expanded>MAX_EXPANDED:
                raise ValueError('문서 XML 해제 크기 상한 초과')
            if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
                raise ValueError('문서 XML의 DTD·엔터티 선언은 처리하지 않습니다')
            element=ET.fromstring(raw)
            for node in element.iter():
                _check(deadline)
                key=node.tag.rsplit('}',1)[-1]
                if name.startswith('docProps/') and node.text and key in ('title','subject','creator','created','modified','Application','Pages'):
                    meta[key]=node.text[:1024]
                elif key in ('t','v') and node.text and text_size<32768:
                    part=node.text[:min(4096,32768-text_size)]
                    text.append(part);text_size+=len(part)
        extensions={'zip':('.zip',),'docx':('.docx','.docm'),'xlsx':('.xlsx','.xlsm'),'pptx':('.pptx','.pptm')}[format]
        return {'format':format,'extensions':extensions,'metadata':meta,'text':'\n'.join(text),'warnings':warnings}


def _pdf(data, deadline, codepage):
    header=re.match(rb'%PDF-([0-9]\.[0-9])',data)
    if not header: raise ValueError('PDF 버전 헤더 오류')
    meta={'version':header[1].decode('ascii')};text=[]
    count=re.search(rb'/Count\s+([0-9]{1,8})\b',data)
    if count:
        meta['page_count_hint']=int(count[1]);meta['page_count_verified']=False
    title=re.search(rb'/Title\s*\(([^\r\n]{0,1024}?)\)',data)
    if title: meta['title']=decode_text(title[1],codepage)['text']
    title_hex=re.search(rb'/Title\s*<([0-9A-Fa-f\s]{2,4096})>',data)
    if title_hex:
        meta['title']=decode_text(bytes.fromhex(title_hex[1].decode('ascii')),codepage)['text']
    cursor=0
    for _ in range(32):
        _check(deadline)
        start=data.find(b'stream',cursor)
        if start<0: break
        end=data.find(b'endstream',start+6)
        if end<0: break
        dictionary=data[max(0,data.rfind(b'<<',0,start)):start]
        if b'/Filter' not in dictionary:
            raw=data[start+6:min(end,start+6+65536)]
            for match in re.finditer(rb'\(((?:[^()\\]|\\.){0,4096})\)\s*Tj',raw):
                value=re.sub(rb'\\([()\\])',rb'\1',match[1])
                text.append(decode_text(value,codepage)['text'])
        cursor=end+9
    return {'format':'pdf','extensions':('.pdf',),'metadata':meta,'text':'\n'.join(text),
            'warnings':['PDF 페이지 수는 선언값이며 검증하지 않았습니다. 압축되지 않은 단순 텍스트만 읽습니다.']}


def _summary(data):
    if len(data)<48 or data[:2]!=b'\xfe\xff': return {}
    count=struct.unpack_from('<I',data,24)[0]
    if not 1<=count<=2: return {}
    offset=struct.unpack_from('<I',data,44)[0]
    if offset+8>len(data): return {}
    size,properties=struct.unpack_from('<II',data,offset)
    if size<8 or offset+size>len(data) or properties>64 or 8+properties*8>size: return {}
    entries={}
    for index in range(properties):
        key,pos=struct.unpack_from('<II',data,offset+8+index*8)
        if pos+4<=size: entries[key]=offset+pos
    codepage=None
    if 1 in entries and entries[1]+6<=offset+size and struct.unpack_from('<I',data,entries[1])[0]==2:
        codepage=struct.unpack_from('<H',data,entries[1]+4)[0]
    result={}
    for key,label in ((2,'title'),(3,'subject'),(4,'author'),(18,'application')):
        pos=entries.get(key)
        if pos is None or pos+8>offset+size: continue
        kind,length=struct.unpack_from('<II',data,pos)
        length=length*2 if kind==31 else length
        if kind not in (30,31) or length>4096 or pos+8+length>offset+size: continue
        raw=data[pos+8:pos+8+length]
        result[label]=raw.decode('utf-16-le',errors='replace').rstrip('\0') if kind==31 else decode_ansi(raw.rstrip(b'\0'),codepage)['text']
    return result


def _ole(data, deadline):
    from log_hunter.parser.cfb import CompoundFile
    cfb=CompoundFile(data);names=[];meta={};hwp=False
    pending=[struct.unpack_from('<I',cfb.entries[0],76)[0]];seen=set()
    while pending and len(seen)<256:
        _check(deadline)
        index=pending.pop()
        if index in seen or not 0<index<len(cfb.entries): continue
        seen.add(index);entry=cfb.entries[index]
        pending.extend(struct.unpack_from('<II',entry,68))
        if entry[66]!=2: continue
        length=struct.unpack_from('<H',entry,64)[0]
        if not 2<=length<=64 or length%2: continue
        name=entry[:length-2].decode('utf-16-le',errors='replace');names.append(name)
        if name not in ('FileHeader','\x05SummaryInformation','\x05HwpSummaryInformation'): continue
        size=cfb._size(entry);start=struct.unpack_from('<I',entry,116)[0]
        if size>256*1024: continue
        raw=cfb._small(start,size) if size<4096 else cfb._regular(start,size)
        if name=='FileHeader' and raw.startswith(b'HWP Document File'):
            hwp=True
            if len(raw)>=40:
                version,flags=struct.unpack_from('<II',raw,32)
                meta['version']='.'.join(str(version>>shift&255) for shift in (24,16,8,0))
                meta['body_compressed']=bool(flags&1);meta['password_protected']=bool(flags&2)
        elif 'SummaryInformation' in name: meta.update(_summary(raw))
    meta['streams']=names
    if pending: meta['stream_list_truncated']=True
    return {'format':'hwp' if hwp else 'ole','extensions':('.hwp',) if hwp else ('.hwp','.doc','.xls','.ppt','.ole'),
            'metadata':meta,'warnings':['복합 문서의 헤더·요약 정보만 읽습니다. 본문·매크로는 실행하거나 해제하지 않습니다.']}


def document_preview(data, deadline, *, complete, codepage=None):
    if data.startswith((b'PK\x03\x04',b'PK\x05\x06')): return _zip(data,deadline,complete)
    if data.startswith(b'%PDF-'): return _pdf(data,deadline,codepage)
    if data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        if not complete: return {'format':'ole','extensions':('.hwp','.doc','.xls','.ppt'), 'warnings':['크기 상한으로 복합 문서 전체를 읽지 못했습니다.']}
        return _ole(data,deadline)
    return None
