# 학습 해설: 실행 원본과 동일한 코드입니다.
"""Defender 로그·보호 기록·격리 항목 파일의 읽기 전용 메타데이터 파서입니다."""
from datetime import datetime,timezone
import hashlib
from itertools import islice
from pathlib import Path
import re
import uuid

from .base import ArtifactParser
from .defender_history import is_history,read_history
from .evtx import defender_path
from log_hunter.core.models import ForensicEvent
from log_hunter.core.text import decode_text,target_acp

MAX_INPUT=32*1024*1024
_TIME=re.compile(r'^\[?(\d{4}-\d{2}-\d{2})[ T]?(\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?)(Z|[+-]\d{2}:?\d{2})?\]?\s*')
_DETECTION=re.compile(r'^DETECTIONEVENT\s+(MPSOURCE_[A-Z0-9_]+)\s+(\S+)\s+(.+)$')


def _parts(path):
    return [p.lower() for p in str(path).replace('\\','/').split('/') if p]


def _payload(path):
    parts=_parts(path)
    return 'quarantine' in parts and any(p in ('resourcedata','resources') for p in parts)


def _single_path(resource):
    path=defender_path(resource)
    return path if path and (re.match(r'^[A-Za-z]:\\',path) or path.startswith('\\\\')) else None


def _lines(data, codepage):
    probe=decode_text(data[:65536],codepage);encoding=probe['encoding']
    offset=0;delimiter=b'\n'
    if encoding.startswith('utf-16'):
        little=not data.startswith(b'\xfe\xff') and encoding!='utf-16-be'
        encoding='utf-16-le' if little else 'utf-16-be'
        delimiter=b'\n\0' if little else b'\0\n'
        offset=2 if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 0
    elif encoding=='utf-8-sig':
        encoding='utf-8';offset=3
    number=0
    while offset<len(data) and number<500000:
        end=data.find(delimiter,offset)
        if len(delimiter)==2:
            while end>=0 and (end-offset)%2: end=data.find(delimiter,end+1)
        end=len(data) if end<0 else end+len(delimiter)
        raw=data[offset:min(end,offset+16384)];truncated=end-offset>len(raw)
        failed=False
        try: text=raw.decode(encoding)
        except UnicodeDecodeError: text=raw.decode(encoding,errors='replace');failed=True
        number+=1
        yield number,text.rstrip('\r\n'),{'encoding':encoding,'inferred':probe['inferred'],'decode_error':failed,
            **({'raw_hex':raw.hex()} if failed or probe['inferred'] else {}),'line_truncated':truncated}
        offset=end
    if offset<len(data):
        raise ValueError('로그 줄 개수 상한 초과')


class DefenderParser(ArtifactParser):
    artifact='defender'

    def parse(self,path):
        source=Path(path)
        if _payload(source):
            self.error(source,'content','격리된 원본 내용은 이 파서에서 읽거나 복원하지 않습니다','info')
            return
        def selected(file):
            parts=_parts(file)
            return not _payload(file) and file.is_file() and (file.name.lower().startswith('mplog-') or 'detectionhistory' in parts
                or 'quarantine' in parts and 'entries' in parts)
        files=sorted(islice((f for f in source.rglob('*') if selected(f)),8193)) if source.is_dir() else [source]
        for index,file in enumerate(files):
            if index>=8192:
                self.error(source,'files','백신 파일 개수 상한 초과','warning');break
            if _payload(file):
                self.error(file,'content','격리된 원본 내용은 이 파서에서 읽거나 복원하지 않습니다','info');continue
            try:
                with file.open('rb') as stream: data=stream.read(MAX_INPUT+1)
                clipped=len(data)>MAX_INPUT;data=data[:MAX_INPUT]
                if clipped: self.error(file,'size','백신 파일 읽기 상한으로 앞부분만 분석합니다','warning')
                if file.name.lower().startswith('mplog-') and file.suffix.lower()=='.log':
                    yield from self._log(file,data,clipped)
                elif is_history(data):
                    if clipped: raise ValueError('DetectionHistory 전체를 읽지 못했습니다')
                    yield from self._history(file,data)
                elif 'quarantine' in _parts(file) and file.parent.name.lower()=='entries':
                    try: identity=str(uuid.UUID(file.name.strip('{}')))
                    except ValueError: identity=None
                    self.error(file,'format','격리 항목의 암호화된 내부 형식은 미지원이며 파일 메타데이터만 제공합니다','warning')
                    yield ForensicEvent(self.artifact,str(file),'defender_quarantine_metadata',locator='file',status='partial',
                        details={'quarantine_entry_file_id':identity,'metadata_file_size_read':len(data),
                            'metadata_file_sha256':None if clipped else hashlib.sha256(data).hexdigest(),
                            'metadata_format_supported':False,'quarantine_payload_recovered':False,
                            'remediation_confirmed':False,'threat_execution_confirmed':False})
                else:
                    self.error(file,'format','지원하지 않는 백신 파일 형식입니다','warning')
            except (OSError,ValueError,OverflowError) as exc:
                self.error(file,'content',exc,'warning')

    def _log(self,file,data,clipped):
        found=0
        for number,line,encoding in _lines(data,target_acp(self.environment)):
            time_match=_TIME.match(line);body=(line[time_match.end():] if time_match else line).lstrip()
            detail={'log_line':line[:8192],'text_decoding':[encoding],
                    'line_number':number,'threat_execution_confirmed':False,'remediation_confirmed':False}
            timestamp=None;path=None
            if time_match:
                raw=time_match[1]+'T'+time_match[2]+(time_match[3] or '')
                detail['log_time_raw']=raw
                if time_match[3]:
                    try: timestamp=datetime.fromisoformat(raw.replace('Z','+00:00')).astimezone(timezone.utc).isoformat()
                    except ValueError: detail['log_time_invalid']=True
                else: detail['timezone_known']=False
            match=_DETECTION.match(body)
            if match:
                action='defender_detection'
                detail.update(detection_source=match[1],threat_name=match[2],threat_resource=match[3])
                resource=match[3]
                if resource.endswith(';') and resource.count(';')==1: resource=resource[:-1]
                if resource.startswith('file:') and not resource.startswith('file:_'): resource=resource[5:]
                if not encoding['decode_error'] and not encoding['line_truncated']: path=_single_path(resource)
            elif re.search(r'\bThreat Name\s*:',body,re.I):
                action='defender_log_reference';detail['log_marker']='threat_name'
                detail['threat_name_raw']=re.split(r'\bThreat Name\s*:',body,maxsplit=1,flags=re.I)[1].strip()
                if re.fullmatch(r'[^:\s]+:[^\s]+',detail['threat_name_raw']): detail['threat_name']=detail['threat_name_raw']
            elif re.search(r'\b(?:Exclusion|Excluded|Exclusions)\b',body,re.I):
                action='defender_exclusion_reference';detail['log_marker']='exclusion_text_reference'
            elif re.search(r'\b(?:Scan Source|Begin Resource Scan|End Resource Scan)\b',body,re.I):
                action='defender_scan_reference';detail['log_marker']='scan_text_reference'
            elif 'ProcessImageName' in body or re.search(r'\bSDN\b',body):
                action='defender_log_reference';detail['log_marker']='process_or_file_text_reference'
            else: continue
            found+=1
            if found>10000:
                self.error(file,'records','로그 이벤트 개수 상한 초과','warning');break
            yield ForensicEvent(self.artifact,str(file),action,timestamp,
                'defender_log_record_time' if timestamp else None,path=path,locator=f'line:{number}',
                status='partial' if clipped or encoding['decode_error'] or encoding['line_truncated'] or detail.get('log_time_invalid') else 'ok',details=detail)
        if not found: self.error(file,'format','인식 가능한 백신 로그 표식을 찾지 못했습니다','warning')

    def _history(self,file,data):
        history=read_history(data)
        for warning in history.pop('warnings'): self.error(file,'values',warning,'warning')
        resources=history.pop('resources')
        for number,resource in enumerate(resources or [{}]):
            kind=resource.get('resource_type');location=resource.get('resource_location','')
            path=_single_path(location) if kind=='file' and not resource.get('resource_decode_error') else None
            yield ForensicEvent(self.artifact,str(file),'defender_history_record',path=path,locator=f'resource:{number}',
                status='partial' if not resources or resource.get('resource_decode_error') or history['threat_name_decode_error'] else 'ok',
                details={**history,**resource,'history_format':'1.2','time_meaning_verified':False,
                    'threat_execution_confirmed':False,'remediation_confirmed':False})
