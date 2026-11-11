# 학습 해설: 실행 원본과 동일한 코드입니다.
"""DetectionHistory 1.2의 형식이 확인된 값과 리소스만 읽습니다."""
import hashlib
import struct
import uuid

from log_hunter.core.timestamp import filetime

MAGIC='Magic.Version:1.2'


def is_history(data):
    return (len(data)>=82 and data[:8]==struct.pack('<II',8,8)
            and data[16:24]==struct.pack('<II',16,0x1e)
            and data[44:48]==struct.pack('<I',0x15)
            and data[48:82]==MAGIC.encode('utf-16-le'))


def read_history(data):
    if not is_history(data):
        raise ValueError('확인된 DetectionHistory 1.2 헤더가 아닙니다')
    values=[];offset=0;warnings=[]
    for _ in range(8192):
        if offset==len(data): break
        if offset+8>len(data): raise ValueError('잘린 DetectionHistory 값 헤더')
        size,kind=struct.unpack_from('<II',data,offset)
        end=offset+8+size
        if size>1024*1024 or end>len(data): raise ValueError('DetectionHistory 값 크기 범위 초과')
        raw=data[offset+8:end]
        item={'offset':offset,'wire_type':kind,'size':size,'decode_error':False}
        if kind==0x15:
            if size%2: raise ValueError('DetectionHistory UTF-16 길이 오류')
            limited=raw[:16384]
            try: value=limited.decode('utf-16-le').rstrip('\0')
            except UnicodeDecodeError:
                value=limited.decode('utf-16-le',errors='replace').rstrip('\0')
                item.update(decode_error=True,raw_hex=limited.hex())
            if size>len(limited): item['truncated']=True
            item['value']=value
        elif kind in (0,5,6) and size==4:
            item['value']=struct.unpack('<I',raw)[0]
        elif kind in (8,0x0a) and size==8:
            number=struct.unpack('<Q',raw)[0]
            item['value']=str(number)
            if kind==0x0a:
                item['filetime_decoded']=filetime(number)
                item['time_meaning_verified']=False
        elif kind==0x1e and size==16:
            item['value']=str(uuid.UUID(bytes_le=raw))
        else:
            item.update(raw_prefix_hex=raw[:64].hex(),data_sha256=hashlib.sha256(raw).hexdigest())
        values.append(item)
        next_offset=(end+7)&~7
        if next_offset>len(data):
            if end!=len(data): raise ValueError('DetectionHistory 정렬 패딩 범위 초과')
            warnings.append('마지막 값의 정렬 패딩이 없습니다')
            offset=len(data)
        else:
            if any(data[end:next_offset]): warnings.append('0이 아닌 정렬 패딩이 있습니다')
            offset=next_offset
    else:
        if offset<len(data): raise ValueError('DetectionHistory 값 개수 상한 초과')
    if len(values)<4 or values[1]['wire_type']!=0x1e:
        raise ValueError('DetectionHistory 기본 식별 값 부족')
    groups=[];current=None
    for item in values[2:]:
        if item.get('value')==MAGIC and item['wire_type']==0x15:
            current=[];groups.append(current)
        elif current is None:
            raise ValueError('DetectionHistory 구역 구분자 누락')
        else:
            current.append(item)
    if not groups or not groups[0] or groups[0][0]['wire_type']!=0x15:
        raise ValueError('DetectionHistory 위협 이름 구역 부족')
    threat=groups[0]
    resources=[]
    for group in groups[1:513]:
        if len(group)<2 or any(item['wire_type']!=0x15 for item in group[:2]):
            warnings.append('리소스 구역의 종류·위치 값이 손상되었습니다');continue
        resources.append({'resource_type':group[0].get('value',''),
                          'resource_location':group[1].get('value',''),
                          'resource_decode_error':any(item['decode_error'] or item.get('truncated',False) for item in group[:2]),
                          'history_values':group[:64], 'history_values_truncated':len(group)>64})
    if len(groups)>513: warnings.append('DetectionHistory 리소스 구역 상한을 적용했습니다')
    return {'history_file_guid':values[1]['value'],'threat_id':values[0].get('value'),
            'threat_name':threat[0].get('value'), 'threat_name_decode_error':threat[0]['decode_error'] or threat[0].get('truncated',False),
            'threat_category_raw':threat[3].get('value') if len(threat)>3 else None,
            'threat_values':threat[:32], 'resources':resources,'warnings':warnings}
