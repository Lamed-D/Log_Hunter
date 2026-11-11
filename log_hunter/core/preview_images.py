"""표준 라이브러리로 제한된 이미지 바이트·변환·메타데이터를 만듭니다."""
import struct
import time
import zlib
from .text import decode_text

PNG = b'\x89PNG\r\n\x1a\n'
MAX_PIXELS = 512 * 512


def _check(deadline):
    if time.monotonic() >= deadline:
        raise ValueError('이미지 미리보기 시간 상한 초과')


def _chunk(kind, data):
    return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)


def _png(width, height, rows):
    return PNG+_chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,6,0,0,0))+_chunk(b'IDAT',zlib.compress(rows))+_chunk(b'IEND',b'')


def _png_info(data, deadline):
    if len(data)<33 or data[12:16]!=b'IHDR' or struct.unpack_from('>I',data,8)[0]!=13:
        raise ValueError('PNG 헤더가 손상되었습니다')
    if zlib.crc32(data[12:29])&0xffffffff != struct.unpack_from('>I',data,29)[0]:
        raise ValueError('PNG 헤더 체크섬 불일치')
    width,height,depth,color,compression,filtering,interlace=struct.unpack_from('>IIBBBBB',data,16)
    if not width or not height or depth not in (1,2,4,8,16) or color not in (0,2,3,4,6) or compression or filtering or interlace not in (0,1):
        raise ValueError('지원하지 않는 PNG 헤더입니다')
    if color==3 and depth==16 or color in (2,4,6) and depth not in (8,16):
        raise ValueError('PNG 색상과 비트 깊이 조합 오류')
    meta={'width':width,'height':height,'bit_depth':depth,'color_type':color}
    if width*height>MAX_PIXELS:
        return {'format':'png','extensions':('.png',),'metadata':meta,'warnings':['해상도 상한으로 이미지 바이트를 표시하지 않습니다.']}
    channels={0:1,2:3,3:1,4:2,6:4}[color]
    passes=[(0,0,1,1)] if interlace==0 else [(0,0,8,8),(4,0,8,8),(0,4,4,8),(2,0,4,4),(0,2,2,4),(1,0,2,2),(0,1,1,2)]
    expected=0
    for x,y,dx,dy in passes:
        w,h=max(0,(width-x+dx-1)//dx),max(0,(height-y+dy-1)//dy)
        if w and h: expected+=h*(1+(w*channels*depth+7)//8)
    position,compressed,ended=8,bytearray(),False
    palette,transparency,dropped=b'',b'',False
    for _ in range(4096):
        _check(deadline)
        if position+12>len(data): break
        size=struct.unpack_from('>I',data,position)[0]
        end=position+12+size
        if end>len(data): raise ValueError('PNG 청크 길이 범위 초과')
        kind=data[position+4:position+8];payload=data[position+8:end-4]
        if kind==b'IHDR' and position!=8:
            raise ValueError('PNG 헤더가 중복됩니다')
        if kind[:1].isupper() and kind not in (b'IHDR',b'PLTE',b'IDAT',b'IEND'):
            raise ValueError('지원하지 않는 PNG 필수 청크입니다')
        if zlib.crc32(kind+payload)&0xffffffff != struct.unpack_from('>I',data,end-4)[0]:
            raise ValueError('PNG 청크 체크섬 불일치')
        if kind==b'IDAT': compressed.extend(payload)
        elif kind==b'PLTE':
            if not 0<size<=768 or size%3: raise ValueError('PNG 팔레트 크기 오류')
            palette=_chunk(kind,payload)
        elif kind==b'tRNS':
            if size>768: raise ValueError('PNG 투명도 청크 크기 오류')
            transparency=_chunk(kind,payload)
        elif kind not in (b'IHDR',b'IEND'):
            dropped=True
        position=end
        if kind==b'IEND':
            if size: raise ValueError('PNG 종료 청크 크기 오류')
            ended=True;break
    if not ended: raise ValueError('PNG 종료 청크가 없습니다')
    decoder=zlib.decompressobj();raw=decoder.decompress(compressed,expected+1)
    if len(raw)!=expected or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
        raise ValueError('PNG 해제 크기 또는 압축 데이터가 올바르지 않습니다')
    if color==3 and not palette: raise ValueError('PNG 팔레트가 없습니다')
    meta['ancillary_metadata_removed']=dropped
    safe=PNG+_chunk(b'IHDR',data[16:29])+palette+transparency+_chunk(b'IDAT',compressed)+_chunk(b'IEND',b'')
    return {'kind':'image','format':'png','extensions':('.png',),'image_bytes':safe,'metadata':meta}


def _gif(data, deadline):
    if len(data)<13: raise ValueError('GIF 헤더가 잘렸습니다')
    width,height=struct.unpack_from('<HH',data,6)
    if not width or not height: raise ValueError('GIF 크기 오류')
    result={'format':'gif','extensions':('.gif',),'metadata':{'width':width,'height':height}}
    if width*height>MAX_PIXELS:
        result['warnings']=['해상도 상한으로 이미지를 표시하지 않습니다.'];return result
    position=13+(3*(2<<(data[10]&7)) if data[10]&0x80 else 0);frames=0
    def blocks(cursor):
        for _ in range(32768):
            _check(deadline)
            if cursor>=len(data): raise ValueError('GIF 블록이 잘렸습니다')
            size=data[cursor];cursor+=1
            if size==0: return cursor
            cursor+=size
            if cursor>len(data): raise ValueError('GIF 블록 길이 오류')
        raise ValueError('GIF 블록 개수 상한 초과')
    for _ in range(4096):
        _check(deadline)
        if position>=len(data): break
        marker=data[position];position+=1
        if marker==0x3b:
            if not frames: raise ValueError('GIF 이미지 데이터가 없습니다')
            result.update(kind='image',image_bytes=data[:position]);return result
        if marker==0x21:
            position+=1;position=blocks(position)
        elif marker==0x2c:
            if position+9>len(data): raise ValueError('GIF 이미지 헤더가 잘렸습니다')
            x,y,w,h=struct.unpack_from('<4H',data,position);packed=data[position+8]
            if not w or not h or x+w>width or y+h>height: raise ValueError('GIF 이미지 크기 범위 초과')
            frames+=1
            if frames>16: raise ValueError('GIF 프레임 상한 초과')
            position+=9+(3*(2<<(packed&7)) if packed&0x80 else 0)
            if position>=len(data) or not 2<=data[position]<=8: raise ValueError('GIF 압축 헤더 오류')
            position=blocks(position+1)
        else: raise ValueError('GIF 블록 종류 오류')
    raise ValueError('GIF 종료 표시가 없습니다')


def _bitmap(data, deadline, icon=False):
    dib=0 if icon else 14
    if len(data)<dib+40: raise ValueError('BMP/ICO 비트맵 헤더가 잘렸습니다')
    header=struct.unpack_from('<I',data,dib)[0]
    width,height,planes,bits,compression=struct.unpack_from('<iiHHI',data,dib+4)
    if header<40 or dib+header>len(data) or width<=0 or height==0 or planes!=1:
        raise ValueError('BMP/ICO 크기 또는 헤더 오류')
    if icon:
        if height%2: raise ValueError('ICO 비트맵 높이 오류')
        height//=2
    meta={'width':width,'height':abs(height),'bit_depth':bits}
    format='ico' if icon else 'bmp'
    if bits not in (24,32) or compression!=0 or width*abs(height)>4*MAX_PIXELS:
        return {'format':format,'extensions':('.'+format,),'metadata':meta,'warnings':['지원하지 않는 비트맵 형식 또는 해상도 상한입니다.']}
    start=dib+header if icon else struct.unpack_from('<I',data,10)[0]
    stride=((width*bits+31)//32)*4;rows=abs(height)
    if start<dib+header or start+stride*rows>len(data): raise ValueError('비트맵 픽셀 데이터가 잘렸습니다')
    out_w,out_h=min(width,256),min(rows,256)
    scale=max(width/out_w,rows/out_h);out_w=max(1,int(width/scale));out_h=max(1,int(rows/scale))
    output=bytearray();mask_start=start+stride*rows;mask_stride=((width+31)//32)*4
    for y in range(out_h):
        _check(deadline);output.append(0)
        sy=min(rows-1,int(y*scale));sy=rows-1-sy if height>0 else sy
        for x in range(out_w):
            sx=min(width-1,int(x*scale));pos=start+sy*stride+sx*(bits//8)
            blue,green,red=data[pos:pos+3]
            alpha=data[pos+3] if icon and bits==32 else 255
            mask=mask_start+sy*mask_stride+sx//8
            if icon and mask_start+mask_stride*rows<=len(data) and data[mask]&(0x80>>(sx%8)):
                alpha=0
            output.extend((red,green,blue,alpha))
    meta.update(preview_width=out_w,preview_height=out_h)
    return {'kind':'image','format':format,'extensions':('.'+format,),'metadata':meta,'image_bytes':_png(out_w,out_h,output)}


def _exif(data):
    if len(data)<8 or data[:2] not in (b'II',b'MM'): return {}
    endian='<' if data[:2]==b'II' else '>'
    if struct.unpack_from(endian+'H',data,2)[0]!=42: return {}
    pending=[struct.unpack_from(endian+'I',data,4)[0]];seen=set();result={}
    for _ in range(4):
        if not pending: break
        offset=pending.pop()
        if offset in seen or offset+2>len(data): continue
        seen.add(offset);count=struct.unpack_from(endian+'H',data,offset)[0]
        if count>64 or offset+2+count*12>len(data): continue
        for index in range(count):
            pos=offset+2+index*12;tag,kind,size=struct.unpack_from(endian+'HHI',data,pos)
            if tag==0x8769 and kind==4 and size==1:
                pending.append(struct.unpack_from(endian+'I',data,pos+8)[0])
            elif tag in (0x010f,0x0110,0x0132,0x9003) and kind==2 and 0<size<=256:
                start=pos+8 if size<=4 else struct.unpack_from(endian+'I',data,pos+8)[0]
                if start+size<=len(data):
                    key={0x010f:'camera_make',0x0110:'camera_model',0x0132:'date_time_raw',0x9003:'date_time_original_raw'}[tag]
                    decoded=decode_text(data[start:start+size].rstrip(b'\0'))
                    result[key]=decoded.pop('text')
                    if decoded['inferred'] or decoded['decode_error']:
                        result.setdefault('text_decoding',[]).append({'field':key,**decoded})
    if 'date_time_raw' in result or 'date_time_original_raw' in result:
        result['timezone_known']=False
    return result


def image_preview(data, deadline):
    if data.startswith(PNG): return _png_info(data,deadline)
    if data.startswith((b'GIF87a',b'GIF89a')): return _gif(data,deadline)
    if data.startswith(b'BM'): return _bitmap(data,deadline)
    if data.startswith(b'\0\0\1\0'):
        if len(data)<22: raise ValueError('ICO 헤더가 잘렸습니다')
        count=struct.unpack_from('<H',data,4)[0]
        if not 1<=count<=32 or 6+16*count>len(data): raise ValueError('ICO 항목 개수 오류')
        size,offset=struct.unpack_from('<II',data,14)
        if offset<6+16*count or offset+size>len(data): raise ValueError('ICO 이미지 범위 오류')
        content=data[offset:offset+size]
        result=_png_info(content,deadline) if content.startswith(PNG) else _bitmap(content,deadline,True)
        result.update(format='ico',extensions=('.ico',))
        return result
    if data.startswith(b'\xff\xd8'):
        position,meta=2,{}
        for _ in range(512):
            _check(deadline)
            if position+2>len(data) or data[position]!=0xff: break
            marker=data[position+1];position+=2
            if marker in (0xd9,0xda): break
            if marker==0xff: position-=1;continue
            if marker in (0x01,*range(0xd0,0xd9)): continue
            if position+2>len(data): raise ValueError('JPEG 세그먼트가 잘렸습니다')
            size=struct.unpack_from('>H',data,position)[0]
            if size<2 or position+size>len(data): raise ValueError('JPEG 세그먼트 범위 오류')
            payload=data[position+2:position+size]
            if marker in (0xc0,0xc1,0xc2) and len(payload)>=6:
                height,width=struct.unpack_from('>HH',payload,1)
                meta.update(width=width,height=height,encoding='baseline' if marker==0xc0 else 'progressive_or_other')
            if marker==0xe1 and payload.startswith(b'Exif\0\0'): meta.update(_exif(payload[6:]))
            position+=size
        return {'format':'jpeg','extensions':('.jpg','.jpeg','.jpe'),'metadata':meta,'warnings':['JPEG는 해독하지 않고 크기·EXIF 메타데이터만 표시합니다.']}
    return None
