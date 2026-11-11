"""파일을 실행하지 않고 제한된 실제 내용과 복구 추정을 미리보기로 제공합니다."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import time

from .models import ParserError
from .text import decode_text

MAX_READ = 8 * 1024 * 1024
TEXT_READ = 64 * 1024


@dataclass
class PreviewSource:
    name: str
    size: int
    reader: object
    in_use: bool = True
    allocated: bool = True
    resident: bool = False
    sparse: bool = False
    encrypted: bool = False
    compressed: bool = False
    readable_size: object = None


@dataclass
class PreviewResult:
    kind: str = 'none'
    name: str = ''
    size: int = 0
    data_state: str = 'unavailable'
    reason: str = ''
    signature_format: str = ''
    extension: str = ''
    extension_mismatch: bool = False
    truncated: bool = False
    text: str = ''
    image_bytes: bytes = b''
    metadata: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _source(source):
    if isinstance(source, PreviewSource):
        return source
    if isinstance(source, bytes):
        return PreviewSource('', len(source), lambda offset, length: source[offset:offset+length], resident=True)
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
        if path.is_symlink():
            raise ValueError('링크는 따라가지 않습니다')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('일반 파일이 아닙니다')
        def read(offset, length):
            with path.open('rb') as stream:
                stream.seek(offset)
                return stream.read(length)
        flags = getattr(info, 'st_file_attributes', 0)
        return PreviewSource(path.name, info.st_size, read, sparse=bool(flags & 0x200),
                             encrypted=bool(flags & 0x4000), compressed=bool(flags & 0x800))
    # 이미지 탐색 엔진의 ImageFile을 그대로 받을 수 있습니다.
    if hasattr(source, 'record') and hasattr(source, 'read') and hasattr(source, 'volume'):
        if source.record.directory:
            raise ValueError('폴더는 내용 미리보기 대상이 아닙니다')
        fragments = source.volume._fragments(source.record, 0x80, '')
        flags = 0
        for fragment in fragments:
            flags |= fragment.flags
        resident = source.resident is not None
        sparse = bool(flags & 0x8000) or any(lcn is None for _, lcn, _ in source.extents)
        return PreviewSource(source.parts[-1] if source.parts else str(source.mft_record),
            source.size, source.read, in_use=source.record.in_use,
            allocated=resident or bool(source.extents), resident=resident,
            sparse=sparse, encrypted=bool(flags & 0x4000), compressed=bool(flags & 1),
            readable_size=source.initialized)
    raise TypeError('지원하지 않는 미리보기 입력입니다')


def _printable(text):
    return ''.join(c if c in '\n\r\t' or c.isprintable() else '\ufffd' for c in text)


def preview(source, *, max_bytes=MAX_READ, seconds=1.0, codepage=None):
    """Path·bytes·PreviewSource·ImageFile → PreviewResult. 호출자가 이미지를 계속 열어 둡니다."""
    result = PreviewResult()
    deadline = time.monotonic() + max(0.0, min(float(seconds), 5.0))
    try:
        item = _source(source)
        result.name, result.size = item.name, item.size
        result.extension = Path(item.name).suffix.lower()
        for state, message in ((item.encrypted, 'EFS 암호화 파일'), (item.compressed, '지원하지 않는 압축 데이터'),
                               (item.sparse, '희소 파일'), (item.size == 0, '빈 파일'),
                               (not item.resident and not item.allocated, '할당 데이터가 확인되지 않음')):
            if state:
                result.reason = message
                return result
        if item.size < 0 or not 0 < max_bytes <= MAX_READ:
            raise ValueError('파일 크기 또는 읽기 상한 오류')
        if time.monotonic() >= deadline:
            raise ValueError('미리보기 시간 상한 초과')
        readable = item.size if item.readable_size is None else min(item.size, item.readable_size)
        if readable <= 0:
            result.reason = '초기화된 데이터가 없습니다'
            return result
        amount = min(readable, max_bytes, TEXT_READ)
        data = item.reader(0, amount)
        if not isinstance(data, bytes) or len(data) > amount:
            raise ValueError('읽기 함수가 요청 범위를 초과했습니다')
        if not data:
            result.reason = '읽을 수 있는 실제 데이터가 없습니다'
            return result
        signatures=(b'\x89PNG',b'GIF87a',b'GIF89a',b'BM',b'\0\0\1\0',b'\xff\xd8',b'PK\x03\x04',b'PK\x05\x06',b'%PDF-',b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
        if len(data)==amount and len(data)<min(readable,max_bytes) and data.startswith(signatures):
            remaining=min(readable,max_bytes)-len(data)
            tail=item.reader(len(data),remaining)
            if not isinstance(tail,bytes) or len(tail)>remaining:
                raise ValueError('읽기 함수가 요청 범위를 초과했습니다')
            data+=tail
        result.truncated = len(data) < item.size
        result.data_state = 'actual' if item.in_use else 'recovery_estimate'
        if not item.in_use:
            result.warnings.append('삭제된 기록의 복구 추정입니다. 다른 파일로 덮어써졌을 수 있습니다.')
        if result.truncated:
            result.warnings.append('크기 또는 초기화 범위 상한으로 앞부분만 읽었습니다.')
        from .preview_images import image_preview
        from .preview_documents import document_preview
        if time.monotonic() >= deadline:
            raise ValueError('미리보기 시간 상한 초과')
        parsed = image_preview(data, deadline)
        if parsed is None:
            parsed = document_preview(data, deadline, complete=not result.truncated, codepage=codepage)
        if parsed is not None:
            result.kind = parsed.get('kind', 'metadata')
            result.signature_format = parsed['format']
            result.image_bytes = parsed.get('image_bytes', b'')
            result.text = _printable(parsed.get('text', ''))[:TEXT_READ]
            result.metadata = parsed.get('metadata', {})
            if result.image_bytes:
                result.metadata['preview_format']='png' if result.image_bytes.startswith(b'\x89PNG') else 'gif'
            result.warnings.extend(parsed.get('warnings', []))
            expected = parsed.get('extensions', ())
            result.extension_mismatch = bool(result.extension and expected and result.extension not in expected)
            if result.extension_mismatch:
                result.warnings.append('파일 확장자와 실제 내용의 시그니처가 다릅니다.')
        else:
            decoded = decode_text(data[:TEXT_READ], codepage)
            text = decoded.pop('text')
            if text and sum(c.isprintable() or c in '\r\n\t' for c in text) / len(text) >= .90 and '\x00' not in text:
                result.kind, result.signature_format = 'text', 'text'
                result.text = _printable(text)
                result.metadata['text_decoding'] = decoded
                if result.extension in ('.png','.gif','.bmp','.ico','.jpg','.jpeg','.pdf','.docx','.xlsx','.pptx','.hwp','.zip','.exe','.dll'):
                    result.extension_mismatch=True
                    result.warnings.append('파일 확장자는 바이너리 형식이지만 실제 내용은 텍스트입니다.')
            else:
                result.kind, result.signature_format = 'hex', 'binary'
                result.text = '\n'.join(f'{offset:08X}  '+data[offset:offset+16].hex(' ') for offset in range(0,min(len(data),4096),16))
                result.metadata['strings'] = _printable(text)[:1024]
        if time.monotonic() >= deadline:
            raise ValueError('미리보기 시간 상한 초과')
        return result
    except Exception as exc:
        result.kind, result.image_bytes, result.text = 'none', b'', ''
        result.reason = str(exc)
        result.errors.append(ParserError(result.name, 'preview', 'content', str(exc), 'warning'))
        return result
