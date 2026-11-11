# ▶ 원본: log_hunter/parser/thumbcache.py
# ▶ 미리 보기 캐시의 구조·위치·해시를 읽습니다. 경로·열람 시각은 추정하지 않고 이미지를 내보내지 않습니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Read bounded thumbnail-cache metadata without exporting or decoding images."""
import hashlib
import os
from pathlib import Path
import struct

from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent


# version: (file header size, first-entry pointer offset, entry header size)
LAYOUTS = {21: (24, 12, 48), 26: (24, 12, 56), 28: (28, 16, 56),
           30: (24, 16, 56), 31: (24, 16, 56), 32: (24, 16, 56)}
MAX_FILES = 4096
MAX_ENTRIES = 100000
MAX_IDENTIFIER = 65536
MAX_DATA_HASH = 64 * 1024 * 1024
MAX_TOTAL_HASH = 512 * 1024 * 1024
READ_BLOCK = 65536


def image_signature(prefix):
    if prefix.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if prefix.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if prefix.startswith(b'BM'):
        return 'bmp'
    return 'unknown'


class ThumbcacheParser(ArtifactParser):
    artifact = 'thumbcache'

    def parse(self, path):
        path = Path(path)
        if path.is_dir():
            files = (p for p in path.rglob('*') if p.is_file()
                     and p.name.lower().startswith('thumbcache_') and p.suffix.lower() == '.db')
        else:
            files = iter((path,))
        try:
            for index, source in enumerate(files):
                if index >= MAX_FILES:
                    self.error(path, 'files', '미리 보기 캐시 파일 개수 상한 초과', 'warning')
                    break
                try:
                    with source.open('rb') as stream:
                        yield from self._entries(source, stream)
                except (OSError, ValueError, struct.error) as exc:
                    self.error(source, 'read', exc, 'warning')
        except OSError as exc:
            self.error(path, 'files', exc, 'warning')

    def _entries(self, source, stream):
        size = os.fstat(stream.fileno()).st_size
        header = stream.read(12)
        if header[:4] == b'IMMM' or header[4:8] == b'IMMM':
            self.error(source, 'header', '미리 보기 인덱스의 경로 연결은 지원하지 않습니다', 'info')
            return
        if len(header) != 12 or header[:4] != b'CMMM':
            self.error(source, 'header', '미리 보기 캐시 헤더가 없거나 잘렸습니다', 'warning')
            return
        version, cache_type = struct.unpack_from('<II', header, 4)
        layout = LAYOUTS.get(version)
        if layout is None:
            self.error(source, 'header', f'지원하지 않는 미리 보기 캐시 버전: {version}', 'warning')
            return
        file_header, pointer_offset, entry_header = layout
        rest = stream.read(file_header - 12)
        if len(rest) != file_header - 12:
            self.error(source, 'header', '미리 보기 캐시 헤더가 잘렸습니다', 'warning')
            return
        first, available = struct.unpack_from('<II', header + rest, pointer_offset)
        if first == 0:
            return
        if not file_header <= first <= size:
            self.error(source, 'header', '첫 캐시 항목 위치가 파일 범위를 벗어납니다', 'warning')
            return
        if available and not first <= available <= size:
            self.error(source, 'header', '캐시 사용 범위가 파일 범위를 벗어납니다', 'warning')
            return
        limit = available or size
        if limit < size:
            stream.seek(limit)
            tail = stream.read(min(entry_header, size - limit))
            if (len(tail) >= 28 and tail[:4] == b'CMMM'
                    and any(struct.unpack_from('<QIII', tail, 8))):
                self.error(source, hex(limit), '사용 범위 밖 캐시 항목 후보는 자동 복구하지 않습니다', 'info')
        offset, hashed = first, 0
        for _ in range(MAX_ENTRIES):
            if offset == limit:
                return
            stream.seek(offset)
            raw = stream.read(min(entry_header, limit - offset))
            if len(raw) != entry_header or raw[:4] != b'CMMM':
                self.error(source, hex(offset), '캐시 항목 헤더가 없거나 잘렸습니다', 'warning')
                return
            entry_size, cache_id, identifier_size, padding_size, data_size = struct.unpack_from('<IQIII', raw, 4)
            if entry_size < entry_header or entry_size > limit - offset:
                self.error(source, hex(offset), '캐시 항목 길이가 사용 범위를 벗어납니다', 'warning')
                return
            next_offset = offset + entry_size
            minimum = entry_header + identifier_size + padding_size + data_size
            if identifier_size % 2 or identifier_size > MAX_IDENTIFIER or minimum > entry_size:
                self.error(source, hex(offset), '캐시 식별자·패딩·이미지 길이 오류', 'warning')
                offset = next_offset
                continue
            identifier_raw = stream.read(identifier_size)
            if len(identifier_raw) != identifier_size:
                self.error(source, hex(offset), '캐시 식별자가 잘렸습니다', 'warning')
                return
            try:
                identifier = identifier_raw.decode('utf-16-le').rstrip('\0')
                status = 'ok'
            except UnicodeDecodeError:
                identifier = identifier_raw.decode('utf-16-le', errors='replace').rstrip('\0')
                status = 'warning'
                self.error(source, hex(offset), '캐시 식별자 UTF-16 오류', 'warning')
            identifier_error = status == 'warning'
            data_offset = offset + entry_header + identifier_size + padding_size
            stream.seek(data_offset)
            prefix = stream.read(min(data_size, 8))
            digest, hash_status = None, 'empty' if not data_size else 'limit'
            if data_size and data_size <= MAX_DATA_HASH and hashed + data_size <= MAX_TOTAL_HASH:
                stream.seek(data_offset)
                checksum = hashlib.sha256()
                remaining = data_size
                while remaining:
                    block = stream.read(min(READ_BLOCK, remaining))
                    if not block:
                        self.error(source, hex(data_offset), '캐시 이미지 데이터가 잘렸습니다', 'warning')
                        return
                    checksum.update(block)
                    remaining -= len(block)
                hashed += data_size
                digest, hash_status = checksum.hexdigest(), 'complete'
            elif data_size:
                status = 'partial'
                self.error(source, hex(offset), '캐시 이미지 해시 계산 크기 상한 초과 (메타데이터만 보존)', 'warning')
            stored_data, stored_header = struct.unpack_from('<QQ', raw, entry_header - 16)
            yield ForensicEvent(self.artifact, str(source), 'thumbnail_cached', sid=self.sid,
                                locator=hex(offset), status=status, details={
                                    'cache_version': version, 'cache_type': cache_type,
                                    'cache_id': f'{cache_id:016x}', 'cache_identifier': identifier,
                                    'entry_offset': offset, 'entry_size': entry_size,
                                    'data_offset': data_offset, 'data_size': data_size,
                                    'image_format': image_signature(prefix) if data_size else 'empty',
                                    'image_sha256': digest, 'image_hash_status': hash_status,
                                    'identifier_decode_error': identifier_error,
                                    **({'entry_aux_28': struct.unpack_from('<I', raw, 28)[0],
                                        'entry_aux_32': struct.unpack_from('<I', raw, 32)[0]}
                                       if entry_header == 56 else {}),
                                    'stored_data_checksum': f'{stored_data:016x}',
                                    'stored_header_checksum': f'{stored_header:016x}',
                                    'checksum_verified': False, 'original_path_confirmed': False,
                                    'view_confirmed': False,
                                })
            offset = next_offset
        if offset < limit:
            self.error(source, hex(offset), '캐시 항목 개수 상한 초과', 'warning')
