# 학습용 사본: 저장 위치 검증과 스냅숏 출처·완전성 구분을 함께 살펴보세요.
"""검증된 저장 블록만 읽는 부분 VSS 뷰입니다. 미매핑 영역을 채우지 않습니다."""
from dataclasses import dataclass, field
import hashlib

from log_hunter.core.models import ParserError
from .ewf import DiskImage, ImageError
from .vss import BLOCK_SIZE, MAX_BLOCK_DESCRIPTORS, read_block_list, read_store_sequence
from .vss_map import build_descriptor_map

MAX_READ = 8 * 1024 * 1024
MAX_RESOLUTION_STEPS = 1000000
MAX_VERIFY_BLOCKS = MAX_BLOCK_DESCRIPTORS


class _MappingError(ImageError):
    def __init__(self, offset, message, status="unmapped"):
        super().__init__(message)
        self.offset = offset
        self.status = status


class VSSMappedVolume(DiskImage):
    """빌린 이미지의 저장 바이트만 읽습니다. close는 원래 이미지를 닫지 않습니다."""
    format = 'vss-mapped-partial'

    def __init__(self, image, volume, stores, maps, source):
        self._image, self._volume, self._maps = image, volume, maps
        snapshot = stores[0]['snapshot']
        self.size = snapshot['volume_size']
        self.errors = []
        self.verification = {'status': 'not_checked', 'bytes_verified': 0, 'sha256': None}
        self.origin = {'source': str(source), 'volume_index': volume.index,
                       'store_id': snapshot['store_id'],
                       'snapshot_id': stores[0]['header']['metadata']['snapshot_id'],
                       'snapshot_set_id': stores[0]['header']['metadata']['snapshot_set_id'],
                       'created_at': snapshot['created_at'],
                       'creation_filetime_raw': snapshot['creation_filetime_raw'],
                       'time_field': snapshot['time_field'], 'reconstruction_complete': False,
                       'reconstruction_sha256': None}

    def info(self):
        return {**super().info(), 'origin': dict(self.origin),
                'reconstruction_complete': self.origin['reconstruction_complete'],
                'reconstruction_verification': dict(self.verification)}

    def _ranges(self, offset, length, budget):
        """Resolve every sector before I/O with a bounded budget per read."""
        ranges = []
        while length:
            take = min(length, 512 - offset % 512)
            logical, found = offset, False
            for index, mapping in enumerate(self._maps):
                budget[0] += 1
                if budget[0] > MAX_RESOLUTION_STEPS:
                    raise _MappingError(offset, 'VSS 블록 해결의 처리 횟수 상한 초과', 'limit')
                block = logical // BLOCK_SIZE * BLOCK_SIZE
                within = logical - block
                entry = mapping.blocks.get(block)
                if entry is None:
                    continue
                overlay = entry['overlay'] if index == 0 else None
                if overlay and overlay['allocation_bitmap'] & (1 << (within // 512)):
                    stored = overlay['store_offset'] + within
                elif entry['base'] is not None:
                    base = entry['base']
                    if base['flags'] == 1:
                        logical = base['relative_offset'] + within
                        continue
                    stored = base['store_offset'] + within
                else:
                    continue
                volume = self._volume
                absolute = volume.offset + stored
                if (stored < 0 or stored + take > volume.size or absolute < 0
                        or absolute + take > self._image.size):
                    raise _MappingError(offset, 'VSS 저장 데이터 읽기가 원래 볼륨 범위를 벗어납니다', 'invalid_mapping')
                if ranges and ranges[-1][0] + ranges[-1][1] == absolute:
                    ranges[-1][1] += take
                else:
                    ranges.append([absolute, take, offset])
                found = True
                break
            if not found:
                raise _MappingError(offset, 'VSS 미매핑 영역입니다. 현재 볼륨이나 0으로 보완하지 않습니다')
            offset += take
            length -= take
        return ranges

    def verify_reconstruction(self, progress=None, cancel=None):
        """Check coverage per bounded read, then stream/hash the whole mapped view.

        progress(done, total, phase) uses phases mapping/hashing. Cancellation never
        publishes a complete digest. Source bytes are not read during mapping.
        """
        self.origin['reconstruction_complete'] = False
        self.origin['reconstruction_sha256'] = None
        self.format = 'vss-mapped-partial'
        self.verification = {'status': 'unverified', 'bytes_verified': 0, 'sha256': None}

        def cancelled():
            if cancel and cancel():
                self.verification['status'] = 'cancelled'
                return True
            return False

        if (self.size + BLOCK_SIZE - 1) // BLOCK_SIZE > MAX_VERIFY_BLOCKS:
            self.verification.update(status='limit', reason='max_blocks')
            return False
        if progress:
            progress(0, self.size, 'mapping')
        try:
            for offset in range(0, self.size, MAX_READ):
                if cancelled():
                    return False
                take = min(MAX_READ, self.size - offset)
                self._ranges(offset, take, [0])
                if progress:
                    progress(offset + take, self.size, 'mapping')
        except _MappingError as exc:
            self.verification.update(status=exc.status, offset=exc.offset, reason=str(exc))
            return False
        digest = hashlib.sha256()
        if progress:
            progress(0, self.size, 'hashing')
        try:
            for offset in range(0, self.size, MAX_READ):
                if cancelled():
                    return False
                take = min(MAX_READ, self.size - offset)
                data = self.read(offset, take)
                if len(data) != take:
                    raise ImageError('snapshot verification returned a short read')
                digest.update(data)
                self.verification['bytes_verified'] += len(data)
                if progress:
                    progress(offset + take, self.size, 'hashing')
        except ImageError:
            self.verification['status'] = 'read_error'
            return False
        if cancelled():
            return False
        self.verification.update(status='verified', sha256=digest.hexdigest())
        self.origin['reconstruction_complete'] = True
        self.origin['reconstruction_sha256'] = digest.hexdigest()
        self.format = 'vss-mapped'
        return True

    def read(self, offset, length):
        """저장 위치를 확인할 수 없는 부분이 있으면 바이트를 반환하지 않고 실패합니다."""
        error_offset = offset
        try:
            if (type(offset) is not int or type(length) is not int or offset < 0 or length < 0
                    or offset + length > self.size or length > MAX_READ):
                raise ImageError('VSS 부분 읽기의 범위 또는 한 번의 읽기 상한 초과')
            ranges = self._ranges(offset, length, [0])
            chunks = []
            for absolute, take, logical in ranges:
                error_offset = logical
                if absolute + take > self._image.size:
                    raise ImageError('VSS 저장 데이터 읽기가 이미지 범위를 벗어납니다')
                data = self._image.read(absolute, take)
                if len(data) != take:
                    raise ImageError('VSS 저장 데이터가 요청한 길이보다 짧습니다')
                chunks.append(data)
            return b''.join(chunks)
        except (ImageError, OSError, ValueError) as exc:
            error_offset = getattr(exc, 'offset', error_offset)
            if self.origin['reconstruction_complete']:
                self.origin['reconstruction_complete'] = False
                self.origin['reconstruction_sha256'] = None
                self.format = 'vss-mapped-partial'
                self.verification.update(status='read_error', sha256=None)
            if len(self.errors) < 256:
                self.errors.append(ParserError(self.origin['source'], 'vss', f'read:{error_offset}', str(exc), 'warning'))
            raise ImageError(str(exc)) from exc


@dataclass
class VSSPreparedVolume:
    reader: object = None
    errors: list = field(default_factory=list)


def prepare_mapped_volume(image, volume, catalog, store_id, source='image'):
    """스냅숏과 이후 스토어를 검증합니다. 전체 볼륨 읽기 보장은 하지 않습니다."""
    result = VSSPreparedVolume()
    sequence = read_store_sequence(image, volume, catalog, source)
    result.errors.extend(sequence.errors)
    if not sequence.complete:
        return result
    try:
        positions = [i for i, item in enumerate(sequence.stores) if item['snapshot']['store_id'] == store_id]
        if len(positions) != 1:
            raise ValueError('선택한 스토어 식별자가 완전한 카탈로그에 없습니다')
        stores = sequence.stores[positions[0]:]
        maps, total = [], 0
        for item in stores:
            blocks = read_block_list(image, volume, item['snapshot'], source)
            result.errors.extend(blocks.errors)
            if not blocks.complete:
                return result
            total += len(blocks.descriptors)
            if total > MAX_BLOCK_DESCRIPTORS:
                raise ValueError('VSS 스냅숏 연결 전체의 기술자 개수 상한 초과')
            mapping = build_descriptor_map(blocks, item['snapshot']['volume_size'], source)
            result.errors.extend(mapping.errors)
            if not mapping.complete:
                return result
            maps.append(mapping)
        result.reader = VSSMappedVolume(image, volume, stores, maps, source)
    except ValueError as exc:
        result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}/prepare', str(exc), 'warning'))
    return result
