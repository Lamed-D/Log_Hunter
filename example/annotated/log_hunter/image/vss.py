# 학습 해설: 실행 원본과 동일한 코드입니다.
"""이미지의 기존 VSS 카탈로그를 읽습니다. 스냅숏 생성·복원은 하지 않습니다."""
from dataclasses import asdict, dataclass, field
import struct
import uuid

from log_hunter.core.models import ParserError
from log_hunter.core.timestamp import filetime
from .ewf import ImageError, open_image
from .live import is_live_path
from .volumes import find_volumes

SIGNATURE = uuid.UUID('3808876b-c176-4e48-b7ae-04046e6cc752').bytes_le
HEADER_OFFSET = 0x1e00
BLOCK_SIZE = 0x4000
MAX_BLOCKS = 4096
MAX_STORES = 16384
MAX_BLOCK_DESCRIPTORS = 65536
MAX_CHAIN_STORES = 512


@dataclass
class VSSCatalog:
    volume: dict
    present: bool = False
    header: dict = field(default_factory=dict)
    snapshots: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def read_catalog(image, volume, source='image'):
    """카탈로그 항목을 GUID로 연결합니다. 반환한 목록은 아직 읽을 수 있는 가상 볼륨이 아닙니다."""
    result = VSSCatalog(volume.to_dict())

    def warning(locator, message):
        if len(result.errors) < 256:
            result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}/{locator}', message, 'warning'))
        elif len(result.errors) == 256:
            result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}',
                                             '추가 VSS 진단의 표시 상한을 적용했습니다', 'warning'))

    def read(offset, length):
        if (volume.offset < 0 or volume.size < 0 or volume.offset + volume.size > image.size
                or offset < 0 or length < 0 or offset + length > volume.size):
            raise ValueError('VSS 읽기 범위가 원래 볼륨 경계를 벗어납니다')
        data = image.read(volume.offset + offset, length)
        if len(data) != length:
            raise ValueError('VSS 데이터가 요청한 길이보다 짧습니다')
        return data

    if volume.filesystem != 'ntfs' or volume.size < HEADER_OFFSET + 100:
        return result
    try:
        header = read(HEADER_OFFSET, 100)
        if header[:16] != SIGNATURE:
            return result
        result.present = True
        version, kind, current = struct.unpack_from('<IIQ', header, 16)
        catalog_offset, maximum = struct.unpack_from('<QQ', header, 48)
        result.header = {'version': version, 'catalog_offset': catalog_offset, 'maximum_size': maximum,
                         'volume_id_raw': str(uuid.UUID(bytes_le=header[64:80])),
                         'storage_volume_id_raw': str(uuid.UUID(bytes_le=header[80:96]))}
        if version not in (1, 2) or kind != 1 or current != HEADER_OFFSET:
            raise ValueError('지원하지 않거나 손상된 VSS 볼륨 헤더')
        if header[64:80] != header[80:96]:
            warning('header', '볼륨 식별 값이 다릅니다. 별도 저장 볼륨 여부와 스토어 접근은 아직 확인하지 않았습니다')
        stores, locations, ambiguous, seen = {}, {}, set(), set()
        offset = catalog_offset
        while offset:
            if offset in seen:
                raise ValueError('VSS 카탈로그 연결이 순환합니다')
            if len(seen) >= MAX_BLOCKS:
                raise ValueError('VSS 카탈로그 블록 개수 상한 초과')
            if offset % 512:
                raise ValueError('VSS 카탈로그 오프셋의 섹터 정렬 오류')
            seen.add(offset)
            block = read(offset, BLOCK_SIZE)
            block_version, block_kind = struct.unpack_from('<II', block, 16)
            if (block[:16] != SIGNATURE or block_version != 1 or block_kind != 2
                    or struct.unpack_from('<Q', block, 32)[0] != offset):
                raise ValueError('VSS 카탈로그 블록 헤더가 손상되었거나 미지원입니다')
            for index in range(128, BLOCK_SIZE, 128):
                entry = block[index:index + 128]
                entry_kind, = struct.unpack_from('<Q', entry)
                locator = f'catalog:{offset}/entry:{index}'
                if entry_kind in (0, 1):
                    if entry_kind == 0 and any(entry):
                        warning(locator, '빈 항목의 나머지 바이트가 0이 아닙니다')
                    continue
                if entry_kind not in (2, 3):
                    warning(locator, f'지원하지 않는 카탈로그 항목 종류: {entry_kind}')
                    continue
                identity = str(uuid.UUID(bytes_le=entry[16:32]))
                if not any(entry[16:32]):
                    warning(locator, '카탈로그 항목의 스토어 식별자가 비어 있습니다'); continue
                table = stores if entry_kind == 2 else locations
                if identity in table:
                    ambiguous.add(identity)
                    warning(locator, '같은 식별자의 카탈로그 항목이 중복됩니다. 자동 선택하지 않습니다')
                    continue
                if len(table) >= MAX_STORES:
                    raise ValueError('VSS 스토어 항목 개수 상한 초과')
                if entry_kind == 2:
                    size, = struct.unpack_from('<Q', entry, 8)
                    creation, = struct.unpack_from('<Q', entry, 48)
                    timestamp = filetime(creation)
                    table[identity] = {'store_id': identity, 'volume_size': size,
                        'created_at': timestamp, 'creation_filetime_raw': str(creation),
                        'time_field': 'snapshot_creation_time' if timestamp else None,
                        'catalog_entry_offset': offset + index}
                    if timestamp is None:
                        warning(locator, '스냅숏 생성 시각을 해석할 수 없습니다')
                    if not 0 < size <= volume.size:
                        ambiguous.add(identity)
                        warning(locator, '기록된 스냅숏 볼륨 크기가 현재 볼륨 범위와 맞지 않습니다')
                else:
                    offsets = {'block_list_offset': 8, 'store_header_offset': 32,
                               'block_ranges_offset': 40, 'bitmap_offset': 48,
                               'previous_bitmap_offset': 72}
                    table[identity] = {key: struct.unpack_from('<Q', entry, pos)[0] for key, pos in offsets.items()}
                    table[identity]['ntfs_file_reference'] = str(struct.unpack_from('<Q', entry, 56)[0])
                    for key in offsets:
                        pointer = table[identity][key]
                        if pointer and (pointer % 512 or pointer + BLOCK_SIZE > volume.size):
                            ambiguous.add(identity)
                            warning(locator, f'스토어 위치 범위 또는 정렬 오류: {key}')
            offset = struct.unpack_from('<Q', block, 40)[0]
    except (ImageError, OSError, ValueError, struct.error) as exc:
        warning('catalog', str(exc))
        # 손상 지점 이전의 유효 항목도 보존하되 불완전한 목록임을 표시합니다.
        if 'stores' not in locals():
            return result
    complete = not result.errors
    for identity, snapshot in stores.items():
        location = locations.get(identity)
        if location is None:
            warning(identity, '대응하는 스토어 위치 항목이 없습니다')
        result.snapshots.append({**snapshot, 'store': location, 'ambiguous': identity in ambiguous,
                                 'catalog_complete': complete and location is not None,
                                 'readable': False})
    for identity in locations.keys() - stores.keys():
        warning(identity, '스냅숏 기본 항목이 없는 스토어 위치 항목입니다')
    result.snapshots.sort(key=lambda item: (item['created_at'] or '', item['store_id']))
    if result.errors:
        for item in result.snapshots: item['catalog_complete'] = False
    return result


@dataclass
class VSSBlockList:
    """스토어의 원시 블록 기술자 목록입니다. 스냅숏 내용 읽기 지원을 의미하지 않습니다."""
    store_id: str
    descriptors: list = field(default_factory=list)
    complete: bool = False
    readable: bool = False
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def read_block_list(image, volume, snapshot, source='image'):
    """검증된 카탈로그 항목의 블록 목록만 읽고 순서·원시 플래그를 보존합니다."""
    result = VSSBlockList(str(snapshot.get('store_id', '')))

    def warning(locator, message):
        if len(result.errors) < 256:
            result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}/{locator}', message, 'warning'))
        elif len(result.errors) == 256:
            result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}',
                                             '추가 VSS 블록 진단의 표시 상한을 적용했습니다', 'warning'))

    def read(offset):
        if (volume.offset < 0 or volume.size < 0 or volume.offset + volume.size > image.size
                or offset < 0 or offset % 512 or offset + BLOCK_SIZE > volume.size):
            raise ValueError('VSS 블록 목록의 범위 또는 섹터 정렬 오류')
        data = image.read(volume.offset + offset, BLOCK_SIZE)
        if len(data) != BLOCK_SIZE:
            raise ValueError('VSS 블록 목록이 요청한 길이보다 짧습니다')
        return data

    try:
        if (volume.filesystem != 'ntfs' or snapshot.get('ambiguous')
                or not snapshot.get('catalog_complete') or not result.store_id):
            raise ValueError('완전하고 모호하지 않은 NTFS 카탈로그 항목이 필요합니다')
        size = snapshot.get('volume_size')
        if type(size) is not int or not 0 < size <= volume.size:
            raise ValueError('스냅숏 볼륨 크기 오류')
        store = snapshot.get('store')
        if not isinstance(store, dict) or type(store.get('block_list_offset')) is not int:
            raise ValueError('스토어 블록 목록 위치가 없습니다')
        offset, seen = store['block_list_offset'], set()
        if volume.offset < 0 or volume.size < 0 or volume.offset + volume.size > image.size:
            raise ValueError('VSS 볼륨이 이미지 범위를 벗어납니다')
        while offset:
            if offset in seen or len(seen) >= MAX_BLOCKS:
                raise ValueError('VSS 블록 목록 연결의 순환 또는 블록 개수 상한 초과')
            seen.add(offset)
            block = read(offset)
            version, kind = struct.unpack_from('<II', block, 16)
            if (block[:16] != SIGNATURE or version != 1 or kind != 3
                    or struct.unpack_from('<Q', block, 32)[0] != offset):
                raise ValueError('VSS 블록 목록 헤더가 손상되었거나 미지원입니다')
            for position in range(128, BLOCK_SIZE, 32):
                original, relative, stored, flags, bitmap = struct.unpack_from('<QQQII', block, position)
                if not any((original, relative, stored, flags, bitmap)):
                    continue
                if len(result.descriptors) >= MAX_BLOCK_DESCRIPTORS:
                    raise ValueError('VSS 블록 기술자 개수 상한 초과')
                locator = f'block_list:{offset}/entry:{position}'
                descriptor = {'original_offset': original, 'relative_offset': relative,
                              'store_offset': stored, 'flags': flags, 'allocation_bitmap': bitmap,
                              'entry_offset': offset + position, 'valid': True,
                              'kind': 'unused' if flags & 4 else 'forwarder' if flags & 1 else
                                      'overlay' if flags & 2 else 'plain'}
                reason = None
                if flags & 4:
                    # Unused entries are retained as metadata, never dereferenced.
                    pass
                elif flags & ~7 or flags & 3 == 3:
                    reason = '지원하지 않거나 서로 충돌하는 블록 플래그'
                elif original % BLOCK_SIZE or original >= size:
                    reason = '원래 블록 오프셋의 정렬 또는 스냅숏 범위 오류'
                elif flags & 1:
                    if stored or bitmap or relative % BLOCK_SIZE or relative >= size:
                        reason = '전달 블록의 대상 또는 부가 필드 오류'
                elif not stored or stored % 512 or stored + BLOCK_SIZE > volume.size:
                    reason = '저장 데이터 블록의 범위 또는 정렬 오류'
                elif not flags & 2 and bitmap:
                    reason = '일반 블록에 예상하지 않은 할당 비트맵이 있습니다'
                if reason:
                    descriptor['valid'] = False
                    warning(locator, reason)
                result.descriptors.append(descriptor)
            offset = struct.unpack_from('<Q', block, 40)[0]
        result.complete = not result.errors
    except (ImageError, OSError, ValueError, struct.error) as exc:
        warning('block_list', str(exc))
    return result


@dataclass
class VSSBitmap:
    """비트 값만 보존합니다. 데이터가 없거나 읽지 못한 비트는 None으로 반환합니다."""
    store_id: str
    previous: bool
    block_count: int = 0
    data: bytes = field(default=b'', repr=False)
    present: bool = False
    complete: bool = False
    errors: list = field(default_factory=list)

    def is_set(self, block_index):
        if type(block_index) is not int or not 0 <= block_index < self.block_count:
            return None
        index, bit = divmod(block_index, 8)
        if index >= len(self.data):
            return None
        return bool(self.data[index] & (1 << bit))


def read_store_bitmap(image, volume, snapshot, previous=False, source='image'):
    """현재/이전 스토어의 비트맵 연결을 검증합니다. 할당 상태를 내용 읽기로 해석하지 않습니다."""
    result = VSSBitmap(str(snapshot.get('store_id', '')), previous)
    data = bytearray()

    def warning(locator, message):
        result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}/{locator}', message, 'warning'))

    try:
        if (volume.filesystem != 'ntfs' or snapshot.get('ambiguous')
                or not snapshot.get('catalog_complete') or not result.store_id):
            raise ValueError('완전하고 모호하지 않은 NTFS 카탈로그 항목이 필요합니다')
        size = snapshot.get('volume_size')
        if (type(size) is not int or not 0 < size <= volume.size or volume.offset < 0
                or volume.offset + volume.size > image.size):
            raise ValueError('스냅숏 또는 원래 볼륨의 이미지 범위 오류')
        result.block_count = (size + BLOCK_SIZE - 1) // BLOCK_SIZE
        required = (result.block_count + 7) // 8
        if required > 32 * 1024 * 1024:
            raise ValueError('VSS 비트맵 메모리 상한 초과')
        store = snapshot.get('store')
        key = 'previous_bitmap_offset' if previous else 'bitmap_offset'
        if not isinstance(store, dict) or type(store.get(key)) is not int:
            raise ValueError('스토어 비트맵 위치가 없습니다')
        offset = store[key]
        if not offset:
            # Missing previous bitmaps are possible. Absence is never all-clear.
            return result
        result.present = True
        seen = set()
        while offset:
            if offset in seen or len(seen) >= MAX_BLOCKS:
                raise ValueError('VSS 비트맵 연결의 순환 또는 블록 개수 상한 초과')
            if offset < 0 or offset % 512 or offset + BLOCK_SIZE > volume.size:
                raise ValueError('VSS 비트맵 블록의 범위 또는 섹터 정렬 오류')
            seen.add(offset)
            block = image.read(volume.offset + offset, BLOCK_SIZE)
            if len(block) != BLOCK_SIZE:
                raise ValueError('VSS 비트맵 블록이 요청한 길이보다 짧습니다')
            version, kind = struct.unpack_from('<II', block, 16)
            if (block[:16] != SIGNATURE or version != 1 or kind != 6
                    or struct.unpack_from('<Q', block, 32)[0] != offset):
                raise ValueError('VSS 비트맵 블록 헤더가 손상되었거나 미지원입니다')
            take = min(BLOCK_SIZE - 128, required - len(data))
            if take:
                data.extend(block[128:128 + take])
            offset = struct.unpack_from('<Q', block, 40)[0]
        if len(data) < required:
            raise ValueError('VSS 비트맵이 스냅숏 볼륨의 전체 블록 범위를 포함하지 않습니다')
        result.complete = True
    except (ImageError, OSError, ValueError, struct.error) as exc:
        warning('previous_bitmap' if previous else 'bitmap', str(exc))
    result.data = bytes(data)
    return result


@dataclass
class VSSStoreHeader:
    """카탈로그 스토어 ID와 별개인 스냅숏 ID 및 원시 속성입니다."""
    store_id: str
    metadata: dict = field(default_factory=dict)
    complete: bool = False
    readable: bool = False
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def read_store_header(image, volume, snapshot, source='image'):
    """한 블록 안의 스토어 정보를 읽습니다. 미지원 연결은 따라가지 않습니다."""
    result = VSSStoreHeader(str(snapshot.get('store_id', '')))
    try:
        if (volume.filesystem != 'ntfs' or snapshot.get('ambiguous')
                or not snapshot.get('catalog_complete') or not result.store_id):
            raise ValueError('완전하고 모호하지 않은 NTFS 카탈로그 항목이 필요합니다')
        store = snapshot.get('store')
        offset = store.get('store_header_offset') if isinstance(store, dict) else None
        if (type(offset) is not int or offset <= 0 or offset % 512
                or volume.offset < 0 or volume.size < 0
                or volume.offset + volume.size > image.size or offset + BLOCK_SIZE > volume.size):
            raise ValueError('VSS 스토어 헤더의 위치 또는 볼륨 범위 오류')
        block = image.read(volume.offset + offset, BLOCK_SIZE)
        if len(block) != BLOCK_SIZE:
            raise ValueError('VSS 스토어 헤더가 요청한 길이보다 짧습니다')
        version, kind, relative, current, following, info_size = struct.unpack_from('<IIQQQQ', block, 16)
        if block[:16] != SIGNATURE or version != 1 or kind != 4 or current != offset:
            raise ValueError('VSS 스토어 헤더가 손상되었거나 미지원입니다')
        result.metadata = {'header_offset': offset, 'relative_offset_raw': relative,
                           'next_offset_raw': following, 'information_size_raw': info_size}
        if following:
            raise ValueError('연결된 VSS 스토어 헤더 정보는 아직 지원하지 않습니다')
        # A zero declaration supplies no tighter bound than the physical block.
        if info_size and not 68 <= info_size <= BLOCK_SIZE - 128:
            raise ValueError('VSS 스토어 정보의 선언 길이가 지원 범위를 벗어납니다')
        end = 128 + info_size if info_size else BLOCK_SIZE
        payload = block[128:end]
        for key, position in (('identifier_raw', 0), ('snapshot_id', 16), ('snapshot_set_id', 32)):
            raw = payload[position:position + 16]
            result.metadata[key] = str(uuid.UUID(bytes_le=raw))
        context, provider, attributes, reserved = struct.unpack_from('<IIII', payload, 48)
        result.metadata.update(context_raw=context, provider_raw=provider,
                               attributes_raw=attributes, reserved_raw=reserved)
        position = 64
        for key in ('operating_machine', 'service_machine'):
            if position + 2 > len(payload):
                raise ValueError('VSS 컴퓨터 이름의 길이 필드가 잘렸습니다')
            length, = struct.unpack_from('<H', payload, position)
            position += 2
            if length % 2 or position + length > len(payload):
                raise ValueError('VSS 컴퓨터 이름의 바이트 길이 또는 범위 오류')
            result.metadata[key] = payload[position:position + length].decode('utf-16-le')
            position += length
        if not any(payload[16:32]) or not any(payload[32:48]):
            raise ValueError('스냅숏 또는 스냅숏 세트 식별자가 비어 있습니다')
        result.complete = True
    except (ImageError, OSError, ValueError, struct.error) as exc:
        result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}/store_header',
                                         str(exc), 'warning'))
    return result


@dataclass
class VSSStoreSequence:
    """생성 시각이 유일할 때만 오래된 순서의 후보를 반환합니다."""
    stores: list = field(default_factory=list)
    complete: bool = False
    readable: bool = False
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def read_store_sequence(image, volume, catalog, source='image'):
    """생성 FILETIME의 원시 정수로 정렬합니다. 동률을 ID로 임의 해소하지 않습니다."""
    result = VSSStoreSequence()

    def warning(message):
        if len(result.errors) < 256:
            result.errors.append(ParserError(str(source), 'vss', f'volume:{volume.index}/store_sequence',
                                             message, 'warning'))

    if (not isinstance(catalog, VSSCatalog) or catalog.errors or not catalog.present
            or catalog.volume != volume.to_dict()):
        warning('같은 볼륨의 완전한 VSS 카탈로그가 필요합니다')
        return result
    snapshots = catalog.snapshots
    if len(snapshots) > MAX_CHAIN_STORES:
        warning('스냅숏 순서 검증의 스토어 개수 상한 초과')
        return result
    seen_stores, seen_times, seen_copies, sizes = set(), set(), set(), set()
    candidates = []
    for snapshot in snapshots:
        identity = snapshot.get('store_id')
        raw = snapshot.get('creation_filetime_raw')
        size = snapshot.get('volume_size')
        # FILETIME may exceed microsecond precision. Never order by the display string.
        if (not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal()
                or len(raw) > 20):
            warning('스냅숏 생성 시각의 원시 정수가 없거나 손상되었습니다')
            continue
        creation = int(raw)
        if (not filetime(creation) or snapshot.get('ambiguous') or not snapshot.get('catalog_complete')
                or type(size) is not int or not 0 < size <= volume.size or not isinstance(identity, str)
                or not identity):
            warning('순서 검증에 필요한 스냅숏 항목이 불완전합니다')
            continue
        if identity in seen_stores or creation in seen_times:
            warning('스토어 식별자 또는 생성 시각이 중복되어 순서를 확정할 수 없습니다')
            continue
        seen_stores.add(identity)
        seen_times.add(creation)
        sizes.add(size)
        candidates.append((creation, snapshot))
    if len(sizes) > 1:
        warning('스토어 사이의 스냅숏 볼륨 크기가 달라 단일 읽기 연결로 사용할 수 없습니다')
    if result.errors:
        return result
    for _, snapshot in sorted(candidates, key=lambda item: item[0]):
        info = read_store_header(image, volume, snapshot, source)
        if not info.complete:
            warning(f"스토어 헤더 검증 실패: {info.store_id}")
            for error in info.errors:
                if len(result.errors) < 256:
                    result.errors.append(error)
        copy_id = info.metadata.get('snapshot_id')
        if info.complete and copy_id in seen_copies:
            warning('서로 다른 스토어가 같은 스냅숏 식별자를 사용합니다')
        seen_copies.add(copy_id)
        result.stores.append({'snapshot': {**snapshot, 'store': dict(snapshot['store'])},
                              'header': info.to_dict()})
    result.complete = not result.errors
    # Failed validation must not masquerade as a usable order.
    if not result.complete:
        result.stores.clear()
    return result


def list_snapshots(path):
    """오프라인 이미지의 NTFS 볼륨별 목록과 진단을 반환합니다. 출력 파일을 쓰지 않습니다."""
    if is_live_path(path) or str(path).startswith(('\\\\.\\', '\\\\?\\')):
        raise ValueError('스냅숏 목록은 오프라인 이미지에서만 읽을 수 있습니다')
    with open_image(path) as image:
        return [read_catalog(image, volume, path).to_dict() for volume in find_volumes(image)
                if volume.filesystem == 'ntfs']
