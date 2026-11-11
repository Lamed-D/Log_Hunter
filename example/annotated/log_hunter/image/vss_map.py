"""충돌 없는 VSS 기술자를 색인합니다. 미해결 재매핑을 추정하지 않습니다."""
from dataclasses import dataclass, field

from log_hunter.core.models import ParserError
from .vss import BLOCK_SIZE, MAX_BLOCK_DESCRIPTORS, VSSBlockList


@dataclass
class VSSDescriptorMap:
    store_id: str
    blocks: dict = field(default_factory=dict)
    reverse: dict = field(default_factory=dict)
    rewrites: list = field(default_factory=list)
    complete: bool = False
    readable: bool = False
    errors: list = field(default_factory=list)


def build_descriptor_map(block_list, volume_size, source='image'):
    """순차 전달 대상을 원래 블록으로 되돌려 색인합니다. I/O는 없습니다."""
    result = VSSDescriptorMap(block_list.store_id if isinstance(block_list, VSSBlockList) else '')
    try:
        if (not isinstance(block_list, VSSBlockList) or not block_list.complete or block_list.errors
                or not block_list.store_id or type(volume_size) is not int or volume_size <= 0):
            raise ValueError('완전한 VSS 블록 목록과 스냅숏 볼륨 크기가 필요합니다')
        if len(block_list.descriptors) > MAX_BLOCK_DESCRIPTORS:
            raise ValueError('VSS 매핑 기술자 개수 상한 초과')
        for item in block_list.descriptors:
            fields = ('original_offset', 'relative_offset', 'store_offset', 'flags', 'allocation_bitmap')
            if not isinstance(item, dict) or any(type(item.get(key)) is not int for key in fields):
                raise ValueError('VSS 매핑 기술자의 필드 형식 오류')
            original, relative, stored, flags, bits = (item[key] for key in fields)
            if not item.get('valid') or min(original, relative, stored, flags, bits) < 0:
                raise ValueError('유효하지 않은 VSS 매핑 기술자')
            if flags & 4:
                continue
            if flags & ~3 or flags == 3 or not 0 <= bits <= 0xffffffff:
                raise ValueError('미지원 VSS 매핑 플래그 또는 할당 비트맵')
            if original % BLOCK_SIZE or original >= volume_size:
                raise ValueError('VSS 매핑의 원래 오프셋 범위 또는 정렬 오류')
            if flags == 1:
                if stored or bits or relative % BLOCK_SIZE or relative >= volume_size:
                    raise ValueError('VSS 전달 기술자의 대상 또는 부가 필드 오류')
                if relative == original or relative in result.reverse:
                    raise ValueError('자기 전달 또는 중복 역방향 대상은 추가 정규화가 필요합니다')
            elif not stored or stored % 512 or (flags == 0 and bits):
                raise ValueError('VSS 저장 기술자의 위치 또는 부가 필드 오류')
            raw_original = original
            rewritten = False
            if flags != 2 and original in result.reverse:
                owner = result.reverse[original]
                previous = result.blocks[owner]['base']
                if (original in result.blocks or previous is None or previous['flags'] != 1
                        or previous['relative_offset'] != original):
                    raise ValueError('전달 대상에 이미 기술자가 있어 순차 재매핑을 확정할 수 없습니다')
                if flags == 1 and relative == owner:
                    raise ValueError('순차 재매핑이 자기 전달로 돌아와 추가 검증이 필요합니다')
                del result.reverse[original]
                original, rewritten = owner, True
                result.rewrites.append({'entry_offset': item.get('entry_offset'),
                                        'from_original': raw_original, 'to_original': original})
            entry = result.blocks.setdefault(original, {'base': None, 'overlay': None})
            descriptor = {key: item[key] for key in fields}
            descriptor['original_offset_raw'] = raw_original
            descriptor['original_offset'] = original
            descriptor['entry_offset'] = item.get('entry_offset')
            if flags == 2:
                overlay = entry['overlay']
                if relative not in (0, 1) or (relative == 1 and overlay is None):
                    raise ValueError('?? ????? ?? ?? ?? ?? ?? ???? ??? ? ????')
                if overlay is None:
                    entry['overlay'] = {**descriptor, 'source_descriptors': [dict(descriptor)]}
                elif overlay['store_offset'] == stored:
                    # Only a single verified storage block can share sector bits.
                    overlay['allocation_bitmap'] |= bits
                    overlay['source_descriptors'].append(dict(descriptor))
                else:
                    raise ValueError('?? ?? ?? ??? ?? ?? ????? ?? ???? ?????')
            else:
                if entry['base'] is not None and not rewritten:
                    raise ValueError('같은 원래 블록의 기본 기술자가 중복되어 추가 정규화가 필요합니다')
                entry['base'] = descriptor
                if flags == 1:
                    result.reverse[relative] = original
        # Forward targets that also have base entries require ordered rewriting.
        if any(target in result.blocks and result.blocks[target]['base'] is not None
               for target in result.reverse):
            raise ValueError('전달 대상과 기본 기술자의 연결은 순차 재매핑 검증이 필요합니다')
        result.complete = True
    except ValueError as exc:
        result.blocks.clear()
        result.reverse.clear()
        result.rewrites.clear()
        result.errors.append(ParserError(str(source), 'vss', f'store:{result.store_id}/descriptor_map',
                                         str(exc), 'warning'))
    return result
