# ▶ 원본: log_hunter/parser/xpress.py
# ▶ 순수 Python으로 XPRESS Huffman을 해제합니다. 출력 크기·블록·매치 참조를 검사합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Bounded XPRESS Huffman decoding for compressed Prefetch (MS-XCA section 2.2)."""
from array import array
from functools import lru_cache

MAX_OUTPUT = 64 * 1024 * 1024


@lru_cache(maxsize=8)
def _table(header):
    lengths = [length for byte in header for length in (byte & 15, byte >> 4)]
    table = array("H")
    for length in range(1, 16):
        for symbol, width in enumerate(lengths):
            if width == length:
                count = 1 << (15 - length)
                if len(table) + count > 32768:
                    raise ValueError("과도한 XPRESS 허프만 코드")
                table.extend(array("H", [(symbol << 4) | length]) * count)
    if len(table) != 32768:
        raise ValueError("불완전한 XPRESS 허프만 테이블")
    return table


class _Bits:
    def __init__(self, data, position):
        self.data, self.position = data, position
        self.value = (self.read(2) << 16) | self.read(2)
        self.extra = 16

    def read(self, count):
        end = self.position + count
        if end > len(self.data):
            raise ValueError("잘린 XPRESS 압축 데이터")
        value = int.from_bytes(self.data[self.position:end], "little")
        self.position = end
        return value

    def take(self, count):
        value = self.value >> (32 - count) if count else 0
        self.value = (self.value << count) & 0xffffffff
        self.extra -= count
        if self.extra < 0:
            self.value |= self.read(2) << -self.extra
            self.extra += 16
        return value


def decompress(data, size):
    """Decode to exactly size bytes, with a fixed output ceiling and bounded blocks."""
    if not isinstance(size, int) or not 0 <= size <= MAX_OUTPUT:
        raise ValueError("XPRESS 확장 크기 범위 초과")
    output, position = bytearray(), 0
    while len(output) < size:
        if position + 260 > len(data):
            raise ValueError("잘린 XPRESS 블록 헤더")
        table = _table(bytes(data[position:position + 256]))
        bits = _Bits(data, position + 256)
        block_end = min(len(output) + 65536, size)
        while len(output) < block_end:
            entry = table[bits.value >> 17]
            symbol = entry >> 4
            bits.take(entry & 15)
            if symbol < 256:
                output.append(symbol)
                continue
            match = symbol - 256
            length, offset_bits = match & 15, match >> 4
            if length == 15:
                length = bits.read(1)
                if length == 255:
                    length = bits.read(2)
                    if length == 0:
                        length = bits.read(4)
                    if length < 15:
                        raise ValueError(f"잘못된 XPRESS 확장 길이: {length}, 출력 {len(output)}, 입력 {bits.position}")
                    length -= 15
                length += 15
            length += 3
            distance = (1 << offset_bits) + bits.take(offset_bits)
            if distance > len(output) or length > size - len(output):
                raise ValueError("XPRESS 매치 범위 초과")
            # Repeat a complete period to preserve overlapping LZ77 copies.
            period = output[-distance:]
            repeats, remainder = divmod(length, distance)
            output.extend(period * repeats)
            output.extend(period[:remainder])
        position = bits.position
    return bytes(output)


def decompress_prefetch(data):
    if len(data) < 8 or data[:4] != b"MAM\x04":
        raise ValueError("CRC/미지원 MAM 압축 유형")
    size = int.from_bytes(data[4:8], "little")
    if not 84 <= size <= MAX_OUTPUT:
        raise ValueError("MAM 확장 크기 범위 초과")
    return decompress(data[8:], size)
