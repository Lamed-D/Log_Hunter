"""Read-only reader for ESE (Extensible Storage Engine) database files: header, B-tree pages, catalog, table records,
long values and the column compression used by browser cache databases. Written from the public format description;
damaged pages are skipped with a warning, never fatal."""
import struct

SIGNATURE = 0x89ABCDEF
CATALOG_ROOT = 4  # MSysObjects always starts at page 4
FLAG_ROOT, FLAG_LEAF, FLAG_PARENT, FLAG_EMPTY, FLAG_SPACE, FLAG_LONG = 0x1, 0x2, 0x4, 0x8, 0x20, 0x80
TAG_DELETED, TAG_COMMON = 0x2, 0x4  # tag flags (top three bits of the tag size or of the value's first word)
MAX_DEPTH, MAX_PAGES_PER_TREE = 32, 1_000_000

# Column types
BIT, U8, I16, I32, CURRENCY, FLOAT, DOUBLE, DATETIME, BINARY, TEXT, LONG_BINARY, LONG_TEXT, SLV, U32, I64, GUID, U16 = (
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)
FIXED_SIZE = {BIT: 1, U8: 1, I16: 2, I32: 4, CURRENCY: 8, FLOAT: 4, DOUBLE: 8, DATETIME: 8, U32: 4, I64: 8, GUID: 16, U16: 2}
CODEPAGE_UTF16 = 1200
# Flags byte in front of a tagged value: variable size, compressed, stored separately as a long value, multi-valued.
TAGGED_VARIABLE, TAGGED_COMPRESSED, TAGGED_LONG_VALUE, TAGGED_MULTI = 0x01, 0x02, 0x04, 0x08
COMPRESS_7BIT_ASCII, COMPRESS_7BIT_UNICODE = 1, 2


class ESEError(ValueError):
    pass


class Column:
    __slots__ = ("id", "name", "type", "size", "codepage")

    def __init__(self, column_id, name, column_type, size, codepage):
        self.id, self.name, self.type, self.size, self.codepage = column_id, name, column_type, size, codepage


class Table:
    def __init__(self, name, objid, root):
        self.name, self.objid, self.root = name, objid, root
        self.columns = {}
        self.long_value_root = None


class ESEDatabase:
    def __init__(self, path):
        with open(path, "rb") as stream:
            self.data = stream.read()
        self.warnings = []
        if len(self.data) < 4096 or struct.unpack_from("<I", self.data, 4)[0] != SIGNATURE:
            raise ESEError("ESE 데이터베이스 시그니처가 없습니다")
        self.format_version, = struct.unpack_from("<I", self.data, 8)
        self.state, = struct.unpack_from("<I", self.data, 52)
        self.revision, = struct.unpack_from("<I", self.data, 0xE8)
        self.page_size, = struct.unpack_from("<I", self.data, 0xEC)
        if self.page_size not in (2048, 4096, 8192, 16384, 32768):
            raise ESEError(f"지원하지 않는 페이지 크기 {self.page_size}")
        self.large = self.page_size >= 16384
        self.extended_header = self.revision >= 0x11 and self.large
        self.header_size = 80 if self.extended_header else 40
        self.pages = len(self.data) // self.page_size - 2
        self.tables = {}
        self._read_catalog()

    # --- pages -------------------------------------------------------------------------------------------------
    def _page(self, number):
        if not 1 <= number <= self.pages:
            raise ESEError(f"페이지 번호 범위 밖 {number}")
        start = (number + 1) * self.page_size
        page = memoryview(self.data)[start:start + self.page_size]
        prev_page, next_page, objid = struct.unpack_from("<III", page, 16)
        tags, = struct.unpack_from("<H", page, 34)
        flags, = struct.unpack_from("<I", page, 36)
        if tags * 4 > self.page_size - self.header_size:
            raise ESEError(f"페이지 {number}: 태그 수가 페이지보다 큽니다")
        return page, next_page, objid, tags, flags

    def _values(self, page, tags):
        """(flags, bytes) per tag; tag 0 is the page's own header value."""
        result = []
        body = self.page_size - self.header_size
        for index in range(tags):
            size, offset = struct.unpack_from("<HH", page, self.page_size - 4 * (index + 1))
            if self.large:
                size, offset = size & 0x7FFF, offset & 0x7FFF
                flags = 0
            else:
                flags = offset >> 13
                size, offset = size & 0x1FFF, offset & 0x1FFF
            if offset + size > body:
                raise ESEError("태그가 페이지 밖을 가리킵니다")
            value = bytes(page[self.header_size + offset:self.header_size + offset + size])
            if self.large and index > 0 and len(value) >= 2:
                flags = value[1] >> 5
                value = bytes([value[0], value[1] & 0x1F]) + value[2:]
            result.append((flags, value))
        return result

    def _entry(self, flags, value, branch):
        """(key, payload) of a branch/leaf entry; the common key prefix is not needed to read the data."""
        offset = 0
        if flags & TAG_COMMON:
            offset += 2
        if len(value) < offset + 2:
            raise ESEError("항목이 너무 짧습니다")
        key_size, = struct.unpack_from("<H", value, offset)
        offset += 2
        key = value[offset:offset + key_size]
        payload = value[offset + key_size:]
        if branch and len(payload) < 4:
            raise ESEError("가지 항목에 하위 페이지 번호가 없습니다")
        return key, payload

    def leaf_entries(self, root, objid=None):
        """Every live (key, data) entry of the B-tree rooted at `root`, in key order. Damaged pages are skipped."""
        seen = set()

        def walk(number, depth):
            if depth > MAX_DEPTH or number in seen or len(seen) > MAX_PAGES_PER_TREE:
                self.warnings.append(f"페이지 {number}: 순환하거나 너무 깊은 트리를 건너뜁니다")
                return
            seen.add(number)
            try:
                page, _next, page_objid, tags, flags = self._page(number)
                if objid is not None and page_objid != objid:
                    raise ESEError(f"페이지 {number}: 다른 객체({page_objid})의 페이지입니다")
                values = self._values(page, tags)
            except (ESEError, struct.error) as exc:
                self.warnings.append(str(exc))
                return
            if flags & FLAG_SPACE or flags & FLAG_EMPTY:
                return
            for value_flags, value in values[1:]:
                if value_flags & TAG_DELETED:
                    continue
                try:
                    key, payload = self._entry(value_flags, value, not flags & FLAG_LEAF)
                except ESEError as exc:
                    self.warnings.append(f"페이지 {number}: {exc}")
                    continue
                if flags & FLAG_LEAF:
                    yield key, payload
                else:
                    yield from walk(struct.unpack_from("<I", payload, len(payload) - 4)[0], depth + 1)
        yield from walk(root, 0)

    # --- records -----------------------------------------------------------------------------------------------
    def _record(self, data, columns):
        """{column id: raw bytes or None} of one data record (fixed, variable and tagged columns)."""
        if len(data) < 4:
            raise ESEError("레코드 머리가 짧습니다")
        last_fixed, last_variable, variable_offset = data[0], data[1], struct.unpack_from("<H", data, 2)[0]
        values = {}
        position = 4
        for column_id in range(1, last_fixed + 1):
            column = columns.get(column_id)
            size = column.size if column else 0
            if not size:
                raise ESEError(f"고정 열 {column_id}의 크기를 모릅니다")
            values[column_id] = data[position:position + size]
            position += size
        bitmap = data[position:position + (last_fixed + 7) // 8]
        for column_id in range(1, last_fixed + 1):
            if bitmap and bitmap[(column_id - 1) // 8] & (1 << ((column_id - 1) % 8)):
                values[column_id] = None
        count = max(0, last_variable - 127)
        ends = [struct.unpack_from("<H", data, variable_offset + 2 * i)[0] for i in range(count)]
        start = variable_offset + 2 * count
        previous = 0
        for i, end in enumerate(ends):
            empty, end = end & 0x8000, end & 0x7FFF
            values[128 + i] = None if empty else data[start + previous:start + end]
            previous = end
        tagged = start + previous
        if tagged < len(data):
            values.update(self._tagged(data[tagged:]))
        return values

    def _tagged(self, data):
        entries = []
        first_offset = None
        position = 0
        while position + 4 <= len(data):
            column_id, raw = struct.unpack_from("<HH", data, position)
            offset = raw & (0x7FFF if self.large else 0x3FFF)
            has_flags = bool(raw & 0x4000) if not self.large else True
            entries.append((column_id, offset, has_flags))
            if first_offset is None:
                first_offset = offset
            position += 4
            if position >= first_offset:
                break
        result = {}
        for index, (column_id, offset, has_flags) in enumerate(entries):
            if column_id < 256:
                continue  # tagged ids start at 256; a lower id here is damage, not a fixed or variable column
            end = entries[index + 1][1] if index + 1 < len(entries) else len(data)
            value = data[offset:end]
            flags = 0
            if value and has_flags and (self.large or self.revision >= 0x11):
                flags, value = value[0], value[1:]
            result[column_id] = (flags, value)
        return result

    # --- catalog -------------------------------------------------------------------------------------------------
    def _read_catalog(self):
        fixed = {1: Column(1, "ObjidTable", I32, 4, 0), 2: Column(2, "Type", I16, 2, 0), 3: Column(3, "Id", I32, 4, 0),
                 4: Column(4, "ColtypOrPgnoFDP", I32, 4, 0), 5: Column(5, "SpaceUsage", I32, 4, 0),
                 6: Column(6, "Flags", I32, 4, 0), 7: Column(7, "PagesOrLocale", I32, 4, 0),
                 8: Column(8, "RootFlag", U8, 1, 0), 9: Column(9, "RecordOffset", I16, 2, 0),
                 10: Column(10, "LCMapFlags", I32, 4, 0), 11: Column(11, "KeyMost", U16, 2, 0),
                 12: Column(12, "LVChunkMax", I32, 4, 0)}
        by_objid = {}
        for _key, data in self.leaf_entries(CATALOG_ROOT):
            try:
                row = self._record(data, fixed)
            except (ESEError, struct.error) as exc:
                self.warnings.append(f"카탈로그: {exc}")
                continue
            def number(cid, fmt="<i"):
                value = row.get(cid)
                if not isinstance(value, (bytes, bytearray)) or len(value) < struct.calcsize(fmt):
                    return None
                return struct.unpack(fmt, bytes(value[:struct.calcsize(fmt)]))[0]
            kind, objid, ident, coltype = number(2, "<h"), number(1), number(3), number(4)
            name = (row.get(128) or b"").decode("ascii", "replace")
            if kind == 1:
                table = Table(name, objid, coltype)
                by_objid[objid] = table
                self.tables[name] = table
            elif kind == 2 and objid in by_objid:
                size = number(5) or FIXED_SIZE.get(coltype, 0)
                codepage = number(7) or 0
                by_objid[objid].columns[ident] = Column(ident, name, coltype, FIXED_SIZE.get(coltype, size), codepage)
            elif kind == 4 and objid in by_objid:
                by_objid[objid].long_value_root = coltype

    # --- values ------------------------------------------------------------------------------------------------
    def rows(self, table_name, skip=()):
        """Each record of a table as {column name: Python value}; unreadable values become None with a warning.
        Columns named in `skip` are not decoded at all (e.g. cookie values)."""
        table = self.tables.get(table_name)
        if table is None:
            raise ESEError(f"테이블 없음: {table_name}")
        long_values = None
        for _key, data in self.leaf_entries(table.root, table.objid):
            try:
                raw = self._record(data, table.columns)
            except (ESEError, struct.error, IndexError) as exc:
                self.warnings.append(f"{table_name}: {exc}")
                continue
            row = {}
            for column_id, value in raw.items():
                column = table.columns.get(column_id)
                if column is None or column.name in skip:
                    continue
                flags = 0
                if isinstance(value, tuple):
                    flags, value = value
                if value is not None and flags & TAGGED_LONG_VALUE and len(value) >= 4:  # stored as a separate long value
                    if long_values is None:
                        long_values = self._long_values(table)
                    value = long_values.get(self.long_value_key(value))
                    if value is None:
                        self.warnings.append(f"{table_name}.{column.name}: 긴 값을 찾지 못했습니다")
                try:
                    row[column.name] = None if value is None else self._convert(column, value, flags)
                except (ValueError, struct.error, UnicodeError) as exc:
                    self.warnings.append(f"{table_name}.{column.name}: {exc}")
                    row[column.name] = None
            yield row

    def _long_values(self, table):
        """{long value id as the tree keys it (big endian): joined bytes}. The tree holds a header entry keyed by the
        id alone, then chunks keyed by id + 4-byte offset. Ids are 4 bytes, or 8 bytes when the top bit is set."""
        chunks = {}
        if not table.long_value_root:
            return {}
        for key, data in self.leaf_entries(table.long_value_root):
            key = bytes(key)
            size = 8 if key[:1] and key[0] & 0x80 and len(key) in (8, 12) else 4
            if len(key) == size + 4:
                chunks.setdefault(key[:size], []).append((int.from_bytes(key[size:], "big"), bytes(data)))
        return {lid: b"".join(chunk for _offset, chunk in sorted(parts)) for lid, parts in chunks.items()}

    @staticmethod
    def long_value_key(value):
        """Tree key of the long value a separated column points to (the record stores the id little endian)."""
        value = bytes(value)
        size = 8 if len(value) >= 8 and value[3] & 0x80 else 4
        return value[:size][::-1]

    def _convert(self, column, value, flags):
        if flags & TAGGED_COMPRESSED:
            value = decompress(value)
        kind = column.type
        if kind in (TEXT, LONG_TEXT):
            if column.codepage == CODEPAGE_UTF16:
                return bytes(value).decode("utf-16-le", "replace").rstrip("\x00")
            return bytes(value).decode("cp1252", "replace").rstrip("\x00")
        if kind in (BINARY, LONG_BINARY):
            return bytes(value)
        fmt = {BIT: "<B", U8: "<B", I16: "<h", I32: "<i", CURRENCY: "<q", FLOAT: "<f", DOUBLE: "<d", DATETIME: "<d",
               U32: "<I", I64: "<q", U16: "<H"}.get(kind)
        if fmt:
            return struct.unpack(fmt, bytes(value[:struct.calcsize(fmt)]))[0]
        if kind == GUID:
            return bytes(value).hex()
        return bytes(value)


def decompress(value):
    """Undo ESE's 7-bit packing of short text. First byte: scheme << 3 | (bits used in the last byte - 1);
    scheme 1 = 7-bit ASCII, 2 = 7-bit characters of UTF-16 text. Other schemes (Xpress) are not supported."""
    value = bytes(value)
    if len(value) < 2:
        raise ValueError("압축 값이 너무 짧습니다")
    scheme = value[0] >> 3
    if scheme not in (COMPRESS_7BIT_ASCII, COMPRESS_7BIT_UNICODE):
        raise ValueError(f"지원하지 않는 압축 방식 {scheme}")
    total = (len(value) - 2) * 8 + (value[0] & 0x7) + 1
    bits = int.from_bytes(value[1:], "little")
    data = bytes((bits >> (7 * index)) & 0x7F for index in range(total // 7))
    return data.decode("ascii").encode("utf-16-le") if scheme == COMPRESS_7BIT_UNICODE else data
