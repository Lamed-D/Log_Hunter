"""Build small synthetic ESE databases (large-page layout, one leaf page per table) for reader tests.
All values are fake; the same input always gives the same bytes."""
import struct

PAGE = 32768
HEADER = 80
TEXT, LONG_TEXT, LONG_BINARY, I16, I32, U32, I64 = 10, 12, 11, 3, 4, 14, 15
FIXED = {I16: 2, I32: 4, U32: 4, I64: 8}


def _page(objid, flags, values):
    """values: [bytes] for tags 1..n (tag 0 is an empty page header value)."""
    page = bytearray(PAGE)
    struct.pack_into("<III", page, 16, 0, 0, objid)
    entries = [b""] + list(values)
    struct.pack_into("<H", page, 34, len(entries))
    struct.pack_into("<I", page, 36, flags)
    offset = 0
    for index, value in enumerate(entries):
        page[HEADER + offset:HEADER + offset + len(value)] = value
        struct.pack_into("<HH", page, PAGE - 4 * (index + 1), len(value), offset)
        offset += len(value)
    assert HEADER + offset < PAGE - 4 * len(entries), "page overflow"
    return bytes(page)


def _leaf_entry(key, data):
    return struct.pack("<H", len(key)) + key + data


def record(columns, values):
    """columns: {id: (name, type)}; values: {id: python value}. Fixed ids 1..127, variable 128..255, tagged 256+."""
    fixed_ids = sorted(i for i in columns if i < 128)
    last_fixed = max([i for i in fixed_ids if i in values] or [0])
    fixed = b""
    nulls = bytearray((last_fixed + 7) // 8)
    for cid in range(1, last_fixed + 1):
        kind = columns[cid][1]
        if values.get(cid) is None:
            fixed += bytes(FIXED[kind])
            nulls[(cid - 1) // 8] |= 1 << ((cid - 1) % 8)
        else:
            fixed += struct.pack({I16: "<h", I32: "<i", U32: "<I", I64: "<q"}[kind], values[cid])
    variable_ids = [i for i in sorted(columns) if 128 <= i < 256]
    last_variable = max([i for i in variable_ids if i in values] or [127])
    ends, data, end = b"", b"", 0
    for cid in range(128, last_variable + 1):
        value = values.get(cid)
        if value is None:
            ends += struct.pack("<H", end | 0x8000)
            continue
        blob = value.encode("ascii") if isinstance(value, str) else value
        data += blob
        end += len(blob)
        ends += struct.pack("<H", end)
    head = struct.pack("<BBH", last_fixed, last_variable, 4 + len(fixed) + len(nulls))
    out = head + fixed + bytes(nulls) + ends + data
    tagged = [(cid, values[cid]) for cid in sorted(columns) if cid >= 256 and values.get(cid) is not None]
    if tagged:
        table = b""
        blobs = b""
        position = 4 * len(tagged)
        for cid, value in tagged:
            flags, blob = value if isinstance(value, tuple) else (0x01, value)
            blob = blob.encode("utf-16-le") if isinstance(blob, str) else blob
            table += struct.pack("<HH", cid, position)
            item = bytes([flags]) + blob
            blobs += item
            position += len(item)
        out += table + blobs
    return out


CATALOG_COLUMNS = {1: ("ObjidTable", I32), 2: ("Type", I16), 3: ("Id", I32), 4: ("ColtypOrPgnoFDP", I32),
                   5: ("SpaceUsage", I32), 6: ("Flags", I32), 7: ("PagesOrLocale", I32), 128: ("Name", TEXT)}


def build(path, tables, *, state=3, long_values=None):
    """tables: [(name, {id: (column name, type, codepage)}, [ {id: value} rows ])].
    long_values: {table name: {4-byte id: bytes}} stored in that table's long value tree."""
    long_values = long_values or {}
    pages = {}
    catalog = []
    next_page, next_objid = 5, 10
    for name, columns, rows in tables:
        objid, root = next_objid, next_page
        next_objid += 1
        next_page += 1
        catalog.append({1: objid, 2: 1, 3: objid, 4: root, 5: 0, 6: 0, 7: 0, 128: name})
        for cid, (cname, ctype, codepage) in columns.items():
            catalog.append({1: objid, 2: 2, 3: cid, 4: ctype, 5: FIXED.get(ctype, 0), 6: 0, 7: codepage, 128: cname})
        plain = {cid: (c[0], c[1]) for cid, c in columns.items()}
        entries = [_leaf_entry(struct.pack(">I", i + 1), record(plain, row)) for i, row in enumerate(rows)]
        pages[root] = _page(objid, 0x2003, entries)  # root | leaf | new record format
        if name in long_values:
            lv_page = next_page
            next_page += 1
            catalog.append({1: objid, 2: 4, 3: objid + 1000, 4: lv_page, 5: 0, 6: 0, 7: 0, 128: "LV"})
            lv_entries = []
            for lid, blob in sorted(long_values[name].items()):
                key = lid[::-1]  # the tree keys long values big endian
                lv_entries.append(_leaf_entry(key, struct.pack("<II", 1, len(blob))))
                lv_entries.append(_leaf_entry(key + struct.pack(">I", 0), blob))
            pages[lv_page] = _page(objid + 1000, 0x2083, lv_entries)
    pages[4] = _page(2, 0x2003, [_leaf_entry(struct.pack(">I", i), record(CATALOG_COLUMNS, row))
                                  for i, row in enumerate(catalog)])
    header = bytearray(PAGE)
    struct.pack_into("<I", header, 4, 0x89ABCDEF)
    struct.pack_into("<I", header, 8, 0x620)
    struct.pack_into("<I", header, 52, state)
    struct.pack_into("<I", header, 0xE8, 0x11)
    struct.pack_into("<I", header, 0xEC, PAGE)
    count = max(pages)
    body = b"".join(pages.get(n, _page(0, 0x8, [])) for n in range(1, count + 1))
    with open(path, "xb") as stream:
        stream.write(bytes(header) + bytes(header) + body)
