"""Bounded EVTX BinXML fragments, chunk-relative names, templates and substitutions."""
import struct
from datetime import datetime, timedelta, timezone

TOKEN_EOF = 0x00
TOKEN_OPEN_START = 0x01
TOKEN_CLOSE_START = 0x02
TOKEN_CLOSE_EMPTY = 0x03
TOKEN_END_ELEMENT = 0x04
TOKEN_VALUE = 0x05
TOKEN_ATTRIBUTE = 0x06
TOKEN_CDATA_SECTION = 0x07
TOKEN_ENTITY_REF = 0x09
TOKEN_PI_TARGET = 0x0A
TOKEN_PI_DATA = 0x0B
TOKEN_TEMPLATE_INSTANCE = 0x0C
TOKEN_NORMAL_SUBSTITUTION = 0x0D
TOKEN_OPTIONAL_SUBSTITUTION = 0x0E

VALUE_NULL = 0x00
VALUE_STRING = 0x01
VALUE_ANSI_STRING = 0x02
VALUE_INT8 = 0x03
VALUE_UINT8 = 0x04
VALUE_INT16 = 0x05
VALUE_UINT16 = 0x06
VALUE_INT32 = 0x07
VALUE_UINT32 = 0x08
VALUE_INT64 = 0x09
VALUE_UINT64 = 0x0A
VALUE_REAL32 = 0x0B
VALUE_REAL64 = 0x0C
VALUE_BOOL = 0x0D
VALUE_BINARY = 0x0E
VALUE_GUID = 0x0F
VALUE_SIZET = 0x10
VALUE_FILETIME = 0x11
VALUE_SYSTEMTIME = 0x12
VALUE_SID = 0x13
VALUE_HEX32 = 0x14
VALUE_HEX64 = 0x15
VALUE_BINXML = 0x21

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def decode_value(data, offset, value_type, length):
    end = offset + length
    if offset < 0 or length < 0 or end > len(data):
        return None, end
    if length == 0:
        if value_type & 0x80:
            return [], end
        return ("" if value_type in (VALUE_STRING, VALUE_ANSI_STRING, VALUE_BINARY) else None), end
    if value_type == VALUE_NULL:
        return None, end
    widths = {3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8,
              11: 4, 12: 8, 13: 4, 15: 16, 17: 8, 18: 16, 20: 4, 21: 8}
    if value_type & 0x80:
        base_type = value_type & 0x7f
        raw = data[offset:end]
        if base_type in (VALUE_STRING, VALUE_ANSI_STRING):
            if base_type == VALUE_STRING and length % 2:
                return None, end
            encoding = "utf-16-le" if base_type == VALUE_STRING else "latin1"
            return raw.decode(encoding, errors="replace").rstrip("\0").split("\0"), end
        width = widths.get(base_type)
        if not width or length % width:
            return None, end
        return [decode_value(raw, i, base_type, width)[0] for i in range(0, length, width)], end
    width = widths.get(value_type)
    if width and length != width:
        return None, end
    if value_type == VALUE_SIZET and length not in (4, 8):
        return None, end
    try:
        if value_type == VALUE_STRING:
            return data[offset:end].decode("utf-16-le", errors="replace").rstrip("\0"), end
        if value_type == VALUE_ANSI_STRING:
            return data[offset:end].decode("latin-1", errors="replace").rstrip("\0"), end
        if value_type == VALUE_UINT8:
            return data[offset], end
        if value_type == VALUE_INT8:
            return struct.unpack_from("<b", data, offset)[0], end
        if value_type == VALUE_UINT16:
            return struct.unpack_from("<H", data, offset)[0], end
        if value_type == VALUE_INT16:
            return struct.unpack_from("<h", data, offset)[0], end
        if value_type == VALUE_UINT32 or value_type == VALUE_HEX32:
            return struct.unpack_from("<I", data, offset)[0], end
        if value_type == VALUE_INT32:
            return struct.unpack_from("<i", data, offset)[0], end
        if value_type == VALUE_UINT64 or value_type == VALUE_HEX64:
            return struct.unpack_from("<Q", data, offset)[0], end
        if value_type == VALUE_INT64:
            return struct.unpack_from("<q", data, offset)[0], end
        if value_type == VALUE_REAL32:
            return struct.unpack_from("<f", data, offset)[0], end
        if value_type == VALUE_REAL64:
            return struct.unpack_from("<d", data, offset)[0], end
        if value_type == VALUE_BOOL:
            return struct.unpack_from("<I", data, offset)[0] != 0, end
        if value_type == VALUE_SIZET:
            return int.from_bytes(data[offset:end], "little"), end
        if value_type == VALUE_SYSTEMTIME:
            year, month, _, day, hour, minute, second, millis = struct.unpack_from("<8H", data, offset)
            if millis > 999:
                return None, end
            # SYSTEMTIME carries no timezone; the event provider defines its clock.
            return datetime(year, month, day, hour, minute, second, millis * 1000).isoformat(), end
        if value_type == VALUE_FILETIME:
            raw = struct.unpack_from("<Q", data, offset)[0]
            if raw == 0 or raw == 0x7FFFFFFFFFFFFFFF:
                return None, end
            try:
                return (FILETIME_EPOCH + timedelta(microseconds=raw // 10)).isoformat(), end
            except OverflowError:
                return None, end
        if value_type == VALUE_SID:
            if length >= 8:
                rev, sub_count = data[offset], data[offset + 1]
                if rev != 1 or sub_count > 15 or length != 8 + 4 * sub_count:
                    return None, end
                auth = int.from_bytes(data[offset + 2:offset + 8], "big")
                subs = []
                for i in range(min(sub_count, (length - 8) // 4)):
                    subs.append(struct.unpack_from("<I", data, offset + 8 + i * 4)[0])
                return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs), end
            return None, end
        if value_type == VALUE_GUID:
            if length >= 16:
                a, b, c = struct.unpack_from("<IHH", data, offset)
                d = data[offset + 8:offset + 16]
                return f"{a:08x}-{b:04x}-{c:04x}-{d[:2].hex()}-{d[2:].hex()}", end
            return data[offset:end].hex(), end
        if value_type == VALUE_BINARY:
            return data[offset:end].hex(), end
    except (struct.error, UnicodeDecodeError, ValueError):
        return None, end
    return data[offset:end].hex(), end


class _Fragment(list):
    pass


class BinXmlParser:
    """Decode one EVTX fragment while retaining chunk-relative name/template addresses."""
    def __init__(self, data, offset=0, substitutions=None, end=None, depth=0, active=None, budget=None, dependency=True, warnings=None):
        self.warnings = [] if warnings is None else warnings
        self.data, self.offset = data, offset
        self.end = len(data) if end is None else end
        self.substitutions = substitutions or []
        self.depth, self.active = depth, active or frozenset()
        self.budget = [100000] if budget is None else budget
        self.elements, self.stack, self.pending = [], [], None
        self.dependency, self.ends = dependency, []
        self.pending_end = self.attributes_end = None
        if not 0 <= offset <= self.end <= len(data) or depth > 32:
            raise ValueError("BinXML fragment range or nesting limit")

    def _need(self, size):
        if size < 0 or self.offset + size > self.end:
            raise ValueError("Truncated BinXML fragment")

    def _take(self, fmt):
        size = struct.calcsize(fmt)
        self._need(size)
        result = struct.unpack_from(fmt, self.data, self.offset)
        self.offset += size
        return result[0] if len(result) == 1 else result

    def _charge(self, count=1):
        self.budget[0] -= count
        if self.budget[0] < 0:
            raise ValueError("BinXML expansion limit")

    def _child(self, offset, end, substitutions=None, active=None, dependency=True):
        return BinXmlParser(self.data, offset, substitutions, end, self.depth + 1,
                            self.active if active is None else active, self.budget, dependency, self.warnings)

    def _name(self):
        reference = self._take("<I")
        if reference > self.offset or reference + 8 > len(self.data):
            raise ValueError("Invalid BinXML name reference")
        length = struct.unpack_from("<H", self.data, reference + 6)[0]
        end = reference + 8 + length * 2
        if end + 2 > len(self.data) or self.data[end:end + 2] != b"\0\0":
            raise ValueError("Invalid BinXML name length")
        name = self.data[reference + 8:end].decode("utf-16-le", errors="replace")
        if reference == self.offset:
            self._need(end + 2 - self.offset)
            self.offset = end + 2
        elif end + 2 > self.offset:
            raise ValueError("Overlapping BinXML name reference")
        return name

    def _attach(self, elements):
        count, pending = 0, [(element, 1) for element in elements]
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > self.budget[0] or depth + len(self.stack) + self.depth > 128:
                raise ValueError("BinXML expanded tree limit")
            pending.extend((child, depth + 1) for child in node.get("children", []))
        self._charge(count)
        target = self.stack[-1]["children"] if self.stack else self.elements
        target.extend(elements)

    def _content(self, token):
        kind = token & 0x3f
        if kind == TOKEN_VALUE:
            value_type = self._take("<B")
            if value_type != VALUE_STRING:
                raise ValueError("Unsupported inline BinXML value type")
            count = self._take("<H") * 2
            self._need(count)
            text = self.data[self.offset:self.offset + count].decode("utf-16-le", errors="replace")
            self.offset += count
            return text, False
        if kind in (TOKEN_NORMAL_SUBSTITUTION, TOKEN_OPTIONAL_SUBSTITUTION):
            index, _value_type = self._take("<HB")
            if index >= len(self.substitutions):
                raise ValueError("BinXML substitution index out of range")
            return self.substitutions[index], kind == TOKEN_OPTIONAL_SUBSTITUTION
        if kind == TOKEN_CDATA_SECTION:
            count = self._take("<H") * 2
            self._need(count)
            text = self.data[self.offset:self.offset + count].decode("utf-16-le", errors="replace")
            self.offset += count
            return text, False
        if kind == 8:
            return chr(self._take("<H")), False
        if kind == TOKEN_ENTITY_REF:
            name = self._name()
            entities = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
            if name not in entities:
                raise ValueError("Unknown BinXML entity")
            return entities[name], False
        raise ValueError("Unsupported BinXML content token")

    def _attribute(self):
        if self.pending is None:
            raise ValueError("BinXML attribute outside start tag")
        name = self._name()
        token = self._take("<B")
        value, optional = self._content(token)
        while token & 0x40:
            token = self._take("<B")
            more, _ = self._content(token)
            value = str(value or "") + str(more or "")
        if not (optional and value is None):
            self.pending["attrs"][name] = value
        if self.attributes_end is None or self.offset > self.attributes_end:
            raise ValueError("BinXML attribute list range")

    def _template(self):
        _version, _identifier, reference = self._take("<BII")
        if reference in self.active or reference > self.offset or reference + 24 > len(self.data):
            raise ValueError("Invalid or recursive BinXML template reference")
        size = struct.unpack_from("<I", self.data, reference + 20)[0]
        body, end = reference + 24, reference + 24 + size
        if not size or end > len(self.data):
            raise ValueError("Invalid BinXML template length")
        if reference == self.offset:
            self._need(end - self.offset)
            self.offset = end
        elif end > self.offset:
            raise ValueError("Overlapping BinXML template reference")
        count = self._take("<I")
        if count > 4096:
            raise ValueError("BinXML substitution count limit")
        self._need(count * 4)
        descriptors = [self._take("<HBB") for _ in range(count)]
        active = self.active | {reference}
        values = []
        for length, kind, reserved in descriptors:
            if reserved:
                raise ValueError("Invalid BinXML value descriptor")
            self._need(length)
            if kind == VALUE_BINXML:
                try:
                    nodes = self._child(self.offset, self.offset + length, active=active, dependency=False).parse()
                except ValueError:
                    nodes = self._child(self.offset, self.offset + length, active=active).parse()
                value = _Fragment(nodes)
            else:
                value, _ = decode_value(self.data, self.offset, kind, length)
                if (kind & 0x7f) > VALUE_HEX64:
                    self.warnings.append({"offset": self.offset, "type": kind, "length": length})
            values.append(value)
            self.offset += length
        self._attach(self._child(body, end, values, active).parse())

    def parse(self):
        while self.offset < self.end:
            self._charge()
            token = self._take("<B")
            kind = token & 0x3f
            if kind == TOKEN_EOF:
                if self.stack or self.pending is not None:
                    raise ValueError("Unclosed BinXML element")
                return self._clean(self.elements)
            if kind == 0x0f:
                if self._take("<BBB") != (1, 1, 0):
                    raise ValueError("Unsupported BinXML fragment version")
            elif kind == TOKEN_OPEN_START:
                if self.pending is not None or len(self.stack) >= 128:
                    raise ValueError("Invalid BinXML element nesting")
                dependency, size = self._take("<HI") if self.dependency else (0xffff, self._take("<I"))
                if size > self.end - self.offset:
                    raise ValueError("Invalid BinXML element size")
                self.pending_end = self.offset + size
                self.pending = {"name": self._name(), "attrs": {}, "text": None, "children": []}
                if dependency < len(self.substitutions) and self.substitutions[dependency] is None:
                    self.pending["_omit"] = True
                if token & 0x40:
                    attributes_size = self._take("<I")
                    self._need(attributes_size)
                    self.attributes_end = self.offset + attributes_size
                else:
                    self.attributes_end = None
            elif kind == TOKEN_ATTRIBUTE:
                self._attribute()
            elif kind in (TOKEN_CLOSE_START, TOKEN_CLOSE_EMPTY):
                if self.pending is None:
                    raise ValueError("BinXML close tag without start tag")
                if self.attributes_end is not None and self.offset - 1 != self.attributes_end:
                    raise ValueError("BinXML attribute list length mismatch")
                element, self.pending = self.pending, None
                self._attach([element])
                if kind == TOKEN_CLOSE_START:
                    self.stack.append(element)
                    self.ends.append(self.pending_end)
                elif self.offset != self.pending_end:
                    raise ValueError("BinXML empty element length mismatch")
            elif kind == TOKEN_END_ELEMENT:
                if not self.stack:
                    raise ValueError("Unexpected BinXML end element")
                if self.offset != self.ends.pop():
                    raise ValueError("BinXML element length mismatch")
                self.stack.pop()
            elif kind == TOKEN_TEMPLATE_INSTANCE:
                self._template()
            elif kind in (TOKEN_VALUE, TOKEN_NORMAL_SUBSTITUTION, TOKEN_OPTIONAL_SUBSTITUTION,
                          TOKEN_CDATA_SECTION, TOKEN_ENTITY_REF, 8):
                if not self.stack:
                    raise ValueError("BinXML content outside element")
                value, optional = self._content(token)
                element = self.stack[-1]
                if optional and value is None:
                    element["_omit"] = True
                elif isinstance(value, _Fragment):
                    self._attach(value)
                elif value is not None:
                    element["text"] = value if element["text"] is None else str(element["text"]) + str(value)
            else:
                raise ValueError(f"Unsupported BinXML token: {kind:#x}")
        raise ValueError("BinXML fragment has no end token")

    def _clean(self, elements):
        result = []
        for element in elements:
            if not element.get("_omit", False):
                element["children"] = self._clean(element["children"])
                result.append(element)
        return result


def _user_data_values(elements, result):
    for element in elements:
        children = element.get('children') or []
        if children:
            _user_data_values(children, result)
        elif element.get('name') and element.get('text') is not None:
            key = element['name'].split('}')[-1]
            value = element['text']
            if key in result:
                previous = result[key]
                result[key] = previous + [value] if isinstance(previous, list) else [previous, value]
            else:
                result[key] = value


def extract_event_fields(elements, fields=None):
    """Walk parsed BinXML elements and extract standard EVTX System fields."""
    if fields is None:
        fields = {}
    for elem in elements:
        name = (elem.get("name") or "").split("}")[-1] if elem.get("name") else ""
        attrs = elem.get("attrs") or {}
        text = elem.get("text")
        children = elem.get("children") or []
        if name == "EventID":
            try:
                fields["event_id"] = int(text) if text else None
            except (ValueError, TypeError):
                fields["event_id"] = None
            if attrs.get("Qualifiers"):
                fields["event_id_qualifiers"] = attrs["Qualifiers"]
        elif name == "Level":
            try:
                fields["level"] = int(text) if text else None
            except (ValueError, TypeError):
                fields["level"] = text
        elif name == "Task":
            try:
                fields["task"] = int(text) if text else None
            except (ValueError, TypeError):
                fields["task"] = text
        elif name == "Keywords":
            fields["keywords"] = text
        elif name == "TimeCreated":
            fields["time_created"] = attrs.get("SystemTime")
        elif name == "EventRecordID":
            try:
                fields["record_id"] = int(text) if text else None
            except (ValueError, TypeError):
                fields["record_id"] = text
        elif name == "Channel":
            fields["channel"] = text
        elif name == "Computer":
            fields["computer"] = text
        elif name == "Provider":
            fields["provider_name"] = attrs.get("Name")
            fields["provider_guid"] = attrs.get("Guid")
        elif name == "Security":
            fields["security_user_id"] = attrs.get("UserID")
        elif name == "Execution":
            fields["process_id"] = attrs.get("ProcessID")
            fields["thread_id"] = attrs.get("ThreadID")
        elif name == "Correlation":
            fields["activity_id"] = attrs.get("ActivityID")
        elif name == "Data":
            data_name = attrs.get("Name", "")
            data_list = fields.setdefault("event_data", {})
            if data_name:
                data_list[data_name] = text
            elif text:
                unnamed = data_list.setdefault("_unnamed", [])
                unnamed.append(text)
        elif name == 'UserData':
            _user_data_values(children, fields.setdefault('user_data', {}))
        elif name == "EventData" or name == "System":
            extract_event_fields(children, fields)
        else:
            if children:
                extract_event_fields(children, fields)
    return fields
