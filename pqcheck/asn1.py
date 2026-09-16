"""Minimal DER/BER parser (definite and indefinite lengths) and OID decoding."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Node:
    tag: int            # full first identifier octet
    cls: int            # 0 universal, 1 application, 2 context, 3 private
    constructed: bool
    number: int
    offset: int
    value: bytes
    children: List["Node"] = field(default_factory=list)

    @property
    def is_seq(self):
        return self.cls == 0 and self.number in (16, 17)

    @property
    def is_oid(self):
        return self.cls == 0 and self.number == 6 and not self.constructed

    @property
    def is_int(self):
        return self.cls == 0 and self.number == 2

    @property
    def is_octets(self):
        return self.cls == 0 and self.number == 4

    @property
    def is_bits(self):
        return self.cls == 0 and self.number == 3

    def oid(self) -> Optional[str]:
        return decode_oid(self.value) if self.is_oid else None

    def int_bits(self) -> int:
        v = self.value
        i = 0
        while i < len(v) and v[i] == 0:
            i += 1
        if i >= len(v):
            return 0
        return (len(v) - i - 1) * 8 + v[i].bit_length()


class ParseError(Exception):
    pass


def decode_oid(b: bytes) -> str:
    if not b:
        return ""
    parts = []
    first = b[0]
    if first < 40:
        parts += [0, first]
    elif first < 80:
        parts += [1, first - 40]
    else:
        parts += [2, first - 80]
    val = 0
    for c in b[1:]:
        val = (val << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _read_header(data: bytes, pos: int):
    if pos >= len(data):
        raise ParseError("truncated")
    tag = data[pos]
    cls = tag >> 6
    constructed = bool(tag & 0x20)
    number = tag & 0x1F
    pos += 1
    if number == 0x1F:
        number = 0
        while True:
            if pos >= len(data):
                raise ParseError("truncated tag")
            c = data[pos]
            pos += 1
            number = (number << 7) | (c & 0x7F)
            if not c & 0x80:
                break
    if pos >= len(data):
        raise ParseError("truncated length")
    l = data[pos]
    pos += 1
    if l == 0x80:
        length = None  # indefinite
    elif l & 0x80:
        n = l & 0x7F
        if n > 4 or pos + n > len(data):
            raise ParseError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = l
    return tag, cls, constructed, number, length, pos


def parse(data: bytes, pos: int = 0, end: Optional[int] = None, depth: int = 0) -> List[Node]:
    """Parse a sequence of TLVs in data[pos:end]. Raises ParseError."""
    if end is None:
        end = len(data)
    nodes = []
    if depth > 64:
        raise ParseError("too deep")
    while pos < end:
        if data[pos] == 0 and pos + 1 < end and data[pos + 1] == 0:
            # end-of-contents in indefinite form handled by caller
            break
        start = pos
        tag, cls, constructed, number, length, pos = _read_header(data, pos)
        if length is None:
            if not constructed:
                raise ParseError("indefinite primitive")
            children = parse(data, pos, end, depth + 1)
            cpos = children[-1]._end if children else pos
            if cpos + 2 > end or data[cpos] != 0 or data[cpos + 1] != 0:
                raise ParseError("missing EOC")
            node = Node(tag, cls, constructed, number, start, data[pos:cpos], children)
            node._end = cpos + 2
            pos = cpos + 2
        else:
            if pos + length > end:
                raise ParseError("value overruns")
            value = data[pos:pos + length]
            children = []
            if constructed:
                children = parse(data, pos, pos + length, depth + 1)
            node = Node(tag, cls, constructed, number, start, value, children)
            node._end = pos + length
            pos += length
        nodes.append(node)
    return nodes


def try_parse(data: bytes) -> Optional[List[Node]]:
    try:
        nodes = parse(data)
    except (ParseError, IndexError, RecursionError):
        return None
    if not nodes:
        return None
    # must consume the buffer (allow trailing NULs/whitespace)
    tail = data[nodes[-1]._end:]
    if tail.strip(b"\x00\r\n\t ") != b"":
        return None
    return nodes


def looks_like_der(data: bytes) -> bool:
    return len(data) > 2 and data[0] == 0x30 and try_parse(data) is not None


def walk(nodes: List[Node], depth: int = 0):
    for n in nodes:
        yield n, depth
        for sub in walk(n.children, depth + 1):
            yield sub
