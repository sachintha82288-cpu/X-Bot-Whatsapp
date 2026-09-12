"""WhatsApp's binary XML ("WABinary") encoder/decoder.

The wire format is a token-compressed, length-prefixed serialisation of
``<tag attr="value">…</tag>`` nodes.  This is a from-scratch Python port of
the well documented format (Baileys ``WABinary/encode.ts`` /
``decode.ts``, whatsmeow ``binary``).

Node representation::

    Node(tag="iq", attrs={"type": "get"}, content=[Node(...), "text", b"bytes"])

``content`` may be ``None``, ``str``, ``bytes`` or a ``list`` mixing nodes,
strings and bytes.
"""

from __future__ import annotations

import zlib
from typing import Any, Iterable, List, Optional, Union

from . import tokens as T

TAGS = T.TAGS
SINGLE_BYTE_TOKENS = T.SINGLE_BYTE_TOKENS
DOUBLE_BYTE_TOKENS = T.DOUBLE_BYTE_TOKENS
TOKEN_MAP = T.TOKEN_MAP

LIST_EMPTY = TAGS["LIST_EMPTY"]
LIST_8 = TAGS["LIST_8"]
LIST_16 = TAGS["LIST_16"]
JID_PAIR = TAGS["JID_PAIR"]
AD_JID = TAGS["AD_JID"]
FB_JID = TAGS["FB_JID"]
INTEROP_JID = TAGS["INTEROP_JID"]
HEX_8 = TAGS["HEX_8"]
NIBBLE_8 = TAGS["NIBBLE_8"]
BINARY_8 = TAGS["BINARY_8"]
BINARY_20 = TAGS["BINARY_20"]
BINARY_32 = TAGS["BINARY_32"]
DICTIONARY_0 = TAGS["DICTIONARY_0"]
PACKED_MAX = TAGS["PACKED_MAX"]

WA_DOMAINS = {"whatsapp": 0, "lid": 1, "hosted": 128, "hosted.lid": 129}


class Node:
    """A binary-protocol node (cheap ``__slots__`` object like Baileys)."""

    __slots__ = ("tag", "attrs", "content")

    def __init__(self, tag: str, attrs: Optional[dict] = None,
                 content: Union[None, str, bytes, list] = None):
        self.tag = tag
        self.attrs = dict(attrs) if attrs else {}
        self.content = content

    # ---------------------------------------------------------------- lookup
    def child(self, tag: str) -> Optional["Node"]:
        for item in self.iter_children():
            if item.tag == tag:
                return item
        return None

    def children(self, tag: Optional[str] = None) -> List["Node"]:
        items = list(self.iter_children())
        if tag is None:
            return items
        return [i for i in items if i.tag == tag]

    def iter_children(self) -> Iterable["Node"]:
        if isinstance(self.content, list):
            for item in self.content:
                if isinstance(item, Node):
                    yield item

    def buffer(self) -> Optional[bytes]:
        """Content as bytes (Baileys' ``getBinaryNodeChildBuffer``)."""
        if isinstance(self.content, (bytes, bytearray)):
            return bytes(self.content)
        if isinstance(self.content, str):
            return self.content.encode()
        return None

    def text(self) -> Optional[str]:
        if isinstance(self.content, str):
            return self.content
        if isinstance(self.content, (bytes, bytearray)):
            try:
                return bytes(self.content).decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None

    def int_value(self) -> Optional[int]:
        try:
            return int(self.attrs.get("value", ""))
        except ValueError:
            return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Node({self.tag!r}, {self.attrs!r}, {self.content!r})"


def jid_decode(jid: Optional[str]):
    """``user[:device][_agent]@server`` -> (user, server, device, domain_type)."""
    if not jid or not isinstance(jid, str):
        return None
    sep = jid.find("@")
    if sep < 0:
        return None
    server = jid[sep + 1:]
    user_combined = jid[:sep]
    user_agent, _, device = user_combined.partition(":")
    user, _, agent = user_agent.partition("_")
    domain_type = 0
    if server == "lid":
        domain_type = 1
    elif server == "hosted":
        domain_type = 128
    elif server == "hosted.lid":
        domain_type = 129
    elif agent:
        try:
            domain_type = int(agent)
        except ValueError:
            domain_type = 0
    return user, server, (int(device) if device else None), domain_type


def jid_encode(user, server: str, device: Optional[int] = None, agent: Optional[int] = None) -> str:
    out = f"{'' if user is None else user}"
    if agent:
        out += f"_{agent}"
    if device:
        out += f":{device}"
    return f"{out}@{server}"


def jid_normalized(jid: Optional[str]) -> str:
    d = jid_decode(jid)
    if not d:
        return ""
    user, server, _device, _dt = d
    if server == "c.us":
        server = "s.whatsapp.net"
    return f"{user}@{server}"


def is_jid_group(jid: Optional[str]) -> bool:
    return bool(jid) and jid.endswith("@g.us")


def is_jid_lid(jid: Optional[str]) -> bool:
    return bool(jid) and jid.endswith("@lid")


def is_jid_pn(jid: Optional[str]) -> bool:
    return bool(jid) and jid.endswith("@s.whatsapp.net")


def is_jid_status(jid: Optional[str]) -> bool:
    return jid == "status@broadcast"


def is_jid_newsletter(jid: Optional[str]) -> bool:
    return bool(jid) and jid.endswith("@newsletter")


def jid_user(jid: Optional[str]) -> Optional[str]:
    d = jid_decode(jid)
    return d[0] if d else None


def are_jids_same_user(a: Optional[str], b: Optional[str]) -> bool:
    ua, ub = jid_user(a), jid_user(b)
    return ua is not None and ua == ub


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------


def _is_nibble(s: str) -> bool:
    if not s or len(s) > PACKED_MAX:
        return False
    for ch in s:
        if not ("0" <= ch <= "9" or ch in "-."):
            return False
    return True


def _is_hex(s: str) -> bool:
    if not s or len(s) > PACKED_MAX:
        return False
    for ch in s:
        if not ("0" <= ch <= "9" or "A" <= ch <= "F"):
            return False
    return True


_NIBBLE_PACK = {"-": 10, ".": 11, "\x00": 15}
for _d in range(10):
    _NIBBLE_PACK[str(_d)] = _d

_HEX_PACK = {"\x00": 15}
for _d in range(10):
    _HEX_PACK[str(_d)] = _d
for _c in "ABCDEF":
    _HEX_PACK[_c] = 10 + ord(_c) - ord("A")
for _c in "abcdef":
    _HEX_PACK[_c] = 10 + ord(_c) - ord("a")


class Writer:
    __slots__ = ("buf",)

    def __init__(self, flag: int = 0):
        self.buf = bytearray([flag & 0xFF])

    # --- primitives
    def byte(self, v: int) -> None:
        self.buf.append(v & 0xFF)

    def int(self, value: int, n: int) -> None:
        for i in range(n):
            self.buf.append((value >> ((n - 1 - i) * 8)) & 0xFF)

    def int16(self, value: int) -> None:
        self.buf += bytes([(value >> 8) & 0xFF, value & 0xFF])

    def int20(self, value: int) -> None:
        self.buf += bytes([(value >> 16) & 0x0F, (value >> 8) & 0xFF, value & 0xFF])

    def raw(self, data: bytes) -> None:
        self.buf += data

    def write_byte_length(self, length: int) -> None:
        if length >= 1 << 20:
            self.byte(BINARY_32)
            self.int(length, 4)
        elif length >= 256:
            self.byte(BINARY_20)
            self.int20(length)
        else:
            self.byte(BINARY_8)
            self.byte(length)

    def write_string_raw(self, s: str) -> None:
        data = s.encode("utf-8")
        self.write_byte_length(len(data))
        self.raw(data)

    def write_packed(self, s: str, kind: str) -> None:
        if len(s) > PACKED_MAX:
            raise ValueError("too many bytes to pack")
        self.byte(NIBBLE_8 if kind == "nibble" else HEX_8)
        rounded = (len(s) + 1) // 2
        if len(s) % 2:
            rounded |= 128
        self.byte(rounded)
        pack = _NIBBLE_PACK if kind == "nibble" else _HEX_PACK
        for i in range(0, len(s) - 1, 2):
            self.byte((pack[s[i]] << 4) | pack[s[i + 1]])
        if len(s) % 2:
            self.byte((pack[s[-1]] << 4) | 0x0F)

    def write_jid(self, user: str, server: str, device: Optional[int], domain_type: int) -> None:
        if device is not None:
            self.byte(AD_JID)
            self.byte(domain_type or 0)
            self.byte(device or 0)
            self.write_string(user)
        else:
            self.byte(JID_PAIR)
            if user:
                self.write_string(user)
            else:
                self.byte(LIST_EMPTY)
            self.write_string(server)

    def write_string(self, s: Optional[str]) -> None:
        if s is None:
            self.byte(LIST_EMPTY)
            return
        if s == "":
            self.write_string_raw(s)
            return
        token = TOKEN_MAP.get(s)
        if token is not None:
            d, index = token
            if d is not None:
                self.byte(DICTIONARY_0 + d)
            self.byte(index)
            return
        if _is_nibble(s):
            self.write_packed(s, "nibble")
            return
        if _is_hex(s):
            self.write_packed(s, "hex")
            return
        decoded = jid_decode(s)
        if decoded:
            user, server, device, domain_type = decoded
            self.write_jid(user, server, device, domain_type)
            return
        self.write_string_raw(s)

    def write_list_start(self, size: int) -> None:
        if size == 0:
            self.byte(LIST_EMPTY)
        elif size < 256:
            self.buf += bytes([LIST_8, size])
        else:
            self.byte(LIST_16)
            self.int16(size)

    # --- nodes
    def write_node(self, node: Node) -> None:
        attrs = {k: v for k, v in (node.attrs or {}).items() if v is not None}
        content = node.content
        size = 2 * len(attrs) + 1 + (1 if content is not None else 0)
        self.write_list_start(size)
        self.write_string(node.tag)
        for key, value in attrs.items():
            if isinstance(value, str):
                self.write_string(key)
                self.write_string(value)
            else:
                self.write_string(key)
                self.write_string(str(value))
        if isinstance(content, str):
            self.write_string(content)
        elif isinstance(content, (bytes, bytearray)):
            self.write_byte_length(len(content))
            self.raw(bytes(content))
        elif isinstance(content, list):
            valid = [c for c in content if isinstance(c, Node) or isinstance(c, (bytes, bytearray, str))]
            self.write_list_start(len(valid))
            for item in valid:
                if isinstance(item, Node):
                    self.write_node(item)
                elif isinstance(item, str):
                    self.write_string(item)
                else:
                    self.write_byte_length(len(item))
                    self.raw(bytes(item))
        elif content is None:
            pass
        else:
            raise ValueError(f"invalid content for tag {node.tag!r}: {content!r}")


def encode(node: Node, flag: int = 0) -> bytes:
    """Encode a node (flag byte prepended, as Baileys does)."""
    w = Writer(flag)
    w.write_node(node)
    return bytes(w.buf)


def compress(node: Node) -> bytes:
    """Encode a node with the deflate flag set (used for large stanzas)."""
    w = Writer(0)
    w.write_node(node)
    return bytes([2]) + zlib.compress(bytes(w.buf[1:]))


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------


class Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def next_byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("end of stream")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("end of stream")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_int(self, n: int) -> int:
        val = 0
        for _ in range(n):
            val = (val << 8) | self.next_byte()
        return val

    def read_int20(self) -> int:
        return ((self.next_byte() & 15) << 16) + (self.next_byte() << 8) + self.next_byte()

    def read_packed(self, tag: int) -> str:
        start = self.next_byte()
        out = []
        for _ in range(start & 127):
            cur = self.next_byte()
            out.append(_unpack(tag, (cur & 0xF0) >> 4))
            out.append(_unpack(tag, cur & 0x0F))
        value = "".join(out)
        if start >> 7:
            value = value[:-1]
        return value

    def read_jid_pair(self) -> str:
        user = self.read_string(self.next_byte())
        server = self.read_string(self.next_byte())
        if not server:
            raise ValueError("invalid jid pair")
        return f"{user or ''}@{server}"

    def read_ad_jid(self) -> str:
        domain_type = self.next_byte()
        device = self.next_byte()
        user = self.read_string(self.next_byte())
        if domain_type == 1:
            server = "lid"
        elif domain_type == 128:
            server = "hosted"
        elif domain_type == 129:
            server = "hosted.lid"
        else:
            server = "s.whatsapp.net"
        return jid_encode(user, server, device)

    def read_fb_jid(self) -> str:
        user = self.read_string(self.next_byte())
        device = self.read_int(2)
        server = self.read_string(self.next_byte())
        return f"{user}:{device}@{server}"

    def read_interop_jid(self) -> str:
        user = self.read_string(self.next_byte())
        device = self.read_int(2)
        integrator = self.read_int(2)
        server = "interop"
        before = self.pos
        try:
            server = self.read_string(self.next_byte())
        except Exception:
            self.pos = before
        return f"{integrator}-{user}:{device}@{server}"

    def read_string(self, tag: int) -> str:
        if 1 <= tag < len(SINGLE_BYTE_TOKENS):
            return SINGLE_BYTE_TOKENS[tag]
        if tag in (DICTIONARY_0, DICTIONARY_0 + 1, DICTIONARY_0 + 2, DICTIONARY_0 + 3):
            dictionary = DOUBLE_BYTE_TOKENS[tag - DICTIONARY_0]
            index = self.next_byte()
            if index >= len(dictionary):
                raise ValueError("invalid double-byte token")
            return dictionary[index]
        if tag == LIST_EMPTY:
            return ""
        if tag == BINARY_8:
            return self.read(self.next_byte()).decode("utf-8", "replace")
        if tag == BINARY_20:
            return self.read(self.read_int20()).decode("utf-8", "replace")
        if tag == BINARY_32:
            return self.read(self.read_int(4)).decode("utf-8", "replace")
        if tag == JID_PAIR:
            return self.read_jid_pair()
        if tag == FB_JID:
            return self.read_fb_jid()
        if tag == INTEROP_JID:
            return self.read_interop_jid()
        if tag == AD_JID:
            return self.read_ad_jid()
        if tag in (HEX_8, NIBBLE_8):
            return self.read_packed(tag)
        raise ValueError(f"invalid string tag: {tag}")

    def read_list_size(self, tag: int) -> int:
        if tag == LIST_EMPTY:
            return 0
        if tag == LIST_8:
            return self.next_byte()
        if tag == LIST_16:
            return self.read_int(2)
        raise ValueError(f"invalid list tag: {tag}")

    def read_node(self) -> Node:
        list_size = self.read_list_size(self.next_byte())
        header = self.read_string(self.next_byte())
        if not list_size or not header:
            raise ValueError("invalid node")
        attrs = {}
        attr_count = (list_size - 1) >> 1
        for _ in range(attr_count):
            key = self.read_string(self.next_byte())
            value = self.read_string(self.next_byte())
            attrs[key] = value
        content: Any = None
        if list_size % 2 == 0:
            tag = self.next_byte()
            if tag in (LIST_EMPTY, LIST_8, LIST_16):
                size = self.read_list_size(tag)
                content = [self.read_node() for _ in range(size)]
            elif tag == BINARY_8:
                content = self.read(self.next_byte())
            elif tag == BINARY_20:
                content = self.read(self.read_int20())
            elif tag == BINARY_32:
                content = self.read(self.read_int(4))
            else:
                content = self.read_string(tag)
        return Node(header, attrs, content)


def _unpack(tag: int, value: int) -> str:
    if tag == NIBBLE_8:
        if value <= 9:
            return str(value)
        if value == 10:
            return "-"
        if value == 11:
            return "."
        if value == 15:
            return "\x00"
        raise ValueError(f"invalid nibble: {value}")
    if value < 10:
        return str(value)
    if value < 16:
        return chr(ord("A") + value - 10)
    raise ValueError(f"invalid hex: {value}")


def decompress(data: bytes) -> bytes:
    """Strip the compression flag byte, inflating when needed."""
    if not data:
        raise ValueError("empty frame")
    if data[0] & 2:
        return zlib.decompress(data[1:])
    return data[1:]


def decode(data: bytes) -> Node:
    """Decode a raw (already decrypted) binary payload."""
    return Reader(decompress(data)).read_node()


def decode_frame_payload(data: bytes) -> Node:
    """Decode a decrypted transport frame."""
    return decode(data)


__all__ = [
    "Node", "encode", "decode", "compress", "decompress", "Reader", "Writer",
    "jid_decode", "jid_encode", "jid_normalized", "jid_user", "is_jid_group",
    "is_jid_lid", "is_jid_pn", "is_jid_status", "is_jid_newsletter",
    "are_jids_same_user", "TAGS",
]
