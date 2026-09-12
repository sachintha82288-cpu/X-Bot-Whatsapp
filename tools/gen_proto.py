#!/usr/bin/env python3
"""Regenerate ``xbot/wa/protoschema.py`` from WhatsApp's ``WAProto.proto``.

``WAProto.proto`` is the public protobuf description of WhatsApp's wire
messages (the same file ships with Baileys and whatsmeow).  We only need the
*field numbers and types*: the runtime codec in ``xbot/wa/protobuf.py`` is a
generic protobuf implementation driven by this table, so no protobuf library
is required at runtime.

Usage:
    python3 tools/gen_proto.py /path/to/WAProto/WAProto.proto
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "xbot", "wa", "protoschema.py"))

VARINT = re.compile(r"^(int32|int64|uint32|uint64|sint32|sint64|bool|enum)$")
FIXED64 = re.compile(r"^(fixed64|sfixed64|double)$")
FIXED32 = re.compile(r"^(fixed32|sfixed32|float)$")

SCALARS = {
    "double": "double", "float": "float", "int32": "int", "int64": "int",
    "uint32": "int", "uint64": "int", "sint32": "sint", "sint64": "sint",
    "fixed32": "fixed32", "fixed64": "fixed64", "sfixed32": "fixed32",
    "sfixed64": "fixed64", "bool": "bool", "string": "str", "bytes": "bytes",
}


class Parser:
    def __init__(self, text: str):
        # strip comments
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        self.t = text
        self.i = 0

    def skip_ws(self):
        while self.i < len(self.t) and self.t[self.i] in " \t\r\n;":
            self.i += 1

    def peek_word(self) -> str:
        self.skip_ws()
        m = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", self.t[self.i:])
        return m.group(0) if m else ""

    def read_word(self) -> str:
        w = self.peek_word()
        self.i += len(w)
        return w

    def expect(self, ch: str):
        self.skip_ws()
        if self.i < len(self.t) and self.t[self.i] == ch:
            self.i += 1
            return True
        return False

    def block(self) -> str:
        """Return the text inside the next {...} block."""
        if not self.expect("{"):
            raise SyntaxError("expected { at %d" % self.i)
        depth = 1
        start = self.i
        while self.i < len(self.t) and depth:
            ch = self.t[self.i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            self.i += 1
        body = self.t[start:self.i]
        self.i += 1
        return body


def parse_body(body: str, prefix: str, messages: dict, enums: dict) -> None:
    p = Parser(body)
    fields = []
    while True:
        p.skip_ws()
        if p.i >= len(p.t):
            break
        word = p.peek_word()
        if not word:
            p.i += 1
            continue
        if word == "message":
            p.read_word()
            name = p.read_word()
            inner = p.block()
            full = f"{prefix}.{name}" if prefix else name
            parse_body(inner, full, messages, enums)
        elif word == "enum":
            p.read_word()
            name = p.read_word()
            inner = p.block()
            full = f"{prefix}.{name}" if prefix else name
            values = {}
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)", inner):
                values[m.group(1)] = int(m.group(2))
            enums[full] = values
        elif word == "oneof":
            p.read_word()
            p.read_word()
            inner = p.block()
            parse_fields(inner, prefix, fields)
        elif word in ("option", "reserved", "extensions"):
            # skip to the next ';'
            while p.i < len(p.t) and p.t[p.i] != ";":
                p.i += 1
            p.i += 1
        else:
            parse_fields_from(p, prefix, fields)
    full = prefix
    if prefix:
        messages[prefix] = fields


def parse_fields(body: str, prefix: str, out: list) -> None:
    p = Parser(body)
    while True:
        p.skip_ws()
        if p.i >= len(p.t):
            break
        if not p.peek_word():
            p.i += 1
            continue
        parse_fields_from(p, prefix, out)


def parse_fields_from(p: Parser, prefix: str, out: list) -> None:
    label = "optional"
    word = p.peek_word()
    if word in ("optional", "repeated", "required"):
        label = p.read_word()
        word = p.peek_word()
    if word in ("message", "enum", "oneof", "option", "reserved", "extensions"):
        return  # handled by the caller
    type_name = p.read_word()
    name = p.read_word()
    p.skip_ws()
    if not p.expect("="):
        while p.i < len(p.t) and p.t[p.i] not in ";\n":
            p.i += 1
        p.i += 1
        return
    p.skip_ws()
    num = ""
    while p.i < len(p.t) and p.t[p.i].isdigit():
        num += p.t[p.i]
        p.i += 1
    # skip options like [packed=true]
    rest = ""
    while p.i < len(p.t) and p.t[p.i] != ";":
        rest += p.t[p.i]
        p.i += 1
    p.i += 1
    if not num:
        return
    packed = "packed=true" in rest.replace(" ", "")
    if SCALARS.get(type_name):
        kind = SCALARS[type_name]
        target = None
    else:
        kind = "msg"
        target = type_name
    out.append((name, int(num), label, kind, target, packed))


ENUMS_SET: set = set()


def parse_file(path: str):
    messages: dict = {}
    enums: dict = {}
    text = open(path, encoding="utf-8").read()
    p = Parser(text)
    while True:
        p.skip_ws()
        if p.i >= len(p.t):
            break
        word = p.peek_word()
        if word == "message":
            p.read_word()
            name = p.read_word()
            body = p.block()
            parse_body(body, name, messages, enums)
        elif word == "enum":
            p.read_word()
            name = p.read_word()
            body = p.block()
            values = {}
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)", body):
                values[m.group(1)] = int(m.group(2))
            enums[name] = values
        elif word in ("syntax", "package", "option", "import"):
            while p.i < len(p.t) and p.t[p.i] != ";":
                p.i += 1
            p.i += 1
        else:
            p.i += 1
    return messages, enums


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    messages, enums = parse_file(sys.argv[1])
    global ENUMS_SET
    ENUMS_SET = set(enums.keys())

    lines = [
        '"""WhatsApp protobuf field tables (generated by tools/gen_proto.py).',
        "",
        "Only numbers/types are stored; ``xbot/wa/protobuf.py`` implements the",
        "wire format itself, so no protobuf runtime library is used.",
        '"""',
        "",
        "# name, field number, label, kind, type/target, packed",
        "MESSAGES = {",
    ]
    for name, fields in sorted(messages.items()):
        if not fields:
            continue
        lines.append(f"    {name!r}: (")
        for f in fields:
            lines.append(f"        {f!r},")
        lines.append("    ),")
    lines.append("}")
    lines.append("")
    lines.append("ENUMS = {")
    for name, values in sorted(enums.items()):
        lines.append(f"    {name!r}: {values!r},")
    lines.append("}")
    lines.append("")
    lines.append("# enum name -> {value: name} for pretty printing")
    lines.append("ENUM_NAMES = {k: {v: n for n, v in vals.items()} for k, vals in ENUMS.items()}")
    lines.append("")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {OUT}: {sum(1 for v in messages.values() if v)} messages, {len(enums)} enums")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
