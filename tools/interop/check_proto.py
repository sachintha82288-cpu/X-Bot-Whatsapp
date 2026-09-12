#!/usr/bin/env python3
"""Compare the pure-Python protobuf codec against Baileys' generated classes.

Run ``node proto-interop.mjs /tmp/proto-vectors.json`` first (see README in
this folder), then::

    python3 tools/interop/check_proto.py /tmp/proto-vectors.json
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from xbot.wa import protobuf as pb  # noqa: E402


def convert(value, message):
    fields = {f[0]: f for f in pb.fields_of(message)}
    out = {}
    for key, val in value.items():
        field = fields.get(key)
        if field is None:
            continue
        if field[2] == "repeated":
            items = val if isinstance(val, list) else [val]
            out[key] = [convert_one(field, item) for item in items]
        else:
            out[key] = convert_one(field, val)
    return out


def convert_one(field, val):
    kind, target = field[3], field[4]
    if kind == "bytes":
        return base64.b64decode(val)
    if kind == "msg":
        return convert(val, target) if isinstance(val, dict) else val
    if kind == "bool":
        return bool(val)
    if kind in ("int", "sint", "fixed32", "fixed64"):
        return int(val)
    if kind in ("double", "float"):
        return float(val)
    return val


def norm(value):
    if isinstance(value, dict):
        return {k: norm(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [norm(v) for v in value]
    return value


def show(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: show(v) for k, v in value.items()}
    if isinstance(value, list):
        return [show(v) for v in value]
    return value


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/proto-vectors.json"
    vectors = json.load(open(path))
    fails = 0
    for vec in vectors:
        name = vec["name"]
        raw = bytes.fromhex(vec["bytes"])
        obj = vec["json"]
        if isinstance(obj, str):
            obj = json.loads(obj)
        expect = convert(obj, name)
        got = pb.decode(name, raw)
        if norm(got) != norm(expect):
            fails += 1
            print(f"DECODE MISMATCH {name}")
            print("  ref :", json.dumps(show(expect))[:300])
            print("  ours:", json.dumps(show(got))[:300])
        ours = pb.encode(name, got)
        if ours != raw:
            fails += 1
            print(f"REENCODE MISMATCH {name}\n  ref : {raw.hex()[:120]}\n  ours: {ours.hex()[:120]}")
    print(f"protobuf interop: {len(vectors) - fails}/{len(vectors)} identical, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
