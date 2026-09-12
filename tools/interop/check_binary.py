#!/usr/bin/env python3
"""Check the WABinary node codec against Baileys.

* Baileys encodes a list of nodes        -> we must produce identical bytes
* We encode the same nodes               -> Baileys must decode them back to
  the same structure (checked by comparing the decoded JSON)

Run with::

    python3 tools/interop/check_binary.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from xbot.wa import binary as wab  # noqa: E402

INTEROP = os.path.dirname(os.path.abspath(__file__))


def to_node(data: dict) -> wab.Node:
    content = data.get("content")
    if isinstance(content, list):
        parsed = [to_node(item) for item in content]
    elif isinstance(content, dict) and "b64" in content:
        parsed = base64.b64decode(content["b64"])
    else:
        parsed = content
    return wab.Node(data["tag"], data.get("attrs") or {}, parsed)


def as_text(value):
    """Return ``value`` as text when it is a byte blob/Buffer, else ``None``."""
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(value, dict) and set(value) == {"b64"}:
        try:
            return base64.b64decode(value["b64"]).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    return None


def equiv(ref, got) -> bool:
    """Deep-compare a reference node with a dumped one.

    Baileys' decoder hands back a ``Buffer`` for anything written with the
    BINARY_* tags, while ours hands back ``bytes`` -- including for plain node
    content that was a Python ``str`` before encoding.  Text that round-trips as
    UTF-8 is therefore accepted in either representation; real binary payloads
    still have to match byte for byte.
    """
    if isinstance(ref, str) and not isinstance(got, str):
        text = as_text(got)
        return text is not None and text == ref
    if isinstance(ref, dict) and set(ref) == {"b64"}:
        if isinstance(got, str):
            return base64.b64encode(got.encode()).decode() == ref["b64"]
        if isinstance(got, dict) and set(got) == {"b64"}:
            return got["b64"] == ref["b64"]
        return isinstance(got, (bytes, bytearray)) and base64.b64encode(bytes(got)).decode() == ref["b64"]
    if isinstance(ref, list) and isinstance(got, list):
        return len(ref) == len(got) and all(equiv(a, b) for a, b in zip(ref, got))
    if isinstance(ref, dict) and isinstance(got, dict):
        return set(ref) == set(got) and all(equiv(ref[key], got[key]) for key in ref)
    return ref == got


def dump(node: wab.Node):
    content = node.content
    if isinstance(content, list):
        dumped = [dump(item) for item in content]
    elif isinstance(content, (bytes, bytearray)):
        dumped = {"b64": base64.b64encode(bytes(content)).decode()}
    else:
        dumped = content
    return {"tag": node.tag, "attrs": node.attrs, "content": dumped}


def main() -> int:
    vectors_path = os.path.join(tempfile.gettempdir(), "xbot-binary-vectors.json")
    ours_path = os.path.join(tempfile.gettempdir(), "xbot-binary-ours.json")
    decoded_path = os.path.join(tempfile.gettempdir(), "xbot-binary-decoded.json")

    result = subprocess.run(["node", "binary-interop.mjs", "encode", vectors_path],
                            cwd=INTEROP, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(result.stdout, result.stderr)
        print("binary interop: FAILED (could not generate vectors)")
        return 1

    vectors = json.load(open(vectors_path))
    mismatches = 0
    our_payloads = []
    for index, vector in enumerate(vectors):
        node = to_node(vector["node"])
        encoded = wab.encode(node)
        expected = bytes.fromhex(vector["hex"])
        our_payloads.append(encoded.hex())
        if encoded != expected:
            mismatches += 1
            print(f"  vector {index} ({node.tag}): bytes differ")
            print(f"    ref : {expected.hex()[:120]}")
            print(f"    ours: {encoded.hex()[:120]}")
        decoded = wab.decode(expected)
        if not equiv(vector["node"], dump(decoded)):
            mismatches += 1
            print(f"  vector {index} ({node.tag}): decode mismatch")
            print(f"    ref : {json.dumps(vector['node'])[:160]}")
            print(f"    ours: {json.dumps(dump(decoded))[:160]}")

    json.dump(our_payloads, open(ours_path, "w"))
    result = subprocess.run(["node", "binary-interop.mjs", "decode", ours_path, decoded_path],
                            cwd=INTEROP, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(result.stdout, result.stderr)
        print("binary interop: FAILED (Baileys could not decode our payloads)")
        return 1

    decoded = json.load(open(decoded_path))
    for index, (vector, got) in enumerate(zip(vectors, decoded)):
        if "error" in got:
            mismatches += 1
            print(f"  vector {index}: Baileys failed to decode our bytes: {got['error']}")
        elif not equiv(vector["node"], got):
            mismatches += 1
            print(f"  vector {index} ({vector['node']['tag']}): Baileys decoded a different structure")
            print(f"    ref : {json.dumps(vector['node'])[:200]}")
            print(f"    got : {json.dumps(got)[:200]}")

    total = len(vectors)
    print(f"binary interop: {total} vectors, {mismatches} mismatches -> "
          + ("OK" if mismatches == 0 else "FAILED"))
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
