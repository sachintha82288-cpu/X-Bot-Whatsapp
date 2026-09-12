#!/usr/bin/env python3
"""Check the pure-python QR encoder against a real decoder (jsQR) and the
`qrcode` npm package.

Run with::

    python3 tools/interop/check_qr.py
"""

from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from xbot.bot.qr import encode_qr  # noqa: E402

INTEROP = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    random.seed(11)
    alphabet = string.ascii_letters + string.digits + ":/.?&=#-_@,"
    cases = ["HELLO WORLD",
             "https://wa.me/settings/linked_devices#" + "A" * 40 + "," + "B" * 44 + "," + "C" * 44 + ",adv,1"]
    for length in (1, 5, 12, 20, 33, 45, 60, 75, 90, 110, 130, 150, 170, 185, 200, 220, 250, 271):
        cases.append("".join(random.choice(alphabet) for _ in range(length)))

    payload = {}
    for text in cases:
        matrix = encode_qr(text)
        payload[text] = {
            "size": len(matrix),
            "rows": ["".join("1" if value else "0" for value in row) for row in matrix],
        }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        path = handle.name

    try:
        reference = subprocess.run(["node", "qr-reference.mjs", path], cwd=INTEROP,
                                   capture_output=True, text=True, timeout=120)
        print(reference.stdout.strip() or reference.stderr.strip())
        decoded = subprocess.run(["node", "qr-decode.mjs", path], cwd=INTEROP,
                                 capture_output=True, text=True, timeout=120)
        print(decoded.stdout.strip() or decoded.stderr.strip())
        # a different (still valid) mask is acceptable: the decoder decides
        ok = "ALL" in decoded.stdout
    finally:
        os.unlink(path)
    print("qr interop:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
