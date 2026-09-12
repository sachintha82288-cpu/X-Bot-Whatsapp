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

from xbot.bot.qr import encode_qr, render_qr, render_qr_plain  # noqa: E402

INTEROP = os.path.dirname(os.path.abspath(__file__))


def parse_ansi_render(text: str, size: int, quiet: int = 4):
    """Decode the terminal rendering back into a module matrix.

    Each character cell is one module wide and two modules tall: the upper half
    is painted with the foreground colour, the lower half with the background.
    """
    rows = []
    for line in text.splitlines():
        top_row, bottom_row = [], []
        foreground = background = True        # light until a colour says otherwise
        index = 0
        while index < len(line):
            if line[index] == "\x1b":
                end = line.index("m", index)
                code = line[index + 2:end]
                if code == "30":
                    foreground = False
                elif code == "37":
                    foreground = True
                elif code == "40":
                    background = False
                elif code == "47":
                    background = True
                index = end + 1
                continue
            if line[index] == "\u2580":       # upper half block: fg over bg
                top_row.append(not foreground)
                bottom_row.append(not background)
            else:                              # a space: background only
                top_row.append(not background)
                bottom_row.append(not background)
            index += 1
        rows.append(top_row)
        rows.append(bottom_row)
    assert len(rows) >= size + quiet * 2, "rendered texture is too short"
    return [row[quiet:quiet + size] for row in rows[quiet:quiet + size]]


def check_renderer(matrix) -> None:
    size = len(matrix)
    plain = render_qr_plain(matrix, quiet=2)
    plain_rows = [[character == "\u2588" for character in line[::2]]
                  for line in plain.splitlines()]
    assert [row[2:2 + size] for row in plain_rows[2:2 + size]] == matrix, "plain renderer mismatch"
    ansi = render_qr(matrix)
    assert parse_ansi_render(ansi, size) == matrix, "ansi renderer mismatch"


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
        check_renderer(matrix)
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
    print("terminal rendering round trip: OK")
    print("qr interop:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
