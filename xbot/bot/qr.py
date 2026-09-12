"""A dependency-free QR code encoder (byte mode, error level L, versions 1-10).

WhatsApp pairing links are ~190 characters, which fits comfortably in a
version 10-L symbol, so that is the range implemented here.  The encoder
produces the module matrix; rendering it as text is done by ``main.py``.
"""

from __future__ import annotations

from typing import List

# total codewords, EC codewords per block, then (blocks, data codewords) groups
VERSION_INFO = {
    1: (26, 7, [(1, 19)]),
    2: (44, 10, [(1, 34)]),
    3: (70, 15, [(1, 55)]),
    4: (100, 20, [(1, 80)]),
    5: (134, 26, [(1, 108)]),
    6: (172, 18, [(2, 68)]),
    7: (196, 20, [(2, 78)]),
    8: (242, 24, [(2, 97)]),
    9: (292, 30, [(2, 116)]),
    10: (346, 18, [(2, 68), (2, 69)]),
    11: (404, 20, [(4, 81)]),
    12: (466, 24, [(2, 92), (2, 93)]),
}

ALIGNMENT = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
    11: [6, 30, 54], 12: [6, 32, 58],
}

# --------------------------------------------------------------------------
# GF(256)
# --------------------------------------------------------------------------
GF_EXP = [0] * 512
GF_LOG = [0] * 256
_value = 1
for _index in range(255):
    GF_EXP[_index] = _value
    GF_LOG[_value] = _index
    _value <<= 1
    if _value & 0x100:
        _value ^= 0x11D
for _index in range(255, 512):
    GF_EXP[_index] = GF_EXP[_index - 255]


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def rs_generator(degree: int) -> List[int]:
    poly = [1]
    for index in range(degree):
        factor = GF_EXP[index]
        poly.append(0)
        for position in range(len(poly) - 1, 0, -1):
            poly[position] ^= gf_mul(poly[position - 1], factor)
    return poly


def rs_encode(data: List[int], ec_length: int) -> List[int]:
    generator = rs_generator(ec_length)
    remainder = [0] * ec_length
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for index in range(ec_length):
                remainder[index] ^= gf_mul(generator[index + 1], factor)
    return remainder


# --------------------------------------------------------------------------
# BCH codes for format / version information
# --------------------------------------------------------------------------


def bch_format(value: int) -> int:
    encoded = value << 10
    generator = 0x537
    for bit in range(14, 9, -1):
        if encoded & (1 << bit):
            encoded ^= generator << (bit - 10)
    return ((value << 10) | encoded) ^ 0x5412


def bch_version(version: int) -> int:
    encoded = version << 12
    generator = 0x1F25
    for bit in range(17, 11, -1):
        if encoded & (1 << bit):
            encoded ^= generator << (bit - 12)
    return (version << 12) | encoded


# --------------------------------------------------------------------------
# matrix building
# --------------------------------------------------------------------------


class Matrix:
    def __init__(self, version: int):
        self.version = version
        self.size = 17 + 4 * version
        self.modules = [[False] * self.size for _ in range(self.size)]
        self.reserved = [[False] * self.size for _ in range(self.size)]

    def set(self, row: int, column: int, value: bool, reserve: bool = True) -> None:
        self.modules[row][column] = value
        if reserve:
            self.reserved[row][column] = True

    def finder(self, row: int, column: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = row + dr, column + dc
                if 0 <= r < self.size and 0 <= c < self.size:
                    inside = 0 <= dr <= 6 and 0 <= dc <= 6
                    border = dr in (0, 6) or dc in (0, 6)
                    core = 2 <= dr <= 4 and 2 <= dc <= 4
                    self.set(r, c, bool(inside and (border or core)))

    def alignment(self, row: int, column: int) -> None:
        for dr in range(-2, 3):
            for dc in range(-2, 3):
                inside = max(abs(dr), abs(dc)) != 1
                self.set(row + dr, column + dc, inside)

    def reserve_format(self) -> None:
        for index in range(9):
            if index != 6:
                self.set(8, index, False)
                self.set(index, 8, False)
        for index in range(8):
            self.set(8, self.size - 1 - index, False)
            self.set(self.size - 1 - index, 8, False)
        self.set(self.size - 8, 8, True)  # the always-dark module

    def write_format(self, mask: int, level_bits: int) -> None:
        value = bch_format((level_bits << 3) | mask)
        # bits[0] is the most significant bit of the 15 bit format string
        bits = [(value >> (14 - index)) & 1 for index in range(15)]
        size = self.size
        # first copy: around the top-left finder pattern
        for index in range(6):
            self.modules[8][index] = bool(bits[index])
        self.modules[8][7] = bool(bits[6])
        self.modules[8][8] = bool(bits[7])
        self.modules[7][8] = bool(bits[8])
        for index in range(9, 15):
            self.modules[14 - index][8] = bool(bits[index])
        # second copy: bottom-left (bits 8-14 upwards) and top-right (bits 7-0)
        for index in range(7):
            self.modules[size - 7 + index][8] = bool(bits[6 - index])
        for index in range(8):
            self.modules[8][size - 8 + index] = bool(bits[7 + index])

    def write_version(self) -> None:
        if self.version < 7:
            return
        value = bch_version(self.version)
        for index in range(18):
            bit = bool((value >> index) & 1)
            row, column = divmod(index, 3)
            self.set(row, self.size - 11 + column, bit)
            self.set(self.size - 11 + column, row, bit)

    def draw_functions(self) -> None:
        size = self.size
        self.finder(0, 0)
        self.finder(0, size - 7)
        self.finder(size - 7, 0)
        for index in range(8, size - 8):
            value = index % 2 == 0
            self.set(6, index, value)
            self.set(index, 6, value)
        corners = {(6, 6), (6, size - 7), (size - 7, 6)}
        for row in ALIGNMENT[self.version]:
            for column in ALIGNMENT[self.version]:
                if (row, column) in corners:
                    continue  # these three spots hold finder patterns
                self.alignment(row, column)
        self.reserve_format()
        self.write_version()


# --------------------------------------------------------------------------
# data & interleaving
# --------------------------------------------------------------------------


def pick_version(length: int) -> int:
    for version in sorted(VERSION_INFO):
        total, _ec, groups = VERSION_INFO[version]
        data_codewords = sum(blocks * data for blocks, data in groups)
        length_bits = 8 if version < 10 else 16
        needed = 4 + length_bits + 8 * length
        if needed <= data_codewords * 8:
            return version
    raise ValueError("data too long for the supported QR versions")


def encode_data(text: bytes, version: int) -> List[int]:
    _total, ec_per_block, groups = VERSION_INFO[version]
    capacity = sum(blocks * data for blocks, data in groups)
    length_bits = 8 if version < 10 else 16
    bits: List[int] = []

    def push(value: int, count: int) -> None:
        for index in range(count - 1, -1, -1):
            bits.append((value >> index) & 1)

    push(0b0100, 4)               # byte mode
    push(len(text), length_bits)
    for byte in text:
        push(byte, 8)
    push(0, min(4, capacity * 8 - len(bits)))  # terminator
    while len(bits) % 8:
        bits.append(0)
    codewords = [int("".join(str(bit) for bit in bits[index:index + 8]), 2)
                 for index in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    index = 0
    while len(codewords) < capacity:
        codewords.append(pad[index % 2])
        index += 1

    blocks: List[List[int]] = []
    pointer = 0
    for count, data_length in groups:
        for _ in range(count):
            blocks.append(codewords[pointer:pointer + data_length])
            pointer += data_length

    ec_blocks = [rs_encode(block, ec_per_block) for block in blocks]

    result: List[int] = []
    for position in range(max(len(block) for block in blocks)):
        for block in blocks:
            if position < len(block):
                result.append(block[position])
    for position in range(ec_per_block):
        for block in ec_blocks:
            result.append(block[position])
    return result


MASK_FUNCTIONS = (
    lambda row, column: (row + column) % 2 == 0,
    lambda row, column: row % 2 == 0,
    lambda row, column: column % 3 == 0,
    lambda row, column: (row + column) % 3 == 0,
    lambda row, column: (row // 2 + column // 3) % 2 == 0,
    lambda row, column: (row * column) % 2 + (row * column) % 3 == 0,
    lambda row, column: ((row * column) % 2 + (row * column) % 3) % 2 == 0,
    lambda row, column: ((row + column) % 2 + (row * column) % 3) % 2 == 0,
)


def place_data(matrix: Matrix, codewords: List[int]) -> None:
    bits: List[int] = []
    for codeword in codewords:
        for index in range(7, -1, -1):
            bits.append((codeword >> index) & 1)
    size = matrix.size
    pointer = 0
    column = size - 1
    upward = True
    while column > 0:
        if column == 6:
            column -= 1
        for offset in range(size):
            row = size - 1 - offset if upward else offset
            for current in (column, column - 1):
                if not matrix.reserved[row][current]:
                    bit = bits[pointer] if pointer < len(bits) else 0
                    matrix.modules[row][current] = bool(bit)
                    matrix.reserved[row][current] = True
                    pointer += 1
        column -= 2
        upward = not upward


def penalty(matrix: Matrix) -> int:
    size = matrix.size
    modules = matrix.modules
    score = 0
    # rule 1: runs of the same colour
    for line in list(modules) + [list(column) for column in zip(*modules)]:
        run = 1
        for index in range(1, size):
            if line[index] == line[index - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        if run >= 5:
            score += 3 + (run - 5)
    # rule 2: 2x2 blocks
    for row in range(size - 1):
        for column in range(size - 1):
            if (modules[row][column] == modules[row][column + 1]
                    == modules[row + 1][column] == modules[row + 1][column + 1]):
                score += 3
    # rule 3: finder-like patterns
    pattern_a = [True, False, True, True, True, False, True, False, False, False, False]
    pattern_b = list(reversed(pattern_a))
    for line in list(modules) + [list(column) for column in zip(*modules)]:
        for index in range(size - 10):
            window = line[index:index + 11]
            if window == pattern_a or window == pattern_b:
                score += 40
    # rule 4: dark/light balance
    dark = sum(1 for row in modules for value in row if value)
    ratio = dark * 100 // (size * size)
    score += min(abs(ratio - 50), abs(100 - ratio)) // 5 * 10
    return score


def encode_qr(text: str) -> List[List[bool]]:
    """Encode ``text`` and return a matrix of booleans (True = dark module)."""
    data = text.encode("utf-8")
    version = pick_version(len(data))
    codewords = encode_data(data, version)

    best = None
    best_score = None
    for mask in range(8):
        matrix = Matrix(version)
        matrix.draw_functions()
        # snapshot which modules are function modules *before* the data lands
        function_map = [row[:] for row in matrix.reserved]
        place_data(matrix, codewords)
        # apply the mask only to data modules
        for row in range(matrix.size):
            for column in range(matrix.size):
                if not function_map[row][column] and MASK_FUNCTIONS[mask](row, column):
                    matrix.modules[row][column] = not matrix.modules[row][column]
        matrix.write_format(mask, 0b01)  # level L
        score = penalty(matrix)
        if best_score is None or score < best_score:
            best, best_score = matrix, score
    return best.modules


DARK_ON_LIGHT = "\x1b[30m\x1b[47m"   # black foreground, white background
LIGHT_ON_DARK = "\x1b[37m\x1b[40m"   # white foreground, black background
BLACK_BG = "\x1b[30m\x1b[40m"        # both halves dark
WHITE_BG = "\x1b[37m\x1b[47m"        # both halves light
RESET = "\x1b[0m"


def render_qr(matrix, quiet: int = 4) -> str:
    """Render a QR matrix as ANSI coloured half blocks.

    Every character cell holds one module wide and two modules tall, which
    matches the ~1:2 aspect ratio of a terminal cell, so the code stays
    square *and* narrow enough for a phone terminal (no need to zoom out).
    Dark modules are drawn black on white -- the orientation every scanner
    expects -- whatever colour scheme the terminal uses.
    """
    size = len(matrix)

    def dark(row: int, column: int) -> bool:
        return 0 <= row < size and 0 <= column < size and matrix[row][column]

    lines = []
    for row in range(-quiet, size + quiet, 2):
        parts = []
        for column in range(-quiet, size + quiet):
            top, bottom = dark(row, column), dark(row + 1, column)
            if top and bottom:
                parts.append(BLACK_BG + " ")
            elif not top and not bottom:
                parts.append(WHITE_BG + " ")
            elif top:
                parts.append(DARK_ON_LIGHT + "\u2580")   # upper half dark
            else:
                parts.append(LIGHT_ON_DARK + "\u2580")   # upper half light
        lines.append("".join(parts) + RESET)
    return "\n".join(lines)


def render_qr_plain(matrix, quiet: int = 2) -> str:
    """Fallback for dumb terminals / redirected output (no escape codes)."""
    size = len(matrix)
    lines = []
    for row in range(-quiet, size + quiet):
        line = ""
        for column in range(-quiet, size + quiet):
            inside = 0 <= row < size and 0 <= column < size
            line += "\u2588\u2588" if inside and matrix[row][column] else "  "
        lines.append(line)
    return "\n".join(lines)


__all__ = ["encode_qr", "render_qr", "render_qr_plain"]
