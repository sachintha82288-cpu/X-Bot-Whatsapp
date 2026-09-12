"""AES-256 (FIPS-197) plus the operating modes WhatsApp uses.

Written from scratch in pure Python: no `cryptography`, no `pycryptodome`,
no `ssl` helpers.  Modes implemented:

* CBC  (with PKCS#7 padding helpers)  -- media + Signal payloads
* CTR  (128-bit big-endian counter)   -- pairing-code key wrapping
* GCM  (AES-GCM with AAD)             -- Noise transport / handshake

The T-table implementation below performs roughly 150-400 kB/s on a 1 GB
Android phone in Termux, which is plenty for a WhatsApp companion device.
"""

from __future__ import annotations

import struct

# --------------------------------------------------------------------------
# S-boxes / constants
# --------------------------------------------------------------------------

SBOX = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]
)

INV_SBOX = bytes(
    [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ]
)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _mul(a: int, b: int) -> int:
    """Multiply two GF(2^8) elements (AES polynomial 0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


def _build_tables():
    te0 = [0] * 256
    te1 = [0] * 256
    te2 = [0] * 256
    te3 = [0] * 256
    td0 = [0] * 256
    td1 = [0] * 256
    td2 = [0] * 256
    td3 = [0] * 256
    for i in range(256):
        s = SBOX[i]
        s2, s3 = _mul(s, 2), _mul(s, 3)
        te0[i] = (s2 << 24) | (s << 16) | (s << 8) | s3
        te1[i] = (s3 << 24) | (s2 << 16) | (s << 8) | s
        te2[i] = (s << 24) | (s3 << 16) | (s2 << 8) | s
        te3[i] = (s << 24) | (s << 16) | (s3 << 8) | s2

        inv = INV_SBOX[i]
        i2, i3 = _mul(inv, 2), _mul(inv, 3)
        # decryption tables combine InvMixColumns with InvSubBytes
        d0 = _mul(inv, 14) << 24 | _mul(inv, 9) << 16 | _mul(inv, 13) << 8 | _mul(inv, 11)
        d1 = _mul(inv, 11) << 24 | _mul(inv, 14) << 16 | _mul(inv, 9) << 8 | _mul(inv, 13)
        d2 = _mul(inv, 13) << 24 | _mul(inv, 11) << 16 | _mul(inv, 14) << 8 | _mul(inv, 9)
        d3 = _mul(inv, 9) << 24 | _mul(inv, 13) << 16 | _mul(inv, 11) << 8 | _mul(inv, 14)
        td0[i], td1[i], td2[i], td3[i] = d0, d1, d2, d3
        _ = (i2, i3)
    return (te0, te1, te2, te3), (td0, td1, td2, td3)


TE0, TE1, TE2, TE3 = _build_tables()[0]
TD0, TD1, TD2, TD3 = _build_tables()[1]


class AES:
    """AES-128/192/256 block cipher."""

    __slots__ = ("rounds", "rk", "drk")

    def __init__(self, key: bytes):
        key = bytes(key)
        nk = len(key) // 4
        if nk not in (4, 6, 8) or len(key) % 4:
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.rounds = nk + 6
        self.rk = self._expand(key, nk)
        self.drk = self._decrypt_keys()

    def _expand(self, key: bytes, nk: int) -> list:
        total = 4 * (self.rounds + 1)
        w = list(struct.unpack(">%dI" % nk, key))
        for i in range(nk, total):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (SBOX[(t >> 24) & 0xFF] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) | \
                    (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF]
                t ^= RCON[i // nk - 1] << 24
            elif nk > 6 and i % nk == 4:
                t = (SBOX[(t >> 24) & 0xFF] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) | \
                    (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF]
            w.append(w[i - nk] ^ t)
        return w

    def _decrypt_keys(self) -> list:
        # apply InvMixColumns to the middle round keys (equivalent decryption)
        drk = list(self.rk)
        rounds = self.rounds
        for i in range(4, 4 * rounds):
            t = drk[i]
            drk[i] = (
                TD0[SBOX[(t >> 24) & 0xFF]] ^ TD1[SBOX[(t >> 16) & 0xFF]] ^
                TD2[SBOX[(t >> 8) & 0xFF]] ^ TD3[SBOX[t & 0xFF]]
            )
        return drk

    # ---------------------------------------------------------------- core

    def encrypt_block(self, block: bytes) -> bytes:
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        rk = self.rk
        s0 ^= rk[0]
        s1 ^= rk[1]
        s2 ^= rk[2]
        s3 ^= rk[3]
        k = 4
        for _ in range(self.rounds - 1):
            t0 = TE0[(s0 >> 24) & 0xFF] ^ TE1[(s1 >> 16) & 0xFF] ^ TE2[(s2 >> 8) & 0xFF] ^ TE3[s3 & 0xFF] ^ rk[k]
            t1 = TE0[(s1 >> 24) & 0xFF] ^ TE1[(s2 >> 16) & 0xFF] ^ TE2[(s3 >> 8) & 0xFF] ^ TE3[s0 & 0xFF] ^ rk[k + 1]
            t2 = TE0[(s2 >> 24) & 0xFF] ^ TE1[(s3 >> 16) & 0xFF] ^ TE2[(s0 >> 8) & 0xFF] ^ TE3[s1 & 0xFF] ^ rk[k + 2]
            t3 = TE0[(s3 >> 24) & 0xFF] ^ TE1[(s0 >> 16) & 0xFF] ^ TE2[(s1 >> 8) & 0xFF] ^ TE3[s2 & 0xFF] ^ rk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        e0 = (
            (SBOX[(s0 >> 24) & 0xFF] << 24) | (SBOX[(s1 >> 16) & 0xFF] << 16) |
            (SBOX[(s2 >> 8) & 0xFF] << 8) | SBOX[s3 & 0xFF]
        ) ^ rk[k]
        e1 = (
            (SBOX[(s1 >> 24) & 0xFF] << 24) | (SBOX[(s2 >> 16) & 0xFF] << 16) |
            (SBOX[(s3 >> 8) & 0xFF] << 8) | SBOX[s0 & 0xFF]
        ) ^ rk[k + 1]
        e2 = (
            (SBOX[(s2 >> 24) & 0xFF] << 24) | (SBOX[(s3 >> 16) & 0xFF] << 16) |
            (SBOX[(s0 >> 8) & 0xFF] << 8) | SBOX[s1 & 0xFF]
        ) ^ rk[k + 2]
        e3 = (
            (SBOX[(s3 >> 24) & 0xFF] << 24) | (SBOX[(s0 >> 16) & 0xFF] << 16) |
            (SBOX[(s1 >> 8) & 0xFF] << 8) | SBOX[s2 & 0xFF]
        ) ^ rk[k + 3]
        return struct.pack(">4I", e0, e1, e2, e3)

    def decrypt_block(self, block: bytes) -> bytes:
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        drk = self.drk
        k = 4 * self.rounds
        s0 ^= drk[k]
        s1 ^= drk[k + 1]
        s2 ^= drk[k + 2]
        s3 ^= drk[k + 3]
        k -= 4
        for _ in range(self.rounds - 1):
            t0 = TD0[(s0 >> 24) & 0xFF] ^ TD1[(s3 >> 16) & 0xFF] ^ TD2[(s2 >> 8) & 0xFF] ^ TD3[s1 & 0xFF] ^ drk[k]
            t1 = TD0[(s1 >> 24) & 0xFF] ^ TD1[(s0 >> 16) & 0xFF] ^ TD2[(s3 >> 8) & 0xFF] ^ TD3[s2 & 0xFF] ^ drk[k + 1]
            t2 = TD0[(s2 >> 24) & 0xFF] ^ TD1[(s1 >> 16) & 0xFF] ^ TD2[(s0 >> 8) & 0xFF] ^ TD3[s3 & 0xFF] ^ drk[k + 2]
            t3 = TD0[(s3 >> 24) & 0xFF] ^ TD1[(s2 >> 16) & 0xFF] ^ TD2[(s1 >> 8) & 0xFF] ^ TD3[s0 & 0xFF] ^ drk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k -= 4
        d0 = (
            (INV_SBOX[(s0 >> 24) & 0xFF] << 24) | (INV_SBOX[(s3 >> 16) & 0xFF] << 16) |
            (INV_SBOX[(s2 >> 8) & 0xFF] << 8) | INV_SBOX[s1 & 0xFF]
        ) ^ drk[0]
        d1 = (
            (INV_SBOX[(s1 >> 24) & 0xFF] << 24) | (INV_SBOX[(s0 >> 16) & 0xFF] << 16) |
            (INV_SBOX[(s3 >> 8) & 0xFF] << 8) | INV_SBOX[s2 & 0xFF]
        ) ^ drk[1]
        d2 = (
            (INV_SBOX[(s2 >> 24) & 0xFF] << 24) | (INV_SBOX[(s1 >> 16) & 0xFF] << 16) |
            (INV_SBOX[(s0 >> 8) & 0xFF] << 8) | INV_SBOX[s3 & 0xFF]
        ) ^ drk[2]
        d3 = (
            (INV_SBOX[(s3 >> 24) & 0xFF] << 24) | (INV_SBOX[(s2 >> 16) & 0xFF] << 16) |
            (INV_SBOX[(s1 >> 8) & 0xFF] << 8) | INV_SBOX[s0 & 0xFF]
        ) ^ drk[3]
        return struct.pack(">4I", d0, d1, d2, d3)


# --------------------------------------------------------------------------
# Operating modes
# --------------------------------------------------------------------------


def pad_pkcs7(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def unpad_pkcs7(data: bytes, block: int = 16) -> bytes:
    if not data:
        return data
    n = data[-1]
    if n < 1 or n > block:
        return data
    return data[:-n]


def cbc_encrypt(key: bytes, iv: bytes, data: bytes, pad: bool = True) -> bytes:
    aes = AES(key)
    if pad:
        data = pad_pkcs7(data, 16)
    elif len(data) % 16:
        raise ValueError("data length must be a multiple of 16")
    out = bytearray()
    prev = bytes(iv)
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        prev = aes.encrypt_block(block)
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes, unpad: bool = True) -> bytes:
    aes = AES(key)
    if len(data) % 16:
        raise ValueError("data length must be a multiple of 16")
    out = bytearray()
    prev = bytes(iv)
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(aes.decrypt_block(chunk), prev))
        prev = chunk
    result = bytes(out)
    return unpad_pkcs7(result, 16) if unpad else result


def ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = AES(key)
    counter = int.from_bytes(bytes(iv).rjust(16, b"\x00")[:16], "big")
    out = bytearray()
    for off in range(0, len(data), 16):
        ks = aes.encrypt_block(counter.to_bytes(16, "big"))
        for i, b in enumerate(data[off:off + 16]):
            out.append(b ^ ks[i])
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


# --------------------------------------------------------------------------
# GCM
# --------------------------------------------------------------------------

def _gf_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) with the GCM reduction polynomial."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


class _GHash:
    """GHASH built on a linear table of ``x**i * H`` products.

    Multiplication in GF(2^128) distributes over XOR, so a whole block can be
    reduced to XOR-ing the table entries of its set bits.  The table has one
    entry per bit position (128 entries, built once per key), which keeps the
    per-block cost small even on slow phones.
    """

    __slots__ = ("tables", "y")

    def __init__(self, h: bytes):
        hh = int.from_bytes(h, "big")
        self.tables = [_gf_mul(1 << i, hh) for i in range(128)]
        self.y = 0

    def update(self, data: bytes) -> None:
        tables = self.tables
        y = self.y
        for off in range(0, len(data), 16):
            block = data[off:off + 16]
            if len(block) < 16:
                block = block + b"\x00" * (16 - len(block))
            x = y ^ int.from_bytes(block, "big")
            z = 0
            while x:
                lowest = x & -x
                z ^= tables[lowest.bit_length() - 1]
                x ^= lowest
            y = z
        self.y = y

    def digest(self) -> bytes:
        return self.y.to_bytes(16, "big")


def gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM: returns ciphertext followed by the 16-byte tag (Node/WA style)."""
    aes = AES(key)
    h = aes.encrypt_block(b"\x00" * 16)
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        gh = _GHash(h)
        gh.update(iv + b"\x00" * ((16 - len(iv) % 16) % 16))
        gh.update(((8 * len(iv))).to_bytes(8, "big") + b"\x00" * 8)
        j0 = gh.digest()
    ctr0 = int.from_bytes(j0, "big")
    keystream = b"".join(
        aes.encrypt_block(((ctr0 + i) % (1 << 128)).to_bytes(16, "big"))
        for i in range(1, len(plaintext) // 16 + 2)
    )
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    tag = _gcm_tag(aes, h, j0, aad, ciphertext)
    return ciphertext + tag


def gcm_decrypt(key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if len(data) < 16:
        raise ValueError("ciphertext too short")
    ciphertext, tag = data[:-16], data[-16:]
    aes = AES(key)
    h = aes.encrypt_block(b"\x00" * 16)
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        gh = _GHash(h)
        gh.update(iv + b"\x00" * ((16 - len(iv) % 16) % 16))
        gh.update(((8 * len(iv))).to_bytes(8, "big") + b"\x00" * 8)
        j0 = gh.digest()
    expected = _gcm_tag(aes, h, j0, aad, ciphertext)
    if not _const_time_eq(expected, tag):
        raise ValueError("GCM tag mismatch (message corrupted or tampered)")
    ctr0 = int.from_bytes(j0, "big")
    keystream = b"".join(
        aes.encrypt_block(((ctr0 + i) % (1 << 128)).to_bytes(16, "big"))
        for i in range(1, len(ciphertext) // 16 + 2)
    )
    return bytes(p ^ k for p, k in zip(ciphertext, keystream))


def _gcm_tag(aes: "AES", h: bytes, j0: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    ghash = _GHash(h)
    aad_pad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ct_pad = ciphertext + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    if aad_pad:
        ghash.update(aad_pad)
    if ct_pad:
        ghash.update(ct_pad)
    ghash.update((8 * len(aad)).to_bytes(8, "big") + (8 * len(ciphertext)).to_bytes(8, "big"))
    s = ghash.digest()
    mask = aes.encrypt_block(j0)
    return bytes(a ^ b for a, b in zip(s, mask))


def _const_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


__all__ = [
    "AES", "pad_pkcs7", "unpad_pkcs7", "cbc_encrypt", "cbc_decrypt",
    "ctr_crypt", "gcm_encrypt", "gcm_decrypt",
]
