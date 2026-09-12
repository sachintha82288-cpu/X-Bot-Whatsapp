"""Pure-Python hash primitives used by X-Bot.

Everything here is implemented from scratch (no hashlib, no third-party
packages).  If ``config.crypto.prefer_stdlib_hash`` is enabled the thin
``fast_*`` wrappers will transparently use ``hashlib`` instead, which is a
lot quicker on low-end phones.  Set that option to ``false`` (or run with
``--pure-crypto``) if you want *every* byte to be produced by this file.

Implemented: SHA-256, SHA-512, SHA-1, MD5, HMAC, HKDF (RFC 5869),
PBKDF2-HMAC-SHA256 (RFC 8018).
"""

from __future__ import annotations

import struct
from typing import Iterable, Union

BytesLike = Union[bytes, bytearray, memoryview]

# --------------------------------------------------------------------------
# SHA-256
# --------------------------------------------------------------------------

_K256 = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

_H256 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)


def _sha256_compress(h: list, block: bytes) -> None:
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = w[i - 15]
        s0 = ((s0 >> 7) | (s0 << 25)) & 0xFFFFFFFF ^ ((s0 >> 18) | (s0 << 14)) & 0xFFFFFFFF ^ (s0 >> 3)
        s1 = w[i - 2]
        s1 = ((s1 >> 17) | (s1 << 15)) & 0xFFFFFFFF ^ ((s1 >> 19) | (s1 << 13)) & 0xFFFFFFFF ^ (s1 >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        S1 = ((e >> 6) | (e << 26)) & 0xFFFFFFFF ^ ((e >> 11) | (e << 21)) & 0xFFFFFFFF ^ ((e >> 25) | (e << 7)) & 0xFFFFFFFF
        ch = (e & f) ^ (~e & 0xFFFFFFFF & g)
        t1 = (hh + S1 + ch + _K256[i] + w[i]) & 0xFFFFFFFF
        S0 = ((a >> 2) | (a << 30)) & 0xFFFFFFFF ^ ((a >> 13) | (a << 19)) & 0xFFFFFFFF ^ ((a >> 22) | (a << 10)) & 0xFFFFFFFF
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    h[0] = (h[0] + a) & 0xFFFFFFFF
    h[1] = (h[1] + b) & 0xFFFFFFFF
    h[2] = (h[2] + c) & 0xFFFFFFFF
    h[3] = (h[3] + d) & 0xFFFFFFFF
    h[4] = (h[4] + e) & 0xFFFFFFFF
    h[5] = (h[5] + f) & 0xFFFFFFFF
    h[6] = (h[6] + g) & 0xFFFFFFFF
    h[7] = (h[7] + hh) & 0xFFFFFFFF


def _pad(data: bytes, block_size: int, length_bytes: int, big_endian_len: bool) -> bytes:
    bitlen = len(data) * 8
    pad = b"\x80" + b"\x00" * ((block_size - (len(data) + 1 + length_bytes) % block_size) % block_size)
    if big_endian_len:
        return data + pad + bitlen.to_bytes(length_bytes, "big")
    return data + pad + bitlen.to_bytes(length_bytes, "little")


def sha256(data: BytesLike) -> bytes:
    data = bytes(data)
    h = list(_H256)
    padded = _pad(data, 64, 8, True)
    for off in range(0, len(padded), 64):
        _sha256_compress(h, padded[off:off + 64])
    return struct.pack(">8I", *h)


# --------------------------------------------------------------------------
# SHA-512
# --------------------------------------------------------------------------

_K512 = (
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
)

_H512 = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)

_M64 = 0xFFFFFFFFFFFFFFFF


def _rotr64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & _M64


def _sha512_compress(h: list, block: bytes) -> None:
    w = list(struct.unpack(">16Q", block)) + [0] * 64
    for i in range(16, 80):
        s0 = _rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
        s1 = _rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _M64

    a, b, c, d, e, f, g, hh = h
    for i in range(80):
        S1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
        ch = (e & f) ^ (~e & _M64 & g)
        t1 = (hh + S1 + ch + _K512[i] + w[i]) & _M64
        S0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _M64
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _M64, c, b, a, (t1 + t2) & _M64
    for i, v in enumerate((a, b, c, d, e, f, g, hh)):
        h[i] = (h[i] + v) & _M64


def sha512(data: BytesLike) -> bytes:
    data = bytes(data)
    h = list(_H512)
    padded = _pad(data, 128, 16, True)
    for off in range(0, len(padded), 128):
        _sha512_compress(h, padded[off:off + 128])
    return struct.pack(">8Q", *h)


# --------------------------------------------------------------------------
# SHA-1 / MD5  (only used by the ``hash`` user command, not by the protocol)
# --------------------------------------------------------------------------


def sha1(data: BytesLike) -> bytes:
    data = bytes(data)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = _pad(data, 64, 8, True)
    for off in range(0, len(padded), 64):
        block = padded[off:off + 64]
        w = list(struct.unpack(">16I", block)) + [0] * 64
        for i in range(16, 80):
            v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w[i] = ((v << 1) | (v >> 31)) & 0xFFFFFFFF
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f = (b & c) | (~b & 0xFFFFFFFF & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            tmp = (((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[i]
            e, d, c, b, a = d, c, ((b << 30) | (b >> 2)) & 0xFFFFFFFF, a, tmp & 0xFFFFFFFF
        for i, v in enumerate((a, b, c, d, e)):
            h[i] = (h[i] + v) & 0xFFFFFFFF
    return struct.pack(">5I", *h)


def md5(data: BytesLike) -> bytes:
    data = bytes(data)
    s = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    k = [int(abs(__import__("math").sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    padded = data + b"\x80" + b"\x00" * ((56 - (len(data) + 1) % 64) % 64) + (len(data) * 8).to_bytes(8, "little")
    for off in range(0, len(padded), 64):
        m = list(struct.unpack("<16I", padded[off:off + 64]))
        a, b, c, d = a0, b0, c0, d0
        for i in range(64):
            if i < 16:
                f, g = (b & c) | (~b & 0xFFFFFFFF & d), i
            elif i < 32:
                f, g = (d & b) | (~d & 0xFFFFFFFF & c), (5 * i + 1) % 16
            elif i < 48:
                f, g = b ^ c ^ d, (3 * i + 5) % 16
            else:
                f, g = c ^ (b | (~d & 0xFFFFFFFF)), (7 * i) % 16
            f = (f + a + k[i] + m[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + ((f << s[i]) | (f >> (32 - s[i])))) & 0xFFFFFFFF
        a0, b0, c0, d0 = (a0 + a) & 0xFFFFFFFF, (b0 + b) & 0xFFFFFFFF, (c0 + c) & 0xFFFFFFFF, (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


# --------------------------------------------------------------------------
# HMAC / HKDF / PBKDF2
# --------------------------------------------------------------------------


def hmac_sha256(key: BytesLike, message: BytesLike) -> bytes:
    key = bytes(key)
    if len(key) > 64:
        key = sha256(key)
    key = key + b"\x00" * (64 - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return sha256(opad + sha256(ipad + bytes(message)))


def hmac_sha512(key: BytesLike, message: BytesLike) -> bytes:
    key = bytes(key)
    if len(key) > 128:
        key = sha512(key)
    key = key + b"\x00" * (128 - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return sha512(opad + sha512(ipad + bytes(message)))


def hkdf_sha256(ikm: BytesLike, length: int, salt: bytes = b"", info: BytesLike = b"") -> bytes:
    """HKDF (RFC 5869) with SHA-256, as used by WhatsApp/Signal."""
    ikm = bytes(ikm)
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_sha256(salt, ikm)
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + bytes(info) + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def pbkdf2_sha256(password: BytesLike, salt: BytesLike, iterations: int, length: int) -> bytes:
    password, salt = bytes(password), bytes(salt)
    blocks = (length + 31) // 32
    out = b""
    for i in range(1, blocks + 1):
        u = hmac_sha256(password, salt + struct.pack(">I", i))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac_sha256(password, u)
            for j in range(32):
                t[j] ^= u[j]
        out += bytes(t)
    return out[:length]


# --------------------------------------------------------------------------
# Optional stdlib acceleration
# --------------------------------------------------------------------------

_PREFER_STDLIB = False
_HASHLIB = None


def set_prefer_stdlib(enabled: bool) -> None:
    """Use hashlib/hmac (stdlib) for the hash primitives when available."""
    global _PREFER_STDLIB, _HASHLIB
    _PREFER_STDLIB = bool(enabled)
    if _PREFER_STDLIB and _HASHLIB is None:
        try:  # pragma: no cover - depends on interpreter
            import hashlib  # type: ignore

            _HASHLIB = hashlib
        except Exception:  # pragma: no cover
            _HASHLIB = False


def fast_sha256(data: BytesLike) -> bytes:
    if _HASHLIB:
        return _HASHLIB.sha256(bytes(data)).digest()
    return sha256(data)


def fast_sha512(data: BytesLike) -> bytes:
    if _HASHLIB:
        return _HASHLIB.sha512(bytes(data)).digest()
    return sha512(data)


def fast_hmac_sha256(key: BytesLike, message: BytesLike) -> bytes:
    if _HASHLIB:
        return _HASHLIB.new("sha256", bytes(message), bytes(key)).digest()
    return hmac_sha256(key, message)


def fast_hmac_sha512(key: BytesLike, message: BytesLike) -> bytes:
    if _HASHLIB:
        return _HASHLIB.new("sha512", bytes(message), bytes(key)).digest()
    return hmac_sha512(key, message)


__all__ = [
    "sha256", "sha512", "sha1", "md5",
    "hmac_sha256", "hmac_sha512", "hkdf_sha256", "pbkdf2_sha256",
    "fast_sha256", "fast_sha512", "fast_hmac_sha256", "fast_hmac_sha512",
    "set_prefer_stdlib",
]
