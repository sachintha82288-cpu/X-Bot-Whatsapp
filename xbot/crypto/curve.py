"""Curve25519 / Ed25519 / XEdDSA — implemented from scratch.

WhatsApp's Noise handshake uses X25519 (``Curve.sharedKey``), while all its
signatures (device identity, signed pre-keys, sender-key messages) use
**XEdDSA** — Ed25519 signatures performed with a Montgomery (X25519) key
pair.  Both directions are implemented here so the bot can talk to the real
WhatsApp servers and to libsignal-based clients.

Reference behaviour: Signal's ``curve_sigs.c`` / ``libsignal-protocol-go``
``ecc.SignCurve25519``, which is what whatsmeow and Baileys interoperate
with.
"""

from __future__ import annotations

import os

from .hashes import fast_sha512, sha512

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
A24 = 121665
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# --------------------------------------------------------------------------
# X25519 (Montgomery ladder)
# --------------------------------------------------------------------------


def _clamp_scalar(k: bytes) -> int:
    a = bytearray(k)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """X25519 ECDH (RFC 7748) — returns the 32-byte shared secret."""
    k = _clamp_scalar(private_key)
    u = int.from_bytes(bytes(public_key)[:32], "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) % P) ** 2 % P
        z3 = (x1 * ((da - cb) % P) ** 2) % P
        x2 = (aa * bb) % P
        z2 = (e * ((aa + A24 * e) % P)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    shared = (x2 * pow(z2, P - 2, P)) % P
    return shared.to_bytes(32, "little")


def x25519_base(private_key: bytes) -> bytes:
    return x25519(private_key, (9).to_bytes(32, "little"))


# --------------------------------------------------------------------------
# Ed25519 arithmetic (extended twisted Edwards coordinates)
# --------------------------------------------------------------------------


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


# Base point
_BY = (4 * _inv(5)) % P
_BX = None  # computed lazily below


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * SQRT_M1) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX, _BY, 1, (_BX * _BY) % P)


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * D) % P
    dd = (2 * z1 * z2) % P
    e, f, g, h = (b - a) % P, (dd - c) % P, (dd + c) % P, (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _ed_double(p):
    x1, y1, z1, _t1 = p
    a = (x1 * x1) % P
    b = (y1 * y1) % P
    c = (2 * z1 * z1) % P
    h = (a + b) % P
    e = (h - (x1 + y1) ** 2) % P
    g = (a - b) % P
    f = (c + g) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _ed_scalar_mult(point, scalar: int):
    q = (0, 1, 1, 0)
    for i in range(255, -1, -1):
        q = _ed_double(q)
        if (scalar >> i) & 1:
            q = _ed_add(q, point)
    return q


def _ed_encode(p) -> bytes:
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % P
    y = (y * zi) % P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _ed_decode(data: bytes):
    data = bytes(data)
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def ed25519_public_from_scalar(scalar: int) -> bytes:
    return _ed_encode(_ed_scalar_mult(_B, scalar % L))


def ed25519_sign_modified(private_key: bytes, public_ed: bytes, message: bytes, random: bytes) -> bytes:
    """XEdDSA signing (Signal's ``crypto_sign_modified``).

    ``private_key`` is the clamped Curve25519 private key, ``public_ed`` the
    Ed25519 public key derived from it (sign bit cleared), ``random`` 64 bytes
    of entropy mixed into the nonce.
    """
    a = _clamp_scalar(private_key)
    diversifier = bytes([0xFE]) + b"\xFF" * 31
    nonce = fast_sha512(diversifier + bytes(private_key) + message + random)
    r = int.from_bytes(nonce, "little") % L
    R = _ed_encode(_ed_scalar_mult(_B, r))
    # NOTE: the *uncleared* public key (including its x sign bit) goes into
    # the challenge hash; the sign bit is then carried in the signature's
    # most significant bit, exactly like Signal's implementation.
    hram = fast_sha512(bytes(R) + bytes(public_ed) + message)
    h = int.from_bytes(hram, "little") % L
    s = (r + h * (a % L)) % L
    sig = bytearray(R + s.to_bytes(32, "little"))
    sig[63] |= bytes(public_ed)[31] & 0x80
    return bytes(sig)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Plain RFC 8032 Ed25519 verification (cofactorless, libsignal style)."""
    try:
        if len(signature) != 64:
            return False
        A = _ed_decode(public_key)
        if A is None:
            return False
        R = _ed_decode(signature[:32])
        if R is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        h = int.from_bytes(fast_sha512(signature[:32] + bytes(public_key) + message), "little") % L
        lhs = _ed_scalar_mult(_B, s)
        rhs = _ed_add(R, _ed_scalar_mult(A, h))
        return _ed_encode(lhs) == _ed_encode(rhs)
    except Exception:
        return False


# --------------------------------------------------------------------------
# XEdDSA (the exact scheme WhatsApp/Signal use)
# --------------------------------------------------------------------------


def _mont_to_ed_y(mont_x: bytes) -> bytes:
    """Convert a Curve25519 u-coordinate into an Ed25519 y-coordinate."""
    u = int.from_bytes(bytes(mont_x)[:32], "little") & ((1 << 255) - 1)
    ed_y = ((u - 1) * _inv(u + 1)) % P
    return ed_y.to_bytes(32, "little")


def xeddsa_sign(private_key: bytes, message: bytes, random: bytes | None = None) -> bytes:
    """Signal-compatible signature (returned by ``Curve.sign``)."""
    if random is None:
        random = os.urandom(64)
    scalar = _clamp_scalar(private_key)
    public_ed = ed25519_public_from_scalar(scalar)
    return ed25519_sign_modified(private_key, public_ed, message, random)


def xeddsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature made over a Curve25519 public key."""
    if len(signature) != 64 or len(public_key) not in (32, 33):
        return False
    pk = bytes(public_key)[-32:]
    clean_pk = bytearray(pk)
    clean_pk[31] &= 0x7F
    ed_y = bytearray(_mont_to_ed_y(bytes(clean_pk)))
    ed_y[31] |= signature[63] & 0x80
    sig = bytearray(signature)
    sig[63] &= 0x7F
    return ed25519_verify(bytes(ed_y), message, bytes(sig))


# --------------------------------------------------------------------------
# Key pair helpers used by the WA layer
# --------------------------------------------------------------------------


def generate_key_pair() -> tuple[bytes, bytes]:
    """Return ``(private, public)`` for a fresh Curve25519 key pair."""
    private = os.urandom(32)
    return private, x25519_base(private)


def shared_key(private_key: bytes, public_key: bytes) -> bytes:
    """DH: accepts both 32-byte and 33-byte (0x05-prefixed) public keys."""
    return x25519(private_key, bytes(public_key)[-32:])


__all__ = [
    "P", "L", "x25519", "x25519_base", "generate_key_pair", "shared_key",
    "xeddsa_sign", "xeddsa_verify", "ed25519_verify", "ed25519_public_from_scalar",
    "ed25519_sign_modified",
]
