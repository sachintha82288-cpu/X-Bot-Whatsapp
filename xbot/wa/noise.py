"""WhatsApp's Noise handshake (Noise_XX_25519_AESGCM_SHA256) + transport.

This is a faithful re-implementation of the handshake WhatsApp Web performs
on connect:

* prologue/hash initialised with the ASCII mode string
* ``WA\\x06\\x03`` (client header) is authenticated into the hash, then the
  client's static public key
* handshake frames are length-prefixed and AES-256-GCM encrypted with a
  counter-based nonce; keywords mixing is done with HKDF-SHA256
* after the handshake, the transport is a pair of AES-GCM keys with a
  32-bit big-endian counter in the last four bytes of the 12-byte IV

The first frame on the wire additionally carries the ``WA\\x06\\x03`` intro
header (and the routing-info "ED" block when reconnecting).
"""

from __future__ import annotations

import struct
from typing import Callable, List, Optional, Tuple, Union

from ..crypto.aes import gcm_decrypt, gcm_encrypt
from ..crypto import curve
from ..crypto.hashes import fast_sha256 as sha256
from ..crypto.hashes import hkdf_sha256 as hkdf
from . import binary
from . import protobuf as pb

NOISE_MODE = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
NOISE_HEADER = b"WA\x06\x03"
DICT_VERSION = 3
KEY_BUNDLE_TYPE = b"\x05"

# WhatsApp's long-term certificate authority public key (used to verify the
# server's certificate chain).  This constant is part of every WhatsApp client.
WA_CERT_DETAILS = {
    "SERIAL": 0,
    "ISSUER": "WhatsAppLongTerm1",
    "PUBLIC_KEY": bytes.fromhex(
        "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b"
    ),
}


class NoiseError(Exception):
    pass


def as_key_pair(key_pair) -> Tuple[bytes, bytes]:
    """Accept both ``(private, public)`` tuples and ``{private, public}`` dicts."""
    if isinstance(key_pair, dict):
        return bytes(key_pair["private"]), bytes(key_pair["public"])
    private, public = key_pair
    return bytes(private), bytes(public)


class TransportState:
    """Post-handshake AES-256-GCM transport with counter nonces."""

    __slots__ = ("enc_key", "dec_key", "read_counter", "write_counter", "read_iv", "write_iv")

    def __init__(self, enc_key: bytes, dec_key: bytes):
        self.enc_key = enc_key
        self.dec_key = dec_key
        self.read_counter = 0
        self.write_counter = 0
        self.read_iv = bytearray(12)
        self.write_iv = bytearray(12)

    def encrypt(self, plaintext: bytes) -> bytes:
        counter = self.write_counter
        self.write_counter = (counter + 1) & 0xFFFFFFFF
        iv = self.write_iv
        iv[8:] = struct.pack(">I", counter)
        return gcm_encrypt(self.enc_key, bytes(iv), plaintext, b"")

    def decrypt(self, ciphertext: bytes) -> bytes:
        counter = self.read_counter
        self.read_counter = (counter + 1) & 0xFFFFFFFF
        iv = self.read_iv
        iv[8:] = struct.pack(">I", counter)
        return gcm_decrypt(self.dec_key, bytes(iv), ciphertext, b"")


class NoiseHandler:
    """Handshake + transport, mirroring Baileys' ``makeNoiseHandler``."""

    def __init__(self, key_pair, noise_header: bytes = NOISE_HEADER,
                 routing_info: Optional[bytes] = None, logger=None, cert_authority=None):
        self.private_key, self.public_key = as_key_pair(key_pair)
        self.logger = logger
        # WhatsApp's own CA is used by default; tests may inject their own
        self.cert_authority = cert_authority or WA_CERT_DETAILS
        data = NOISE_MODE
        self.hash = data if len(data) == 32 else sha256(data)
        self.salt = self.hash
        self.enc_key = self.hash
        self.dec_key = self.hash
        self.counter = 0
        self.transport: Optional[TransportState] = None
        self._pending: List = []
        self._buffer = bytearray()
        self._sent_intro = False
        self._waiting_for_transport = False

        if routing_info:
            header = bytearray()
            header += b"ED"
            header.append(0)
            header.append(1)
            header += struct.pack(">I", len(routing_info))[1:]
            header += routing_info
            header += noise_header
            self.intro_header = bytes(header)
        else:
            self.intro_header = bytes(noise_header)

        self._authenticate(noise_header)
        self._authenticate(self.public_key)

    # ------------------------------------------------------------- internals
    def _authenticate(self, data: bytes) -> None:
        if self.transport is None:
            self.hash = sha256(self.hash + bytes(data))

    @staticmethod
    def _iv(counter: int) -> bytes:
        iv = bytearray(12)
        iv[8:] = struct.pack(">I", counter & 0xFFFFFFFF)
        return bytes(iv)

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.transport is not None:
            return self.transport.encrypt(plaintext)
        result = gcm_encrypt(self.enc_key, self._iv(self.counter), plaintext, self.hash)
        self.counter += 1
        self._authenticate(result)
        return result

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.transport is not None:
            return self.transport.decrypt(ciphertext)
        result = gcm_decrypt(self.dec_key, self._iv(self.counter), ciphertext, self.hash)
        self.counter += 1
        self._authenticate(ciphertext)
        return result

    def _local_hkdf(self, data: bytes) -> Tuple[bytes, bytes]:
        key = hkdf(data, 64, self.salt, b"")
        return key[:32], key[32:]

    def _mix_into_key(self, data: bytes) -> None:
        write, read = self._local_hkdf(data)
        self.salt = write
        self.enc_key = read
        self.dec_key = read
        self.counter = 0

    def finish_init(self) -> None:
        write, read = self._local_hkdf(b"")
        self.transport = TransportState(write, read)
        pending, self._pending = self._pending, []
        for callback, frame in pending:
            self._handle_decrypted(callback, frame)

    # -------------------------------------------------------------- handshake
    def process_handshake(self, server_hello: dict, noise_key_pair: Tuple[bytes, bytes]) -> bytes:
        """Consume the server's hello and return the encrypted static key."""
        ephemeral = server_hello.get("ephemeral")
        static = server_hello.get("static")
        payload = server_hello.get("payload")
        if not ephemeral or not static or not payload:
            raise NoiseError("incomplete server hello")

        self._authenticate(ephemeral)
        self._mix_into_key(curve.shared_key(self.private_key, ephemeral))

        dec_static = self.decrypt(static)
        self._mix_into_key(curve.shared_key(self.private_key, dec_static))

        cert_chain = pb.decode("CertChain", self.decrypt(payload))
        leaf = cert_chain.get("leaf") or {}
        intermediate = cert_chain.get("intermediate") or {}
        if not leaf.get("details") or not leaf.get("signature"):
            raise NoiseError("invalid noise leaf certificate")
        if not intermediate.get("details") or not intermediate.get("signature"):
            raise NoiseError("invalid noise intermediate certificate")

        details = pb.decode("CertChain.NoiseCertificate.Details", intermediate["details"])

        if not curve.xeddsa_verify(details["key"], leaf["details"], leaf["signature"]):
            raise NoiseError("noise certificate signature invalid")
        if not curve.xeddsa_verify(self.cert_authority["PUBLIC_KEY"], intermediate["details"],
                                   intermediate["signature"]):
            raise NoiseError("noise intermediate certificate signature invalid")
        if details.get("issuerSerial") != self.cert_authority["SERIAL"]:
            raise NoiseError("certification match failed")

        private, public = as_key_pair(noise_key_pair)
        key_enc = self.encrypt(public)
        self._mix_into_key(curve.shared_key(private, ephemeral))
        return key_enc

    # ----------------------------------------------------------------- framing
    def encode_frame(self, data: bytes) -> bytes:
        if self.transport is not None:
            data = self.transport.encrypt(data)
        size = len(data)
        intro = b"" if self._sent_intro else self.intro_header
        self._sent_intro = True
        return intro + bytes([
            (size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF
        ]) + data

    def decode_frame(self, data: bytes, on_frame: Callable[[Union[bytes, binary.Node]], None]) -> None:
        self._buffer += data
        while True:
            if len(self._buffer) < 3:
                return
            size = (self._buffer[0] << 16) | (self._buffer[1] << 8) | self._buffer[2]
            if len(self._buffer) < size + 3:
                return
            frame = bytes(self._buffer[3:size + 3])
            del self._buffer[:size + 3]
            if self.transport is None:
                # handshake frames are raw protobuf; the caller parses them
                on_frame(frame)
            else:
                self._handle_decrypted(on_frame, self.transport.decrypt(frame))

    def _handle_decrypted(self, on_frame, plaintext: bytes) -> None:
        try:
            node = binary.decode(plaintext)
        except Exception as exc:  # pragma: no cover - protocol errors
            if self.logger:
                self.logger.debug("failed to decode frame: %s", exc)
            return
        on_frame(node)


__all__ = ["NoiseHandler", "NoiseError", "TransportState", "NOISE_HEADER", "WA_CERT_DETAILS",
           "as_key_pair"]
