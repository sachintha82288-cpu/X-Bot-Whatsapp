"""Media encryption / upload / download for WhatsApp.

WhatsApp media is sent as::

    AES-256-CBC(cipherKey, iv, plaintext + PKCS7)  ||  HMAC-SHA256(macKey, iv||ciphertext)[:10]

The keys come from ``HKDF(mediaKey, 112, "WhatsApp <Type> Keys")`` and the
encrypted blob is uploaded to ``https://<host>/mms/<type>/<sha256-b64>`` using
plain ``http.client`` — no request library is involved.

Downloads stream the same blob from ``mmg.whatsapp.net`` and reverse it.
"""

from __future__ import annotations

import base64
import http.client
import os
import ssl
import time
import urllib.parse
from typing import Dict, Optional, Tuple

from .crypto.aes import AES, cbc_decrypt, cbc_encrypt
from .crypto.hashes import fast_sha256 as sha256
from .crypto.hashes import hkdf_sha256 as hkdf
from .crypto.hashes import hmac_sha256
from .wa.binary import Node

DEFAULT_ORIGIN = "https://web.whatsapp.com"
DEF_MEDIA_HOST = "mmg.whatsapp.net"
AES_CHUNK = 16
MAC_LENGTH = 10

# HKDF info suffix per media type
MEDIA_HKDF_KEY_MAPPING = {
    "audio": "Audio",
    "document": "Document",
    "gif": "Video",
    "image": "Image",
    "ppic": "",
    "product": "Image",
    "ptt": "Audio",
    "sticker": "Image",
    "video": "Video",
    "thumbnail-document": "Document Thumbnail",
    "thumbnail-image": "Image Thumbnail",
    "thumbnail-video": "Video Thumbnail",
    "thumbnail-link": "Link Thumbnail",
    "md-msg-hist": "History",
    "md-app-state": "App State",
    "product-catalog-image": "",
    "ptv": "Video",
}

MEDIA_PATH_MAP = {
    "image": "/mms/image",
    "video": "/mms/video",
    "document": "/mms/document",
    "audio": "/mms/audio",
    "sticker": "/mms/image",
    "thumbnail-link": "/mms/image",
    "ptv": "/mms/video",
    "md-msg-hist": "/mms/md-app-state",
}

# mimetype -> (media type, extension)
MIMETYPE_MAP = {
    "image/jpeg": ("image", "jpg"),
    "image/png": ("image", "png"),
    "image/webp": ("sticker", "webp"),
    "video/mp4": ("video", "mp4"),
    "audio/mp4": ("audio", "m4a"),
    "audio/ogg": ("audio", "ogg"),
    "audio/mpeg": ("audio", "mp3"),
    "application/pdf": ("document", "pdf"),
    "application/octet-stream": ("document", "bin"),
    "text/plain": ("document", "txt"),
}


def guess_type(mimetype: str) -> Tuple[str, str]:
    """``mimetype`` -> ``(media_type, extension)``."""
    mimetype = (mimetype or "").split(";")[0].strip().lower()
    if mimetype in MIMETYPE_MAP:
        return MIMETYPE_MAP[mimetype]
    if mimetype.startswith("image/"):
        return "image", mimetype.split("/")[1] or "jpg"
    if mimetype.startswith("video/"):
        return "video", mimetype.split("/")[1] or "mp4"
    if mimetype.startswith("audio/"):
        return "audio", mimetype.split("/")[1] or "ogg"
    return "document", "bin"


def mimetype_for(extension: str) -> str:
    lookup = {
        "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
        "webp": "image/webp", "gif": "image/gif", "mp4": "video/mp4",
        "m4a": "audio/mp4", "ogg": "audio/ogg", "opus": "audio/ogg",
        "mp3": "audio/mpeg", "pdf": "application/pdf", "txt": "text/plain",
    }
    return lookup.get(extension.lower().lstrip("."), "application/octet-stream")


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------


def media_keys(media_key: bytes, media_type: str) -> Dict[str, bytes]:
    """Derive ``iv``/``cipherKey``/``macKey`` from a 32 byte media key."""
    info = "WhatsApp %s Keys" % MEDIA_HKDF_KEY_MAPPING.get(media_type, "Image")
    expanded = hkdf(media_key, 112, b"", info.encode())
    return {
        "iv": expanded[0:16],
        "cipherKey": expanded[16:48],
        "macKey": expanded[48:80],
    }


def get_media_retry_key(media_key: bytes) -> bytes:
    return hkdf(media_key, 32, b"", b"WhatsApp Media Retry Notification")


def encrypt_media(data: bytes, media_type: str = "image") -> Dict[str, object]:
    """Encrypt bytes for upload; returns the blob and its metadata."""
    media_key = os.urandom(32)
    keys = media_keys(media_key, media_type)
    ciphertext = cbc_encrypt(keys["cipherKey"], keys["iv"], data, pad=True)
    mac = hmac_sha256(keys["macKey"], keys["iv"] + ciphertext)[:MAC_LENGTH]
    body = ciphertext + mac
    return {
        "mediaKey": media_key,
        "ciphertext": ciphertext,
        "iv": keys["iv"],
        "cipherKey": keys["cipherKey"],
        "macKey": keys["macKey"],
        "mac": mac,
        "body": body,
        "fileLength": len(data),
        "fileSha256": sha256(data),
        "fileEncSha256": sha256(body),
    }


def decrypt_media(body: bytes, media_key: bytes, media_type: str = "image") -> bytes:
    """Decrypt a downloaded media blob (verifies the trailing MAC)."""
    if len(body) <= MAC_LENGTH + AES_CHUNK:
        raise ValueError("media blob too small")
    keys = media_keys(media_key, media_type)
    ciphertext, mac = body[:-MAC_LENGTH], body[-MAC_LENGTH:]
    expected = hmac_sha256(keys["macKey"], keys["iv"] + ciphertext)[:MAC_LENGTH]
    if expected != mac:
        raise ValueError("media MAC mismatch")
    return cbc_decrypt(keys["cipherKey"], keys["iv"], ciphertext, unpad=True)


# --------------------------------------------------------------------------
# HTTP (stdlib only)
# --------------------------------------------------------------------------


def _connection(url: str, timeout: float = 60.0):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def http_request(url: str, method: str = "GET", body: Optional[bytes] = None,
                 headers: Optional[Dict[str, str]] = None, timeout: float = 60.0,
                 max_bytes: int = 64 * 1024 * 1024) -> Tuple[int, Dict[str, str], bytes]:
    """A tiny ``requests``-free HTTP(S) helper."""
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    connection = _connection(url, timeout)
    all_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Origin": DEFAULT_ORIGIN,
    }
    all_headers.update(headers or {})
    try:
        connection.request(method, path, body=body, headers=all_headers)
        response = connection.getresponse()
        raw = response.read(max_bytes)
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, response_headers, raw
    finally:
        try:
            connection.close()
        except OSError:  # pragma: no cover
            pass


def b64_for_upload(data: bytes) -> str:
    """Base64url without padding, percent-encoded (what the CDN expects)."""
    encoded = base64.b64encode(data).decode()
    encoded = encoded.replace("+", "-").replace("/", "_").rstrip("=")
    return urllib.parse.quote(encoded, safe="")


# --------------------------------------------------------------------------
# client-side helpers (a thin mixin used by WAClient)
# --------------------------------------------------------------------------


class MediaSupport:
    """Upload/download helpers for :class:`xbot.client.WAClient`."""

    _media_conn: Optional[dict] = None

    def refresh_media_conn(self, force: bool = False) -> dict:
        cached = self._media_conn
        if (not force and cached
                and time.time() - cached.get("fetchDate", 0) < cached.get("ttl", 0)):
            return cached
        result = self.query(Node("iq", {"type": "set", "xmlns": "w:m", "to": "s.whatsapp.net"},
                                 [Node("media_conn", {})]))
        media_conn = result.child("media_conn") if result is not None else None
        if media_conn is None:
            raise RuntimeError("could not fetch media connection info")
        node = {
            "auth": media_conn.attrs.get("auth"),
            "ttl": float(media_conn.attrs.get("ttl") or 0),
            "fetchDate": time.time(),
            "hosts": [host.attrs.get("hostname") for host in media_conn.children("host")],
        }
        self._media_conn = node
        return node

    def upload_media(self, data: bytes, media_type: str = "image",
                     mimetype: Optional[str] = None) -> Dict[str, object]:
        """Encrypt and upload ``data``; returns the proto fields to embed."""
        encrypted = encrypt_media(data, media_type)
        media_conn = self.refresh_media_conn()
        digest = b64_for_upload(encrypted["fileEncSha256"])
        auth = urllib.parse.quote(media_conn.get("auth") or "", safe="")
        path = MEDIA_PATH_MAP.get(media_type, "/mms/document")
        result = {}
        for hostname in media_conn.get("hosts") or [DEF_MEDIA_HOST]:
            url = f"https://{hostname}{path}/{digest}?auth={auth}&token={digest}"
            try:
                status, _headers, raw = http_request(
                    url, "POST", encrypted["body"],
                    {"Content-Type": "application/octet-stream"})
                if status in (200, 201) and raw:
                    import json as _json

                    result = _json.loads(raw.decode() or "{}")
                    if result.get("url") or result.get("direct_path"):
                        break
            except Exception:  # pragma: no cover - network dependent
                continue
        if not result.get("direct_path"):
            raise RuntimeError("media upload failed")

        return {
            "url": result.get("url"),
            "directPath": result.get("direct_path"),
            "mediaKey": encrypted["mediaKey"],
            "fileSha256": encrypted["fileSha256"],
            "fileEncSha256": encrypted["fileEncSha256"],
            "fileLength": encrypted["fileLength"],
            "mediaKeyTimestamp": int(time.time()),
            "mimetype": mimetype,
        }

    def download_media(self, message: dict, media_type: str,
                       max_bytes: int = 64 * 1024 * 1024) -> bytes:
        """Download and decrypt the media referenced by a message body."""
        direct_path = message.get("directPath")
        url = message.get("url")
        if direct_path:
            url = f"https://{DEF_MEDIA_HOST}{direct_path}"
        if not url:
            raise ValueError("message has no media url")
        status, _headers, body = http_request(url, headers={"Origin": DEFAULT_ORIGIN},
                                              max_bytes=max_bytes + 1024)
        if status != 200:
            raise RuntimeError(f"media download failed with status {status}")
        media_key = message.get("mediaKey")
        if not media_key:
            raise ValueError("message has no mediaKey")
        return decrypt_media(body, bytes(media_key), media_type)


__all__ = [
    "media_keys", "encrypt_media", "decrypt_media", "guess_type", "mimetype_for",
    "MediaSupport", "http_request", "get_media_retry_key", "MEDIA_PATH_MAP",
    "MEDIA_HKDF_KEY_MAPPING",
]
