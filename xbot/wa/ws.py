"""Minimal WebSocket (RFC 6455) client.

Only ``socket`` and ``ssl`` from the standard library are used — the framing,
masking and control-frame handling are implemented here.  TLS itself is
delegated to the interpreter (implementing TLS by hand is neither sensible
nor needed: it is a transport, not part of the WhatsApp protocol).

The reader runs in its own thread and hands binary messages to a callback.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
import struct
import threading
import time
from typing import Callable, Dict, Optional
from urllib.parse import urlparse

from ..crypto.hashes import fast_sha256, sha1

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BIN = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class WebSocketError(Exception):
    pass


class WebSocketClient:
    """A small, dependency-free WebSocket client (binary frames)."""

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        on_message: Optional[Callable[[bytes], None]] = None,
        on_open: Optional[Callable[[], None]] = None,
        on_close: Optional[Callable[[Optional[int], str], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        connect_timeout: float = 20.0,
        user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        origin: str = "https://web.whatsapp.com",
    ):
        self.url = url
        self.extra_headers = headers or {}
        self.on_message = on_message
        self.on_open = on_open
        self.on_close = on_close
        self.on_error = on_error
        self.connect_timeout = connect_timeout
        self.user_agent = user_agent
        self.origin = origin

        self.sock: Optional[ssl.SSLSocket] = None
        self.is_open = False
        self._send_lock = threading.Lock()
        self._reader: Optional[threading.Thread] = None
        self._close_sent = False
        self._fragments = bytearray()
        self._fragment_opcode = 0
        self.last_recv = time.time()

    # ------------------------------------------------------------------ setup
    def connect(self) -> None:
        parsed = urlparse(self.url)
        secure = parsed.scheme in ("wss", "https")
        host = parsed.hostname or "web.whatsapp.com"
        port = parsed.port or (443 if secure else 80)
        path = parsed.path or "/ws/chat"
        if parsed.query:
            path += "?" + parsed.query

        raw = socket.create_connection((host, port), timeout=self.connect_timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if secure:
            context = ssl.create_default_context()
            context.check_hostname = True
            sock = context.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.settimeout(self.connect_timeout)
        self.sock = sock  # type: ignore[assignment]

        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            f"Origin: {self.origin}",
            f"User-Agent: {self.user_agent}",
        ]
        for header, value in self.extra_headers.items():
            lines.append(f"{header}: {value}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode()

        sock.sendall(request)

        # read the HTTP response headers
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            buffer += chunk
            if len(buffer) > 65536:
                raise WebSocketError("handshake response too large")
        header, _, rest = buffer.partition(b"\r\n\r\n")
        text = header.decode("latin-1")
        status_line = text.split("\r\n", 1)[0]
        if "101" not in status_line:
            raise WebSocketError(f"websocket upgrade failed: {status_line}")
        expected = base64.b64encode(sha1((key + WS_GUID).encode())).decode()
        if expected not in text:
            raise WebSocketError("invalid Sec-WebSocket-Accept")

        sock.settimeout(None)
        self.is_open = True
        self._pending = rest
        self.last_recv = time.time()
        if self.on_open:
            self.on_open()

    def start_reader(self) -> None:
        self._reader = threading.Thread(target=self._read_loop, name="wa-ws-reader", daemon=True)
        self._reader.start()

    # ------------------------------------------------------------------ send
    def send(self, data) -> None:
        if not self.sock or not self.is_open:
            raise WebSocketError("socket is not open")
        payload = data if isinstance(data, (bytes, bytearray)) else bytes(data)
        header = bytearray()
        header.append(0x80 | OP_BIN)
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < (1 << 16):
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            try:
                self.sock.sendall(bytes(header) + masked)
            except OSError as exc:  # pragma: no cover - network dependent
                self.is_open = False
                raise WebSocketError(str(exc)) from exc

    def _send_control(self, opcode: int, payload: bytes = b"") -> None:
        if not self.sock:
            return
        mask = os.urandom(4)
        frame = bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + bytes(
            b ^ mask[i % 4] for i, b in enumerate(payload)
        )
        try:
            with self._send_lock:
                self.sock.sendall(frame)
        except OSError:
            pass

    def ping(self) -> None:
        self._send_control(OP_PING)

    def close(self, code: int = 1000) -> None:
        if self._close_sent:
            return
        self._close_sent = True
        self.is_open = False
        self._send_control(OP_CLOSE, struct.pack(">H", code))
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------ recv
    def _recv_exact(self, count: int) -> bytes:
        assert self.sock is not None
        buffer = getattr(self, "_pending", b"")
        if buffer:
            chunk = buffer[:count]
            self._pending = buffer[count:]
            if len(chunk) == count:
                return chunk
            return chunk + self._recv_exact(count - len(chunk))
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise WebSocketError("connection closed by peer")
            data += chunk
        return data

    def _read_loop(self) -> None:
        close_code: Optional[int] = None
        close_reason = ""
        try:
            while self.is_open:
                try:
                    head = self._recv_exact(2)
                except WebSocketError:
                    break
                fin = head[0] & 0x80
                opcode = head[0] & 0x0F
                masked = head[1] & 0x80
                length = head[1] & 0x7F
                if length == 126:
                    length = struct.unpack(">H", self._recv_exact(2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", self._recv_exact(8))[0]
                mask = self._recv_exact(4) if masked else b""
                payload = self._recv_exact(length) if length else b""
                if masked:
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                self.last_recv = time.time()

                if opcode == OP_CLOSE:
                    if len(payload) >= 2:
                        close_code = struct.unpack(">H", payload[:2])[0]
                        close_reason = payload[2:].decode("utf-8", "replace")
                    self.is_open = False
                    self._send_control(OP_CLOSE, payload[:2])
                    break
                if opcode == OP_PING:
                    self._send_control(OP_PONG, payload)
                    continue
                if opcode == OP_PONG:
                    continue
                if opcode == OP_CONT:
                    self._fragments += payload
                    if fin:
                        data = bytes(self._fragments)
                        self._fragments = bytearray()
                        self._dispatch(data)
                    continue
                if opcode in (OP_BIN, OP_TEXT):
                    if fin:
                        self._dispatch(payload)
                    else:
                        self._fragment_opcode = opcode
                        self._fragments = bytearray(payload)
                    continue
        except Exception as exc:  # pragma: no cover - network dependent
            if self.on_error:
                self.on_error(exc)
        finally:
            self.is_open = False
            if self.on_close:
                self.on_close(close_code, close_reason)

    def _dispatch(self, payload: bytes) -> None:
        if self.on_message:
            try:
                self.on_message(payload)
            except Exception as exc:  # pragma: no cover - callback safety
                if self.on_error:
                    self.on_error(exc)


def websocket_accept_key(client_key: str) -> str:
    """Helper (also used by the local test server)."""
    return base64.b64encode(sha1((client_key + WS_GUID).encode())).decode()


__all__ = ["WebSocketClient", "WebSocketError", "websocket_accept_key"]
