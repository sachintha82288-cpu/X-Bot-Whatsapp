"""The WhatsApp multi-device client.

This module glues the hand written protocol pieces together:

``ws`` (RFC 6455) -> ``noise`` (Noise XX) -> ``binary`` (WA nodes) ->
``protobuf`` (WhatsApp protobufs) -> ``signal`` (E2E encryption).

Only the standard library is used.  The client runs a single reader thread for
the WebSocket plus a small keep-alive timer, so it stays usable on a phone with
1 GB of RAM.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Callable, Dict, List, Optional

from .crypto import curve
from .crypto.aes import ctr_crypt, unpad_pkcs7
from .crypto.hashes import fast_sha256 as sha256
from .crypto.hashes import hmac_sha256, md5, pbkdf2_sha256
from .store import AuthStore, b64, encode_big_endian, unb64
from .wa import binary, protobuf as pb
from .wa import signal as sig
from .wa.noise import NOISE_HEADER, NoiseHandler
from .wa.ws import WebSocketClient, WebSocketError

S_WHATSAPP_NET = "s.whatsapp.net"
DEFAULT_ORIGIN = "https://web.whatsapp.com"
WA_URL = "wss://web.whatsapp.com/ws/chat"
KEY_BUNDLE_TYPE = b"\x05"
KEEP_ALIVE_INTERVAL = 30.0
MIN_PREKEY_COUNT = 5
INITIAL_PREKEY_COUNT = 812
MAX_PREKEY_UPLOAD = 200
NO_MESSAGE_FOUND = "Message absent from node"
MISSING_KEYS = "Key used already or never filled"
CROCKFORD = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"

# signature prefixes used by the companion device registration
ACCOUNT_SIG_PREFIX = b"\x06\x00"
DEVICE_SIG_PREFIX = b"\x06\x01"
HOSTED_SIG_PREFIX = b"\x06\x05"

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


class Logger:
    """Dead simple stdout logger (Termux friendly, no dependencies)."""

    def __init__(self, level: str = "info"):
        self.level = level
        self.levels = {"trace": 0, "debug": 1, "info": 2, "warn": 3, "error": 4, "silent": 9}

    def _log(self, name: str, message: str, *args) -> None:
        if self.levels.get(name, 2) < self.levels.get(self.level, 2):
            return
        if args:
            try:
                message = message % args
            except (TypeError, ValueError):
                message = message + " " + repr(args)
        stamp = time.strftime("%H:%M:%S")
        print(f"[{stamp}] {name.upper():5} {message}", flush=True)

    def trace(self, message, *args):
        self._log("trace", message, *args)

    def debug(self, message, *args):
        self._log("debug", message, *args)

    def info(self, message, *args):
        self._log("info", message, *args)

    def warn(self, message, *args):
        self._log("warn", message, *args)

    def error(self, message, *args):
        self._log("error", message, *args)


def get_child(node: Optional[binary.Node], tag: str) -> Optional[binary.Node]:
    if node is None:
        return None
    return node.child(tag)


def get_children(node: Optional[binary.Node], tag: Optional[str] = None) -> List[binary.Node]:
    if node is None or not isinstance(node.content, list):
        return []
    return node.children(tag)


def child_bytes(node: Optional[binary.Node], tag: str) -> Optional[bytes]:
    child = get_child(node, tag)
    if child is None:
        return None
    raw = child.buffer()
    return bytes(raw) if raw is not None else None


def child_text(node: Optional[binary.Node], tag: str) -> Optional[str]:
    child = get_child(node, tag)
    return child.text() if child is not None else None


def child_int(node: Optional[binary.Node], tag: str, size: int = 4) -> Optional[int]:
    raw = child_bytes(node, tag)
    if raw is None:
        return None
    return int.from_bytes(raw[:size], "big")


def write_random_pad_max16(data: bytes) -> bytes:
    pad = os.urandom(1)[0] & 0x0F
    length = pad + 1
    return data + bytes([length]) * length


def unpad_random_max16(data: bytes) -> bytes:
    if not data:
        return data
    size = data[-1]
    if size > len(data):
        return data
    return data[: len(data) - size]


def generate_md_tag_prefix() -> str:
    raw = os.urandom(4)
    return f"{int.from_bytes(raw[:2], 'big')}.{int.from_bytes(raw[2:], 'big')}-"


def bytes_to_crockford(data: bytes) -> str:
    value = 0
    for byte in data:
        value = (value << 8) | byte
    out = ""
    for _ in range(8):
        value, index = divmod(value, 32)
        out = CROCKFORD[index] + out
    return out


def generate_message_id_v2(user_id: Optional[str]) -> str:
    buffer = bytearray(8 + 20 + 16)
    buffer[0:8] = int(time.time()).to_bytes(8, "big")
    if user_id:
        decoded = binary.jid_decode(user_id)
        if decoded and decoded[0]:
            user = decoded[0].encode()
            buffer[8:8 + len(user)] = user
            suffix = b"@c.us"
            buffer[8 + len(user):8 + len(user) + len(suffix)] = suffix
    buffer[28:44] = os.urandom(16)
    digest = sha256(bytes(buffer)).hex().upper()
    return "3EB0" + digest[:18]


def generate_participant_hash(participants: List[str]) -> str:
    digest = b64(sha256("".join(sorted(participants)).encode()))
    return "2:" + digest[:6]


def unprefix_key(raw: Optional[bytes]) -> bytes:
    """Signal public keys travel with a 0x05 type prefix; strip it."""
    if not raw:
        return b""
    data = bytes(raw)
    if len(data) == 33 and data[0] == 0x05:
        return data[1:]
    return data[-32:] if len(data) > 32 else data


def jid_to_signal_address(jid: str) -> str:
    decoded = binary.jid_decode(jid)
    if not decoded:
        return jid
    user, _server, device, _domain = decoded
    return f"{user}.{device or 0}"


def is_hosted_jid(jid: Optional[str]) -> bool:
    return bool(jid) and (jid.endswith("@hosted") or jid.endswith("@hosted.lid"))


# --------------------------------------------------------------------------
# client
# --------------------------------------------------------------------------


class WAClient:
    """A WhatsApp companion-device client."""

    def __init__(self, store: AuthStore, config: Optional[dict] = None, logger=None):
        config = config or {}
        self.store = store
        self.config = config
        self.log = logger or Logger(config.get("log_level", "info"))
        self.version = list(config.get("version") or store.creds.get("version") or [2, 3000, 1043857760])
        self.browser = list(config.get("browser") or ["Mac OS", "Chrome", "14.4.1"])
        self.country_code = config.get("country_code", "US")
        self.push_name = config.get("push_name") or "X-Bot"
        self.sync_full_history = bool(config.get("sync_full_history", False))
        self.url = config.get("url", WA_URL)
        self.keep_alive = float(config.get("keep_alive", KEEP_ALIVE_INTERVAL))
        self.query_timeout = float(config.get("query_timeout", 30))
        self.use_device_cache = bool(config.get("device_cache", True))
        self.log_qr = bool(config.get("log_qr", True))

        self.ws: Optional[WebSocketClient] = None
        self.noise: Optional[NoiseHandler] = None
        self.is_open = False
        self.connected = False
        self.last_disconnect_reason: Optional[str] = None
        self.incoming: "queue.Queue[dict]" = queue.Queue()

        self._handlers: Dict[str, List[Callable]] = {}
        self._queries: Dict[str, dict] = {}
        self._query_lock = threading.Lock()
        self._handshake_lock = threading.RLock()
        self._handshake_event = threading.Event()
        self._handshake_message: Optional[dict] = None
        self._epoch = 1
        self._uq_tag_id = generate_md_tag_prefix()
        self._stop = threading.Event()
        self._keepalive_thread: Optional[threading.Thread] = None
        self._last_recv = time.time()
        self._qr_count = 0
        self.server_time_offset = 0.0

    # ----------------------------------------------------------------- events
    def on(self, event: str, callback: Callable) -> None:
        self._handlers.setdefault(event, []).append(callback)

    def emit(self, event: str, *args) -> None:
        for callback in list(self._handlers.get(event, [])):
            try:
                callback(*args)
            except Exception as exc:  # pragma: no cover - callback safety
                self.log.error("handler for %s failed: %s", event, exc)

    # ------------------------------------------------------------ connection
    @property
    def me_id(self) -> Optional[str]:
        return self.store.me_id

    @property
    def me_lid(self) -> Optional[str]:
        return self.store.me_lid

    def connect(self) -> bool:
        """Open the socket, run the Noise handshake and log in."""
        self._stop.clear()
        self._handshake_event.clear()
        self._handshake_message = None
        self._last_recv = time.time()

        url = self.url
        routing_info = self.store.creds.get("routingInfo")
        routing_bytes = unb64(routing_info) if routing_info else None
        if routing_bytes:
            import base64 as _b64

            url = f"{url}?ED={_b64.urlsafe_b64encode(routing_bytes).rstrip(b'=').decode()}"

        ephemeral = curve.generate_key_pair()
        self.noise = NoiseHandler(ephemeral, NOISE_HEADER, routing_info=routing_bytes,
                                  logger=self.log,
                                  cert_authority=self.config.get("cert_authority"))
        self.ws = WebSocketClient(
            url,
            on_message=self._on_ws_message,
            on_close=self._on_ws_close,
            on_error=self._on_ws_error,
        )
        try:
            self.ws.connect()
        except (OSError, WebSocketError) as exc:
            self.log.error("websocket connection failed: %s", exc)
            return False

        self.is_open = True
        self.ws.start_reader()
        self.emit("connection", "connecting")

        self.send_raw(pb.encode("HandshakeMessage", {
            "clientHello": {"ephemeral": ephemeral[1]},
        }))

        if not self._handshake_event.wait(timeout=30):
            self.log.error("timed out waiting for the server handshake")
            self.disconnect("handshake timeout")
            return False

        handshake = self._handshake_message or {}
        try:
            with self._handshake_lock:
                server_hello = handshake.get("serverHello") or handshake
                key_enc = self.noise.process_handshake(server_hello, self.store.creds["noiseKey"])
                payload = self._login_payload()
                payload_enc = self.noise.encrypt(pb.encode("ClientPayload", payload))
                self.send_raw(pb.encode("HandshakeMessage", {
                    "clientFinish": {"static": key_enc, "payload": payload_enc},
                }))
                self.noise.finish_init()
        except Exception as exc:
            self.log.error("noise handshake failed: %s", exc)
            self.disconnect("noise handshake failed")
            return False

        self.connected = True
        self._start_keepalive()
        return True

    def disconnect(self, reason: str = "closed") -> None:
        self._stop.set()
        self.connected = False
        self.is_open = False
        self.last_disconnect_reason = reason
        if self.ws:
            try:
                self.ws.close()
            except Exception:  # pragma: no cover
                pass
        self.emit("connection", "close", reason)

    # ---------------------------------------------------------------- sending
    def send_raw(self, data: bytes) -> None:
        if not self.ws or not self.noise:
            raise WebSocketError("client is not connected")
        self.ws.send(self.noise.encode_frame(data))

    def send_node(self, node: binary.Node) -> None:
        self.log.trace("send %r", node)
        self.send_raw(binary.encode(node))

    def next_tag(self) -> str:
        tag = f"{self._uq_tag_id}{self._epoch}"
        self._epoch += 1
        return tag

    def query(self, node: binary.Node, timeout: Optional[float] = None):
        """Send an ``<iq>`` node and wait for its matching result."""
        if not node.attrs.get("id"):
            node.attrs["id"] = self.next_tag()
        msg_id = node.attrs["id"]
        entry = {"event": threading.Event(), "result": None}
        with self._query_lock:
            self._queries[msg_id] = entry
        try:
            self.send_node(node)
        except WebSocketError:
            with self._query_lock:
                self._queries.pop(msg_id, None)
            raise
        if entry["event"].wait(timeout or self.query_timeout):
            result = entry["result"]
            if result is not None and result.attrs.get("type") == "error":
                raise RuntimeError(f"query failed: {result.attrs}")
            return result
        with self._query_lock:
            self._queries.pop(msg_id, None)
        raise TimeoutError(f"query {node.tag} timed out")

    # ------------------------------------------------------------------ recv
    def _on_ws_message(self, payload: bytes) -> None:
        self._last_recv = time.time()
        if not self.noise:
            return
        with self._handshake_lock:
            try:
                self.noise.decode_frame(payload, self._on_frame)
            except Exception as exc:
                self.log.debug("frame decode failed: %s", exc)
                if self.is_open and not self._handshake_event.is_set():
                    self._handshake_event.set()

    def _on_frame(self, frame) -> None:
        if isinstance(frame, (bytes, bytearray)):
            # still handshaking: this is the server hello
            try:
                self._handshake_message = pb.decode("HandshakeMessage", bytes(frame))
            except Exception as exc:
                self.log.debug("handshake decode failed: %s", exc)
            self._handshake_event.set()
            return
        try:
            self._on_node(frame)
        except Exception as exc:
            self.log.error("node handling failed: %s", exc)

    def _on_ws_close(self, code, reason) -> None:
        self.is_open = False
        self.connected = False
        if not self._handshake_event.is_set():
            self._handshake_event.set()
        self.log.info("connection closed (%s %s)", code, reason)
        self.emit("connection", "close", reason or f"code {code}")

    def _on_ws_error(self, exc: Exception) -> None:
        self.log.debug("websocket error: %s", exc)

    # ------------------------------------------------------------- node router
    def _on_node(self, node: binary.Node) -> None:
        self.log.trace("recv %r", node)
        tag = node.tag
        attrs = node.attrs

        if attrs.get("t"):
            try:
                self.server_time_offset = float(attrs["t"]) - time.time()
            except ValueError:
                pass

        if tag == "iq" and attrs.get("type") in ("result", "error") and attrs.get("id"):
            with self._query_lock:
                entry = self._queries.pop(attrs["id"], None)
            if entry:
                entry["result"] = node
                entry["event"].set()
            if attrs.get("type") == "set":
                self._send_ack(node)
            return

        if tag == "iq":
            if attrs.get("type") == "set":
                self._handle_iq_set(node)
            return

        if tag == "message":
            self._handle_message_node(node)
            return

        if tag == "notification":
            self._handle_notification(node)
            return

        if tag == "receipt":
            self.emit("receipt", node)
            return

        if tag in ("presence", "chatstate", "call", "ack"):
            self.emit(tag, node)
            return

        if tag == "success":
            self._handle_success(node)
            return

        if tag == "failure":
            reason = attrs.get("reason", "?")
            self.log.error("stream failure: reason=%s", reason)
            self.emit("stream_error", int(reason) if str(reason).isdigit() else 500)
            self.disconnect("failure")
            return

        if tag == "stream:error":
            self.log.error("stream error: %s", node)
            self.emit("stream_error", 500)
            self.disconnect("stream:error")
            return

        if tag == "xmlstreamend":
            self.disconnect("server closed the stream")
            return

        if tag == "ib":
            self._handle_ib(node)
            return

        self.log.debug("unhandled node tag=%s", tag)

    def _send_ack(self, node: binary.Node) -> None:
        attrs = {
            "id": node.attrs.get("id"),
            "to": node.attrs.get("from"),
            "class": node.tag,
        }
        if node.attrs.get("participant"):
            attrs["participant"] = node.attrs["participant"]
        if node.attrs.get("recipient"):
            attrs["recipient"] = node.attrs["recipient"]
        if node.attrs.get("type"):
            attrs["type"] = node.attrs["type"]
        if node.tag == "message" and self.me_id:
            attrs["from"] = self.me_id
        try:
            self.send_node(binary.Node("ack", attrs))
        except WebSocketError:
            pass

    def _handle_iq_set(self, node: binary.Node) -> None:
        child = node.content[0] if isinstance(node.content, list) and node.content else None
        tag = child.tag if child is not None else None
        if tag == "pair-device":
            self._handle_pair_device(node, child)
            return
        if tag == "pair-success" or (child is not None and get_child(child, "device-identity") is not None):
            self._handle_pair_success(node, child)
            return
        if self.store.is_registered():
            self._send_ack(node)

    # ------------------------------------------------------------- registration
    def _client_payload(self) -> dict:
        user_agent = {
            "appVersion": {"primary": self.version[0], "secondary": self.version[1],
                           "tertiary": self.version[2]},
            "platform": 0 if "android" in self.browser[1].lower() else 14,  # ANDROID / WEB
            "releaseChannel": 0,  # RELEASE
            "osVersion": "0.1",
            "device": "Desktop",
            "osBuildNumber": "0.1",
            "localeLanguageIso6391": "en",
            "mnc": "000",
            "mcc": "000",
            "localeCountryIso31661Alpha2": self.country_code,
        }
        payload = {
            "connectType": 1,  # WIFI_UNKNOWN
            "connectReason": 1,  # USER_ACTIVATED
            "userAgent": user_agent,
        }
        if "android" not in self.browser[1].lower():
            payload["webInfo"] = {"webSubPlatform": 0}
        if self.push_name:
            payload["pushName"] = self.push_name
        return payload

    def _login_payload(self) -> dict:
        if not self.store.is_registered():
            return self._registration_payload()
        decoded = binary.jid_decode(self.me_id)
        user, _server, device, _domain = decoded
        payload = self._client_payload()
        payload.update({
            "passive": True,
            "pull": True,
            "username": int(user),
            "device": device or 0,
            "lidDbMigrated": False,
        })
        self.log.info("logging in as %s", self.me_id)
        return payload

    def _registration_payload(self) -> dict:
        creds = self.store.creds
        signed_pre_key = creds["signedPreKey"]
        companion = {
            "os": self.browser[0],
            "platformType": self._platform_type(),
            "requireFullSync": self.sync_full_history,
            "historySyncConfig": {
                "storageQuotaMb": 10240,
                "inlineInitialPayloadInE2EeMsg": True,
                "supportBotUserAgentChatHistory": True,
                "supportCagReactionsAndPolls": True,
                "supportBizHostedMsg": True,
                "supportRecentSyncChunkMessageCountTuning": True,
                "supportHostedGroupMsg": True,
                "supportFbidBotChatHistory": True,
                "supportMessageAssociation": True,
            },
            "version": {"primary": 10, "secondary": 15, "tertiary": 7},
        }
        payload = self._client_payload()
        payload.update({
            "passive": False,
            "pull": False,
            "devicePairingData": {
                "buildHash": md5(".".join(str(part) for part in self.version).encode()),
                "deviceProps": pb.encode("DeviceProps", companion),
                "eRegid": encode_big_endian(creds["registrationId"], 4),
                "eKeytype": KEY_BUNDLE_TYPE,
                "eIdent": creds["signedIdentityKey"]["public"],
                "eSkeyId": encode_big_endian(signed_pre_key["keyId"], 3),
                "eSkeyVal": signed_pre_key["keyPair"]["public"],
                "eSkeySig": signed_pre_key["signature"],
            },
        })
        self.log.info("registering as a new companion device")
        return payload

    def _platform_type(self) -> int:
        platform = self.browser[1].upper()
        if platform == "ANDROID":
            return 16
        try:
            return {"CHROME": 1, "FIREFOX": 2, "IE": 3, "OPERA": 5, "SAFARI": 6,
                    "EDGE": 8}.get(platform, 1)
        except Exception:  # pragma: no cover
            return 1

    # ------------------------------------------------------------------- QR
    def _handle_pair_device(self, stanza: binary.Node, pair_device: binary.Node) -> None:
        self.send_node(binary.Node("iq", {"to": S_WHATSAPP_NET, "type": "result",
                                          "id": stanza.attrs.get("id")}))
        refs = [r.text() for r in get_children(pair_device, "ref")]
        noise_b64 = b64(self.store.creds["noiseKey"]["public"])
        identity_b64 = b64(self.store.creds["signedIdentityKey"]["public"])
        adv_b64 = self.store.creds["advSecretKey"]
        if self._qr_count == 0 and self.log_qr:
            self.log.info("scan the QR code shown by the bot to link this device")
        for ref in refs:
            if self._stop.is_set() or self.store.is_registered():
                return
            qr = ("https://wa.me/settings/linked_devices#" +
                  ",".join([ref, noise_b64, identity_b64, adv_b64, str(self._companion_platform_id())]))
            self._qr_count += 1
            self.emit("qr", qr)
            # a QR ref stays valid for 60s, then 20s for the following ones
            delay = 60 if self._qr_count == 1 else 20
            if self._stop.wait(delay):
                return

    def _companion_platform_id(self) -> int:
        browser = self.browser[1]
        if browser == "Desktop":
            return 8 if self.browser[0] == "Windows" else 7
        return {"Chrome": 1, "Edge": 2, "Firefox": 3, "IE": 4, "Opera": 5,
                "Safari": 6}.get(browser, 9)

    def request_pairing_code(self, phone_number: str, custom_code: Optional[str] = None) -> str:
        """Ask WhatsApp for an 8 character pairing code for ``phone_number``."""
        code = custom_code or bytes_to_crockford(os.urandom(5))
        if custom_code and len(custom_code) != 8:
            raise ValueError("a custom pairing code must be exactly 8 characters")
        phone_number = "".join(ch for ch in str(phone_number) if ch.isdigit())
        self.store.creds["pairingCode"] = code
        self.store.creds["me"] = {"id": binary.jid_encode(phone_number, S_WHATSAPP_NET), "name": "~"}
        self.store.touch()

        salt = os.urandom(32)
        iv = os.urandom(16)
        key = pbkdf2_sha256(code.encode(), salt, 131072, 32)
        ephemeral_public = self.store.creds["pairingEphemeralKeyPair"]["public"]
        wrapped = ctr_crypt(key, iv, ephemeral_public)

        node = binary.Node("iq", {"to": S_WHATSAPP_NET, "type": "set", "xmlns": "md",
                                  "id": self.next_tag()}, [
            binary.Node("link_code_companion_reg", {
                "jid": self.store.creds["me"]["id"],
                "stage": "companion_hello",
                "should_show_push_notification": "true",
            }, [
                binary.Node("link_code_pairing_wrapped_companion_ephemeral_pub", {}, salt + iv + wrapped),
                binary.Node("companion_server_auth_key_pub", {}, self.store.creds["noiseKey"]["public"]),
                binary.Node("companion_platform_id", {}, str(self._companion_platform_id())),
                binary.Node("companion_platform_display", {},
                            f"{self.browser[1]} ({self.browser[0]})"),
                binary.Node("link_code_pairing_nonce", {}, "0"),
            ]),
        ])
        self.send_node(node)
        self.log.info("pairing code: %s", code)
        return code

    def _handle_pair_success(self, stanza: binary.Node, pair_success: binary.Node) -> None:
        device_identity_node = get_child(pair_success, "device-identity")
        device_node = get_child(pair_success, "device")
        platform_node = get_child(pair_success, "platform")
        business_node = get_child(pair_success, "biz")
        if device_identity_node is None or device_node is None:
            self.log.error("pair-success without device identity")
            self.disconnect("bad pair-success")
            return

        payload = device_identity_node.buffer()
        parsed = pb.decode("ADVSignedDeviceIdentityHMAC", bytes(payload))
        details = parsed.get("details")
        hmac = parsed.get("hmac")
        account_type = parsed.get("accountType")
        # WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX / WA_ADV_ACCOUNT_SIG_PREFIX
        hmac_prefix = HOSTED_SIG_PREFIX if account_type == 1 else b""
        expected = hmac_sha256(unb64(self.store.creds["advSecretKey"]), hmac_prefix + details)
        if expected != hmac:
            self.log.error("invalid account signature on pair-success")
            self.disconnect("bad pair-success hmac")
            return

        account = pb.decode("ADVSignedDeviceIdentity", details)
        device_details = account.get("details")
        signature_key = account.get("accountSignatureKey")
        identity_public = self.store.creds["signedIdentityKey"]["public"]
        device_identity = pb.decode("ADVDeviceIdentity", device_details)

        # WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX when the account is hosted, else WA_ADV_ACCOUNT_SIG_PREFIX
        account_prefix = HOSTED_SIG_PREFIX if device_identity.get("deviceType") == 1 else ACCOUNT_SIG_PREFIX
        account_msg = account_prefix + device_details + identity_public
        if not curve.xeddsa_verify(signature_key, account_msg, account["accountSignature"]):
            self.log.error("failed to verify the account signature")
            self.disconnect("bad account signature")
            return

        # WA_ADV_DEVICE_SIG_PREFIX + deviceDetails + identityKey + accountSignatureKey
        device_msg = DEVICE_SIG_PREFIX + device_details + identity_public + signature_key
        account["deviceSignature"] = curve.xeddsa_sign(self.store.creds["signedIdentityKey"]["private"],
                                                       device_msg)

        # `encodeSignedDeviceIdentity(account, false)` — the reply omits the account signature key
        reply_account = dict(account)
        reply_account["accountSignatureKey"] = None
        encoded = pb.encode("ADVSignedDeviceIdentity", reply_account)

        reply = binary.Node("iq", {"to": S_WHATSAPP_NET, "type": "result",
                                   "id": stanza.attrs.get("id")}, [
            binary.Node("pair-device-sign", {}, [
                binary.Node("device-identity",
                            {"key-index": str(device_identity.get("keyIndex") or 0)}, encoded),
            ]),
        ])

        jid = device_node.attrs.get("jid")
        lid = device_node.attrs.get("lid")
        biz_name = business_node.attrs.get("name") if business_node is not None else None
        self.store.creds["account"] = account
        self.store.creds["me"] = {"id": jid, "lid": lid, "name": biz_name}
        self.store.creds["platform"] = platform_node.attrs.get("name") if platform_node is not None else None
        identities = list(self.store.creds.get("signalIdentities") or [])
        identities.append({"identifier": {"name": lid, "deviceId": 0},
                           "identifierKey": sig.prefixed(signature_key)})
        self.store.creds["signalIdentities"] = identities
        self.store.save(force=True)
        self.emit("creds", self.store.creds)
        self.log.info("paired successfully as %s — the server will restart the connection", jid)
        self.send_node(reply)

    # ------------------------------------------------------------ login done
    def _handle_success(self, node: binary.Node) -> None:
        lid = node.attrs.get("lid")
        if lid and self.store.me:
            self.store.creds["me"]["lid"] = lid
            self.store.touch()
        self.log.info("connection opened as %s", self.store.me_id)
        self.emit("open", node)
        self.emit("connection", "open")

        # the phone's pre-keys are uploaded in the background so a slow server
        # never blocks message handling
        def post_login():
            try:
                self._upload_pre_keys_if_required()
            except Exception as exc:
                self.log.warn("pre-key upload failed: %s", exc)
            try:
                self.send_node(binary.Node("iq", {"to": S_WHATSAPP_NET, "type": "set", "xmlns": "passive",
                                                  "id": self.next_tag()},
                                           [binary.Node("active", {})]))
            except WebSocketError:
                pass

        threading.Thread(target=post_login, name="wa-post-login", daemon=True).start()

    # --------------------------------------------------------------- keep alive
    def _start_keepalive(self) -> None:
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            return

        def loop():
            while not self._stop.wait(self.keep_alive):
                if not self.is_open:
                    return
                try:
                    self.send_node(binary.Node("iq", {
                        "to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:p",
                        "id": self.next_tag(),
                    }, [binary.Node("ping", {})]))
                except WebSocketError:
                    return

        self._keepalive_thread = threading.Thread(target=loop, name="wa-keepalive", daemon=True)
        self._keepalive_thread.start()

    @property
    def is_alive(self) -> bool:
        return self.is_open and (time.time() - self._last_recv) < self.keep_alive * 3

    # ------------------------------------------------------------------ prekeys
    def _upload_pre_keys_if_required(self) -> None:
        result = self.query(binary.Node("iq", {
            "to": S_WHATSAPP_NET, "type": "get", "xmlns": "encrypt",
        }, [binary.Node("count", {})]))
        count_node = get_child(result, "count") if result is not None else None
        available = int(count_node.attrs.get("value", 0)) if count_node is not None else 0
        count = INITIAL_PREKEY_COUNT if available == 0 else MIN_PREKEY_COUNT
        self.upload_pre_keys(count)

    def upload_pre_keys(self, count: int = MIN_PREKEY_COUNT) -> None:
        count = max(1, min(count, MAX_PREKEY_UPLOAD))
        creds = self.store.creds
        created = self.store.generate_pre_keys(count)
        nodes = []
        for key_id, pair in created.items():
            nodes.append(binary.Node("key", {}, [
                binary.Node("id", {}, encode_big_endian(key_id, 3)),
                binary.Node("value", {}, pair["public"]),
            ]))
        signed = creds["signedPreKey"]
        nodes.append(binary.Node("skey", {}, [
            binary.Node("id", {}, encode_big_endian(signed["keyId"], 3)),
            binary.Node("value", {}, signed["keyPair"]["public"]),
            binary.Node("signature", {}, signed["signature"]),
        ]))
        iq = binary.Node("iq", {"xmlns": "encrypt", "type": "set", "to": S_WHATSAPP_NET}, [
            binary.Node("registration", {}, encode_big_endian(creds["registrationId"], 4)),
            binary.Node("type", {}, KEY_BUNDLE_TYPE),
            binary.Node("identity", {}, creds["signedIdentityKey"]["public"]),
            binary.Node("list", {}, nodes),
        ])
        self.query(iq)
        self.store.creds["firstUnuploadedPreKeyId"] = max(created.keys()) + 1
        self.store.save()
        self.log.debug("uploaded %d pre-keys", len(created))

    # ------------------------------------------------------------------ usync
    def get_devices(self, jids: List[str], use_cache: bool = True,
                    exclude_zero_devices: bool = False) -> List[dict]:
        """Resolve every device of the given users through USync."""
        results: List[dict] = []
        pending: List[str] = []
        seen_users = set()
        for jid in jids:
            decoded = binary.jid_decode(jid)
            if not decoded:
                continue
            user, server, device, domain = decoded
            if device:
                results.append({"user": user, "device": device, "jid": jid, "server": server})
                continue
            normalized = f"{user}@{server}"
            if normalized in seen_users:
                continue
            seen_users.add(normalized)
            if use_cache and self.use_device_cache:
                cached = self.store.cached_devices(normalized)
                if cached is not None:
                    for item in cached:
                        results.append({"user": user, "device": item["device"],
                                        "jid": item["jid"], "server": item.get("server", server)})
                    continue
            pending.append(normalized)

        if pending:
            user_nodes = [binary.Node("user", {"jid": jid}) for jid in pending]
            iq = binary.Node("iq", {"to": S_WHATSAPP_NET, "type": "get", "xmlns": "usync"}, [
                binary.Node("usync", {"context": "interactive", "mode": "query", "sid": self.next_tag(),
                                      "last": "true", "index": "0"}, [
                    binary.Node("query", {}, [binary.Node("devices", {"version": "2"})]),
                    binary.Node("list", {}, user_nodes),
                ]),
            ])
            result = self.query(iq)
            list_node = get_child(get_child(result, "usync"), "list")
            for user_node in get_children(list_node, "user"):
                jid = user_node.attrs.get("jid") or ""
                decoded = binary.jid_decode(jid)
                if not decoded:
                    continue
                user, server, _device, domain = decoded
                devices_node = get_child(user_node, "devices")
                device_list = get_child(devices_node, "device-list")
                entries = []
                for device in get_children(device_list, "device"):
                    device_id = int(device.attrs.get("id", 0))
                    entries.append({"device": device_id,
                                    "jid": binary.jid_encode(user, server, device_id),
                                    "server": server})
                if not entries:
                    entries = [{"device": 0, "jid": binary.jid_encode(user, server, 0),
                                "server": server}]
                self.store.set_devices(f"{user}@{server}", entries)
                for entry in entries:
                    if exclude_zero_devices and entry["device"] == 0:
                        continue
                    results.append({"user": user, "device": entry["device"],
                                    "jid": entry["jid"], "server": server})
        return results

    # --------------------------------------------------------------- sessions
    def _new_session(self) -> dict:
        return sig.new_session_state(self.store.registration_id(),
                                     self.store.identity_key_pair()["public"])

    def assert_sessions(self, jids: List[str], force: bool = False) -> bool:
        missing: List[str] = []
        for jid in dict.fromkeys(jids):
            state = self.store.session(jid)
            if not force and sig.has_session(state):
                continue
            missing.append(jid)
        if not missing:
            return False
        self.log.debug("fetching pre-key bundles for %s", ", ".join(missing))
        iq = binary.Node("iq", {"to": S_WHATSAPP_NET, "type": "get", "xmlns": "encrypt"}, [
            binary.Node("key", {}, [
                binary.Node("user", {"jid": jid, **({"reason": "identity"} if force else {})})
                for jid in missing
            ]),
        ])
        result = self.query(iq)
        list_node = get_child(result, "list")
        for user_node in get_children(list_node, "user"):
            jid = user_node.attrs.get("jid")
            if not jid:
                continue
            try:
                bundle = self._parse_bundle(user_node)
            except (KeyError, TypeError, ValueError) as exc:
                self.log.warn("could not parse pre-key bundle for %s: %s", jid, exc)
                continue
            state = self.store.session(jid) or self._new_session()
            try:
                sig.process_prekey_bundle(state, bundle, self.store.identity_key_pair(),
                                          self.store.registration_id())
                self.store.set_session(jid, state)
            except ValueError as exc:
                self.log.warn("invalid pre-key bundle for %s: %s", jid, exc)
        return True

    @staticmethod
    def _parse_bundle(user_node: binary.Node) -> dict:
        registration = child_bytes(user_node, "registration")
        identity = child_bytes(user_node, "identity")
        skey = get_child(user_node, "skey")
        key = get_child(user_node, "key")
        if not identity or skey is None:
            raise ValueError("bundle without identity/skey")
        bundle = {
            "registrationId": int.from_bytes(registration[:4], "big") if registration else 0,
            "identityKey": unprefix_key(identity),
            "signedPreKey": {
                "keyId": int.from_bytes(child_bytes(skey, "id") or b"\x00\x00\x00", "big"),
                "public": unprefix_key(child_bytes(skey, "value")),
                "signature": child_bytes(skey, "signature"),
            },
            "oneTimePreKey": None,
        }
        if key is not None:
            bundle["oneTimePreKey"] = {
                "keyId": int.from_bytes(child_bytes(key, "id") or b"\x00\x00\x00", "big"),
                "public": unprefix_key(child_bytes(key, "value")),
            }
        return bundle

    def _encrypt_for(self, jid: str, data: bytes):
        state = self.store.session(jid)
        if state is None or not sig.has_session(state):
            state = self._new_session()
            self.assert_sessions([jid], force=True)
            state = self.store.session(jid) or state
            if not sig.has_session(state):
                raise RuntimeError(f"no signal session with {jid}")
        kind, ciphertext = sig.session_encrypt(state, data)
        self.store.set_session(jid, state)
        return kind, ciphertext

    def _decrypt_from(self, jid: str, kind: str, ciphertext: bytes) -> bytes:
        identity = self.store.identity_key_pair()
        state = self.store.session(jid)
        if kind == "pkmsg":
            if state is None:
                state = self._new_session()
            message = sig.decode_prekey_signal_message(ciphertext)
            pre_key = self.store.take_pre_key(message.get("preKeyId"))
            signed_pre_key = self.store.creds["signedPreKey"]
            plaintext, used = sig.decrypt_prekey_message(
                state, ciphertext, identity, self.store.registration_id(), signed_pre_key, pre_key)
            self.store.set_session(jid, state)
            if used:
                self.store.remove_pre_key(used)
            return plaintext
        if state is None or not sig.has_session(state):
            raise ValueError(MISSING_KEYS)
        plaintext = sig.session_decrypt(state, ciphertext)
        self.store.set_session(jid, state)
        return plaintext

    # -------------------------------------------------------------- encryption
    def encrypt_message(self, jid: str, message: dict) -> bytes:
        return write_random_pad_max16(pb.encode("Message", message))

    def _create_participant_nodes(self, recipients: List[str], message: dict,
                                  dsm_message: Optional[dict] = None,
                                  extra_attrs: Optional[dict] = None) -> List[binary.Node]:
        self.assert_sessions(recipients)
        nodes = []
        for jid in recipients:
            payload = message
            if dsm_message:
                decoded = binary.jid_decode(jid) or ("", "", None, 0)
                own = binary.jid_decode(self.me_id) or ("", "", None, 0)
                own_lid = binary.jid_decode(self.me_lid or "") or ("", "", None, 0)
                is_own_user = decoded[0] in (own[0], own_lid[0])
                is_exact_device = jid == self.me_id or (self.me_lid and jid == self.me_lid)
                if is_own_user and not is_exact_device:
                    payload = dsm_message
            data = self.encrypt_message(jid, payload)
            kind, ciphertext = self._encrypt_for(jid, data)
            attrs = {"v": "2", "type": kind}
            if extra_attrs:
                attrs.update(extra_attrs)
            nodes.append(binary.Node("to", {"jid": jid}, [
                binary.Node("enc", attrs, ciphertext),
            ]))
        return nodes

    # ------------------------------------------------------------------ groups
    def group_metadata(self, jid: str) -> dict:
        result = self.query(binary.Node("iq", {"type": "get", "xmlns": "w:g2", "to": jid}, [
            binary.Node("query", {"request": "interactive"}),
        ]))
        group = get_child(result, "group")
        if group is None:
            raise RuntimeError("group metadata query failed")
        member_nodes = [node for node in get_children(group, "participant") if node.attrs.get("jid")]
        return {
            "id": group.attrs.get("id"),
            "subject": group.attrs.get("subject"),
            "addressing_mode": group.attrs.get("addressing_mode") or "pn",
            "participants": [{"id": node.attrs.get("jid"), "admin": node.attrs.get("type")}
                             for node in member_nodes],
        }

    # -------------------------------------------------------------------- send
    def send_message(self, jid: str, message: dict, message_id: Optional[str] = None,
                     additional_attributes: Optional[dict] = None,
                     stanza_attributes: Optional[dict] = None) -> str:
        """Send a ``Message`` protobuf to ``jid`` (user or group).

        ``additional_attributes`` end up on the ``<enc>`` nodes (eg. ``mediatype``),
        ``stanza_attributes`` on the ``<message>`` stanza itself (eg. ``addressing_mode``).
        """
        decoded = binary.jid_decode(jid)
        if not decoded:
            raise ValueError(f"invalid jid: {jid}")
        user, server, _device, _domain = decoded
        is_group = server == "g.us"
        enc_attrs = dict(additional_attributes or {})
        stanza_attrs = dict(stanza_attributes or {})
        msg_id = message_id or generate_message_id_v2(self.me_id)
        content: List[binary.Node] = []
        participants: List[binary.Node] = []

        if is_group:
            metadata = self.group_metadata(jid)
            addressing_mode = (stanza_attrs.get("addressing_mode")
                               or metadata.get("addressing_mode") or "pn")
            stanza_attrs["addressing_mode"] = addressing_mode
            participant_jids = [p["id"] for p in metadata.get("participants", []) if p.get("id")]
            devices = self.get_devices(participant_jids, self.use_device_cache, False)
            me_recipients = {self.me_id, self.me_lid}
            recipients = []
            for device in devices:
                device_jid = device["jid"]
                if device_jid in me_recipients or device["device"] == 99 or is_hosted_jid(device_jid):
                    continue
                recipients.append(device_jid)

            state = self.store.sender_key(jid)
            if state is None:
                state = sig.new_sender_key_state()
            data = self.encrypt_message(jid, message)
            ciphertext = sig.group_encrypt(state, data)
            self.store.set_sender_key(jid, state)
            skdm = sig.build_skdm(state)

            memory = self.store.creds.setdefault("sender_key_memory", {})
            sent_to = memory.setdefault(jid, {})
            skdm_recipients = [recipient for recipient in recipients if recipient not in sent_to]
            if skdm_recipients:
                skdm_message = {
                    "senderKeyDistributionMessage": {
                        "groupId": jid,
                        "axolotlSenderKeyDistributionMessage": skdm,
                    },
                }
                participants = self._create_participant_nodes(skdm_recipients, skdm_message,
                                                              extra_attrs=enc_attrs)
                for recipient in skdm_recipients:
                    sent_to[recipient] = True
                self.store.touch()
            content.append(binary.Node("enc", {"v": "2", "type": "skmsg", **enc_attrs}, ciphertext))
        else:
            # enumerate both the recipient's and our own devices (the phone
            # still has to receive a copy through the device-sent wrapper).
            # Devices are looked up per *user*, so the device part is stripped.
            own = binary.jid_decode(self.me_id) or ("", "", None, 0)
            own_lid = binary.jid_decode(self.me_lid or "") or ("", "", None, 0)
            if server == "lid" and self.me_lid:
                own_user_jid = binary.jid_encode(own_lid[0], "lid")
            else:
                own_user_jid = binary.jid_encode(own[0], "s.whatsapp.net")
            devices = self.get_devices([binary.jid_encode(user, server), own_user_jid],
                                       self.use_device_cache, False)
            me_recipients: List[str] = []
            other_recipients: List[str] = []
            for device in devices:
                device_jid = device["jid"]
                if device_jid == self.me_id or (self.me_lid and device_jid == self.me_lid):
                    continue  # never encrypt to this very device
                if device["user"] in (own[0], own_lid[0]):
                    me_recipients.append(device_jid)
                else:
                    other_recipients.append(device_jid)
            if not other_recipients:
                other_recipients.append(binary.jid_encode(user, server, 0))
            dsm_message = {
                "deviceSentMessage": {"destinationJid": jid, "message": message},
            }
            all_recipients = me_recipients + other_recipients
            participants = self._create_participant_nodes(all_recipients, message,
                                                          dsm_message=dsm_message,
                                                          extra_attrs=enc_attrs)
            if all_recipients:
                stanza_attrs["phash"] = generate_participant_hash(all_recipients)

        if participants:
            content.append(binary.Node("participants", {}, participants))

        stanza = binary.Node("message", {
            "id": msg_id, "to": jid, "type": "text", **stanza_attrs,
        }, content)
        self.send_node(stanza)
        self.log.debug("sent message %s to %s", msg_id, jid)
        self.emit("message_sent", msg_id, jid)
        return msg_id

    def send_text(self, jid: str, text: str, message_id: Optional[str] = None, **kwargs) -> str:
        return self.send_message(jid, {"conversation": text}, message_id=message_id, **kwargs)

    def reply_text(self, chat_jid: str, quoted: dict, text: str, **kwargs) -> str:
        """Reply to a message (``quoted`` is a decrypted message dict)."""
        stanza_id = quoted["key"]["id"]
        participant = quoted["key"].get("participant") or quoted["key"]["remoteJid"]
        context = {
            "stanzaId": stanza_id,
            "participant": participant,
            "quotedMessage": quoted.get("message") or {},
        }
        message = {
            "extendedTextMessage": {"text": text, "contextInfo": context},
        }
        return self.send_message(chat_jid, message, **kwargs)

    # ------------------------------------------------------------------ receive
    def _handle_notification(self, node: binary.Node) -> None:
        child = node.content[0] if isinstance(node.content, list) and node.content else None
        if child is not None and child.tag in ("encrypt", "server_sync", "devices", "w:gp2"):
            pass
        self.emit("notification", node)
        self._send_ack(node)

    def _handle_ib(self, node: binary.Node) -> None:
        edge_routing = get_child(node, "edge_routing")
        routing_info = get_child(edge_routing, "routing_info") if edge_routing is not None else None
        if routing_info is not None and routing_info.buffer():
            self.store.creds["routingInfo"] = b64(routing_info.buffer())
            self.store.save()
            self.log.debug("stored edge routing info")
        self.emit("ib", node)

    # message decoding ------------------------------------------------------
    def decode_message_node(self, stanza: binary.Node) -> dict:
        attrs = stanza.attrs
        msg_id = attrs.get("id")
        sender = attrs.get("from")
        participant = attrs.get("participant")
        recipient = attrs.get("recipient")
        decoded_from = binary.jid_decode(sender) or ("", "", None, 0)
        is_group = (decoded_from[1] == "g.us")
        me = binary.jid_decode(self.me_id) or ("", "", None, 0)
        me_lid = binary.jid_decode(self.me_lid or "") or ("", "", None, 0)
        from_me = decoded_from[1] in ("s.whatsapp.net", "lid") and decoded_from[0] in (me[0], me_lid[0])
        if recipient and not is_group:
            chat_jid = recipient
        else:
            chat_jid = sender
        author = participant if is_group else sender
        key = {
            "remoteJid": chat_jid,
            "fromMe": from_me,
            "id": msg_id,
            "participant": participant,
        }
        return {
            "key": key,
            "author": author,
            "sender": sender if not is_group else chat_jid,
            "isGroup": is_group,
            "messageTimestamp": int(attrs.get("t") or time.time()),
            "pushName": attrs.get("notify"),
            "addressing_mode": attrs.get("addressing_mode"),
        }

    def _handle_message_node(self, stanza: binary.Node) -> None:
        info = self.decode_message_node(stanza)
        try:
            message = self.decrypt_message_node(stanza, info)
        except Exception as exc:
            self.log.debug("decryption failed for %s: %s", info["key"].get("id"), exc)
            message = None
            self._request_retry(stanza, info)
        self._send_ack(stanza)
        if message is None:
            self.emit("decrypt_failed", info)
            return
        info["message"] = message
        if not info["key"]["fromMe"]:
            chat = info["key"]["remoteJid"]
            participant = info["key"].get("participant")
            self.send_receipt(chat, participant, [info["key"]["id"]])
        self.incoming.put(info)
        self.emit("message", info)

    def decrypt_message_node(self, stanza: binary.Node, info: dict) -> Optional[dict]:
        author = info["author"]
        content = stanza.content if isinstance(stanza.content, list) else []
        decrypted = None
        for child in content:
            if child.tag not in ("enc", "plaintext"):
                continue
            raw = child.buffer()
            if raw is None:
                continue
            kind = child.attrs.get("type")
            if child.tag == "plaintext":
                decrypted = bytes(raw)
                break
            if kind == "skmsg":
                group = info["sender"] if info["isGroup"] else info["key"]["remoteJid"]
                state = self.store.sender_key(f"{group}|{author}")
                if state is None:
                    raise ValueError("no sender key for group message")
                decrypted = sig.group_decrypt(state, bytes(raw))
                self.store.set_sender_key(f"{group}|{author}", state)
                break
            if kind in ("msg", "pkmsg"):
                decrypted = self._decrypt_from(author, kind, bytes(raw))
                break
        if decrypted is None:
            return None

        plaintext = unpad_random_max16(decrypted)
        message = pb.decode("Message", plaintext)
        skdm = message.get("senderKeyDistributionMessage")
        if skdm and skdm.get("axolotlSenderKeyDistributionMessage"):
            group = skdm.get("groupId") or info["key"]["remoteJid"]
            state = self.store.sender_key(f"{group}|{author}") or sig.new_sender_key_state()
            sig.process_skdm(state, bytes(skdm["axolotlSenderKeyDistributionMessage"]))
            self.store.set_sender_key(f"{group}|{author}", state)
        dsm = message.get("deviceSentMessage")
        if dsm and dsm.get("message"):
            inner = dsm["message"]
            if dsm.get("destinationJid"):
                info["key"]["remoteJid"] = dsm["destinationJid"]
            return inner
        return message

    def _request_retry(self, stanza: binary.Node, info: dict) -> None:
        attrs = {
            "id": stanza.attrs.get("id"),
            "to": stanza.attrs.get("from"),
            "type": "retry",
        }
        if stanza.attrs.get("participant"):
            attrs["participant"] = stanza.attrs["participant"]
        if stanza.attrs.get("recipient"):
            attrs["recipient"] = stanza.attrs["recipient"]
        content = [
            binary.Node("retry", {
                "count": "1",
                "id": stanza.attrs.get("id"),
                "t": stanza.attrs.get("t") or str(int(time.time())),
                "v": "1",
                "error": "0",
            }),
            binary.Node("registration", {}, encode_big_endian(self.store.registration_id(), 4)),
        ]
        try:
            self.send_node(binary.Node("receipt", attrs, content))
            self.log.debug("requested a retry for %s", stanza.attrs.get("id"))
        except WebSocketError:
            pass

    def send_receipt(self, chat_jid: str, participant: Optional[str], message_ids: List[str],
                     receipt_type: Optional[str] = None) -> None:
        """Tell the sender we received (or read) their messages."""
        if not message_ids:
            return
        node = binary.Node("receipt", {"id": message_ids[0]})
        if receipt_type in ("read", "read-self"):
            node.attrs["t"] = str(int(time.time()))
        node.attrs["to"] = chat_jid
        if participant:
            node.attrs["participant"] = participant
        if receipt_type:
            node.attrs["type"] = receipt_type
        if len(message_ids) > 1:
            node.content = [binary.Node("list", {}, [
                binary.Node("item", {"id": extra}) for extra in message_ids[1:]
            ])]
        try:
            self.send_node(node)
        except WebSocketError:
            pass


__all__ = ["WAClient", "Logger", "generate_message_id_v2", "write_random_pad_max16",
           "unpad_random_max16", "bytes_to_crockford", "S_WHATSAPP_NET"]
