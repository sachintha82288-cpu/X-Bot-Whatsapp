"""Session/credential storage for the WhatsApp client.

Everything lives in a single JSON file so the bot stays inside a few megabytes
of RAM on a 1 GB Android phone.  Binary values (curve keys, chain keys, ...)
are base64 encoded on the way to disk; the in-memory structures use ``bytes``
exactly like ``xbot.wa.signal`` expects them.

No third party modules are used: only ``base64``/``json``/``os`` from the
standard library.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time

from .crypto import curve
from .wa import signal as sig

# --------------------------------------------------------------------------
# credential helpers
# --------------------------------------------------------------------------

DEFAULT_VERSION = [2, 3000, 1043857760]


def b64(data) -> str:
    if isinstance(data, str):
        return data
    return base64.b64encode(bytes(data)).decode("ascii")


def unb64(text) -> bytes:
    if isinstance(text, (bytes, bytearray)):
        return bytes(text)
    return base64.b64decode(text or "")


def to_jsonable(value):
    """Recursively turn ``bytes`` into ``{"__b64": "..."}`` markers."""
    if isinstance(value, bytes) or isinstance(value, bytearray):
        return {"__b64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def from_jsonable(value):
    if isinstance(value, dict):
        if set(value.keys()) == {"__b64"}:
            return base64.b64decode(value["__b64"])
        return {key: from_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [from_jsonable(item) for item in value]
    return value


def encode_big_endian(number: int, size: int = 4) -> bytes:
    return int(number).to_bytes(size, "big")


def key_pair_to_dict(pair) -> dict:
    private, public = pair
    return {"private": private, "public": public}


def new_key_pair() -> dict:
    return key_pair_to_dict(curve.generate_key_pair())


def generate_credentials(existing: dict | None = None) -> dict:
    """Create a fresh set of credentials (noise key, identity, signed pre-key)."""
    creds = dict(existing or {})
    creds.setdefault("version", list(DEFAULT_VERSION))
    creds["noiseKey"] = new_key_pair()
    creds["signedIdentityKey"] = new_key_pair()
    creds["registrationId"] = sig.generate_registration_id()
    creds["advSecretKey"] = b64(os.urandom(32))
    creds["pairingEphemeralKeyPair"] = new_key_pair()
    creds["signedPreKey"] = sig.signed_key_pair(creds["signedIdentityKey"], 1)
    creds["nextPreKeyId"] = 1
    creds["firstUnuploadedPreKeyId"] = 1
    creds["account"] = None
    creds["me"] = None
    creds["signalIdentities"] = []
    creds["platform"] = None
    creds["routingInfo"] = None
    creds["pairingCode"] = None
    return creds


class AuthStore:
    """Credentials, signal sessions and sender keys persisted as JSON."""

    def __init__(self, path: str, logger=None, generate: bool = True):
        self.path = path
        self.logger = logger
        self.lock = threading.RLock()
        self.creds: dict = {}
        self.prekeys: dict = {}
        self.sessions: dict = {}
        self.sender_keys: dict = {}
        self.device_list: dict = {}
        self.lid_map: dict = {}
        self._dirty = False
        self._last_save = 0.0
        self.load(generate=generate)

    # ------------------------------------------------------------------ io
    def load(self, generate: bool = True) -> None:
        data = {}
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, ValueError) as exc:  # pragma: no cover - disk errors
                if self.logger:
                    self.logger.warn("could not read session file: %s", exc)
                data = {}
        creds = from_jsonable(data.get("creds") or {})
        if not creds and generate:
            creds = generate_credentials()
        self.creds = creds
        self.prekeys = {int(k): from_jsonable(v) for k, v in (data.get("prekeys") or {}).items()}
        self.sessions = from_jsonable(data.get("sessions") or {})
        self.sender_keys = from_jsonable(data.get("sender_keys") or {})
        self.device_list = data.get("device_list") or {}
        self.lid_map = data.get("lid_map") or {}

    def save(self, force: bool = False) -> None:
        """Write the session file (atomically) if something changed."""
        with self.lock:
            if not force and not self._dirty:
                return
            payload = {
                "creds": to_jsonable(self.creds),
                "prekeys": {str(k): to_jsonable(v) for k, v in self.prekeys.items()},
                "sessions": to_jsonable(self.sessions),
                "sender_keys": to_jsonable(self.sender_keys),
                "device_list": self.device_list,
                "lid_map": self.lid_map,
                "saved_at": int(time.time()),
            }
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            temporary = self.path + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
            os.replace(temporary, self.path)
            self._dirty = False
            self._last_save = time.time()

    def touch(self) -> None:
        self._dirty = True

    # -------------------------------------------------------------- convenience
    @property
    def me(self) -> dict | None:
        return self.creds.get("me")

    @property
    def me_id(self) -> str | None:
        me = self.me or {}
        return me.get("id")

    @property
    def me_lid(self) -> str | None:
        me = self.me or {}
        return me.get("lid")

    def is_registered(self) -> bool:
        return bool(self.me_id)

    def identity_key_pair(self) -> dict:
        return self.creds["signedIdentityKey"]

    def registration_id(self) -> int:
        return int(self.creds.get("registrationId") or 0)

    # ------------------------------------------------------------- pre keys
    def take_pre_key(self, key_id: int):
        return self.prekeys.get(int(key_id)) if key_id else None

    def remove_pre_key(self, key_id: int) -> None:
        if key_id is None:
            return
        if self.prekeys.pop(int(key_id), None) is not None:
            self.touch()

    def generate_pre_keys(self, count: int) -> dict:
        """Return ``{id: keypair}`` for the next ``count`` pre-key ids."""
        created = {}
        next_id = int(self.creds.get("nextPreKeyId") or 1)
        for key_id in range(next_id, next_id + count):
            created[key_id] = new_key_pair()
        self.prekeys.update(created)
        self.creds["nextPreKeyId"] = next_id + count
        self.touch()
        return created

    # -------------------------------------------------------------- sessions
    def session(self, address: str):
        return self.sessions.get(address)

    def set_session(self, address: str, state) -> None:
        if state is None:
            self.sessions.pop(address, None)
        else:
            self.sessions[address] = state
        self.touch()

    def sender_key(self, group: str):
        return self.sender_keys.get(group)

    def set_sender_key(self, group: str, state) -> None:
        self.sender_keys[group] = state
        self.touch()

    def cached_devices(self, user: str, max_age: float = 3600.0):
        entry = self.device_list.get(user)
        if not entry:
            return None
        if time.time() - float(entry.get("ts") or 0) > max_age:
            return None
        return entry.get("devices") or []

    def set_devices(self, user: str, devices) -> None:
        self.device_list[user] = {"ts": int(time.time()), "devices": list(devices)}
        self.touch()

    def store_lid_mapping(self, lid: str, pn: str) -> None:
        if not lid or not pn:
            return
        self.lid_map[pn] = lid
        self.touch()

    def lid_for(self, pn: str):
        return self.lid_map.get(pn)


__all__ = [
    "AuthStore", "generate_credentials", "new_key_pair", "key_pair_to_dict",
    "encode_big_endian", "to_jsonable", "from_jsonable", "b64", "unb64",
    "DEFAULT_VERSION",
]
