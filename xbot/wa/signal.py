"""Signal protocol: X3DH session setup, double ratchet, Sender Keys.

Everything WhatsApp encrypts end-to-end is implemented here from the
protocol description:

* ``pkmsg`` / ``msg`` — pairwise session messages (PreKeySignalMessage and
  SignalMessage, libsignal "whisper" format, version 3)
* ``skmsg`` — group messages with Sender Keys, plus the
  SenderKeyDistributionMessage handed to each participant's device

Session state is kept as plain dictionaries so it can be persisted as JSON
without any serialisation library.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from ..crypto.aes import cbc_decrypt, cbc_encrypt
from ..crypto import curve
from ..crypto.hashes import fast_hmac_sha256 as hmac_sha256
from ..crypto.hashes import fast_sha256 as sha256
from ..crypto.hashes import hkdf_sha256 as hkdf
from . import protobuf as pb

CURRENT_VERSION = 3
VERSION_BYTE = 0x33
MAC_LENGTH = 8
MAX_FUTURE_MESSAGES = 2000
KEY_BUNDLE_TYPE = b"\x05"
ZERO_SALT = b"\x00" * 32
DISCONTINUITY = b"\xFF" * 32


# --------------------------------------------------------------------------
# key helpers
# --------------------------------------------------------------------------


def prefixed(public_key: bytes) -> bytes:
    """Ensure the 0x05 key-bundle type byte is present (Signal convention)."""
    public_key = bytes(public_key)
    if len(public_key) == 33:
        return public_key
    return KEY_BUNDLE_TYPE + public_key


def unprefixed(public_key: bytes) -> bytes:
    return bytes(public_key)[-32:]


def generate_registration_id() -> int:
    return int.from_bytes(os.urandom(2), "big") % 16380 + 1


def key_pair(public: bytes, private: bytes) -> dict:
    return {"public": public, "private": private}


def signed_key_pair(identity_key_pair: dict, key_id: int) -> dict:
    private, public = curve.generate_key_pair()
    signature = curve.xeddsa_sign(identity_key_pair["private"], prefixed(public))
    return {
        "keyId": key_id,
        "keyPair": {"private": private, "public": public},
        "signature": signature,
    }


def verify_signature(identity_public: bytes, message: bytes, signature: bytes) -> bool:
    return curve.xeddsa_verify(prefixed(identity_public), message, signature)


# --------------------------------------------------------------------------
# HKDF helpers (libsignal's three derivation domains)
# --------------------------------------------------------------------------


def derive_whisper_text(master_secret: bytes) -> Tuple[bytes, bytes]:
    derived = hkdf(master_secret, 64, ZERO_SALT, b"WhisperText")
    return derived[:32], derived[32:]


def derive_ratchet_secrets(shared_secret: bytes, root_key: bytes) -> Tuple[bytes, bytes]:
    derived = hkdf(shared_secret, 64, root_key, b"WhisperRatchet")
    return derived[:32], derived[32:]


def derive_message_keys(seed: bytes) -> Dict[str, bytes]:
    material = hkdf(seed, 80, ZERO_SALT, b"WhisperMessageKeys")
    return {
        "cipherKey": material[:32],
        "macKey": material[32:64],
        "iv": material[64:80],
    }


# --------------------------------------------------------------------------
# chains
# --------------------------------------------------------------------------


def message_key_seed(chain_key: bytes) -> bytes:
    return hmac_sha256(chain_key, b"\x01")


def next_chain_key(chain_key: bytes) -> bytes:
    return hmac_sha256(chain_key, b"\x02")


def chain_message_keys(chain_key: bytes, index: int) -> dict:
    keys = derive_message_keys(message_key_seed(chain_key))
    keys["index"] = index
    return keys


def root_create_chain(root_key: bytes, their_ratchet_key: bytes, our_ratchet_private: bytes):
    shared = curve.shared_key(our_ratchet_private, unprefixed(their_ratchet_key))
    new_root, chain = derive_ratchet_secrets(shared, root_key)
    return new_root, chain


# --------------------------------------------------------------------------
# session state
# --------------------------------------------------------------------------


def new_session_state(local_registration_id: int, local_identity: bytes) -> dict:
    return {
        "sessionVersion": CURRENT_VERSION,
        "localRegistrationId": local_registration_id,
        "remoteRegistrationId": None,
        "aliceBaseKey": None,
        "localIdentityPublic": prefixed(local_identity),
        "remoteIdentityKey": None,
        "rootKey": None,
        "senderChain": None,
        "receiverChains": [],
        "previousCounter": 0,
        "unacknowledgedPreKeyMessage": None,
    }


def _find_receiver_chain(state: dict, ratchet_key: bytes) -> Optional[dict]:
    key = unprefixed(ratchet_key)
    for chain in state["receiverChains"]:
        if unprefixed(chain["ratchetKey"]) == key:
            return chain
    return None


def has_session(state: Optional[dict]) -> bool:
    return bool(state and state.get("senderChain"))


# --------------------------------------------------------------------------
# session builder
# --------------------------------------------------------------------------


def process_prekey_bundle(state: dict, bundle: dict, our_identity: dict,
                          our_registration_id: int) -> None:
    """Alice side: derive a session from a retrieved pre-key bundle."""
    if not verify_signature(bundle["identityKey"], prefixed(bundle["signedPreKey"]["public"]),
                            bundle["signedPreKey"]["signature"]):
        raise ValueError("invalid signature on device signed pre-key")

    base_private, base_public = curve.generate_key_pair()
    ratchet_private, ratchet_public = curve.generate_key_pair()

    secrets = bytearray(DISCONTINUITY)
    secrets += curve.shared_key(our_identity["private"], unprefixed(bundle["signedPreKey"]["public"]))
    secrets += curve.shared_key(base_private, unprefixed(bundle["identityKey"]))
    secrets += curve.shared_key(base_private, unprefixed(bundle["signedPreKey"]["public"]))
    one_time = bundle.get("oneTimePreKey")
    if one_time:
        secrets += curve.shared_key(base_private, unprefixed(one_time["public"]))

    root_key, chain_key = derive_whisper_text(bytes(secrets))

    state["sessionVersion"] = CURRENT_VERSION
    state["localRegistrationId"] = our_registration_id
    state["remoteRegistrationId"] = bundle.get("registrationId")
    state["aliceBaseKey"] = prefixed(base_public)
    state["localIdentityPublic"] = prefixed(our_identity["public"])
    state["remoteIdentityKey"] = prefixed(bundle["identityKey"])

    sending_root, sending_chain = root_create_chain(
        root_key, bundle["signedPreKey"]["public"], ratchet_private
    )
    state["rootKey"] = sending_root
    state["senderChain"] = {
        "ratchetKey": {"private": ratchet_private, "public": prefixed(ratchet_public)},
        "chainKey": {"index": 0, "key": sending_chain},
    }
    state["receiverChains"] = [{
        "ratchetKey": prefixed(bundle["signedPreKey"]["public"]),
        "chainKey": {"index": 0, "key": chain_key},
        "messageKeys": [],
    }]
    state["previousCounter"] = 0

    if one_time:
        state["unacknowledgedPreKeyMessage"] = {
            "preKeyId": one_time.get("keyId"),
            "signedPreKeyId": bundle["signedPreKey"].get("keyId"),
            "baseKey": prefixed(base_public),
        }
    else:
        state["unacknowledgedPreKeyMessage"] = {
            "preKeyId": None,
            "signedPreKeyId": bundle["signedPreKey"].get("keyId"),
            "baseKey": prefixed(base_public),
        }


def process_prekey_message(state: dict, message: dict, our_identity: dict,
                           our_registration_id: int, signed_pre_key: dict,
                           one_time_pre_key: Optional[dict]) -> bool:
    """Bob side: initialise a session from an incoming PreKeySignalMessage.

    Returns True when the session was (re)created.  ``state`` is updated in
    place.
    """
    if message["version"] < CURRENT_VERSION:
        raise ValueError("legacy message version")
    their_base_key = message["baseKey"]
    already = (state.get("aliceBaseKey") == prefixed(their_base_key)
               and has_session(state))
    if not already:
        secrets = bytearray(DISCONTINUITY)
        secrets += curve.shared_key(signed_pre_key["keyPair"]["private"],
                                    unprefixed(message["identityKey"]))
        secrets += curve.shared_key(our_identity["private"], unprefixed(their_base_key))
        secrets += curve.shared_key(signed_pre_key["keyPair"]["private"], unprefixed(their_base_key))
        if one_time_pre_key:
            secrets += curve.shared_key(one_time_pre_key["private"], unprefixed(their_base_key))

        root_key, chain_key = derive_whisper_text(bytes(secrets))
        state["sessionVersion"] = CURRENT_VERSION
        state["localRegistrationId"] = our_registration_id
        state["remoteRegistrationId"] = message.get("registrationId")
        state["aliceBaseKey"] = prefixed(their_base_key)
        state["localIdentityPublic"] = prefixed(our_identity["public"])
        state["remoteIdentityKey"] = prefixed(message["identityKey"])
        state["rootKey"] = root_key
        state["senderChain"] = {
            "ratchetKey": {
                "private": signed_pre_key["keyPair"]["private"],
                "public": prefixed(signed_pre_key["keyPair"]["public"]),
            },
            "chainKey": {"index": 0, "key": chain_key},
        }
        state["receiverChains"] = []
        state["previousCounter"] = 0
        state["unacknowledgedPreKeyMessage"] = None
    return not already


# --------------------------------------------------------------------------
# message (de)serialisation
# --------------------------------------------------------------------------


def _encode_signal_message_body(ratchet_key: bytes, counter: int, previous_counter: int,
                                ciphertext: bytes) -> bytes:
    return pb.encode("SignalMessage", {
        "ratchetKey": prefixed(ratchet_key),
        "counter": counter,
        "previousCounter": previous_counter,
        "ciphertext": ciphertext,
    })


def _mac(mac_key: bytes, sender_identity: bytes, receiver_identity: bytes, data: bytes) -> bytes:
    """libsignal MAC: HmacSHA256(macKey, senderIdentity || receiverIdentity || message).

    The ``message`` passed in already contains the leading version byte, which
    libsignal includes in the MAC input.
    """
    return hmac_sha256(mac_key, prefixed(sender_identity) + prefixed(receiver_identity) + data)[:MAC_LENGTH]


def decode_signal_message(serialized: bytes) -> dict:
    if len(serialized) < 2:
        raise ValueError("message too short")
    version = (serialized[0] & 0xFF) >> 4
    body = serialized[1:-MAC_LENGTH]
    mac = serialized[-MAC_LENGTH:]
    parsed = pb.decode("SignalMessage", body)
    parsed["version"] = version
    parsed["serialized"] = serialized[:-MAC_LENGTH]  # includes the version byte
    parsed["mac"] = mac
    return parsed


def encode_prekey_signal_message(message: dict, registration_id: int, pre_key_id: Optional[int],
                                 signed_pre_key_id: int, base_key: bytes,
                                 identity_key: bytes, signal_message: bytes) -> bytes:
    body = pb.encode("PreKeySignalMessage", {
        "registrationId": registration_id,
        "preKeyId": pre_key_id if pre_key_id else None,
        "signedPreKeyId": signed_pre_key_id,
        "baseKey": prefixed(base_key),
        "identityKey": prefixed(identity_key),
        "message": signal_message,
    })
    return bytes([VERSION_BYTE]) + body


def decode_prekey_signal_message(serialized: bytes) -> dict:
    version = (serialized[0] & 0xFF) >> 4
    parsed = pb.decode("PreKeySignalMessage", serialized[1:])
    parsed["version"] = version
    return parsed


# --------------------------------------------------------------------------
# session cipher
# --------------------------------------------------------------------------


def session_encrypt(state: dict, plaintext: bytes) -> Tuple[str, bytes]:
    """Encrypt for an established session; returns ``('msg'|'pkmsg', bytes)``."""
    if not has_session(state):
        raise ValueError("uninitialised session")
    chain = state["senderChain"]
    chain_key = chain["chainKey"]["key"]
    index = chain["chainKey"]["index"]
    keys = chain_message_keys(chain_key, index)

    ciphertext = cbc_encrypt(keys["cipherKey"], keys["iv"], plaintext, pad=True)
    sender_identity = state["localIdentityPublic"]
    receiver_identity = state["remoteIdentityKey"]
    body = bytes([VERSION_BYTE]) + _encode_signal_message_body(
        chain["ratchetKey"]["public"], index, state["previousCounter"], ciphertext)
    mac = _mac(keys["macKey"], sender_identity, receiver_identity, body)
    serialized = body + mac

    chain["chainKey"] = {"index": index + 1, "key": next_chain_key(chain_key)}

    unack = state.get("unacknowledgedPreKeyMessage")
    if unack:
        prekey_message = encode_prekey_signal_message(
            {}, state["localRegistrationId"], unack.get("preKeyId"),
            unack["signedPreKeyId"], unprefixed(unack["baseKey"]),
            unprefixed(sender_identity), serialized,
        )
        return "pkmsg", prekey_message
    return "msg", serialized


def session_decrypt(state: dict, serialized: bytes) -> bytes:
    message = decode_signal_message(serialized)
    if not has_session(state):
        raise ValueError("uninitialised session")
    if message["version"] != state["sessionVersion"]:
        raise ValueError("wrong message version")

    their_key = message["ratchetKey"]
    counter = message["counter"]
    chain = _find_receiver_chain(state, their_key)

    if chain is None:
        # new ratchet: derive receiving chain then a fresh sending chain
        root_key = state["rootKey"]
        our_ratchet = state["senderChain"]["ratchetKey"]
        new_root, recv_chain = root_create_chain(root_key, their_key, our_ratchet["private"])
        new_private, new_public = curve.generate_key_pair()
        send_root, send_chain = root_create_chain(new_root, their_key, new_private)
        state["rootKey"] = send_root
        state["previousCounter"] = max(state["senderChain"]["chainKey"]["index"] - 1, 0)
        state["receiverChains"].append({
            "ratchetKey": prefixed(their_key),
            "chainKey": {"index": 0, "key": recv_chain},
            "messageKeys": [],
        })
        state["senderChain"] = {
            "ratchetKey": {"private": new_private, "public": prefixed(new_public)},
            "chainKey": {"index": 0, "key": send_chain},
        }
        chain = _find_receiver_chain(state, their_key)

    index = chain["chainKey"]["index"]
    if index > counter:
        keys = None
        for stored in chain["messageKeys"]:
            if stored["index"] == counter:
                keys = stored
                chain["messageKeys"].remove(stored)
                break
        if keys is None:
            raise ValueError(f"duplicate or old message (counter {counter})")
    else:
        if counter - index > MAX_FUTURE_MESSAGES:
            raise ValueError("message too far into the future")
        while chain["chainKey"]["index"] < counter:
            skipped = chain_message_keys(chain["chainKey"]["key"], chain["chainKey"]["index"])
            chain["messageKeys"].append(skipped)
            chain["chainKey"] = {
                "index": chain["chainKey"]["index"] + 1,
                "key": next_chain_key(chain["chainKey"]["key"]),
            }
        keys = chain_message_keys(chain["chainKey"]["key"], chain["chainKey"]["index"])
        chain["chainKey"] = {
            "index": chain["chainKey"]["index"] + 1,
            "key": next_chain_key(chain["chainKey"]["key"]),
        }
        # keep the skipped-key cache bounded (low-RAM devices)
        if len(chain["messageKeys"]) > 100:
            del chain["messageKeys"][:-100]

    expected = _mac(keys["macKey"], state["remoteIdentityKey"],
                    state["localIdentityPublic"], message["serialized"])
    if expected != message["mac"]:
        raise ValueError("invalid message MAC")

    plaintext = cbc_decrypt(keys["cipherKey"], keys["iv"], message["ciphertext"], unpad=True)
    state["unacknowledgedPreKeyMessage"] = None
    return plaintext


def decrypt_prekey_message(state: dict, serialized: bytes, our_identity: dict,
                           our_registration_id: int, signed_pre_key: dict,
                           one_time_pre_key: Optional[dict]) -> Tuple[bytes, Optional[int]]:
    message = decode_prekey_signal_message(serialized)
    created = process_prekey_message(state, message, our_identity, our_registration_id,
                                     signed_pre_key, one_time_pre_key)
    plaintext = session_decrypt(state, message["message"])
    used_pre_key = message.get("preKeyId") if created else None
    return plaintext, used_pre_key


# --------------------------------------------------------------------------
# Sender keys (groups)
# --------------------------------------------------------------------------


def new_sender_key_state(sender_key_id: Optional[int] = None) -> dict:
    signing_private, signing_public = curve.generate_key_pair()
    return {
        "keyId": sender_key_id if sender_key_id is not None else int.from_bytes(os.urandom(4), "big") % 2147483647,
        "chainKey": os.urandom(32),
        "signingKeyPublic": prefixed(signing_public),
        "signingKeyPrivate": signing_private,
        "iteration": 0,
        "messageKeys": [],
    }


def sender_message_key(seed: bytes) -> Dict[str, bytes]:
    derived = hkdf(seed, 64, ZERO_SALT, b"WhisperGroup")
    cipher_key = derived[16:32] + derived[32:48]
    return {"iv": derived[0:16], "cipherKey": cipher_key}


def _sender_key_material(state: dict, iteration: int) -> dict:
    current = state["iteration"]
    if current > iteration:
        for stored in state["messageKeys"]:
            if stored["index"] == iteration:
                state["messageKeys"].remove(stored)
                return stored["keys"]
        raise ValueError(f"received message with old counter {iteration}")
    if iteration - current > MAX_FUTURE_MESSAGES:
        raise ValueError("over 2000 messages into the future")
    chain_key = state["chainKey"]
    while state["iteration"] < iteration:
        seed = hmac_sha256(chain_key, b"\x01")
        state["messageKeys"].append({"index": state["iteration"],
                                     "keys": sender_message_key(seed)})
        chain_key = hmac_sha256(chain_key, b"\x02")
        state["iteration"] += 1
        if len(state["messageKeys"]) > 100:
            del state["messageKeys"][:-100]
    seed = hmac_sha256(chain_key, b"\x01")
    keys = sender_message_key(seed)
    state["chainKey"] = hmac_sha256(chain_key, b"\x02")
    state["iteration"] += 1
    return keys


def group_encrypt(state: dict, plaintext: bytes) -> bytes:
    # Use the current chain iteration, then let _sender_key_material advance it.
    # (The old `iteration if 0 else iteration+1` form skipped every other
    # counter and broke interop with Baileys / libsignal.)
    iteration = int(state.get("iteration") or 0)
    keys = _sender_key_material(state, iteration)
    ciphertext = cbc_encrypt(keys["cipherKey"], keys["iv"], plaintext, pad=True)
    body = pb.encode("SenderKeyMessage", {
        "id": state["keyId"],
        "iteration": iteration,
        "ciphertext": ciphertext,
    })
    serialized = bytes([VERSION_BYTE]) + body
    signature = curve.xeddsa_sign(state["signingKeyPrivate"], serialized)
    return serialized + signature


def group_decrypt(state: dict, serialized: bytes) -> bytes:
    if len(serialized) < 65:
        raise ValueError("sender key message too short")
    body = serialized[1:-64]
    signature = serialized[-64:]
    if not curve.xeddsa_verify(state["signingKeyPublic"], serialized[:-64], signature):
        raise ValueError("invalid sender key signature")
    message = pb.decode("SenderKeyMessage", body)
    keys = _sender_key_material(state, message["iteration"])
    return cbc_decrypt(keys["cipherKey"], keys["iv"], message["ciphertext"], unpad=True)


def build_skdm(state: dict) -> bytes:
    body = pb.encode("SenderKeyDistributionMessage", {
        "id": state["keyId"],
        "iteration": state["iteration"],
        "chainKey": state["chainKey"],
        "signingKey": state["signingKeyPublic"],
    })
    return bytes([VERSION_BYTE]) + body


def process_skdm(state: dict, serialized: bytes) -> None:
    message = pb.decode("SenderKeyDistributionMessage", serialized[1:])
    state["keyId"] = message["id"]
    state["iteration"] = message["iteration"]
    state["chainKey"] = message["chainKey"]
    state["signingKeyPublic"] = message["signingKey"]
    state["signingKeyPrivate"] = None
    state["messageKeys"] = []


__all__ = [
    "prefixed", "unprefixed", "generate_registration_id", "signed_key_pair",
    "verify_signature", "new_session_state", "process_prekey_bundle",
    "process_prekey_message", "session_encrypt", "session_decrypt",
    "decrypt_prekey_message", "new_sender_key_state", "group_encrypt",
    "group_decrypt", "build_skdm", "process_skdm", "has_session",
    "decode_signal_message", "decode_prekey_signal_message",
]
