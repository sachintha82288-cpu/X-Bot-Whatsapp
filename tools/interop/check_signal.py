#!/usr/bin/env python3
"""Signal-protocol interop test: pure Python <-> libsignal-node (Baileys).

Usage::

    cd tools/interop && npm install baileys      # dev-only
    python3 tools/interop/check_signal.py

The script drives the Node harness (signal-interop.mjs) so a single command
verifies X3DH + the double ratchet + Sender Keys in both directions.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from xbot.crypto import curve  # noqa: E402
from xbot.wa import signal as sig  # noqa: E402

b64 = lambda data: base64.b64encode(data).decode()  # noqa: E731
unb64 = lambda text: base64.b64decode(text)  # noqa: E731
TMP = "/tmp"


def run_node(*args) -> None:
    result = subprocess.run(["node", *args], cwd=HERE, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"node {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")


def main() -> int:
    failures = []

    # ---------------------------------------------------------------- 1:1
    bundle_path = f"{TMP}/signal-bundle.json"
    run_node("signal-interop.mjs", "bundle", bundle_path)
    bundle_raw = json.load(open(bundle_path))
    bob = bundle_raw["bob"]

    alice_private, alice_public = curve.generate_key_pair()
    alice_identity = {"private": alice_private, "public": alice_public}
    alice_registration_id = sig.generate_registration_id()

    prekey_bundle = {
        "identityKey": unb64(bob["identityKey"]),
        "registrationId": bob["registrationId"],
        "signedPreKey": {
            "keyId": bob["signedPreKey"]["keyId"],
            "public": unb64(bob["signedPreKey"]["public"]),
            "signature": unb64(bob["signedPreKey"]["signature"]),
        },
    }
    if bob.get("oneTimePreKey"):
        prekey_bundle["oneTimePreKey"] = {
            "keyId": bob["oneTimePreKey"]["keyId"],
            "public": unb64(bob["oneTimePreKey"]["public"]),
        }

    # sanity: our verifier must accept the reference's signed pre-key
    if not sig.verify_signature(prekey_bundle["identityKey"],
                                sig.prefixed(prekey_bundle["signedPreKey"]["public"]),
                                prekey_bundle["signedPreKey"]["signature"]):
        failures.append("signed pre-key signature verification failed")

    alice_state = sig.new_session_state(alice_registration_id, alice_identity["public"])
    sig.process_prekey_bundle(alice_state, prekey_bundle, alice_identity, alice_registration_id)

    msg_type, ciphertext = sig.session_encrypt(alice_state, b"hello from python")
    payload = {
        "aliceName": "alice",
        "aliceDeviceId": 1,
        "messages": [{"type": msg_type, "body": b64(ciphertext)}],
    }
    json.dump(payload, open(f"{TMP}/signal-to-bob.json", "w"))
    out_path = f"{TMP}/signal-from-bob.json"
    run_node("signal-interop.mjs", "bob-decrypt", f"{TMP}/signal-to-bob.json", out_path)
    bob_out = json.load(open(out_path))
    if bob_out["plaintexts"] != ["hello from python"]:
        failures.append(f"libsignal could not decrypt our pkmsg: {bob_out['plaintexts']}")
    if msg_type != "pkmsg":
        failures.append(f"first message should be pkmsg, got {msg_type}")

    # Alice decrypts Bob's reply (this also clears her pending pre-key message)
    reply_type = bob_out["reply"]["type"]
    reply_body = unb64(bob_out["reply"]["body"])
    try:
        plaintext = sig.session_decrypt(alice_state, reply_body)
        if plaintext != b"reply from node":
            failures.append(f"wrong reply plaintext: {plaintext!r}")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"failed to decrypt reference reply ({reply_type}): {exc}")

    # Alice sends a follow-up: now a plain 'msg' (whisper) message
    follow_type, follow_body = sig.session_encrypt(alice_state, b"second from python")
    if follow_type != "msg":
        failures.append(f"second message should be msg, got {follow_type}")
    json.dump({
        "aliceName": "alice",
        "aliceDeviceId": 1,
        "messages": [{"type": follow_type, "body": b64(follow_body)}],
    }, open(f"{TMP}/signal-to-bob2.json", "w"))
    run_node("signal-interop.mjs", "bob-decrypt", f"{TMP}/signal-to-bob2.json", f"{TMP}/signal-from-bob2.json")
    bob_out2 = json.load(open(f"{TMP}/signal-from-bob2.json"))
    if bob_out2["plaintexts"] != ["second from python"]:
        failures.append(f"libsignal could not decrypt our msg: {bob_out2['plaintexts']}")

    # Bob encrypts again -> Python decrypts (exercises the DH ratchet step)
    json.dump({"aliceName": "alice", "aliceDeviceId": 1, "texts": ["third from node"]},
              open(f"{TMP}/signal-ask-bob.json", "w"))
    run_node("signal-interop.mjs", "bob-encrypt", f"{TMP}/signal-ask-bob.json", f"{TMP}/signal-bob-msgs.json")
    bob_msgs = json.load(open(f"{TMP}/signal-bob-msgs.json"))
    try:
        got = sig.session_decrypt(alice_state, unb64(bob_msgs[0]["body"]))
        if got != b"third from node":
            failures.append(f"ratchet decrypt mismatch: {got!r}")
    except Exception as exc:  # noqa: BLE001
        failures.append(f"failed to decrypt reference message after ratchet: {exc}")

    # once more in the other direction, to be sure the session is usable
    t, body = sig.session_encrypt(alice_state, b"fourth from python")
    json.dump({"aliceName": "alice", "aliceDeviceId": 1, "messages": [{"type": t, "body": b64(body)}]},
              open(f"{TMP}/signal-to-bob3.json", "w"))
    run_node("signal-interop.mjs", "bob-decrypt", f"{TMP}/signal-to-bob3.json", f"{TMP}/signal-from-bob3.json")
    if json.load(open(f"{TMP}/signal-from-bob3.json"))["plaintexts"] != ["fourth from python"]:
        failures.append("continued session broke")

    # ------------------------------------------------------------- groups
    group = "120363012345678901@g.us"
    node_group = {"group": group, "sender": "bob@s.whatsapp.net",
                  "action": "encrypt", "text": "group hello from node", "text2": "group hello two"}
    json.dump(node_group, open(f"{TMP}/signal-group-ask.json", "w"))
    run_node("signal-interop.mjs", "group", f"{TMP}/signal-group-ask.json", f"{TMP}/signal-group-out.json")
    node_group_out = json.load(open(f"{TMP}/signal-group-out.json"))

    bob_state = sig.new_sender_key_state()
    sig.process_skdm(bob_state, unb64(node_group_out["skdm"]))
    plaintexts = []
    for body in node_group_out["messages"]:
        plaintexts.append(sig.group_decrypt(bob_state, unb64(body)).decode())
    if plaintexts != ["group hello from node", "group hello two"]:
        failures.append(f"sender-key decryption mismatch: {plaintexts}")

    # python encrypts a group message; node must be able to read it
    alice_group = sig.new_sender_key_state()
    skdm = sig.build_skdm(alice_group)
    sent = [b64(sig.group_encrypt(alice_group, b"group from python")),
            b64(sig.group_encrypt(alice_group, b"group from python 2"))]
    json.dump({"group": group, "sender": "alice@s.whatsapp.net", "action": "decrypt",
               "skdm": b64(skdm), "messages": sent}, open(f"{TMP}/signal-group-to-node.json", "w"))
    run_node("signal-interop.mjs", "group", f"{TMP}/signal-group-to-node.json", f"{TMP}/signal-group-from-node.json")
    node_seen = json.load(open(f"{TMP}/signal-group-from-node.json"))["plaintexts"]
    if node_seen != ["group from python", "group from python 2"]:
        failures.append(f"node could not decrypt our sender-key messages: {node_seen}")

    if failures:
        print("SIGNAL INTEROP FAILURES:")
        for item in failures:
            print(" -", item)
        return 1
    print("signal interop: X3DH + double ratchet + sender keys OK in both directions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
