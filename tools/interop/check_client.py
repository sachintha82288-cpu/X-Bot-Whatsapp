#!/usr/bin/env python3
"""End-to-end check of ``xbot.client`` against the fake WhatsApp server.

The Node server (``mock-server.mjs``) speaks the real protocol with Baileys'
codec/crypto and libsignal, so this test exercises: WebSocket framing, the
Noise XX handshake, the registration payload, pair-success handling, pre-key
upload, USync device lookup, pre-key bundle parsing, 1:1 encryption (pkmsg +
device-sent wrapper) and decryption of a reply.

Run with::

    python3 tools/interop/check_client.py
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from xbot.client import Logger, WAClient  # noqa: E402
from xbot.store import AuthStore, b64  # noqa: E402

INTEROP_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("MOCK_PORT", "0"))


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="xbot-client-")
    session = os.path.join(workdir, "session.json")
    store = AuthStore(session)
    adv_secret = store.creds["advSecretKey"]

    env = dict(os.environ)
    env["MOCK_PORT"] = str(PORT)
    env["MOCK_ADV_SECRET"] = adv_secret
    server = subprocess.Popen(
        ["node", "mock-server.mjs"],
        cwd=INTEROP_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    ca_public = None
    bound_port = None
    server_lines = []

    def read_server():
        for line in server.stdout:  # type: ignore[union-attr]
            server_lines.append(line.rstrip())
            try:
                event = json.loads(line)
            except ValueError:
                print("server:", line.rstrip(), flush=True)
                continue
            if event.get("event") != "listening":
                print("server:", line.rstrip(), flush=True)

    reader = threading.Thread(target=read_server, daemon=True)
    reader.start()

    # wait for the CA public key the mock prints on startup
    deadline = time.time() + 20
    while time.time() < deadline:
        for line in list(server_lines):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event") == "listening":
                ca_public = event["caPublicKey"]
                bound_port = event["port"]
        if ca_public:
            break
        time.sleep(0.1)
    if not ca_public:
        print("server did not start")
        server.kill()
        return 1

    import base64

    config = {
        "url": f"ws://127.0.0.1:{bound_port}",
        "cert_authority": {"PUBLIC_KEY": base64.b64decode(ca_public), "SERIAL": 0},
        "log_level": os.environ.get("LOG_LEVEL", "debug"),
        "push_name": "X-Bot Test",
    }
    client = WAClient(store, config, Logger(config["log_level"]))

    opened = threading.Event()
    received = queue.Queue()
    client.on("open", lambda *_: opened.set())
    client.on("message", lambda info: received.put(info))

    if not client.connect():
        print("client could not connect")
        server.kill()
        return 1
    if not opened.wait(15):
        print("client never reached the open state")
        server.kill()
        return 1

    print("client is logged in as", store.me_id)
    client.send_text("15551234567@s.whatsapp.net", os.environ.get("MOCK_EXPECT", "ping from python"))

    reply = None
    deadline = time.time() + 15
    while time.time() < deadline and reply is None:
        try:
            reply = received.get(timeout=0.5)
        except queue.Empty:
            continue

    if reply is None:
        print("no reply received")
        server.kill()
        return 1
    text = (reply.get("message") or {}).get("conversation")
    print("client decrypted reply:", text, "from", reply["key"]["remoteJid"])

    # the mock exits by itself once it has printed its summary
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.terminate()
    reader.join(timeout=2)

    summary = None
    for line in server_lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event") == "RESULT":
            summary = event
    if summary is None:
        print("server produced no result")
        return 1

    ok = True
    if not summary.get("registered"):
        print("FAIL: the client did not register")
        ok = False
    parts = (summary.get("incoming") or {}).get("parts") or []
    expected = os.environ.get("MOCK_EXPECT", "ping from python")
    texts = {part.get("jid"): part.get("text") for part in parts}
    dsm = {part.get("jid"): part.get("dsm") for part in parts}
    own_device = texts.get("15550001111@s.whatsapp.net", texts.get("15550001111:0@s.whatsapp.net"))
    own_dsm = dsm.get("15550001111@s.whatsapp.net", dsm.get("15550001111:0@s.whatsapp.net"))
    peer_device = texts.get("15551234567@s.whatsapp.net", texts.get("15551234567:0@s.whatsapp.net"))
    if own_device != expected or not own_dsm:
        print("FAIL: own device copy wrong (device-sent wrapper missing?):", parts)
        ok = False
    if peer_device != expected:
        print("FAIL: peer copy wrong:", parts)
        ok = False
    if text != "pong from the fake phone":
        print("FAIL: client could not decrypt the reply")
        ok = False
    if not summary.get("replySent"):
        print("FAIL: server did not send a reply")
        ok = False

    shutil.rmtree(workdir, ignore_errors=True)
    print("client interop:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
