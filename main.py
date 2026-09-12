#!/usr/bin/env python3
"""X-Bot — a WhatsApp bot written in pure Python (standard library only).

Usage (Termux)::

    python main.py                          # link by scanning a QR code
    python main.py --pairing-code 9477XXXXXXX  # link with an 8 digit code
    python main.py --self                   # only the owner may use commands

Everything (protocol, crypto, WebSocket, HTTP) is implemented inside the
``xbot`` package; no third party module is required.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xbot.bot.qr import encode_qr  # noqa: E402
from xbot.bot.runtime import Bot, Config  # noqa: E402
from xbot.client import Logger, WAClient  # noqa: E402
from xbot.store import AuthStore  # noqa: E402
from xbot.wa.binary import Node  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
BANNER = r"""
 __  __     ____        _
 \ \/ /    | __ )  ___ | |_
  \  /_____|  _ \ / _ \| __|   WhatsApp bot · pure Python
  /  \_____| |_) | (_) | |_    no external libraries
 /_/\_\    |____/ \___/ \__|   Termux ready
"""


def print_qr(text: str) -> None:
    """Show the pairing QR code in the terminal (works in Termux, no libs)."""
    try:
        matrix = encode_qr(text)
    except Exception as exc:  # pragma: no cover - only for oversized payloads
        print("→ could not draw the QR code (%s)" % exc)
        print("  use: python main.py --pairing-code <your number>")
        return
    quiet = 2
    size = len(matrix)
    print("█" * ((size + quiet * 2) * 2))
    for row in range(-quiet, size + quiet):
        line = ""
        for column in range(-quiet, size + quiet):
            inside = 0 <= row < size and 0 <= column < size
            line += "██" if (inside and matrix[row][column]) else "  "
        print(line)
    print("█" * ((size + quiet * 2) * 2))
    print("scan this with WhatsApp ▸ Linked devices")


def build_bot(args) -> tuple:
    storage_dir = args.session or os.path.join(ROOT, "session")
    os.makedirs(storage_dir, exist_ok=True)
    config_path = args.config or os.path.join(storage_dir, "config.json")
    config = Config(config_path)

    if args.self:
        config.set("mode", "self")
    if args.owner:
        config.set("owner", "".join(ch for ch in args.owner if ch.isdigit()))
    if args.prefix:
        config.set("prefix", args.prefix)
    if args.name:
        config.set("bot_name", args.name)
    if args.debug:
        config.set("log_level", "debug")

    logger = Logger(config.get("log_level", "info"))
    store = AuthStore(os.path.join(storage_dir, "session.json"), logger=logger)
    client = WAClient(store, {
        "log_level": config.get("log_level", "info"),
        "push_name": config.get("bot_name", "X-Bot"),
        "sync_full_history": False,
    }, logger)
    bot = Bot(client, config, logger, data_dir=os.path.join(storage_dir, "data"),
              plugin_dirs=[os.path.join(ROOT, "plugins")])
    return client, bot, store, config, logger


def run(args) -> int:
    client, bot, store, config, logger = build_bot(args)
    bot.load_plugins()

    if not store.is_registered():
        print("📱 this device is not linked yet")
        if args.pairing_code:
            print("   asking WhatsApp for a pairing code for +%s …" %
                  "".join(ch for ch in args.pairing_code if ch.isdigit()))
        else:
            print("   a QR code will appear below — scan it from WhatsApp ▸ Linked devices")

    stopped = {"value": False}

    def shutdown(*_):
        if stopped["value"]:
            return
        stopped["value"] = True
        print("\n👋 shutting down…")
        client.disconnect("shutdown")
        store.save(force=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    paired_code_sent = False
    backoff = 3

    while not stopped["value"]:
        logger.info("connecting to WhatsApp…")
        if not client.connect():
            logger.warn("connection failed, retrying in %ds", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        backoff = 3

        if args.pairing_code and not store.is_registered() and not paired_code_sent:
            paired_code_sent = True
            try:
                code = client.request_pairing_code(args.pairing_code)
                print("\n🔑 pairing code: %s" % code)
                print("   enter it on your phone: WhatsApp ▸ Linked devices ▸ Link with phone number\n")
            except Exception as exc:
                logger.error("could not request a pairing code: %s", exc)

        opened = {"value": store.is_registered()}

        def on_open(*_):
            opened["value"] = True
            if not store.is_registered():
                return
            try:
                client.send_node(Node("presence", {"name": config.get("bot_name", "X-Bot")}))
            except Exception as exc:
                logger.debug("could not send presence: %s", exc)

        client.on("open", on_open)
        client.on("qr", print_qr)

        def on_close(*_):
            opened["value"] = False

        client.on("connection", lambda state, *rest: on_close() if state == "close" else None)

        # wait until the session ends
        while not stopped["value"] and client.is_open:
            time.sleep(1)

        if stopped["value"]:
            break
        if not config.get("auto_reconnect", True):
            break
        logger.info("reconnecting in %ds…", backoff)
        time.sleep(backoff)

    store.save(force=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="X-Bot — pure Python WhatsApp bot")
    parser.add_argument("--session", help="folder that stores the session (default ./session)")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--pairing-code", dest="pairing_code",
                        help="link with a phone number instead of a QR code")
    parser.add_argument("--owner", help="owner phone number (only this number is 'owner')")
    parser.add_argument("--prefix", help="command prefix (default .)")
    parser.add_argument("--name", help="bot display name")
    parser.add_argument("--self", action="store_true", help="only the owner may use commands")
    parser.add_argument("--no-banner", action="store_true", help="do not print the banner")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n👋 bye")
        return 0


if __name__ == "__main__":
    sys.exit(main())
