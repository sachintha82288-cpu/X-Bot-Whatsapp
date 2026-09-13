#!/usr/bin/env python3
"""X-Bot — a WhatsApp bot written in pure Python (standard library only).

Usage (Termux)::

    python main.py                          # friendly setup wizard
    python main.py --pairing-code 9477XXXXXXX
    python main.py --qr                     # link with a QR code
    python main.py --self                   # only the owner may use commands

Everything (protocol, crypto, WebSocket, HTTP) is implemented inside the
``xbot`` package; no third party module is required.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xbot.bot.qr import encode_qr, render_qr, render_qr_plain  # noqa: E402
from xbot.bot.runtime import Bot, Config  # noqa: E402
from xbot.client import Logger, WAClient  # noqa: E402
from xbot.store import AuthStore  # noqa: E402
from xbot.wa.binary import Node  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))

# Terminal colours (disabled when stdout is not a TTY)
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(text: str) -> str:
    return _c("1", text)


def green(text: str) -> str:
    return _c("32", text)


def yellow(text: str) -> str:
    return _c("33", text)


def cyan(text: str) -> str:
    return _c("36", text)


def dim(text: str) -> str:
    return _c("2", text)


def red(text: str) -> str:
    return _c("31", text)


BANNER = r"""
 __  __     ____        _
 \ \/ /    | __ )  ___ | |_
  \  /_____|  _ \ / _ \| __|   WhatsApp bot · pure Python
  /  \_____| |_) | (_) | |_    no external libraries
 /_/\_\    |____/ \___/ \__|   Termux ready
"""


def hr(char: str = "─", width: int = 44) -> str:
    return dim(char * width)


def box(title: str, lines: list, width: int = 44) -> None:
    """Print a simple framed block of text."""
    print()
    print(hr("═", width))
    print(bold(f"  {title}"))
    print(hr("─", width))
    for line in lines:
        print(f"  {line}")
    print(hr("═", width))
    print()


def step(number: int, text: str) -> None:
    print(f"  {cyan(f'{number}.')} {text}")


def ok(text: str) -> None:
    print(green(f"  ✓ {text}"))


def warn(text: str) -> None:
    print(yellow(f"  ! {text}"))


def err(text: str) -> None:
    print(red(f"  ✗ {text}"))


def info(text: str) -> None:
    print(f"  → {text}")


def _digits(value: str) -> str:
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def format_code(code: str) -> str:
    """ABCD1234 → ABCD-1234 (easier to read / type)."""
    code = (code or "").strip().upper()
    if len(code) == 8:
        return f"{code[:4]}-{code[4:]}"
    return code


def format_phone(number: str) -> str:
    number = _digits(number)
    if not number:
        return ""
    return f"+{number}"


def normalize_phone_input(raw: str) -> str:
    """Accept +94 77 123 4567, 0771234567, 94771234567, etc."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    # Keep leading + only as a hint for international format.
    has_plus = raw.startswith("+")
    digits = _digits(raw)
    if not digits:
        return ""
    # Local Sri Lankan numbers typed as 07xxxxxxxx → 947xxxxxxxx
    if not has_plus and digits.startswith("0") and len(digits) in (9, 10):
        digits = "94" + digits.lstrip("0")
    # US-style local without country code is left as-is; user should include country code.
    return digits


def validate_phone(number: str) -> str:
    """Return an error message, or empty string if OK."""
    number = _digits(number)
    if not number:
        return "phone number is empty"
    if len(number) < 8:
        return "number is too short (include country code, e.g. 94771234567)"
    if len(number) > 15:
        return "number is too long"
    if not number[0].isdigit() or number[0] == "0":
        return "start with the country code (no leading 0) — e.g. 94771234567"
    return ""


def ask(prompt: str, default: str = "") -> str:
    """Read a line from the user. Returns default on EOF."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        print()
        return default
    except KeyboardInterrupt:
        print()
        raise
    return value or default


def ask_choice(prompt: str, choices: dict, default: str) -> str:
    """choices maps key -> description. Returns the chosen key."""
    keys = list(choices.keys())
    print()
    print(f"  {bold(prompt)}")
    for key, label in choices.items():
        marker = green("●") if key == default else dim("○")
        print(f"    {marker}  {bold(key)})  {label}")
    print()
    while True:
        raw = ask(f"choose ({'/'.join(keys)})", default).lower().strip()
        if raw in choices:
            return raw
        # allow typing the full word
        for key, label in choices.items():
            if raw == label.lower() or raw.startswith(key):
                return key
        warn(f"please type one of: {', '.join(keys)}")


def print_qr(text: str) -> None:
    """Show the pairing QR code in the terminal (works in Termux, no libs)."""
    try:
        matrix = encode_qr(text)
    except Exception as exc:  # pragma: no cover
        err(f"could not draw the QR code ({exc})")
        info("try again with: python main.py   and choose option 1 (phone number)")
        return
    print()
    print(hr())
    print(bold("  📷  Scan this QR with WhatsApp"))
    print(dim("  WhatsApp → Linked devices → Link a device"))
    print(hr())
    print()
    if sys.stdout.isatty():
        print(render_qr(matrix))
    else:
        print(render_qr_plain(matrix))
    print()
    print(dim("  QR refreshes automatically. Keep this screen open."))
    print()


def print_pairing_code(code: str, phone: str) -> None:
    pretty = format_code(code)
    box(
        "🔑  YOUR PAIRING CODE",
        [
            "",
            bold(cyan(f"        {pretty}")),
            "",
            f"for WhatsApp number  {bold(format_phone(phone))}",
            "",
            yellow("type this on your phone within ~1 minute"),
            "",
            "On your phone:",
            "  1. Open WhatsApp",
            "  2. Settings → Linked devices",
            "  3. Link a device",
            "  4. Link with phone number instead",
            f"  5. Enter  {bold(pretty)}",
            "",
        ],
    )


def print_linked(jid: str) -> None:
    number = _digits((jid or "").split("@")[0].split(":")[0])
    box(
        "✅  LINKED SUCCESSFULLY",
        [
            f"account   {bold(format_phone(number) or jid)}",
            f"device    {dim(jid or '?')}",
            "",
            "WhatsApp is finishing the setup…",
            "the bot will come online in a moment.",
        ],
    )


def print_online(jid: str, prefix: str, bot_name: str) -> None:
    number = _digits((jid or "").split("@")[0].split(":")[0])
    box(
        f"🟢  {bot_name} IS ONLINE",
        [
            f"logged in as  {bold(format_phone(number) or jid)}",
            "",
            "Try these in any WhatsApp chat:",
            f"  {bold(prefix + 'ping')}     check the bot",
            f"  {bold(prefix + 'menu')}     list all commands",
            f"  {bold(prefix + 'alive')}    uptime & status",
            "",
            dim("Press Ctrl+C to stop the bot"),
        ],
    )


def interactive_setup(args) -> None:
    """Friendly first-run wizard when the device is not linked yet."""
    box(
        "👋  Welcome to X-Bot",
        [
            "Let's link this bot to your WhatsApp.",
            "",
            "Pick how you want to connect:",
        ],
    )

    # If user already passed flags, honour them and skip the menu.
    if args.pairing_code:
        args.link_method = "code"
        return
    if getattr(args, "qr", False):
        args.link_method = "qr"
        return

    if not sys.stdin.isatty():
        # Non-interactive (piped / nohup) — default to QR so it still works.
        args.link_method = "qr"
        info("no terminal input — using QR code mode")
        info("for pairing code, run: python main.py --pairing-code 9477XXXXXXX")
        return

    choice = ask_choice(
        "How do you want to link?",
        {
            "1": "Phone number  →  get an 8-character code  (recommended on Termux)",
            "2": "QR code       →  scan with WhatsApp camera",
            "q": "Quit",
        },
        default="1",
    )
    if choice == "q":
        print()
        print("  bye 👋")
        print()
        sys.exit(0)

    if choice == "1":
        args.link_method = "code"
        print()
        print(f"  {bold('Enter your WhatsApp number')}")
        print(dim("  country code + number, no spaces  ·  e.g. 94771234567"))
        print(dim("  (Sri Lanka local 07xxxxxxxx is also OK)"))
        print()
        while True:
            raw = ask("phone number")
            number = normalize_phone_input(raw)
            problem = validate_phone(number)
            if not problem:
                args.pairing_code = number
                ok(f"using {format_phone(number)}")
                break
            err(problem)
    else:
        args.link_method = "qr"
        ok("QR code mode — a code will appear after connecting")


def build_bot(args) -> tuple:
    storage_dir = args.session or os.path.join(ROOT, "session")
    os.makedirs(storage_dir, exist_ok=True)
    config_path = args.config or os.path.join(storage_dir, "config.json")
    config = Config(config_path)

    if args.self:
        config.set("mode", "self")
    if args.owner:
        config.set("owner", _digits(args.owner))
    if args.prefix:
        config.set("prefix", args.prefix)
    if args.name:
        config.set("bot_name", args.name)
    if args.debug:
        config.set("log_level", "debug")

    # Default owner to the pairing number so commands work right after link.
    if getattr(args, "pairing_code", None) and not config.get("owner"):
        config.set("owner", _digits(args.pairing_code))

    # Quiet logs for normal users; --debug keeps full detail.
    log_level = config.get("log_level", "info")
    if not args.debug and log_level == "info":
        # Still show warnings/errors; hide routine "connecting…" spam via our own UI.
        pass

    logger = Logger(log_level if args.debug else ("debug" if args.debug else log_level))
    store = AuthStore(os.path.join(storage_dir, "session.json"), logger=logger)
    client = WAClient(store, {
        "log_level": log_level,
        "push_name": config.get("bot_name", "X-Bot"),
        "sync_full_history": False,
        # Suppress client's own "scan the QR" log — we print a nicer banner.
        "log_qr": False,
    }, logger)
    bot = Bot(client, config, logger, data_dir=os.path.join(storage_dir, "data"),
              plugin_dirs=[os.path.join(ROOT, "plugins")])
    return client, bot, store, config, logger


def run(args) -> int:
    client, bot, store, config, logger = build_bot(args)
    bot.load_plugins()

    already_linked = store.is_registered()
    link_method = getattr(args, "link_method", None)
    pairing_number = _digits(args.pairing_code) if args.pairing_code else ""
    want_pairing = bool(pairing_number) and not already_linked
    want_qr = (link_method == "qr" or (not want_pairing and not already_linked))

    if already_linked:
        me = store.me_id or ""
        number = _digits(me.split("@")[0].split(":")[0])
        print()
        ok(f"saved session found — {format_phone(number) or me}")
        info("logging in…")
        print()
    elif want_pairing:
        box(
            "📱  Linking with phone number",
            [
                f"number   {bold(format_phone(pairing_number))}",
                "",
                "Connecting to WhatsApp…",
                "a pairing code will appear next.",
            ],
        )
    else:
        box(
            "📷  Linking with QR code",
            [
                "Connecting to WhatsApp…",
                "a QR code will appear next — scan it with your phone.",
            ],
        )

    stopped = {"value": False}
    online_announced = {"value": False}
    pairing_code_sent = {"value": False}
    connecting_msg = {"value": False}

    def shutdown(*_):
        if stopped["value"]:
            return
        stopped["value"] = True
        print()
        print(yellow("  👋  shutting down…"))
        try:
            client.disconnect("shutdown")
        except Exception:
            pass
        store.save(force=True)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def on_open(*_):
        if not store.is_registered():
            return
        if not config.get("owner"):
            me = store.me_id or ""
            number = _digits(me.split("@")[0].split(":")[0])
            if number:
                config.set("owner", number)
        try:
            client.send_node(Node("presence", {"name": config.get("bot_name", "X-Bot")}))
        except Exception as exc:
            logger.debug("could not send presence: %s", exc)
        if not online_announced["value"]:
            online_announced["value"] = True
            print_online(
                store.me_id or "",
                config.get("prefix", "."),
                config.get("bot_name", "X-Bot"),
            )

    def on_paired(jid=None, *_):
        print_linked(jid or store.me_id or "")

    def on_connection(state, *rest):
        if state == "connecting" and not connecting_msg["value"]:
            connecting_msg["value"] = True
        elif state == "open":
            pass
        elif state == "close":
            reason = rest[0] if rest else ""
            if stopped["value"]:
                return
            if store.is_registered():
                if reason and reason not in ("shutdown",):
                    warn(f"disconnected ({reason}) — reconnecting…")
            logger.debug("connection closed (%s)", reason)

    client.on("open", on_open)
    client.on("qr", print_qr)
    client.on("paired", on_paired)
    client.on("connection", on_connection)

    backoff = 3

    while not stopped["value"]:
        if not already_linked and not store.is_registered():
            # first-time connect: keep UI calm
            pass
        else:
            logger.debug("connecting to WhatsApp…")

        if not client.connect():
            err(f"connection failed — retrying in {backoff}s")
            info("check your internet, then wait…")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        backoff = 3
        connecting_msg["value"] = False

        if want_pairing and not store.is_registered():
            try:
                info("requesting pairing code…")
                code = client.request_pairing_code(pairing_number)
                pairing_code_sent["value"] = True
                print_pairing_code(code, pairing_number)
                info("waiting for you to enter the code on your phone…")
                print(dim("  (this screen stays open — don't close it)"))
                print()
            except Exception as exc:
                err(f"could not get a pairing code: {exc}")
                pairing_code_sent["value"] = False

        elif want_qr and not store.is_registered():
            info("waiting for QR code from WhatsApp…")
            print(dim("  keep this screen open and scan when it appears"))
            print()

        idle_since = time.time()
        last_wait_note = 0.0
        while not stopped["value"] and client.is_open:
            time.sleep(0.5)
            now = time.time()

            # Friendly mid-pairing reminders every 30s
            if (want_pairing and not store.is_registered()
                    and pairing_code_sent["value"]
                    and now - last_wait_note >= 30):
                elapsed = int(now - idle_since)
                info(f"still waiting for the code… ({elapsed}s)")
                print(dim("  WhatsApp → Linked devices → Link with phone number"))
                last_wait_note = now

            if (want_pairing and not store.is_registered()
                    and now - idle_since > 120
                    and pairing_code_sent["value"]):
                warn("pairing timed out — getting a fresh code…")
                try:
                    client.disconnect("pairing timeout")
                except Exception:
                    pass
                pairing_code_sent["value"] = False
                break
            if store.is_registered():
                idle_since = time.time()

        if stopped["value"]:
            break
        if not config.get("auto_reconnect", True):
            break
        if store.is_registered():
            want_pairing = False
            want_qr = False
            already_linked = True
        time.sleep(backoff)

    store.save(force=True)
    print()
    ok("session saved — run python main.py again to reconnect")
    print()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="X-Bot — pure Python WhatsApp bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py                          interactive setup (recommended)
  python main.py --pairing-code 94771234567
  python main.py --qr
  python main.py --self --owner 94771234567
        """,
    )
    parser.add_argument("--session", help="folder that stores the session (default ./session)")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--pairing-code", dest="pairing_code", metavar="NUMBER",
                        help="WhatsApp number with country code (e.g. 94771234567)")
    parser.add_argument("--qr", action="store_true", help="link by scanning a QR code")
    parser.add_argument("--owner", help="owner phone number (digits only)")
    parser.add_argument("--prefix", help="command prefix (default .)")
    parser.add_argument("--name", help="bot display name")
    parser.add_argument("--self", action="store_true", help="only the owner may use commands")
    parser.add_argument("--no-banner", action="store_true", help="do not print the banner")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    args = parser.parse_args()
    args.link_method = None

    if not args.no_banner:
        print(BANNER)
        print(dim("  pure Python · no pip install · Termux ready"))
        print()

    # Normalize number if passed on the CLI
    if args.pairing_code:
        normalized = normalize_phone_input(args.pairing_code)
        problem = validate_phone(normalized)
        if problem:
            err(problem)
            info("example: python main.py --pairing-code 94771234567")
            return 2
        args.pairing_code = normalized
        args.link_method = "code"

    try:
        storage_dir = args.session or os.path.join(ROOT, "session")
        os.makedirs(storage_dir, exist_ok=True)
        session_path = os.path.join(storage_dir, "session.json")
        linked = False
        if os.path.exists(session_path):
            try:
                linked = AuthStore(session_path, generate=False).is_registered()
            except Exception:
                linked = False

        if not linked and not args.pairing_code and not args.qr:
            interactive_setup(args)
        elif not linked and args.qr:
            args.link_method = "qr"
        elif not linked and args.pairing_code:
            args.link_method = "code"

        return run(args)
    except KeyboardInterrupt:
        print()
        print(yellow("  👋  bye"))
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
