#!/usr/bin/env python3
"""Offline tests for the bot runtime and plugins (no network needed)."""

from __future__ import annotations

import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xbot.bot import plugin as _plugin  # noqa: E402
from xbot.bot.message import Message  # noqa: E402
from xbot.bot.runtime import Bot, Config  # noqa: E402

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  ✓ {name}")
    else:
        FAILED.append(name)
        print(f"  ✗ {name} {detail}")


class FakeClient:
    """Records everything the bot tries to send."""

    def __init__(self, me: str = "94770000000:1@s.whatsapp.net", lid: str = "111@lid"):
        self.me_id = me
        self.me_lid = lid
        self.sent = []
        self.queries = []
        self.log = _Log()
        self.known_chats = set()
        self._handlers = {}
        self.group_participants_list = []
        self.addressing = "pn"

    # used by Bot
    def on(self, event, callback):
        self._handlers.setdefault(event, []).append(callback)

    def send_text(self, jid, text, **kwargs):
        self.sent.append(("text", jid, text))
        self.known_chats.add(jid)
        return "MSGID"

    def send_message(self, jid, message, **kwargs):
        self.sent.append(("message", jid, message))
        return "MSGID"

    def reply_text(self, jid, quoted, text, **kwargs):
        self.sent.append(("reply", jid, text))
        return "MSGID"

    def send_reaction(self, jid, key, emoji):
        self.sent.append(("reaction", jid, emoji))

    def send_node(self, node):
        self.sent.append(("node", node.tag, node.attrs))

    def query(self, node, timeout=None):
        self.queries.append(node)
        return _Node("iq", {"type": "result"}, [])

    def group_metadata(self, group):
        return {
            "id": group,
            "subject": "Test Group",
            "addressing_mode": self.addressing,
            "participants": self.group_participants_list,
        }

    def next_tag(self):
        return "TAG"

    def download_media(self, message, media_type="image"):
        return b"fake-media"

    def send_image(self, *args, **kwargs):
        self.sent.append(("image", args[1] if len(args) > 1 else None))

    def send_sticker(self, *args, **kwargs):
        self.sent.append(("sticker",))

    def send_audio(self, *args, **kwargs):
        self.sent.append(("audio",))

    def send_document(self, *args, **kwargs):
        self.sent.append(("document",))


class _Node:
    def __init__(self, tag, attrs=None, content=None):
        self.tag = tag
        self.attrs = attrs or {}
        self.content = content if content is not None else []

    def child(self, tag):
        for item in self.content:
            if getattr(item, "tag", None) == tag:
                return item
        return None

    def children(self, tag=None):
        return [item for item in self.content if tag is None or item.tag == tag]


class _Log:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def make_bot():
    workdir = tempfile.mkdtemp(prefix="xbot-test-")
    config = Config(os.path.join(workdir, "config.json"))
    config.data.update({"owner": "94770000000", "prefix": ".", "bot_name": "X-Bot"})
    client = FakeClient()
    bot = Bot(client, config, data_dir=workdir)
    bot.load_plugins()
    return bot, client, config


def text_message(client, text, chat="94771111111@s.whatsapp.net", sender=None,
                 mentions=None, quoted=None):
    body = {"conversation": text}
    context = {}
    if mentions:
        context["mentionedJid"] = mentions
    if quoted:
        context["stanzaId"] = quoted["key"]["id"]
        context["quotedMessage"] = quoted.get("message") or {"conversation": "quoted"}
        if quoted["key"].get("participant"):
            context["participant"] = quoted["key"]["participant"]
    if context:
        body = {"extendedTextMessage": {"text": text, "contextInfo": context}}
    info = {
        "key": {"remoteJid": chat, "fromMe": False, "id": "MSG1",
                "participant": sender},
        "message": body,
        "pushName": "Tester",
        "messageTimestamp": 1700000000,
    }
    return Message(info, client)


def main() -> int:
    print("bot runtime tests")
    bot, client, config = make_bot()

    check("plugins loaded", len(bot.loaded_plugins) > 0, bot.loaded_plugins)
    check("commands registered", len(bot.get_plugin_commands()) > 15)

    # --- core commands -----------------------------------------------------
    client.sent.clear()
    bot.handle_message(text_message(client, ".ping"))
    check("ping replies", len(client.sent) >= 1 and "pong" in str(client.sent).lower())

    client.sent.clear()
    bot.handle_message(text_message(client, ".alive"))
    check("alive replies", "online" in str(client.sent).lower())

    client.sent.clear()
    bot.handle_message(text_message(client, ".menu"))
    menu_text = str(client.sent)
    check("menu lists commands", ".ping" in menu_text and ".kick" in menu_text)

    client.sent.clear()
    bot.handle_message(text_message(client, ".calc 2*(3+4)"))
    check("calc works", "14" in str(client.sent))

    client.sent.clear()
    bot.handle_message(text_message(client, ".b64 hello"))
    check("base64 works", "aGVsbG8=" in str(client.sent))

    client.sent.clear()
    bot.handle_message(text_message(client, ".unb64 aGVsbG8="))
    check("unbase64 works", "hello" in str(client.sent))

    # unknown command => silence
    client.sent.clear()
    bot.handle_message(text_message(client, ".doesnotexist"))
    check("unknown command ignored", client.sent == [])

    # --- owner gating ------------------------------------------------------
    client.sent.clear()
    bot.handle_message(text_message(client, ".mode self"))
    check("owner-only command blocked for strangers",
          "owner" in str(client.sent).lower())

    client.sent.clear()
    bot.handle_message(text_message(client, ".mode self", chat="94770000000@s.whatsapp.net"))
    check("owner can change mode", config.get("mode") == "self")
    config.set("mode", "public")

    # --- group features ----------------------------------------------------
    group = "12345@g.us"
    client.group_participants_list = [
        {"id": "94770000000@s.whatsapp.net", "admin": "superadmin"},
        {"id": "94771111111@s.whatsapp.net", "admin": None},
    ]
    client.sent.clear()
    bot.handle_message(text_message(client, ".kick", chat=group,
                                    sender="94771111111@s.whatsapp.net",
                                    mentions=["94772222222@s.whatsapp.net"]))
    check("non-admin cannot kick", "admin" in str(client.sent).lower())

    client.sent.clear()
    bot.handle_message(text_message(client, ".kick", chat=group,
                                    sender="94770000000@s.whatsapp.net",
                                    mentions=["94772222222@s.whatsapp.net"]))
    queries = [node for node in client.queries if node.tag == "iq"]
    check("admin kick sends a group iq", any(node.child("remove") for node in queries))

    client.sent.clear()
    bot.handle_message(text_message(client, ".tagall hello", chat=group,
                                    sender="94770000000@s.whatsapp.net"))
    check("tagall mentions everybody", "mention" in str(client.sent).lower()
          or "mentionedJid" in str(client.sent))

    client.sent.clear()
    bot.handle_message(text_message(client, ".toggle antilink on", chat=group,
                                    sender="94770000000@s.whatsapp.net"))
    check("toggle turns antilink on", bot.group_settings.get(group, "antilink") is True)

    client.sent.clear()
    bot.handle_message(text_message(client, "check https://example.com", chat=group,
                                    sender="94771111111@s.whatsapp.net"))
    check("antilink deletes non-admin links",
          any(entry[0] == "message" and "protocolMessage" in str(entry[2]) for entry in client.sent))

    client.sent.clear()
    bot.handle_message(text_message(client, "check https://example.com", chat=group,
                                    sender="94770000000@s.whatsapp.net"))
    check("antilink spares admins", client.sent == [])

    # --- welcome / goodbye --------------------------------------------------
    bot.group_settings.set(group, "welcome", True)
    client.sent.clear()
    bot._notify_group_event("add", group, ["94773333333@s.whatsapp.net"])
    check("welcome message sent", "welcome" in str(client.sent).lower()
          or "👋" in str(client.sent))

    bot.group_settings.set(group, "goodbye", True)
    client.sent.clear()
    bot._notify_group_event("remove", group, ["94773333333@s.whatsapp.net"])
    check("goodbye message sent", "left" in str(client.sent).lower() or "👋" in str(client.sent))

    # --- misc ---------------------------------------------------------------
    client.sent.clear()
    bot.handle_message(text_message(client, ".afk lunch"))
    check("afk replies", "afk" in str(client.sent).lower())

    client.sent.clear()
    bot.handle_message(text_message(client, "hello"))
    check("afk notice on next message", "away" in str(client.sent).lower())

    config.set("disabled", ["ping"])
    client.sent.clear()
    bot.handle_message(text_message(client, ".ping"))
    check("disabled command is ignored", client.sent == [])
    config.set("disabled", [])

    # --- user plugin folder -------------------------------------------------
    bot.plugin_dirs = [os.path.join(ROOT, "plugins")]
    bot.reload_plugins()
    check("example plugin loaded", "example.py" in bot.loaded_plugins)
    client.sent.clear()
    bot.handle_message(text_message(client, ".hello world"))
    check("example plugin command works", "hello world" in str(client.sent))

    client.sent.clear()
    bot.handle_message(text_message(client, ".ping"))
    check("built-in commands survive a plugin reload", client.sent != [])
    check("hooks are not duplicated by a reload",
          len([hook for hook in _plugin.message_hooks()
               if getattr(hook, "__name__", "") == "_afk_notice"]) == 1)

    # --- terminal QR rendering ----------------------------------------------
    from xbot.bot.qr import encode_qr, render_qr, render_qr_plain

    matrix = encode_qr("https://wa.me/settings/linked_devices#test")
    ansi_lines = render_qr(matrix).splitlines()
    visible = [re.sub("\x1b\\[[0-9;]*m", "", line) for line in ansi_lines]
    check("ansi qr is two module rows per terminal line",
          len(ansi_lines) == (len(matrix) + 8 + 1) // 2)
    check("ansi qr is one character per module wide",
          {len(line) for line in visible} == {len(matrix) + 8})
    check("plain qr renders every quiet zone row",
          len(render_qr_plain(matrix).splitlines()) == len(matrix) + 4)

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("failed:", ", ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
