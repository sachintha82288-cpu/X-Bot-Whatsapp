"""Core commands: menu, ping, settings, owner tools."""

from __future__ import annotations

import os
import platform
import shutil
import sys
import time
from typing import List

from .. import plugin as plugin_api
from ...wa.binary import Node, jid_decode

START_TIME = time.time()


def _uptime() -> str:
    seconds = int(time.time() - START_TIME)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def _memory_mb() -> str:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return f"{int(line.split()[1]) / 1024:.1f} MB"
    except OSError:
        pass
    return "n/a"


@plugin_api.command("menu", help="show every command", aliases=["help", "list"],
                    category="core")
def menu(bot, message, args):
    prefix = bot.prefix
    if args:
        entry = plugin_api.COMMANDS.get(args[0].lower())
        if entry is None:
            return message.reply(f"❓ no such command: {args[0]}")
        return message.reply(
            f"*{prefix}{entry.name}*\n{entry.help or 'no description'}\n"
            f"category: {entry.category}"
            + (f"\naliases: {', '.join(entry.aliases)}" if entry.aliases else "")
            + ("\nowner only" if entry.owner_only else "")
        )

    grouped = {}
    for entry in plugin_api.all_commands():
        if entry.hidden:
            continue
        grouped.setdefault(entry.category, []).append(entry)

    name = bot.config.get("bot_name", "X-Bot")
    lines = [f"🤖 *{name}*", f"prefix: `{prefix}`", ""]
    for category in sorted(grouped):
        names = "  ".join(f"{prefix}{entry.name}" for entry in grouped[category])
        lines.append(f"*{category.upper()}*\n{names}\n")
    lines.append("send a command to see it in action 🙂")
    return message.reply("\n".join(lines))


@plugin_api.command("ping", help="check the bot's response time", category="core")
def ping(bot, message, args):
    started = time.time()
    message.reply("🏓 pong!")
    latency = (time.time() - started) * 1000
    return message.send(f"⚡ latency: {latency:.0f} ms\n🕒 uptime: {_uptime()}")


@plugin_api.command("alive", help="is the bot running?", category="core")
def alive(bot, message, args):
    return message.reply(
        f"✅ *{bot.config.get('bot_name', 'X-Bot')}* is online\n"
        f"🕒 uptime: {_uptime()}\n"
        f"🧠 memory: {_memory_mb()}\n"
        f"🐍 python: {platform.python_version()}\n"
        f"📱 platform: {sys.platform}"
    )


@plugin_api.command("id", help="show your WhatsApp id", aliases=["whoami"], category="core")
def identifier(bot, message, args):
    lines = [f"👤 you: `{message.sender}`", f"💬 chat: `{message.chat}`"]
    if message.is_group:
        lines.append("🏷️ group: yes")
    if bot.is_owner(message.sender):
        lines.append("👑 owner: yes")
    return message.reply("\n".join(lines))


@plugin_api.command("owner", help="show the bot owner", category="core")
def owner(bot, message, args):
    owner_number = bot.config.get("owner") or "not configured"
    return message.reply(f"👑 owner: {owner_number}")


@plugin_api.command("stats", help="bot usage statistics", category="core")
def stats(bot, message, args):
    uptime = int(time.time() - bot.stats["started"])
    return message.reply(
        f"📊 *statistics*\n"
        f"messages: {bot.stats['messages']}\n"
        f"commands: {bot.stats['commands']}\n"
        f"plugins: {len(bot.loaded_plugins)}\n"
        f"commands loaded: {len(plugin_api.all_commands())}\n"
        f"uptime: {uptime // 3600}h {(uptime % 3600) // 60}m"
    )


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------


@plugin_api.command("prefix", help="change the command prefix", owner_only=True,
                    aliases=["setprefix"], category="settings")
def set_prefix(bot, message, args):
    if not args:
        return message.reply(f"current prefix: `{bot.prefix}`")
    prefix = args[0][:2]
    bot.config.set("prefix", prefix)
    return message.reply(f"✅ prefix set to `{prefix}`")


@plugin_api.command("mode", help="public or self mode", owner_only=True, category="settings")
def set_mode(bot, message, args):
    if not args or args[0].lower() not in ("public", "self"):
        return message.reply(f"usage: {bot.prefix}mode public|self (now: {bot.config.get('mode')})")
    bot.config.set("mode", args[0].lower())
    return message.reply(f"✅ mode set to *{args[0].lower()}*")


@plugin_api.command("setname", help="change the bot's display name", owner_only=True,
                    aliases=["botname"], category="settings")
def set_name(bot, message, args):
    if not args:
        return message.reply(f"name: {bot.config.get('bot_name')}")
    name = " ".join(args)
    bot.config.set("bot_name", name)
    bot.client.send_node(Node("presence", {"name": name}))
    return message.reply(f"✅ bot name set to *{name}*")


@plugin_api.command("disable", help="disable a command", owner_only=True, category="settings")
def disable(bot, message, args):
    if not args:
        return message.reply("usage: disable <command>")
    names = {item.lower() for item in bot.config.get("disabled") or []}
    names.add(args[0].lower())
    bot.config.set("disabled", sorted(names))
    return message.reply(f"🚫 disabled: {args[0].lower()}")


@plugin_api.command("enable", help="enable a disabled command", owner_only=True,
                    category="settings")
def enable(bot, message, args):
    if not args:
        return message.reply("usage: enable <command>")
    names = {item.lower() for item in bot.config.get("disabled") or []}
    names.discard(args[0].lower())
    bot.config.set("disabled", sorted(names))
    return message.reply(f"✅ enabled: {args[0].lower()}")


@plugin_api.command("reload", help="reload all plugins", owner_only=True, category="settings")
def reload_plugins(bot, message, args):
    bot.reload_plugins()
    return message.reply(f"♻️ reloaded {len(bot.loaded_plugins)} plugin files")


# --------------------------------------------------------------------------
# message tools
# --------------------------------------------------------------------------


@plugin_api.command("del", help="delete the message you replied to", aliases=["delete"],
                    category="core")
def delete_message(bot, message, args):
    quoted = message.quoted or message.raw
    key = (quoted.get("key") or {}) if quoted is not message.raw else message.key
    target_chat = key.get("remoteJid") or message.chat
    bot.client.send_message(target_chat, {
        "protocolMessage": {
            "key": {
                "remoteJid": target_chat,
                "fromMe": bool(key.get("fromMe") if key is not message.key else True),
                "id": key.get("id"),
                "participant": key.get("participant"),
            },
            "type": 0,  # REVOKE
        },
    })
    return None


@plugin_api.command("vv", help="re-send a view-once photo/video", aliases=["viewonce"],
                    category="tools")
def view_once(bot, message, args):
    quoted = message.quoted
    if not quoted or not quoted.get("message"):
        return message.reply("↩️ reply to a view-once message with this command")
    from ..message import Message

    inner = Message({**quoted, "key": {**quoted["key"], "remoteJid": message.chat}}, bot.client)
    media_type = inner.media_type
    if not media_type:
        return message.reply("❓ that message has no media")
    if media_type == "sticker":
        return message.reply("❓ stickers are not view-once media")
    try:
        data = bot.download_media(inner)
    except Exception as exc:
        return message.reply(f"❌ could not download: {exc}")
    caption = (inner.media or {}).get("caption") or "🔓 view once"
    if media_type == "image":
        bot.client.send_image(message.chat, data, caption=caption)
    elif media_type == "video":
        bot.client.send_video(message.chat, data, caption=caption)
    else:
        bot.client.send_document(message.chat, data, "view-once.bin", caption=caption)
    return None


@plugin_api.command("whois", help="look up a number on WhatsApp", category="tools")
def whois(bot, message, args):
    target = message.command_target
    if target is None and args:
        number = "".join(ch for ch in args[0] if ch.isdigit())
        if number:
            target = f"{number}@s.whatsapp.net"
    if not target:
        return message.reply("usage: reply to somebody or send a number")
    decoded = jid_decode(target)
    number = decoded[0] if decoded else ""
    result = bot.client.query_usync_contact([number])
    found = bool(result.get(number))
    lines = [f"🔎 number: +{number}", f"📱 on whatsapp: {'yes' if found else 'no'}"]
    if found and result[number].get("jid"):
        lines.append(f"🆔 jid: `{result[number]['jid']}`")
    try:
        picture = bot.client.profile_picture_url(target)
        if picture:
            lines.append(f"🖼️ profile photo: {picture}")
    except Exception:
        pass
    return message.reply("\n".join(lines))


# ---------------------------------------------------------------- system info
@plugin_api.command("sysinfo", help="system information", owner_only=True, category="settings")
def sysinfo(bot, message, args):
    total, used, free = (0, 0, 0)
    try:
        stat = os.statvfs("/")
        total = stat.f_frsize * stat.f_blocks // (1024 * 1024)
        free = stat.f_frsize * stat.f_bavail // (1024 * 1024)
        used = total - free
    except OSError:
        pass
    ffmpeg = shutil.which("ffmpeg") or "not installed"
    return message.reply(
        f"🖥️ *system*\n"
        f"os: {platform.platform()}\n"
        f"python: {platform.python_version()}\n"
        f"memory: {_memory_mb()}\n"
        f"disk: {used} MB used / {total} MB (free {free} MB)\n"
        f"ffmpeg: {ffmpeg}\n"
        f"uptime: {_uptime()}"
    )
