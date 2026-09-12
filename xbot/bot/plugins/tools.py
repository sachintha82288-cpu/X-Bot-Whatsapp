"""Handy tools that need nothing but the standard library (and optionally
ffmpeg for sticker/image conversion).
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse

from .. import plugin as plugin_api
from ...media import http_request

TMP_DIR = os.path.join("data", "tmp")


def _tmp_path(suffix: str) -> str:
    os.makedirs(TMP_DIR, exist_ok=True)
    return os.path.join(TMP_DIR, f"{int(time.time() * 1000)}-{random.randint(1000, 9999)}{suffix}")


def ffmpeg_path() -> str:
    return shutil.which("ffmpeg") or ""


# --------------------------------------------------------------------------
# stickers & images
# --------------------------------------------------------------------------


@plugin_api.command("sticker", help="turn a photo/video into a sticker", aliases=["s"],
                    category="tools")
def sticker(bot, message, args):
    source = message.quoted
    if source is None and message.media_type in ("image", "video"):
        source = message.raw
    if not source:
        return message.reply("🖼️ send or reply to an image/video with this command")

    from ..message import Message

    media = Message(source, bot.client)
    media_type = media.media_type
    if media_type not in ("image", "video", "sticker"):
        return message.reply("❓ that message has no image or video")
    binary = ffmpeg_path()
    if media_type == "sticker" and source is message.raw:
        return message.reply("🙂 that is already a sticker")
    if not binary:
        return message.reply(
            "⚙️ ffmpeg is required for stickers — install it with:\n`pkg install ffmpeg`"
        )
    try:
        data = bot.download_media(media)
    except Exception as exc:
        return message.reply(f"❌ download failed: {exc}")

    source_path = _tmp_path("." + ("mp4" if media_type == "video" else "webp" if media_type == "sticker" else "jpg"))
    output_path = _tmp_path(".webp")
    with open(source_path, "wb") as handle:
        handle.write(data)
    scale = ("scale=512:512:force_original_aspect_ratio=decrease,"
             "pad=512:512:(ow-iw)/2:(oh-ih)/2:color=0x00000000")
    command = [binary, "-y", "-i", source_path]
    if media_type == "video":
        command += ["-t", "6", "-r", "12", "-an"]
    command += ["-vf", scale, "-c:v", "libwebp", "-lossless", "0", "-q:v", "70",
                "-pix_fmt", "yuva420p", output_path]
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=120)
        if process.returncode != 0 or not os.path.exists(output_path):
            raise RuntimeError(process.stdout.decode("utf-8", "replace")[-200:])
        with open(output_path, "rb") as handle:
            sticker_data = handle.read()
        bot.client.send_sticker(message.chat, sticker_data, quoted=message.raw)
    except Exception as exc:
        return message.reply(f"❌ sticker conversion failed: {exc}")
    finally:
        for path in (source_path, output_path):
            try:
                os.remove(path)
            except OSError:
                pass
    return None


@plugin_api.command("toimg", help="turn a sticker into a photo", aliases=["toimage"],
                    category="tools")
def to_image(bot, message, args):
    source = message.quoted or (message.raw if message.media_type == "sticker" else None)
    if not source:
        return message.reply("↩️ reply to a sticker with this command")
    from ..message import Message

    media = Message(source, bot.client)
    if media.media_type != "sticker":
        return message.reply("❓ that is not a sticker")
    try:
        data = bot.download_media(media)
    except Exception as exc:
        return message.reply(f"❌ download failed: {exc}")
    binary = ffmpeg_path()
    if binary:
        source_path = _tmp_path(".webp")
        output_path = _tmp_path(".png")
        with open(source_path, "wb") as handle:
            handle.write(data)
        process = subprocess.run(
            [binary, "-y", "-i", source_path, output_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        if process.returncode == 0 and os.path.exists(output_path):
            with open(output_path, "rb") as handle:
                data = handle.read()
            bot.client.send_image(message.chat, data, caption="✅ here you go")
            for path in (source_path, output_path):
                try:
                    os.remove(path)
                except OSError:
                    pass
            return None
        return message.reply("❌ conversion failed — is ffmpeg installed?")
    bot.client.send_document(message.chat, data, "sticker.webp", caption="sticker (install ffmpeg to convert)")
    return None


# --------------------------------------------------------------------------
# text tools
# --------------------------------------------------------------------------


@plugin_api.command("calc", help="evaluate a maths expression", aliases=["math"],
                    category="tools")
def calc(bot, message, args):
    expression = " ".join(args) or message.text.split(" ", 1)[-1]
    if not expression:
        return message.reply("usage: calc 2*(3+4)")
    if not re.fullmatch(r"[0-9+\-*/%()., ^e]+", expression):
        return message.reply("❌ only numbers and + - * / % ( ) are allowed")
    try:
        value = eval(expression.replace("^", "**"), {"__builtins__": {}}, {})  # noqa: S307
    except Exception as exc:
        return message.reply(f"❌ {exc}")
    return message.reply(f"🧮 {expression} = *{value}*")


@plugin_api.command("b64", help="base64 encode text", aliases=["base64"], category="tools")
def base64_encode(bot, message, args):
    text = " ".join(args) or (message.quoted or {}).get("message", {}).get("conversation", "")
    if not text:
        return message.reply("usage: b64 <text>")
    return message.reply("```" + base64.b64encode(text.encode()).decode() + "```")


@plugin_api.command("unb64", help="base64 decode text", aliases=["base64decode", "deb64"],
                    category="tools")
def base64_decode(bot, message, args):
    text = " ".join(args)
    if not text:
        return message.reply("usage: unb64 <text>")
    try:
        return message.reply(base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace"))
    except Exception as exc:
        return message.reply(f"❌ {exc}")


@plugin_api.command("password", help="generate a strong password", aliases=["pw", "genpw"],
                    category="tools")
def password(bot, message, args):
    length = 16
    if args and args[0].isdigit():
        length = max(6, min(int(args[0]), 64))
    alphabet = ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*")
    value = "".join(random.choice(alphabet) for _ in range(length))
    return message.reply(f"🔑 `{value}`")


@plugin_api.command("time", help="current date and time", category="tools")
def current_time(bot, message, args):
    return message.reply("🕒 " + time.strftime("%Y-%m-%d %H:%M:%S %Z"))


@plugin_api.command("weather", help="weather for a city", aliases=["wtr"], category="tools")
def weather(bot, message, args):
    city = " ".join(args) or "Colombo"
    try:
        status, _headers, body = http_request(
            f"https://wttr.in/{urllib.parse.quote(city)}?format=3&m", timeout=20)
        if status != 200 or not body:
            raise RuntimeError(f"status {status}")
        return message.reply("🌤️ " + body.decode("utf-8", "replace").strip())
    except Exception as exc:
        return message.reply(f"❌ weather lookup failed: {exc}")


@plugin_api.command("wiki", help="wikipedia summary", aliases=["wikipedia"], category="tools")
def wiki(bot, message, args):
    query = " ".join(args)
    if not query:
        return message.reply("usage: wiki <topic>")
    try:
        status, _headers, body = http_request(
            "https://en.wikipedia.org/api/rest_v1/page/summary/" + urllib.parse.quote(query.replace(" ", "_")),
            timeout=20)
        if status != 200:
            raise RuntimeError(f"status {status}")
        data = json.loads(body.decode())
        extract = data.get("extract") or "no summary available"
        link = (data.get("content_urls", {}).get("desktop", {}) or {}).get("page")
        return message.reply(f"📚 *{data.get('title')}*\n\n{extract[:900]}"
                             + (f"\n\n🔗 {link}" if link else ""))
    except Exception as exc:
        return message.reply(f"❌ wikipedia lookup failed: {exc}")


@plugin_api.command("translate", help="translate text (reply or inline)", aliases=["tr"],
                    category="tools")
def translate(bot, message, args):
    target = "en"
    words = list(args)
    if words and len(words[0]) == 2:
        target = words.pop(0).lower()
    text = " ".join(words)
    if not text and message.quoted:
        from ..message import Message

        text = Message(message.quoted, bot.client).text
    if not text:
        return message.reply("usage: translate si hello  (or reply to a message)")
    try:
        url = ("https://translate.googleapis.com/translate_a/single?client=gtx"
               f"&sl=auto&tl={urllib.parse.quote(target)}&dt=t&q={urllib.parse.quote(text)}")
        status, _headers, body = http_request(url, timeout=20)
        if status != 200:
            raise RuntimeError(f"status {status}")
        data = json.loads(body.decode())
        translated = "".join(part[0] for part in data[0] if part and part[0])
        return message.reply(f"🌍 *{target}*: {translated}")
    except Exception as exc:
        return message.reply(f"❌ translation failed: {exc}")


@plugin_api.command("short", help="shorten a url", aliases=["shorturl"], category="tools")
def shorten(bot, message, args):
    url = args[0] if args else ""
    if not url.startswith("http"):
        return message.reply("usage: short https://example.com/long/link")
    try:
        status, _headers, body = http_request(
            "https://tinyurl.com/api-create.php?url=" + urllib.parse.quote(url, safe=""), timeout=20)
        if status != 200 or not body:
            raise RuntimeError(f"status {status}")
        return message.reply("🔗 " + body.decode().strip())
    except Exception as exc:
        return message.reply(f"❌ could not shorten: {exc}")


@plugin_api.command("tts", help="convert text to a voice note", category="tools")
def text_to_speech(bot, message, args):
    text = " ".join(args)
    if not text and message.quoted:
        from ..message import Message

        text = Message(message.quoted, bot.client).text
    if not text:
        return message.reply("usage: tts <text>")
    try:
        status, _headers, body = http_request(
            "https://translate.google.com/translate_tts?ie=UTF-8&client=tw-ob"
            f"&tl=en&q={urllib.parse.quote(text[:200])}", timeout=30)
        if status != 200 or not body:
            raise RuntimeError(f"status {status}")
        bot.client.send_audio(message.chat, body, mimetype="audio/mpeg", ptt=True)
    except Exception as exc:
        return message.reply(f"❌ tts failed: {exc}")
    return None


# --------------------------------------------------------------------------
# contact / profile helpers
# --------------------------------------------------------------------------


@plugin_api.command("block", help="block a contact", owner_only=True, category="tools")
def block(bot, message, args):
    targets = message.mentions or ([message.chat] if not message.is_group else [])
    if not targets:
        return message.reply("❓ mention somebody to block")
    for jid in targets:
        bot.client.block_contact(jid, "block")
    return message.reply("🚫 blocked")


@plugin_api.command("unblock", help="unblock a contact", owner_only=True, category="tools")
def unblock(bot, message, args):
    targets = message.mentions or ([message.chat] if not message.is_group else [])
    if not targets:
        return message.reply("❓ mention somebody to unblock")
    for jid in targets:
        bot.client.block_contact(jid, "unblock")
    return message.reply("✅ unblocked")


@plugin_api.command("getpp", help="show somebody's profile picture", aliases=["pp"],
                    category="tools")
def get_profile_picture(bot, message, args):
    target = message.command_target or message.chat
    url = bot.client.profile_picture_url(target)
    if not url:
        return message.reply("❌ no profile picture (or it is private)")
    try:
        status, _headers, body = http_request(url, timeout=30)
        if status != 200:
            raise RuntimeError(f"status {status}")
        bot.client.send_image(message.chat, body, caption="🖼️ profile picture")
    except Exception as exc:
        return message.reply(f"❌ {url}\n({exc})")
    return None


@plugin_api.command("broadcast", help="send a message to every chat (owner)", owner_only=True,
                    category="tools")
def broadcast(bot, message, args):
    text = " ".join(args)
    if not text:
        return message.reply("usage: broadcast <text>")
    delivered = 0
    for jid in sorted(bot.client.known_chats):
        try:
            bot.client.send_text(jid, f"📢 *broadcast*\n\n{text}")
            delivered += 1
        except Exception:
            continue
    return message.reply(f"📢 broadcast sent to {delivered} chats")
