"""Media downloaders.

``.dl`` works on any direct link.  The social-media helpers (YouTube, TikTok,
Facebook, Instagram, Twitter) talk to *public* converter endpoints; the list of
endpoints lives in ``config.json`` under ``download_apis`` so it can be updated
without touching the code.  Every failure is reported to the user instead of
crashing the bot.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from typing import Optional

from .. import plugin as plugin_api
from ...media import guess_type, http_request

DEFAULT_APIS = {
    "youtube": [
        "https://api.vevioz.com/api/button/mp3/{id}",
    ],
    "tiktok": [
        "https://tikwm.com/api/?url={url}",
    ],
    "facebook": [
        "https://api.akuari.my.id/downloader/facebook?link={url}",
    ],
    "instagram": [
        "https://api.akuari.my.id/downloader/ig?link={url}",
    ],
    "twitter": [
        "https://api.akuari.my.id/downloader/twitter?link={url}",
    ],
}

MAX_DOWNLOAD = 48 * 1024 * 1024  # WhatsApp media limit is ~64 MB, keep headroom
URL_PATTERN = re.compile(r"https?://[^\s]+")


def _api_list(bot, kind: str):
    configured = (bot.config.get("download_apis") or {}).get(kind)
    return configured if configured else DEFAULT_APIS.get(kind, [])


def _find_url(args) -> Optional[str]:
    for arg in args:
        if URL_PATTERN.match(arg):
            return arg
    return None


def _youtube_id(url: str) -> Optional[str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.hostname in ("youtu.be",):
        return parsed.path.lstrip("/") or None
    query = urllib.parse.parse_qs(parsed.query)
    if "v" in query:
        return query["v"][0]
    match = re.search(r"/(shorts|embed|live)/([A-Za-z0-9_-]{6,})", parsed.path)
    return match.group(2) if match else None


def _first_link(payload) -> Optional[str]:
    """Walk a JSON payload and return the first usable media url."""
    if isinstance(payload, str) and payload.startswith("http"):
        return payload
    if isinstance(payload, dict):
        for key in ("url", "link", "download", "download_url", "play", "hd", "sd",
                    "video", "mp4", "mp3", "audio", "nowm", "wmplay", "data"):
            if key in payload:
                found = _first_link(payload[key])
                if found:
                    return found
        for value in payload.values():
            found = _first_link(value)
            if found:
                return found
    if isinstance(payload, list):
        for item in payload:
            found = _first_link(item)
            if found:
                return found
    return None


def _fetch_via_apis(bot, kind: str, url: str) -> Optional[str]:
    for template in _api_list(bot, kind):
        api = template.replace("{url}", urllib.parse.quote(url, safe=""))
        video_id = _youtube_id(url)
        api = api.replace("{id}", video_id or "")
        if not api.startswith("http"):
            continue
        try:
            status, _headers, body = http_request(api, timeout=25, max_bytes=2 * 1024 * 1024)
            if status != 200 or not body:
                continue
            try:
                payload = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                text = body.decode("utf-8", "replace")
                found = _first_link(text)
                if found:
                    return found
                continue
            found = _first_link(payload)
            if found:
                return found
        except Exception as exc:  # pragma: no cover - network dependent
            bot.log.debug("downloader api %s failed: %s", api, exc)
    return None


def _send_media(bot, message, url: str, caption: str = "", filename: Optional[str] = None):
    status, headers, body = http_request(url, timeout=60, max_bytes=MAX_DOWNLOAD)
    if status != 200 or not body:
        raise RuntimeError(f"download failed with status {status}")
    mimetype = (headers.get("content-type") or "").split(";")[0] or "application/octet-stream"
    media_type, extension = guess_type(mimetype)
    if "mp4" in url.lower() and media_type == "document":
        media_type, mimetype, extension = "video", "video/mp4", "mp4"
    if media_type == "image":
        bot.client.send_image(message.chat, body, mimetype=mimetype, caption=caption,
                              quoted=message.raw)
    elif media_type == "video":
        bot.client.send_video(message.chat, body, mimetype=mimetype, caption=caption,
                              quoted=message.raw)
    elif media_type == "audio":
        bot.client.send_audio(message.chat, body, mimetype=mimetype, quoted=message.raw)
    else:
        name = filename or f"download.{extension}"
        bot.client.send_document(message.chat, body, name, mimetype=mimetype, caption=caption,
                                 quoted=message.raw)


@plugin_api.command("dl", help="download any direct media link", aliases=["download", "url"],
                    category="download")
def download(bot, message, args):
    url = _find_url(args)
    if not url and message.quoted:
        from ..message import Message

        url = _find_url([Message(message.quoted, bot.client).text or ""])
    if not url:
        return message.reply("usage: dl https://example.com/file.mp4")
    try:
        _send_media(bot, message, url, caption=f"⬇️ {os.path.basename(urllib.parse.urlsplit(url).path)[:60]}")
    except Exception as exc:
        return message.reply(f"❌ download failed: {exc}")
    return None


@plugin_api.command("ytdl", help="download a YouTube video or audio",
                    aliases=["yt", "ytmp4", "ytmp3"], category="download")
def youtube(bot, message, args):
    url = _find_url(args)
    if not url:
        return message.reply("usage: ytdl https://youtu.be/xxxx")
    if not _youtube_id(url):
        return message.reply("❌ that does not look like a YouTube link")
    link = _fetch_via_apis(bot, "youtube", url)
    if not link:
        return message.reply("❌ no working download endpoint right now — add one in "
                             "config.json under `download_apis.youtube`")
    try:
        _send_media(bot, message, link, caption="🎬 downloaded with ytdl")
    except Exception as exc:
        return message.reply(f"❌ download failed: {exc}")
    return None


def _social(bot, message, args, kind: str, label: str):
    url = _find_url(args)
    if not url:
        return message.reply(f"usage: {kind} <link>")
    link = _fetch_via_apis(bot, kind, url)
    if not link:
        return message.reply(f"❌ could not get the {label} media (endpoint unavailable)")
    try:
        _send_media(bot, message, link, caption=f"⬇️ {label}")
    except Exception as exc:
        return message.reply(f"❌ download failed: {exc}")
    return None


@plugin_api.command("tiktok", help="download a TikTok video", aliases=["tt", "ttdl"],
                    category="download")
def tiktok(bot, message, args):
    return _social(bot, message, args, "tiktok", "tiktok")


@plugin_api.command("fbdl", help="download a Facebook video", aliases=["facebook"],
                    category="download")
def facebook(bot, message, args):
    return _social(bot, message, args, "facebook", "facebook")


@plugin_api.command("igdl", help="download an Instagram post", aliases=["instagram", "ig"],
                    category="download")
def instagram(bot, message, args):
    return _social(bot, message, args, "instagram", "instagram")


@plugin_api.command("twitter", help="download a Twitter/X video", aliases=["twdl", "x"],
                    category="download")
def twitter(bot, message, args):
    return _social(bot, message, args, "twitter", "twitter")


@plugin_api.command("toaudio", help="extract the audio of a video", aliases=["tomp3"],
                    category="download")
def to_audio(bot, message, args):
    source = message.quoted or (message.raw if message.media_type == "video" else None)
    if not source:
        return message.reply("↩️ reply to a video with this command")
    import shutil
    import subprocess
    import tempfile

    binary = shutil.which("ffmpeg")
    if not binary:
        return message.reply("⚙️ ffmpeg is required — install it with `pkg install ffmpeg`")
    from ..message import Message

    media = Message(source, bot.client)
    if media.media_type not in ("video", "audio"):
        return message.reply("❓ that is not a video")
    try:
        data = bot.download_media(media)
    except Exception as exc:
        return message.reply(f"❌ download failed: {exc}")
    with tempfile.TemporaryDirectory() as directory:
        source_path = os.path.join(directory, "input.mp4")
        output_path = os.path.join(directory, "output.mp3")
        with open(source_path, "wb") as handle:
            handle.write(data)
        process = subprocess.run([binary, "-y", "-i", source_path, "-vn", "-ab", "128k",
                                  output_path],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        if process.returncode != 0 or not os.path.exists(output_path):
            return message.reply("❌ ffmpeg conversion failed")
        with open(output_path, "rb") as handle:
            audio = handle.read()
    bot.client.send_audio(message.chat, audio, mimetype="audio/mpeg", quoted=message.raw)
    return None
