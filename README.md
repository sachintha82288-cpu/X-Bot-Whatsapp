# X-Bot-Whatsapp

A WhatsApp bot written in **pure Python** — every layer of the stack (X25519/Ed25519
crypto, SHA/AES-GCM, HKDF, the Noise handshake, the binary node codec, protobuf,
the Signal double ratchet, WebSocket, HTTP and the pairing QR encoder) is
implemented inside this repository. **No third party Python packages are used**,
not even `requests`, `websockets`, `cryptography` or `qrcode`.

It is built to run on a cheap Android phone: Termux + Python 3, no background
services other than the bot itself, and the whole client loads in roughly 17 MB
of RSS on CPython 3.11 (measured on this checkout) - comfortable on a 1 GB
phone.

```
pkg install python
git clone https://github.com/sachintha82288-cpu/X-Bot-Whatsapp
cd X-Bot-Whatsapp
python main.py
```

> 🇱🇰 **සිංහලෙන් කෙටියෙන්:** Termux එකේ `pkg install python` කරලා, ඔබේ WhatsApp
> අංකයෙන් `python main.py --pairing-code 94XXXXXXXXX` ලෙස run කරන්න. Terminal
> එකේ පෙන්වන අට අකුරු කේතය WhatsApp ▸ Linked devices ▸ Link with phone number
> එකට ඇතුළත් කරන්න. (QR එකකින් link කරන්නත් පුළුවන් — `python main.py`.)

---

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Downloaders](#downloaders)
- [Your own plugins](#your-own-plugins)
- [How it works](#how-it-works)
- [Tests](#tests)
- [Limitations and safety](#limitations-and-safety)

## Quick start

### 1. Install Termux and Python

```bash
pkg update && pkg upgrade
pkg install python            # required
pkg install ffmpeg            # optional: only sticker / toimg / toaudio need it
```

Python 3.9 or newer is required (anything Termux ships today is fine).

### 2. Get the code

```bash
git clone https://github.com/sachintha82288-cpu/X-Bot-Whatsapp
cd X-Bot-Whatsapp
```

There is nothing to `pip install` — the bot imports only the standard library.

### 3. Link the bot to your WhatsApp account

**Option A — pairing code (recommended on a phone):**

```bash
python main.py --pairing-code 94771234567
```

The bot prints an 8 character code. On the phone that *owns* the WhatsApp
account: **Settings ▸ Linked devices ▸ Link a device ▸ Link with phone number
instead** and type the code.

**Option B — QR code:**

```bash
python main.py
```

A QR code is drawn right in the terminal (half blocks + colours, so it is
square and narrow enough for a phone screen). Scan it with **WhatsApp ▸
Linked devices ▸ Link a device**.

Either way the session is stored in `./session/session.json`. **That file *is*
your login** — anyone who copies it can control your WhatsApp. Never commit it
(the bundled `.gitignore` already excludes it) and never share it.

### 4. Run it in the background (optional)

```bash
termux-wake-lock                     # stop Android from freezing Termux
nohup python main.py > bot.log 2>&1 &   # survives the terminal closing
tail -f bot.log                      # watch the log
```

`pkg install tmux` and running the bot inside a tmux session is the friendlier
alternative.

### Command line flags

| flag | meaning |
| --- | --- |
| `--pairing-code <number>` | link with an 8 character code instead of a QR code (number with country code, no `+`) |
| `--session <dir>` | where to keep `session.json`, `config.json` and `data/` (default `./session`) |
| `--config <file>` | use a specific `config.json` |
| `--owner <number>` | phone number that counts as the owner (only this number may use owner commands) |
| `--prefix <.>` | command prefix, default `.` |
| `--name <text>` | bot display name used in messages |
| `--self` | self mode: only the owner may use commands |
| `--debug` | verbose logging |
| `--no-banner` | do not print the ASCII banner |

Owner phone numbers must be entered without `+` and without spaces, e.g.
`94771234567` or `15550001111`.

If the connection drops the bot reconnects by itself (exponential backoff,
`auto_reconnect` in `config.json`).

## Commands

Default prefix is `.` — so `.menu`, `.ping`, `.sticker`, …

### Core

| command | aliases | what it does |
| --- | --- | --- |
| `menu` | `help`, `list` | list every command (`.menu <cmd>` explains one) |
| `ping` | | response time |
| `alive` | | is the bot running (uptime, memory, host) |
| `id` | `whoami` | your WhatsApp id / group id |
| `owner` | | the configured owner |
| `stats` | | messages and commands handled |
| `del` | `delete` | delete the message you replied to |

### Group administration

| command | aliases | what it does |
| --- | --- | --- |
| `kick` | `remove` | remove a member (reply or @mention) |
| `add` | | add a member by number |
| `promote` | `admin` | make somebody an admin |
| `demote` | `unadmin` | take admin rights away |
| `tagall` | `everyone` | mention everybody |
| `groupinfo` | `ginfo` | group details and member list |
| `invite` | | group invite link |
| `setsubject` | | rename the group |
| `setdesc` | | change the group description |
| `leave` | | the bot leaves the group |
| `welcome` / `goodbye` | | set and enable the welcome / goodbye message |
| `toggle` | `set` | turn features on/off: `welcome`, `goodbye`, `antilink` |
| `antilink` | | delete links posted by non admins |
| `mute` / `unmute` | `close` / `open` | only admins may talk / everybody may talk |

Group commands must be used by a group admin (owner commands work anywhere).

### Tools

| command | aliases | what it does |
| --- | --- | --- |
| `vv` | `viewonce` | re-send a view-once photo or video |
| `sticker` | `s` | turn a photo or short video into a sticker |
| `toimg` | `toimage` | turn a sticker back into a photo |
| `tts` | | text to a voice note (google translate voice, no ffmpeg needed) |
| `calc` | `math` | evaluate a maths expression |
| `b64` / `unb64` | `base64` / `deb64` | base64 encode / decode |
| `password` | `pw`, `genpw` | generate a strong password |
| `time` | | current date and time |
| `weather` | `wtr` | weather for a city |
| `wiki` | `wikipedia` | wikipedia summary |
| `translate` | `tr` | translate text (reply to a message or pass it inline) |
| `short` | `shorturl` | shorten a url |
| `whois` | | look a number up on WhatsApp |
| `getpp` | `pp` | somebody's profile picture |
| `afk` | | mark yourself away, tell anybody who mentions you |
| `block` / `unblock` | | block / unblock a contact (owner) |
| `broadcast` | | send a message to every chat the bot knows (owner) |

### Downloaders

| command | aliases | what it does |
| --- | --- | --- |
| `dl` | `download`, `url` | download any direct media link |
| `ytdl` | `yt`, `ytmp4`, `ytmp3` | YouTube video or audio |
| `tiktok` | `tt`, `ttdl` | TikTok video (no watermark when the API returns one) |
| `fbdl` | `facebook` | Facebook video |
| `igdl` | `instagram`, `ig` | Instagram post |
| `twitter` | `twdl`, `x` | Twitter/X video |
| `toaudio` | `tomp3` | extract the audio of a video |

### Settings (owner only)

| command | aliases | what it does |
| --- | --- | --- |
| `prefix` | `setprefix` | change the command prefix |
| `mode` | | `public` or `self` |
| `setname` | `botname` | change the bot's display name |
| `disable` / `enable` | | switch a command off / on |
| `reload` | | reload the plugins folder |
| `sysinfo` | | python version, memory, storage, uptime |

## Configuration

`session/config.json` is created on first run:

```json
{
  "prefix": ".",
  "owner": "94771234567",
  "bot_name": "X-Bot",
  "mode": "public",
  "language": "en",
  "auto_reconnect": true,
  "owners": [],
  "disabled": [],
  "log_level": "info",
  "download_apis": {}
}
```

| key | meaning |
| --- | --- |
| `prefix` | command prefix (`.` by default) |
| `owner` | owner phone number, digits only |
| `owners` | extra numbers that may use owner commands |
| `bot_name` | name shown in `alive`, the menu and the banner |
| `mode` | `public` = everybody may use the bot, `self` = only the owner |
| `auto_reconnect` | reconnect after a dropped connection |
| `disabled` | list of commands nobody may use |
| `download_apis` | your own downloader endpoints (see below) |

Per group settings (welcome/goodbye/antilink/…) live in
`session/data/groups.json` and are changed with the commands themselves.

## Downloaders

The download commands need a public "extractor" API. WhatsApp only sees the
final media URL, so any service that answers with a JSON containing a direct
link works. The built-in defaults are free public endpoints and they *do* go
offline or start rate limiting — when a command stops working, put your own
endpoint in `config.json`:

```json
{
  "download_apis": {
    "youtube": ["https://your-api.example/api/yt?url={url}"],
    "tiktok":  ["https://your-api.example/api/tiktok?url={url}"],
    "facebook": ["https://your-api.example/api/fb?url={url}"],
    "instagram": ["https://your-api.example/api/ig?url={url}"],
    "twitter": ["https://your-api.example/api/twitter?url={url}"]
  }
}
```

* `{url}` is replaced with the (percent encoded) link the user sent, `{id}` with
  the YouTube video id.
* Several endpoints may be listed — they are tried in order until one answers.
* The response may be any JSON: the bot walks it and uses the first
  `http(s)` value it finds under a media-ish key (`url`, `link`, `download`,
  `play`, `hd`, `sd`, `video`, `mp4`, `mp3`, `audio`, `nowm`, …).
* `dl <link>` needs no API at all: it fetches a direct file url and sends it as
  an image, a video, an audio or a document depending on the content type.

Uploads and downloads go through WhatsApp's own media CDN (the bot implements
the media key derivation, AES-CBC payload encryption and HMAC-SHA256 MAC
itself), so no third party file host is involved.

## Your own plugins

Every `*.py` file in `plugins/` is loaded at start-up, and again when the owner
sends `.reload`. A plugin is a few lines:

```python
from xbot.bot.plugin import command, on_message

@command("hello", help="say hello", aliases=["hi"], category="custom")
def hello(bot, message, args):
    return "👋 hello " + " ".join(args)          # return a string = the reply
```

Decorator options: `name`, `help`, `aliases`, `category`, `hidden`,
`owner_only`, `admin_only`, `group_only`.

Inside a handler:

| you can use | for |
| --- | --- |
| `bot.client` | the WhatsApp client (`send_text`, `send_image`, `send_video`, `send_audio`, `send_document`, `send_sticker`, `send_reaction`, `profile_picture_url`, `block_contact`, …) |
| `bot.config` | settings from `config.json` |
| `bot.group_settings` | per group toggles |
| `bot.is_admin(group, jid)` | is a member an admin |
| `message.reply(text)` | reply to the message (auto quotes it) |
| `message.send(text)` | send to the same chat |
| `message.react(emoji)` | react to the message |
| `message.text`, `.args`, `.chat`, `.sender`, `.push_name`, `.is_group`, `.mentions`, `.quoted`, `.media_type` | message details |
| `bot.download_media(message)` | bytes of the photo/video/sticker of a message |
| `bot.log` | the logger |

`plugins/example.py` is a working example — delete it or use it as a starting
point.

## How it works

Everything lives in the `xbot` package:

| module | what it implements |
| --- | --- |
| `xbot/crypto/hashes.py` | SHA-1/256/512, HMAC, HKDF, PBKDF2 |
| `xbot/crypto/aes.py` | AES-128/256 in CBC, CTR and GCM (GHASH included) on top of a small constant time-ish core |
| `xbot/crypto/curve.py` | X25519, Ed25519, XEdDSA (`curve25519` + `ed25519` in pure Python) |
| `xbot/wa/tokens.py` | the WhatsApp dictionary tokens and the "packed nibble/hex" rules |
| `xbot/wa/binary.py` | the binary node codec (encoder + decoder, zlib compressed frames, JIDs) |
| `xbot/wa/protoschema.py` | the generated protobuf schema of WhatsApp's messages |
| `xbot/wa/protobuf.py` | a tiny protobuf reader/writer (varints, packed fields, nested messages) |
| `xbot/wa/ws.py` | RFC 6455 WebSocket client (handshake, masking, ping/pong, fragmented frames) |
| `xbot/wa/noise.py` | the Noise XX handshake with WhatsApp's certificate chain |
| `xbot/wa/signal.py` | X3DH, the double ratchet, sender keys, group (skmsg) encryption, pre-key handling |
| `xbot/media.py` | media key derivation, media payload crypto, upload/download to the WhatsApp CDN |
| `xbot/store.py` | the session file (identity keys, account info, sessions) |
| `xbot/client.py` | the WhatsApp client: login, pairing, message send/receive, receipts, retries, pre-keys, groups |
| `xbot/bot/` | the bot itself: plugin registry, `Message` wrapper, runtime, QR encoder |
| `main.py` | the command line entry point |

The wire format follows the multi-device protocol that the official app uses
for *linked devices*: a Noise-encrypted WebSocket to `wss://web.whatsapp.com/ws/chat`,
Signal-encrypted message stanzas, and the same media CDN for attachments.

## Tests

All checks are offline and use no test framework:

```bash
python3 tools/run_all_checks.py       # everything
```

| check | what it proves |
| --- | --- |
| `tests/test_bot.py` | the bot runtime, command parsing and plugins (fake client) |
| `tools/interop/check_binary.py` | our node codec produces byte-identical output to Baileys and decodes its output |
| `tools/interop/check_proto.py` | our protobuf codec matches WhatsApp's schema |
| `tools/interop/check_signal.py` | X3DH + double ratchet + sender keys interoperate with libsignal |
| `tools/interop/check_qr.py` | a real decoder (jsQR) reads every QR we produce, and the terminal rendering round-trips |
| `tools/interop/check_client.py` | a full login against a fake WhatsApp server, ending with an encrypted message that is sent and a reply that is decrypted |

The interop checks need Node.js and a second checkout of Baileys
(`npm install` inside `tools/interop`); the unit tests and the bot itself need
Python only.

## Limitations and safety

* **This is an unofficial client.** It speaks WhatsApp's private protocol and
  that is against WhatsApp's Terms of Service. Accounts *do* get banned for
  using bots — use a number you can afford to lose, and do not spam.
* The bot can only do what a linked device can do: group administration, media,
  reacting, reading chats. Business-only APIs (catalogues, templates) are not
  implemented.
* Voice/video calls, live location and status stories are not fully
  implemented. `on_call` hooks exist but the bot does not answer calls.
* Group-only features need the bot to be an **admin** of the group.
* `sticker`, `toimg` and `toaudio` shell out to `ffmpeg`/`ffprobe` from Termux
  (`pkg install ffmpeg`); without it those three commands answer with an error,
  everything else still works.
* Everything runs in one process with a handful of threads; media is held in
  memory while it is encrypted, and `dl` refuses files above 48 MB so that a big
  video cannot eat all the RAM.
* Keep `session/session.json` secret, and prefer `mode: "self"` (or
  `python main.py --self`) if you do not want other people to use the bot.
