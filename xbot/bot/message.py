"""A friendly wrapper around the raw message dicts produced by the client.

Plugins only ever see :class:`Message` objects, so they never have to poke at
protobuf field names themselves.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional

# protobuf field -> the human readable content it carries
_TEXT_FIELDS = (
    ("conversation", None),
    ("extendedTextMessage", "text"),
    ("imageMessage", "caption"),
    ("videoMessage", "caption"),
    ("documentMessage", "caption"),
    ("audioMessage", "caption"),
    ("stickerMessage", None),
    ("contactMessage", "displayName"),
    ("locationMessage", None),
    ("reactionMessage", "text"),
    ("pollCreationMessage", "name"),
    ("liveLocationMessage", "caption"),
)

_MEDIA_TYPES = {
    "imageMessage": "image",
    "videoMessage": "video",
    "audioMessage": "audio",
    "documentMessage": "document",
    "stickerMessage": "sticker",
}


class Message:
    """One incoming (or outgoing) chat message."""

    def __init__(self, info: dict, client=None):
        self.raw = info
        self.info = info
        self.client = client
        self.key: Dict = dict(info.get("key") or {})
        self.body: Dict = dict(info.get("message") or {})
        self.chat: str = self.key.get("remoteJid") or ""
        self.sender: str = (self.key.get("participant") or self.chat) if self.is_group else self.chat
        self.push_name: Optional[str] = info.get("pushName")
        self.timestamp: int = int(info.get("messageTimestamp") or time.time())
        self.from_me: bool = bool(self.key.get("fromMe"))
        self.id: Optional[str] = self.key.get("id")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Message {self.id} from {self.sender} chat={self.chat} text={self.text!r}>"

    # ------------------------------------------------------------------ basics
    @property
    def is_group(self) -> bool:
        return self.chat.endswith("@g.us")

    @property
    def is_status(self) -> bool:
        return self.chat == "status@broadcast"

    @property
    def text(self) -> str:
        """The text content of the message (caption included)."""
        for field, sub in _TEXT_FIELDS:
            value = self.body.get(field)
            if value is None:
                continue
            if sub:
                text = value.get(sub) if isinstance(value, dict) else value
                if text:
                    return str(text)
            elif isinstance(value, str):
                return value
        # unwrap view-once / ephemeral wrappers
        for wrapper in ("viewOnceMessage", "viewOnceMessageV2", "ephemeralMessage",
                        "documentWithCaptionMessage"):
            inner = (self.body.get(wrapper) or {}).get("message")
            if inner:
                nested = Message({**self.info, "message": inner}, self.client)
                text = nested.text
                if text:
                    return text
        return ""

    @property
    def media_type(self) -> Optional[str]:
        """``image``/``video``/``audio``/``document``/``sticker`` if any."""
        for field, media_type in _MEDIA_TYPES.items():
            body = self.content
            if body.get(field):
                return media_type
        return None

    @property
    def content(self) -> Dict:
        """The actual message content, unwrapping view-once/ephemeral wrappers."""
        body = self.body
        for _ in range(5):
            for wrapper in ("viewOnceMessage", "viewOnceMessageV2", "viewOnceMessageV2Extension",
                            "ephemeralMessage", "documentWithCaptionMessage"):
                inner = (body.get(wrapper) or {}).get("message")
                if inner:
                    body = inner
                    break
            else:
                return body
        return body

    @property
    def media(self) -> Optional[dict]:
        """The media protobuf of the message (if it carries media)."""
        media_type = self.media_type
        if not media_type:
            return None
        for field, kind in _MEDIA_TYPES.items():
            if kind == media_type:
                return self.content.get(field)
        return None

    @property
    def quoted(self) -> Optional[dict]:
        """The quoted message, already prepared for ``reply_text``-style calls."""
        context = (self.content.get("extendedTextMessage") or {}).get("contextInfo")
        if not context:
            for value in self.content.values():
                if isinstance(value, dict) and value.get("contextInfo"):
                    context = value["contextInfo"]
                    break
        if not context or not context.get("quotedMessage"):
            return None
        return {
            "key": {
                "remoteJid": self.chat,
                "fromMe": bool(context.get("participant") == self.info.get("me")),
                "id": context.get("stanzaId"),
                "participant": context.get("participant"),
            },
            "message": context["quotedMessage"],
            "pushName": None,
            "messageTimestamp": 0,
        }

    @property
    def mentions(self) -> List[str]:
        for value in self.content.values():
            if isinstance(value, dict) and value.get("contextInfo", {}).get("mentionedJid"):
                return list(value["contextInfo"]["mentionedJid"])
        return []

    @property
    def is_view_once(self) -> bool:
        return any(key.startswith("viewOnceMessage") for key in self.body)

    def mentioned_me(self, me: Optional[str]) -> bool:
        if not me:
            return False
        return me in self.mentions

    @property
    def command_target(self) -> Optional[str]:
        """A JID mentioned in the message (used by commands like ``.kick``)."""
        mentions = self.mentions
        if mentions:
            return mentions[0]
        return None

    # ------------------------------------------------------------------ output
    def reply(self, text: str, **kwargs) -> None:
        """Send ``text`` quoting this message (fire and forget)."""
        if self.client is not None:
            self.client.reply_text(self.chat, self.raw, text, **kwargs)

    def send(self, text: str, **kwargs) -> None:
        """Send ``text`` to the same chat without quoting (fire and forget)."""
        if self.client is not None:
            self.client.send_text(self.chat, text, **kwargs)

    def react(self, emoji: str) -> None:
        if self.client is not None:
            self.client.send_reaction(self.chat, self.key, emoji)
