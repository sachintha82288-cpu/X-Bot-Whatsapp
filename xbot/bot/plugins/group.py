"""Group management commands and automatic group features."""

from __future__ import annotations

import time
from typing import List, Optional

from .. import plugin as plugin_api
from ...wa.binary import jid_decode, jid_encode, jid_normalized

LINK_PATTERN = ("chat.whatsapp.com", "wa.me/", "t.me/", "telegram.me", "http://", "https://")


def _targets(message, bot) -> List[str]:
    """Mentioned users, or the quoted message's author."""
    targets = list(message.mentions)
    if not targets:
        quoted = message.quoted
        if quoted and quoted.get("key", {}).get("participant"):
            targets.append(quoted["key"]["participant"])
        elif quoted and quoted.get("key", {}).get("remoteJid") and not message.is_group:
            targets.append(quoted["key"]["remoteJid"])
    if not targets and not message.is_group and message.quoted is None:
        targets.append(message.chat)
    return [jid_normalized(jid) for jid in targets if jid]


def _number_of(jid: str) -> str:
    decoded = jid_decode(jid)
    return decoded[0] if decoded else jid


def _status_text(updated: List[dict]) -> str:
    ok = [item for item in updated if str(item.get("status")) == "200"]
    failed = [item for item in updated if str(item.get("status")) != "200"]
    lines = []
    for item in ok:
        lines.append(f"✅ {_number_of(item['jid'])}")
    for item in failed:
        lines.append(f"❌ {_number_of(item['jid'])} ({item['status']})")
    return "\n".join(lines) or "no changes"


# --------------------------------------------------------------------------
# participants
# --------------------------------------------------------------------------


@plugin_api.command("kick", help="remove a member (reply or @mention)", group_only=True,
                    admin_only=True, aliases=["remove"], category="group")
def kick(bot, message, args):
    targets = _targets(message, bot)
    if not targets:
        return message.reply("❓ mention somebody or reply to their message")
    if any(bot.is_owner(target) for target in targets):
        return message.reply("⛔ I will not kick my owner")
    return message.reply("🚪 " + _status_text(bot.kick(message.chat, targets)))


@plugin_api.command("add", help="add a member by number", group_only=True, admin_only=True,
                    category="group")
def add(bot, message, args):
    numbers = [arg for arg in args if any(ch.isdigit() for ch in arg)]
    if not numbers:
        return message.reply("usage: add 947XXXXXXXX")
    jids = [jid_encode("".join(ch for ch in number if ch.isdigit()), "s.whatsapp.net")
            for number in numbers]
    return message.reply("➕ " + _status_text(bot.add(message.chat, jids)))


@plugin_api.command("promote", help="make somebody an admin", group_only=True,
                    admin_only=True, aliases=["admin"], category="group")
def promote(bot, message, args):
    targets = _targets(message, bot)
    if not targets:
        return message.reply("❓ mention somebody or reply to their message")
    return message.reply("⭐ " + _status_text(bot.promote(message.chat, targets)))


@plugin_api.command("demote", help="remove admin rights", group_only=True, admin_only=True,
                    aliases=["unadmin"], category="group")
def demote(bot, message, args):
    targets = _targets(message, bot)
    if not targets:
        return message.reply("❓ mention somebody or reply to their message")
    return message.reply("⬇️ " + _status_text(bot.demote(message.chat, targets)))


@plugin_api.command("tagall", help="mention everybody", group_only=True, admin_only=True,
                    aliases=["everyone"], category="group")
def tagall(bot, message, args):
    participants = bot.group_participants(message.chat)
    if not participants:
        return message.reply("❓ no participants found")
    reason = " ".join(args) or "attention please"
    names = "\n".join(f"› {_number_of(jid)}" for jid in participants)
    return bot.client.send_message(message.chat, {
        "extendedTextMessage": {
            "text": f"📢 *{reason}*\n\n{names}",
            "contextInfo": {"mentionedJid": participants},
        },
    })


@plugin_api.command("groupinfo", help="show group details", group_only=True,
                    aliases=["ginfo"], category="group")
def groupinfo(bot, message, args):
    metadata = bot.client.group_metadata(message.chat)
    admins = [participant["id"] for participant in metadata.get("participants", [])
              if participant.get("admin") in ("admin", "superadmin")]
    return message.reply(
        f"📋 *{metadata.get('subject') or 'group'}*\n"
        f"🆔 `{metadata.get('id')}`\n"
        f"👥 members: {len(metadata.get('participants', []))}\n"
        f"⭐ admins: {len(admins)}\n"
        f"🔗 addressing: {metadata.get('addressing_mode', 'pn')}"
    )


@plugin_api.command("invite", help="get the group invite link", group_only=True,
                    admin_only=True, category="group")
def invite(bot, message, args):
    code = bot.group_invite_code(message.chat, revoke="new" in args)
    if not code:
        return message.reply("❌ could not fetch the invite link")
    return message.reply(f"🔗 https://chat.whatsapp.com/{code}")


@plugin_api.command("setsubject", help="rename the group", group_only=True, admin_only=True,
                    category="group")
def set_subject(bot, message, args):
    if not args:
        return message.reply("usage: setname <new subject>")
    subject = " ".join(args)
    bot.set_subject(message.chat, subject)
    return message.reply(f"✅ group renamed to *{subject}*")


@plugin_api.command("setdesc", help="change the group description", group_only=True,
                    admin_only=True, category="group")
def set_description(bot, message, args):
    if not args:
        return message.reply("usage: setdesc <text> | setdesc clear")
    description = None if args[0].lower() == "clear" else " ".join(args)
    bot.set_description(message.chat, description)
    return message.reply("✅ description updated")


@plugin_api.command("leave", help="make the bot leave the group", group_only=True,
                    admin_only=True, category="group")
def leave(bot, message, args):
    message.reply("👋 leaving…")
    bot.leave_group(message.chat)
    return None


# --------------------------------------------------------------------------
# group toggles
# --------------------------------------------------------------------------

_TOGGLES = {
    "welcome": "send a greeting when somebody joins",
    "goodbye": "say goodbye when somebody leaves",
    "antilink": "delete links posted by non admins",
    "antidelete": "notify when a message is deleted",
    "antibot": "ignore other bots",
}


@plugin_api.command("toggle", help="turn group features on/off", group_only=True,
                    admin_only=True, aliases=["set"], category="group")
def toggle(bot, message, args):
    if len(args) < 2 or args[0].lower() not in _TOGGLES:
        lines = [f"`{name}` — {help_text}" for name, help_text in _TOGGLES.items()]
        return message.reply("usage: toggle <feature> on|off\n\n" + "\n".join(lines))
    feature = args[0].lower()
    value = args[1].lower() in ("on", "true", "yes", "1")
    bot.group_settings.set(message.chat, feature, value)
    return message.reply(f"{'✅ enabled' if value else '🚫 disabled'} *{feature}*")


@plugin_api.command("welcome", help="set the welcome message", group_only=True,
                    admin_only=True, category="group")
def set_welcome(bot, message, args):
    if not args:
        current = bot.group_settings.get(message.chat, "welcome_text",
                                        "👋 Welcome @user to *@group*!")
        return message.reply(f"current welcome:\n{current}\n\nusage: welcome <text>")
    bot.group_settings.set(message.chat, "welcome_text", " ".join(args))
    bot.group_settings.set(message.chat, "welcome", True)
    return message.reply("✅ welcome message saved")


@plugin_api.command("goodbye", help="set the goodbye message", group_only=True,
                    admin_only=True, category="group")
def set_goodbye(bot, message, args):
    if not args:
        current = bot.group_settings.get(message.chat, "goodbye_text", "👋 @user left the group")
        return message.reply(f"current goodbye:\n{current}\n\nusage: goodbye <text>")
    bot.group_settings.set(message.chat, "goodbye_text", " ".join(args))
    bot.group_settings.set(message.chat, "goodbye", True)
    return message.reply("✅ goodbye message saved")


@plugin_api.command("mute", help="only admins may talk", group_only=True, admin_only=True,
                    aliases=["close"], category="group")
def mute(bot, message, args):
    from ...wa.binary import Node

    bot.client.query(Node("iq", {"to": message.chat, "type": "set", "xmlns": "w:g2"},
                          [Node("announcement", {})]))
    return message.reply("🔇 group is now admin-only")


@plugin_api.command("unmute", help="everybody may talk again", group_only=True,
                    admin_only=True, aliases=["open"], category="group")
def unmute(bot, message, args):
    from ...wa.binary import Node

    bot.client.query(Node("iq", {"to": message.chat, "type": "set", "xmlns": "w:g2"},
                          [Node("not_announcement", {})]))
    return message.reply("🔊 group is open for everybody")


# --------------------------------------------------------------------------
# automatic features
# --------------------------------------------------------------------------


def _render(template: str, participant: str, group: str, metadata: dict) -> tuple:
    user = _number_of(participant)
    text = (template.replace("@user", f"@{user}")
                    .replace("@group", metadata.get("subject") or "this group")
                    .replace("@desc", metadata.get("desc") or ""))
    return text, [participant]


@plugin_api.on_join
def _on_join(bot, group: str, participant: dict, action: str) -> None:
    if not group or not bot.group_settings.get(group, "welcome", False):
        return
    jid = participant.get("jid")
    if not jid:
        return
    template = bot.group_settings.get(group, "welcome_text", "👋 Welcome @user to *@group*!")
    try:
        metadata = bot.client.group_metadata(group)
    except Exception:
        metadata = {}
    text, mentions = _render(template, jid, group, metadata)
    bot.client.send_message(group, {
        "extendedTextMessage": {"text": text, "contextInfo": {"mentionedJid": mentions}},
    })


@plugin_api.on_leave
def _on_leave(bot, group: str, participant: dict, action: str) -> None:
    if not group or not bot.group_settings.get(group, "goodbye", False):
        return
    jid = participant.get("jid")
    if not jid:
        return
    template = bot.group_settings.get(group, "goodbye_text", "👋 @user left the group")
    text, mentions = _render(template, jid, group, {})
    bot.client.send_message(group, {
        "extendedTextMessage": {"text": text, "contextInfo": {"mentionedJid": mentions}},
    })


@plugin_api.command("antilink", help="delete links posted by non admins (alias of toggle)",
                    group_only=True, admin_only=True, category="group")
def antilink(bot, message, args):
    value = not args or args[0].lower() in ("on", "true", "yes", "1")
    bot.group_settings.set(message.chat, "antilink", value)
    return message.reply(f"{'✅ enabled' if value else '🚫 disabled'} antilink")


@plugin_api.on_message
def _antilink_guard(bot, message) -> None:
    if not message.is_group or message.from_me:
        return
    if not bot.group_settings.get(message.chat, "antilink", False):
        return
    text = message.text.lower()
    if not text or not any(token in text for token in LINK_PATTERN):
        return
    if bot.is_admin(message.chat, message.sender) or bot.is_owner(message.sender):
        return
    try:
        bot.client.send_message(message.chat, {
            "protocolMessage": {
                "key": {"remoteJid": message.chat, "fromMe": False,
                        "id": message.id, "participant": message.sender},
                "type": 0,  # REVOKE
            },
        })
        message.reply(f"⛔ links are not allowed here, {_number_of(message.sender)}")
    except Exception:
        pass


@plugin_api.on_message
def _afk_notice(bot, message) -> None:
    if message.from_me:
        entry = bot.clear_afk(message.chat)
        if entry and message.text:
            return message.reply("👋 welcome back! AFK is now off")
        return
    entry = bot.get_afk(message.sender)
    if entry and not message.is_group:
        minutes = max(1, (int(time.time()) - entry["since"]) // 60)
        return message.reply(f"💤 away for {minutes} min — {entry['reason']}")


@plugin_api.command("afk", help="mark yourself as away", category="tools")
def afk(bot, message, args):
    reason = " ".join(args) or "AFK"
    bot.set_afk(message.chat if not message.is_group else message.sender, reason)
    return message.reply(f"💤 you are now AFK: {reason}")
