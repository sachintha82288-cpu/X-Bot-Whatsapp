"""Plugin registry and decorators.

A plugin is just a module inside ``xbot/bot/plugins`` (or ``plugins/`` at the
root of the checkout) that imports :mod:`xbot.bot.plugin` and registers
handlers::

    from xbot.bot.plugin import command, on_message

    @command("ping", help="check that the bot is alive")
    def ping(bot, msg, args):
        return "pong"
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

# command name -> Command
COMMANDS: Dict[str, "Command"] = {}
# aliases resolve to the same Command
_message_hooks: List[Callable] = []
_join_hooks: List[Callable] = []
_leave_hooks: List[Callable] = []
_call_hooks: List[Callable] = []


class Command:
    __slots__ = ("name", "func", "help", "owner_only", "admin_only", "group_only",
                 "aliases", "category", "hidden")

    def __init__(self, name: str, func: Callable, help: str = "", owner_only: bool = False,
                 admin_only: bool = False, group_only: bool = False,
                 aliases: Optional[List[str]] = None, category: str = "general",
                 hidden: bool = False):
        self.name = name
        self.func = func
        self.help = help
        self.owner_only = owner_only
        self.admin_only = admin_only
        self.group_only = group_only
        self.aliases = aliases or []
        self.category = category
        self.hidden = hidden

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Command .{self.name}>"


def command(name: str, help: str = "", owner_only: bool = False, admin_only: bool = False,
            group_only: bool = False, aliases: Optional[List[str]] = None,
            category: str = "general", hidden: bool = False):
    """Register a command handler."""
    def decorator(func: Callable) -> Callable:
        entry = Command(name, func, help, owner_only, admin_only, group_only,
                        aliases, category, hidden)
        COMMANDS[name] = entry
        for alias in aliases or []:
            COMMANDS[alias] = entry
        return func
    return decorator


def on_message(func: Callable) -> Callable:
    """Run for every message (even non-commands)."""
    _message_hooks.append(func)
    return func


def on_join(func: Callable) -> Callable:
    """Run when somebody is added to a group."""
    _join_hooks.append(func)
    return func


def on_leave(func: Callable) -> Callable:
    """Run when somebody leaves / is removed from a group."""
    _leave_hooks.append(func)
    return func


def on_call(func: Callable) -> Callable:
    """Run when an incoming call event arrives."""
    _call_hooks.append(func)
    return func


def message_hooks() -> List[Callable]:
    return list(_message_hooks)


def join_hooks() -> List[Callable]:
    return list(_join_hooks)


def leave_hooks() -> List[Callable]:
    return list(_leave_hooks)


def call_hooks() -> List[Callable]:
    return list(_call_hooks)


def parse_command(text: str, prefixes: str = ".") -> Optional[tuple]:
    """``'.kick @user now'`` -> ``('kick', ['@user', 'now'])``."""
    if not text:
        return None
    text = text.strip()
    if not text or text[0] not in prefixes:
        return None
    rest = text[1:].strip()
    if not rest:
        return None
    parts = re.split(r"\s+", rest)
    name = parts[0].lower()
    if not re.fullmatch(r"[a-z0-9_]+", name):
        return None
    return name, parts[1:]


def all_commands() -> List[Command]:
    unique = {}
    for entry in COMMANDS.values():
        unique[entry.name] = entry
    return sorted(unique.values(), key=lambda item: (item.category, item.name))


__all__ = [
    "COMMANDS", "Command", "command", "on_message", "on_join", "on_leave", "on_call",
    "parse_command", "all_commands", "message_hooks", "join_hooks", "leave_hooks",
    "call_hooks",
]
