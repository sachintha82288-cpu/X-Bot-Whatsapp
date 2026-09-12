"""The bot runtime: config, plugin loading and command dispatch."""

from __future__ import annotations

import importlib
import json
import os
import pkgutil
import sys
import threading
import time
import traceback
from typing import Dict, List, Optional

from ..client import Logger, WAClient
from ..store import AuthStore
from ..wa.binary import Node, jid_decode, jid_normalized
from . import plugin as plugin_api
from .message import Message


class Config:
    """Small JSON backed settings file (``config.json`` next to the bot)."""

    DEFAULTS = {
        "prefix": ".",
        "owner": "",                  # owner phone number, eg. 9477xxxxxxx
        "bot_name": "X-Bot",
        "mode": "public",             # "public" or "self" (only owner may command)
        "language": "en",
        "auto_reconnect": True,
        "owners": [],                 # extra owner numbers
        "disabled": [],               # disabled command names
        "log_level": "info",
    }

    def __init__(self, path: str):
        self.path = path
        self.data = dict(self.DEFAULTS)
        self.lock = threading.RLock()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    self.data.update(json.load(handle))
            except (OSError, ValueError):
                pass

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value) -> None:
        with self.lock:
            self.data[key] = value
            self.save()

    def save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)
        os.replace(temporary, self.path)


class GroupSettings:
    """Per-group toggles (welcome, antilink, ...) stored in one JSON file."""

    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, dict] = {}
        self.lock = threading.RLock()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    self.data = json.load(handle) or {}
            except (OSError, ValueError):
                self.data = {}

    def get(self, group: str, key: str, default=None):
        return (self.data.get(group) or {}).get(key, default)

    def set(self, group: str, key: str, value) -> None:
        with self.lock:
            self.data.setdefault(group, {})[key] = value
            self.save()

    def save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)
        os.replace(temporary, self.path)


class Bot:
    """Wires the WhatsApp client to the plugin system."""

    def __init__(self, client: WAClient, config: Config, logger: Optional[Logger] = None,
                 data_dir: str = "data", plugin_dirs: Optional[List[str]] = None):
        self.client = client
        self.config = config
        self.log = logger or client.log
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(os.path.join(data_dir, "tmp"), exist_ok=True)
        self.group_settings = GroupSettings(os.path.join(data_dir, "groups.json"))
        self.plugin_dirs = plugin_dirs or []
        self.stats = {"started": int(time.time()), "commands": 0, "messages": 0}
        self._afk: Dict[str, dict] = {}
        self.loaded_plugins: List[str] = []
        self._message_lock = threading.Lock()

        client.on("message", self._on_message)
        client.on("notification", self._on_notification)
        client.on("call", self._on_call)
        client.on("receipt", self._on_receipt)

    # ------------------------------------------------------------- properties
    @property
    def me(self) -> Optional[str]:
        return self.client.me_id

    @property
    def me_number(self) -> str:
        decoded = jid_decode(self.client.me_id or "")
        return decoded[0] if decoded else ""

    @property
    def me_lid(self) -> Optional[str]:
        return self.client.me_lid

    @property
    def prefix(self) -> str:
        return self.config.get("prefix", ".")

    def is_owner(self, jid: Optional[str]) -> bool:
        decoded = jid_decode(jid or "")
        number = decoded[0] if decoded else ""
        if not number:
            return False
        owners = [str(self.config.get("owner") or "").lstrip("+")]
        owners += [str(item).lstrip("+") for item in self.config.get("owners") or []]
        if self.me_number:
            owners.append(self.me_number)
        return number in {owner for owner in owners if owner}

    def is_self_mode(self) -> bool:
        return str(self.config.get("mode", "public")).lower() == "self"

    # ----------------------------------------------------------------- plugins
    def load_plugins(self) -> List[str]:
        """Import every plugin module found on the plugin paths."""
        modules = []
        package_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
        modules.extend(self._modules_in(package_dir, "xbot.bot.plugins"))
        for directory in self.plugin_dirs:
            if os.path.isdir(directory):
                modules.extend(self._modules_in(directory, None))
        for name, module_name in modules:
            try:
                if module_name:
                    # reload() re-runs the decorators, a plain import of an
                    # already imported module is a no-op (so .reload would lose
                    # every built-in command)
                    loaded = sys.modules.get(module_name)
                    if loaded is not None:
                        importlib.reload(loaded)
                    else:
                        importlib.import_module(module_name)
                else:
                    spec = importlib.util.spec_from_file_location(f"xbot_plugin_{name}", name)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                self.loaded_plugins.append(os.path.basename(name))
            except Exception as exc:  # pragma: no cover - plugin errors
                self.log.error("plugin %s failed to load: %s", name, exc)
                self.log.debug("%s", traceback.format_exc())
        self.log.info("loaded %d plugin files, %d commands",
                      len(self.loaded_plugins), len(plugin_api.all_commands()))
        return self.loaded_plugins

    def get_plugin_commands(self):
        """Every registered command (used by the menu and by tests)."""
        return plugin_api.all_commands()

    def reload_plugins(self) -> None:
        plugin_api.reset()
        self.loaded_plugins = []
        self.load_plugins()

    @staticmethod
    def _modules_in(directory: str, package: Optional[str]) -> List[tuple]:
        found = []
        if not os.path.isdir(directory):
            return found
        for entry in sorted(os.listdir(directory)):
            if entry.startswith("_") or not entry.endswith(".py"):
                continue
            path = os.path.join(directory, entry)
            module_name = f"{package}.{entry[:-3]}" if package else None
            found.append((path, module_name))
        return found

    # ------------------------------------------------------------- dispatching
    def _on_message(self, info: dict) -> None:
        try:
            message = Message(info, self.client)
        except Exception as exc:  # pragma: no cover
            self.log.debug("could not wrap message: %s", exc)
            return
        self.stats["messages"] += 1
        if message.body.get("messageStubType") is not None:
            self._notify_stub(message)
        self.handle_message(message)

    def handle_message(self, message: Message) -> Optional[str]:
        """Run the message through the plugin pipeline (blocking)."""
        if not self._accept(message):
            return None
        if self.is_self_mode() and not self.is_owner(message.sender):
            return None

        parsed = plugin_api.parse_command(message.text, self.prefix)
        handled_result: Optional[str] = None

        if parsed:
            name, args = parsed
            entry = plugin_api.COMMANDS.get(name)
            disabled = {item.lower() for item in self.config.get("disabled") or []}
            if entry is None:
                return None
            if name in disabled or entry.name in disabled:
                return None
            if entry.owner_only and not self.is_owner(message.sender):
                message.reply("⛔ this command is for the owner only")
                return None
            if entry.group_only and not message.is_group:
                message.reply("⛔ this command only works in groups")
                return None
            if entry.admin_only and message.is_group and not self.is_admin(message.chat, message.sender):
                message.reply("⛔ you need to be a group admin to do that")
                return None

            self.stats["commands"] += 1
            try:
                with self._message_lock:
                    handled_result = entry.func(self, message, args)
                # a handler that *returns* text instead of calling reply() still works
                if isinstance(handled_result, str) and handled_result.strip():
                    message.reply(handled_result)
                    handled_result = None
            except Exception as exc:
                self.log.error("command .%s failed: %s", entry.name, exc)
                self.log.debug("%s", traceback.format_exc())
                try:
                    message.reply(f"❌ error: {exc}")
                except Exception:  # pragma: no cover
                    pass
                return None

        for hook in plugin_api.message_hooks():
            try:
                with self._message_lock:
                    hooked_result = hook(self, message)
                if isinstance(hooked_result, str) and hooked_result.strip():
                    message.reply(hooked_result)
            except Exception as exc:  # pragma: no cover
                self.log.error("message hook %s failed: %s", getattr(hook, "__name__", "?"), exc)
        return handled_result

    def _accept(self, message: Message) -> bool:
        if not message.text and message.media_type is None and not message.body:
            return False
        if message.from_me:
            return False
        return True

    def dispatch_async(self, message: Message) -> None:
        """Handle a message on a worker thread (keeps the socket reader free)."""
        thread = threading.Thread(target=self.handle_message, args=(message,), daemon=True)
        thread.start()

    # -------------------------------------------------------------- group admin
    def is_admin(self, group: str, jid: Optional[str]) -> bool:
        if not jid:
            return False
        try:
            metadata = self.client.group_metadata(group)
        except Exception:
            return False
        target = jid_normalized(jid)
        for participant in metadata.get("participants", []):
            normalized = jid_normalized(participant.get("id"))
            if normalized and normalized == target:
                return participant.get("admin") in ("admin", "superadmin")
        return False

    def _group_query(self, group: str, action: str, children: List[Node],
                     query_tag: str = "set") -> Optional[Node]:
        node = Node("iq", {"type": query_tag, "xmlns": "w:g2", "to": group},
                    [Node(action, {}, children)])
        return self.client.query(node)

    def group_update_participants(self, group: str, action: str,
                                  jids: List[str]) -> List[dict]:
        """``action`` is one of add/remove/promote/demote."""
        nodes = [Node("participant", {"jid": jid}) for jid in jids]
        result = self._group_query(group, action, nodes)
        updated = []
        parent = result.child(action) if result is not None else None
        for participant in parent.children("participant") if parent is not None else []:
            updated.append({"jid": participant.attrs.get("jid"),
                            "status": participant.attrs.get("error") or "200"})
        return updated

    def kick(self, group: str, jids: List[str]) -> List[dict]:
        return self.group_update_participants(group, "remove", jids)

    def add(self, group: str, jids: List[str]) -> List[dict]:
        return self.group_update_participants(group, "add", jids)

    def promote(self, group: str, jids: List[str]) -> List[dict]:
        return self.group_update_participants(group, "promote", jids)

    def demote(self, group: str, jids: List[str]) -> List[dict]:
        return self.group_update_participants(group, "demote", jids)

    def set_subject(self, group: str, subject: str) -> None:
        node = Node("iq", {"type": "set", "xmlns": "w:g2", "to": group},
                    [Node("subject", {}, subject.encode())])
        self.client.query(node)

    def set_description(self, group: str, description: Optional[str]) -> None:
        metadata = self.client.group_metadata(group)
        previous = metadata.get("descId")
        attrs = {"delete": "true"} if not description else {"id": self.client.next_tag()}
        if previous:
            attrs["prev"] = previous
        content = [Node("body", {}, description.encode())] if description else None
        node = Node("iq", {"type": "set", "xmlns": "w:g2", "to": group},
                    [Node("description", attrs, content)])
        self.client.query(node)

    def group_invite_code(self, group: str, revoke: bool = False) -> Optional[str]:
        action = "invite"
        node = Node("iq", {"type": "set" if revoke else "get", "xmlns": "w:g2", "to": group},
                    [Node(action, {})])
        result = self.client.query(node)
        invite = result.child("invite") if result is not None else None
        return invite.attrs.get("code") if invite is not None else None

    def leave_group(self, group: str) -> None:
        node = Node("iq", {"type": "set", "xmlns": "w:g2", "to": "@g.us"},
                    [Node("leave", {}, [Node("group", {"id": group})])])
        self.client.query(node)

    # ------------------------------------------------------------ misc helpers
    def group_participants(self, group: str) -> List[str]:
        metadata = self.client.group_metadata(group)
        return [participant["id"] for participant in metadata.get("participants", [])
                if participant.get("id")]

    def set_afk(self, jid: str, reason: str = "AFK") -> None:
        self._afk[jid] = {"reason": reason, "since": int(time.time())}

    def clear_afk(self, jid: str) -> Optional[dict]:
        return self._afk.pop(jid, None)

    def get_afk(self, jid: str) -> Optional[dict]:
        return self._afk.get(jid)

    def download_media(self, message: Message) -> Optional[bytes]:
        media_type = message.media_type
        if not media_type:
            return None
        body = message.media or {}
        return self.client.download_media(body, media_type)

    def reply(self, message: Message, text: str) -> None:
        message.reply(text)

    # --------------------------------------------------------------- events
    # group system messages (add/remove/promote/…) arrive as stub messages
    JOIN_STUBS = {27: "add", 31: "add"}           # GROUP_PARTICIPANT_ADD / INVITE
    LEAVE_STUBS = {28: "remove", 32: "leave"}     # GROUP_PARTICIPANT_REMOVE / LEAVE

    def _notify_group_event(self, action: str, group: str, jids: List[str],
                            author: Optional[str] = None) -> None:
        hooks = plugin_api.join_hooks() if action == "add" else plugin_api.leave_hooks()
        for jid in jids:
            for hook in hooks:
                try:
                    hook(self, group, {"jid": jid, "author": author}, action)
                except Exception as exc:  # pragma: no cover
                    self.log.error("participant hook failed: %s", exc)

    def _notify_stub(self, message: "Message") -> None:
        """Handle group system messages (participant added/removed/…)."""
        body = message.body or {}
        stub = body.get("messageStubType")
        if stub is None:
            return
        try:
            stub = int(stub)
        except (TypeError, ValueError):
            return
        params = []
        for value in body.get("messageStubParameters") or []:
            if isinstance(value, (bytes, bytearray)):
                params.append(value.decode("utf-8", "replace"))
            else:
                params.append(str(value))
        action = None
        if stub in self.JOIN_STUBS:
            action = "add"
        elif stub in self.LEAVE_STUBS:
            action = "remove"
        if action and params:
            self._notify_group_event(action, message.chat, params, message.sender)

    def _on_notification(self, node: Node) -> None:
        child = node.content[0] if isinstance(node.content, list) and node.content else None
        if child is None:
            return
        if child.tag == "participant" and child.attrs.get("update") in ("add", "remove"):
            # group participant change notification
            group = node.attrs.get("from")
            payload = {}
            for item in child.content if isinstance(child.content, list) else []:
                if item.tag == "participant":
                    payload = item.attrs
            action = child.attrs.get("update")
            for hook in plugin_api.join_hooks() if action == "add" else plugin_api.leave_hooks():
                try:
                    hook(self, group, payload, action)
                except Exception as exc:  # pragma: no cover
                    self.log.error("participant hook failed: %s", exc)

    def _on_call(self, node: Node) -> None:
        for hook in plugin_api.call_hooks():
            try:
                hook(self, node)
            except Exception as exc:  # pragma: no cover
                self.log.error("call hook failed: %s", exc)

    def _on_receipt(self, node: Node) -> None:
        # ack receipts so the phone does not keep resending them
        self.client._send_ack(node)


__all__ = ["Bot", "Config", "GroupSettings"]
