"""Example user plugin.

Every ``*.py`` file in this folder is loaded automatically on start-up (and
again when the owner sends ``.reload``), so you can add your own commands
without touching the rest of the bot.  Delete this file if you do not want it.

    from xbot.bot.plugin import command

    @command("name", help="what it does", aliases=["alias"],
             category="custom", owner_only=False, admin_only=False, group_only=False)
    def handler(bot, message, args):
        # return a string -> sent as the reply, or call message.reply(...) yourself
        return "hello " + " ".join(args)
"""

from xbot.bot.plugin import command, on_message


@command("hello", help="say hello (example plugin)", aliases=["hi"], category="custom")
def hello(bot, message, args):
    who = " ".join(args) or (message.push_name or "there")
    return f"👋 hello {who}!\nthis command lives in `plugins/example.py`"


SEEN = {"count": 0}


@on_message
def count_messages(bot, message):
    """Called for every incoming message, before the command parser runs.

    Returning a string replies to the message; returning ``None`` stays quiet.
    """
    SEEN["count"] += 1
    bot.log.debug("example plugin saw %d messages", SEEN["count"])
    return None
