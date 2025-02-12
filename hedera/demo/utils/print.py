import json

from prompt_toolkit.formatted_text import FormattedText, PygmentsTokens
from prompt_toolkit.shortcuts import clear, print_formatted_text
import pygments
from pygments.filter import Filter
from pygments.lexer import Lexer

from pygments.lexers.data import JsonLdLexer

COLORIZE = True


class PrefixFilter(Filter):
    def __init__(self, **options):
        Filter.__init__(self, **options)
        self.prefix = options.get("prefix")

    def lines(self, stream):
        line = []
        for ttype, value in stream:
            if "\n" in value:
                parts = value.split("\n")
                value = parts.pop()
                for part in parts:
                    line.append((ttype, part))
                    line.append((ttype, "\n"))
                    yield line
                    line = []
            line.append((ttype, value))
        if line:
            yield line

    def filter(self, lexer, stream):
        if isinstance(self.prefix, str):
            prefix = ((pygments.token.Generic, self.prefix),)
        elif self.prefix:
            prefix = self.prefix
        else:
            prefix = ()
        for line in self.lines(stream):
            yield from prefix
            yield from line


def clear_screen():
    clear()


def print_lexer(
    body: str,
    lexer: Lexer,
    label: str | None = None,
    prefix: str | None = None,
    indent: int = 2,
):
    if COLORIZE:
        prefix_str = prefix + " " if prefix else ""
        if prefix_str or indent:
            prefix_body = prefix_str + " " * (indent or 0)
            lexer.add_filter(PrefixFilter(prefix=prefix_body))
        tokens = list(pygments.lex(body, lexer=lexer))
        if label:
            fmt_label = [("fg:ansimagenta", label)]
            if prefix_str:
                fmt_label.insert(0, ("", prefix_str))
            print_formatted_text(FormattedText(fmt_label))
        print_formatted_text(PygmentsTokens(tokens))
    else:
        notify(body, label=label, prefix=prefix)


def notify(
    prefix,
    msg,
    color: str | None = None,
    label: str | None = None,
    indent: int | None = None,
    **kwargs,
):
    prefix_str = prefix or ""
    msg = [msg]
    if prefix:
        prefix_str = f"[{prefix}]"
    if indent:
        prefix_str += " " * indent
    if color and COLORIZE:
        msg = [(color, " ".join(map(str, msg)))]
        if prefix_str:
            msg.insert(0, ("", prefix_str + " "))
        if label:
            msg.insert(0, ("fg:ansimagenta", label + "\n"))
        print_formatted_text(FormattedText(msg), **kwargs)
        return
    if label:
        print(label, **kwargs)
    if prefix_str:
        msg = (prefix_str, *msg)
    print(*msg, **kwargs)


def notify_json(data, label: str | None = None, prefix: str | None = "", indent: int = 2):
    data = json.dumps(data, indent=2)

    print_lexer(body=data, lexer=JsonLdLexer(), label=label, prefix=prefix, indent=indent)
