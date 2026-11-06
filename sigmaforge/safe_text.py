"""Single-line sanitizing for untrusted text (rule titles, engine output) at terminal sinks."""

import re

from shipwright_kit.security.render import safe_render

_LINE_BREAKS = re.compile(r"[\r\n\t\x0b\x0c\x1c\x1d\x1e\x85  ]+")


def plain_safe(x: object) -> str:
    """Line breaks and tabs flattened to a space, then control/ANSI/OSC/bidi characters stripped.
    No markup escaping: for plain sinks (logging to stderr). Rich sinks add `escape` on top."""
    return safe_render(_LINE_BREAKS.sub(" ", str(x)), escape_markup=False)


#: Budget for any untrusted error message printed to a terminal (same as the stderr tail).
ERROR_CAP = 600
_TRUNCATED = " [truncated]"


def plain_safe_capped(x: object, limit: int = ERROR_CAP) -> str:
    """`plain_safe` of at most `limit` characters of `str(x)`, with a visible marker when cut.
    Cut BEFORE sanitizing so the cost is bounded however large the message is."""
    s = str(x)
    cut = len(s) > limit
    return plain_safe(s[:limit]) + (_TRUNCATED if cut else "")


_BRACKET = re.compile(r"(\\*)\[")


def markup_escape(s: str) -> str:
    """Escape EVERY `[` for a Rich markup sink (`rich.markup.escape` leaves unterminated tags raw,
    so two values in one string, or a value before a trusted tag, could form a live tag).
    A backslash run directly before `[` is doubled and the bracket gets one more backslash (odd
    run = literal bracket). A trailing backslash run is made EVEN so it cannot escape a trusted
    tag that follows the value."""
    out = _BRACKET.sub(lambda m: m.group(1) * 2 + "\\[", s)
    run = len(out) - len(out.rstrip("\\"))
    return out + "\\" if run % 2 else out
