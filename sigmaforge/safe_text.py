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
