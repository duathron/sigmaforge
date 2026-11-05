"""Single-line sanitizing for untrusted text (rule titles, engine output) at terminal sinks."""

import re

from shipwright_kit.security.render import safe_render

_LINE_BREAKS = re.compile(r"[\r\n\t\x0b\x0c\x1c\x1d\x1e\x85  ]+")


def plain_safe(x: object) -> str:
    """Line breaks and tabs flattened to a space, then control/ANSI/OSC/bidi characters stripped.
    No markup escaping: for plain sinks (logging to stderr). Rich sinks add `escape` on top."""
    return safe_render(_LINE_BREAKS.sub(" ", str(x)), escape_markup=False)
