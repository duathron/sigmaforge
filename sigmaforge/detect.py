"""Example parse boundary — classify an untrusted input string.

Framework input-contract rule: external/garbage input never raises;
unrecognized input returns "unknown". Replace with your real logic.
"""

from __future__ import annotations

import re

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HASH = re.compile(r"^[A-Fa-f0-9]{32,64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z]{2,})+$")
# File extensions that look like TLDs but are not valid domains for our purposes.
_FILE_EXTS = re.compile(
    r"\.(dll|exe|so|dylib|sys|bin|bat|cmd|sh|ps1"
    r"|py|js|ts|rb|go|rs|c|cpp|h|java|class|jar|war"
    r"|zip|tar|gz|bz2|xz|7z|rar"
    r"|pdf|doc|docx|xls|xlsx|ppt|pptx"
    r"|png|jpg|jpeg|gif|svg|ico|mp3|mp4|avi|mov|mkv"
    r"|log|txt|csv|json|xml|yaml|yml|toml|ini|cfg|conf|env)$",
    re.IGNORECASE,
)


def classify(value: object) -> str:
    """Return a coarse type for value. Never raises; unknown -> "unknown"."""
    if not isinstance(value, str):
        return "unknown"
    v = value.strip()
    if not v:
        return "unknown"
    if _IPV4.match(v):
        parts = v.split(".")
        if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return "ipv4"
        return "unknown"
    if _HASH.match(v):
        return "hash"
    if _DOMAIN.match(v) and not _FILE_EXTS.search(v):
        return "domain"
    return "unknown"
