import re
from pathlib import Path

from sigmaforge.main import app

REPO = Path(__file__).resolve().parent.parent

# Every way dogfood.sh / justfile spell a sigmaforge subcommand call.
_PATTERNS = (
    r'"\$CMD"\s+(\w[\w-]*)',
    r"\bsigmaforge\s+(\w[\w-]*)",
    r'^\s*run\s+\S+\s+(?:"\$CMD"|sigmaforge)\s+(\w[\w-]*)',
    # unquoted spellings: $CMD word / ${CMD} word / "${CMD}" word
    r'(?:"?\$\{CMD\}"?|\$CMD)\s+(\w[\w-]*)',
)


def _registered() -> set[str]:
    return {(c.name or c.callback.__name__.replace("_", "-")) for c in app.registered_commands}


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for pat in _PATTERNS:
        out.update(re.findall(pat, text, re.M))
    return out


def test_dogfood_never_calls_removed_commands():
    registered = _registered()
    for name in ("dogfood.sh", "justfile"):
        tokens = _tokens((REPO / name).read_text())
        assert tokens, f"{name}: no subcommand call found"
        # `sigmaforge` + a bare word can also be prose; only flag words that are not commands
        # AND not a known non-command word ("version"/"--help" style tokens are root options).
        unknown = tokens - registered
        assert not unknown, f"{name} calls unregistered subcommands: {sorted(unknown)}"


def test_dogfood_is_not_vacuous():
    tokens = _tokens((REPO / "dogfood.sh").read_text())
    assert {"manual", "backtest", "hunt"} <= tokens


def test_dogfood_calls_are_hermetic():
    text = (REPO / "dogfood.sh").read_text()
    assert "env -u SIGMAFORGE_HOME -u SIGMAFORGE_ZIRCOLITE" in text
    for line in text.splitlines():
        if re.match(r'^\s*run\s+\S+\s+"\$CMD"\s+(backtest|hunt)\s+(?!--help)', line):
            assert '--config "$EMPTY_CFG"' in line, line


def test_tokens_catch_unquoted_cmd_spellings():
    assert _tokens("  run 0 $CMD classify x") >= {"classify"}
    assert _tokens("  run 0 ${CMD} gone x") >= {"gone"}
    assert _tokens('  run 0 "${CMD}" gone2 x') >= {"gone2"}
    assert _tokens("  uv run $CMD gone3") >= {"gone3"}


def test_dogfood_has_a_past_preflight_case():
    text = (REPO / "dogfood.sh").read_text()
    assert '--engine-home "$FAKE_ENGINE"' in text and "ESC byte" in text
