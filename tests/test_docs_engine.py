"""Docs must not claim the current directory is a config/engine source, and must document the rule."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = {
    "README.md": ROOT / "README.md",
    "MANUAL.md": ROOT / "sigmaforge" / "MANUAL.md",
    "CLAUDE.md": ROOT / "CLAUDE.md",
}

# stale claims (whitespace-normalised, case-insensitive)
STALE = [
    r"\./config\.yaml",
    r"engine_home:\s*\.(\s|$)",
    r"or cwd\b",
    r"defaults? to the current directory",
    r"engine working dir defaults",
    r"run scripts from the repo root",
    r"env \(`?SIGMAFORGE_\*`?\) > `?~/\.sigmaforge",
]


def _text(name: str) -> str:
    return re.sub(r"\s+", " ", DOCS[name].read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", DOCS)
@pytest.mark.parametrize("pattern", STALE)
def test_stale_engine_and_config_claims_are_gone(name, pattern):
    assert re.search(pattern, _text(name), re.I) is None


@pytest.mark.parametrize(
    "needle",
    [
        "--engine-home",
        "SIGMAFORGE_HOME",
        "SIGMAFORGE_ZIRCOLITE",
        "interpreter prefix",
        "relative to that file",
        "uv sync",
        "never from the current directory",
        "trust",
    ],
)
def test_manual_documents_engine_resolution_and_trust_boundary(needle):
    assert needle in _text("MANUAL.md")


def test_manual_names_all_six_config_path_keys():
    text = _text("MANUAL.md")
    for key in ("rules", "attack_corpus", "technique_map", "benign_sample", "comiset_mapping", "engine_home"):
        assert f"`{key}`" in text
