"""Task 3.1 — `compile_ruleset` has an importable home (shared with the script).

The compile path is the SAME Zircolite pySigma sqlite backend the loaded-ruleset
script uses; lifting it into `sigmaforge.ingest.compile` means `hunt` (C3) and the
script share ONE source. The behavioural assertion (a real .yml -> a Zircolite
ruleset) needs the vendored engine + its pySigma deps, so it skips cleanly when
the engine is absent (CI / clean checkout without `scripts/setup_engine.sh`).
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ZIRC = REPO / "Zircolite" / "zircolite.py"
SMOKE_RULES = REPO / "data" / "fixtures" / "smoke" / "rules"


def test_compile_ruleset_is_importable():
    # the import is the shared-source contract: script + hunt both reach it here.
    from sigmaforge.ingest.compile import compile_ruleset  # noqa: F401

    assert callable(compile_ruleset)


@pytest.mark.skipif(
    not ZIRC.exists(),
    reason="engine absent (needs pySigma from the engine reqs; run scripts/setup_engine.sh)",
)
def test_compile_smoke_fixture_yields_one_titled_rule():
    from sigmaforge.ingest.compile import compile_ruleset

    paths = sorted(SMOKE_RULES.glob("*.yml"))
    assert paths, f"no fixture rules under {SMOKE_RULES}"

    ruleset, n_staged = compile_ruleset(paths)

    assert n_staged == len(paths)
    assert len(ruleset) == 1
    assert ruleset[0]["title"] == "Smoke PowerShell"
