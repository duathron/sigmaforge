#!/usr/bin/env python3
"""FIX H: compile ONLY the loaded SigmaHQ rules into ONE engine ruleset.

Problem this fixes (gap-review): the engine fired Zircolite's BUNDLED 2680-rule
snapshot (`Zircolite/rules/rules_windows_sysmon.json`) while the scorer filtered
the ~609 loaded SigmaHQ-clone rules by TITLE. Two sources joined by title =>
(a) firing used a different rule body than the one scored (version skew), and
(b) engine fires whose title was outside the 609 set were silently dropped
(manifest showed benign_fires=767 collapsing to funnel fires=2).

FIX H makes ONE source: take exactly the `partition_rules` loaded list (high+
critical, stateless, process_creation), convert ONLY those .yml files through
Zircolite's own pySigma sqlite backend (the same converter that produced the
bundled snapshot) and write `data/rulesets/sigmaforge_loaded.json`. The engine
then fires the same rule bodies the scorer scores.

Converter invocation (documented):
    Zircolite 3.7.6 converts native Sigma YAML -> Zircolite JSON via its pySigma
    sqlite backend. On the CLI this is:

        uv run python Zircolite/zircolite.py \
            --ruleset <dir-of-yml> --pipeline sysmon --save-ruleset \
            --events <logs> --outfile /dev/null

    `--save-ruleset` writes the converted JSON (random name, CWD). Because that
    path also requires an events pass and a random output name, this script
    drives the SAME converter programmatically via
    `zircolite.rules.RulesetHandler` (cfg.save_ruleset off; we read the in-memory
    `.rulesets`, which is the identical converted list) and writes it to a stable
    path. Same backend, same pipeline ('sysmon'), one source.

Output: data/rulesets/sigmaforge_loaded.json  (gitignored — generated artifact)
Reports: compiled N / 609, and per-rule failures (a logged FINDING, not a
silent loss).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "Zircolite"))

from sigmaforge.ingest.compile import compile_ruleset  # noqa: E402
from sigmaforge.ingest.ruleload import partition_rules  # noqa: E402

PC_GLOB = "sigma/rules/windows/process_creation/*.yml"
OUT_PATH = REPO / "data" / "rulesets" / "sigmaforge_loaded.json"
PIPELINE = "sysmon"
LEVELS = ("high", "critical")


def loaded_rule_paths() -> tuple[list[Path], list[dict]]:
    """Return the .yml paths AND parsed docs of the loaded (in-scope, stateless) rules.

    Tracks the source path per doc so we can stage EXACTLY those files for the
    converter — the same selection `partition_rules` makes, by identity not title.
    """
    docs_with_path: list[tuple[Path, dict]] = []
    for f in sorted((REPO).glob(PC_GLOB)):
        with open(f) as fh:
            for doc in yaml.safe_load_all(fh):
                if doc:
                    docs_with_path.append((f, doc))
    all_docs = [d for _, d in docs_with_path]
    loaded, _excluded = partition_rules(all_docs, levels=LEVELS)
    loaded_ids = {id(d) for d in loaded}
    paths = sorted({p for p, d in docs_with_path if id(d) in loaded_ids})
    return paths, loaded


def main() -> int:
    paths, loaded = loaded_rule_paths()
    n_loaded = len(loaded)
    print(f"[loaded] partition_rules selected {n_loaded} rules ({len(paths)} source .yml files)", flush=True)

    ruleset, n_staged = compile_ruleset(paths)
    n_compiled = len(ruleset)
    print(f"[compile] staged={n_staged}  compiled_ok={n_compiled}", flush=True)

    # FINDING: which loaded titles did NOT survive conversion?
    compiled_titles = {r.get("title") for r in ruleset}
    loaded_titles = {r["title"] for r in loaded}
    failed_titles = sorted(loaded_titles - compiled_titles)
    if failed_titles:
        print(
            f"[FINDING] {len(failed_titles)} loaded rule(s) failed to compile "
            f"(unsupported modifiers / unconvertible). Titles:",
            flush=True,
        )
        for t in failed_titles:
            print(f"    - {t}", flush=True)
    else:
        print("[compile] all loaded titles compiled (no failures)", flush=True)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(ruleset, indent=2))
    print(f"[out] -> {OUT_PATH}  ({n_compiled} rules)", flush=True)

    summary = {
        "loaded_rules": n_loaded,
        "loaded_titles": len(loaded_titles),
        "staged_yml": n_staged,
        "compiled_ok": n_compiled,
        "compiled_titles": len(compiled_titles),
        "failed_count": len(failed_titles),
        "failed_titles": failed_titles,
        "out_path": str(OUT_PATH.relative_to(REPO)),
        "pipeline": PIPELINE,
    }
    (REPO / "reports").mkdir(exist_ok=True)
    (REPO / "reports" / "compile_loaded_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
