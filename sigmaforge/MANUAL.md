# sigmaforge — Manual

Honest Sigma-rule backtest harness. This manual is bundled in the package and shown by
`sigmaforge manual`. Run `sigmaforge version` for the installed version; the `backtest`,
`hunt`, and `manual` commands ship in **0.3.0** (PyPI 0.2.0 predates them).

> **One idea to hold onto:** you cannot compute recall/precision without ground-truth
> labels. That law splits this tool into two commands — `hunt` (unlabeled logs → hits
> only) and `backtest` (labeled corpora → measured recall/precision).

## The two-verb model

| | `sigmaforge hunt` | `sigmaforge backtest` |
|---|---|---|
| Input | rules × **arbitrary, unlabeled** logs | rules × **labeled** corpora (attack + benign) |
| Needs corpora? | **No** — pip-runnable, engine only | **Yes** (+ technique map) |
| Output | hit list (`hits.json`) | `report.md` + `manifest.json` |
| Quality numbers | **none** — precision/recall = `unmeasured — unlabeled corpus` | per-technique recall + label-aware precision + honesty gates |
| If inputs missing | — | a teaching error (exit 4) that points you back to `hunt` |

`hunt` is the path that works right after `pip install` + fetching the engine.
`backtest` is the real measurement and needs the labeled corpora (see *Reproduce a
backtest*).

## Quickstart

```bash
# 1. fetch the engine (not bundled — large third-party tool)
bash scripts/setup_engine.sh

# 2. hunt: rules over ANY logs -> hits only (no corpora needed)
sigmaforge hunt --rules my_rules/ --logs /path/to/logs --out hits.json

# 3. backtest: rules over the LABELED corpora -> measured report (needs corpora)
sigmaforge backtest --rules my_rules/ --config sigmaforge.yaml --out reports/run.md
```

`--rules` accepts a single `.yml` file OR a directory (auto-compiled to one engine
ruleset).

## Commands

### `sigmaforge hunt`
Run Sigma rules against arbitrary (unlabeled) logs and report **hits only**. The
pip-only path: needs the engine but no corpora. Because the logs are unlabeled,
precision/recall are structurally `unmeasured` — the output is a hit list, not a
quality measurement.

| Flag | Required | Default | Meaning |
|------|----------|---------|---------|
| `--rules` | yes | — | Source Sigma rules (`.yml` file OR dir) |
| `--logs` | yes | — | Logs to hunt over (EVTX/XML or JSON, file OR dir) |
| `--out` | no | `hits.json` | Hits output path |
| `--config` | no | discovery | Path to a config YAML (engine override) |

Output `hits.json`: `{"banner": "hits only — NOT a quality measurement …",
"precision": "unmeasured — unlabeled corpus", "recall": "unmeasured — unlabeled
corpus", "hits": [{"rule_id", "event_id", "count"}, …]}`. The banner is also printed to
stdout.

### `sigmaforge backtest`
Backtest Sigma rules against labeled corpora: per-technique recall + label-aware
precision@COMISET + honesty gates + report + manifest (run7-equivalent). Requires the
engine AND labeled corpora. With nothing configured it teaches what to run (exit 4) and
points you at `hunt`. It **never silently pooled-recalls**: a run without per-technique
inputs is refused.

| Flag | Default | Meaning |
|------|---------|---------|
| `--rules` | from config | Source Sigma rules (`.yml` file OR dir) |
| `--attack-corpus` | from config | Native-EVTX attack corpus dir (recall) |
| `--technique-map` | from config | attack_data technique map JSON |
| `--benign-sample` | from config | Benign corpus JSONL (precision) |
| `--comiset-mapping` | from config | COMISET `_source` → Sigma field mapping YAML |
| `--engine-home` | from config / `$SIGMAFORGE_HOME` | Engine root containing `Zircolite/zircolite.py` |
| `--config` | discovery | Path to a config YAML |
| `--out` | `reports/run.md` | Report output path |
| `--floor` | config / `1000` | Override the precision scoring floor |

Output: a Markdown report + a `*_manifest.json` (run_hash, corpus SHAs, aggregates,
`recall_mode`). Every unmeasured cell carries a reason-code (see below).

### `sigmaforge version` / `sigmaforge manual`
`version` prints the installed version. `manual` renders this document.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | usage error (bad/missing flags) |
| 3 | engine not found — run `scripts/setup_engine.sh` (or set `--engine-home` / `$SIGMAFORGE_HOME`) |
| 4 | corpus / required input missing, OR a run that would be pooled-recall (refused) — use `hunt` if you have no corpora |
| 5 | acceptance gate FAILED (engine fires ≠ scored fires) |

Codes 3 and 4 are **teaching errors**: they name what to run and never print a
traceback or an empty report.

## The `unmeasured` contract

`backtest` reports `unmeasured` instead of a fabricated number, always with a
reason-code so you know whether to fix the rule, the tag, or the corpus:

| Reason | Side | Meaning |
|--------|------|---------|
| `no-tag` | recall | the rule carries no usable `attack.tXXXX` technique tag |
| `technique-0-events` | recall | the rule's technique has zero events in the attack corpus |
| `below-floor` | precision | fewer than `floor` events were evaluated for the rule |
| `no-benign-exemplars` | precision | above the floor but no benign events carried the rule's fields (denominator 0) |

`hunt` reports `unmeasured — unlabeled corpus` for both precision and recall (no labels
exist at all).

## Configuration (`sigmaforge.yaml`)

Config resolution: exactly **one** config file is loaded — the **first that exists**, in
order `--config <path>`, then `~/.sigmaforge/config.yaml`, then `./config.yaml`
(first-found wins; the files are **not** merged). Individual CLI flags then override
single values from that file, and built-in defaults (`None`, `floor` 1000) sit
underneath. The defaults bake no repo paths into the package, so outside the repo you
must point the config or flags at your corpora.

```yaml
backtest:
  rules: data/rulesets/sigmaforge_loaded.json   # .json = pre-compiled; a dir/.yml is auto-compiled
  attack_corpus: ~/sigmaforge-v0/attack_data_corpus
  technique_map: data/comiset/attack_data_technique_map.json
  benign_sample: data/comiset/combined_optc_benign_sample.jsonl
  comiset_mapping: data/mappings/comiset.yaml
  engine_home: .            # dir containing Zircolite/  (else $SIGMAFORGE_HOME or cwd)
  floor: 1000               # precision coverage floor
```

## Reproduce a backtest

The engine and corpora are not bundled (engine = large third-party tool; corpora =
large and separately licensed):

```bash
uv sync --group backtest        # script deps (pyyaml, evtx, gdown)
bash scripts/setup_engine.sh    # fetch Zircolite 3.7.6 + its runtime deps
```

Then obtain the corpora (see the README table) into `~/sigmaforge-v0/`, build the
combined samples with the `scripts/build_*` helpers, and run `sigmaforge backtest`
(or the `scripts/run*_backtest.py` runs, which call the **same** `sigmaforge.pipeline`).
The committed `reports/run*.md` are inspectable without running anything.

## Comparing runs across systems

Two machines running the same rules + corpora should produce the same numbers — but
the engine and its dependency closure can shift which events fire. So the manifest
records the full provenance to make any difference attributable:

- `run_hash` — a stable, worker-invariant hash of the fired (rule, event) set. Same
  hash = identical result.
- `ruleset_sha`, `mapping_hash`, `benign_corpus_sha`, `recall_technique_map_sha` —
  verify both machines used the same inputs.
- `provenance.zircolite_commit_sha` + `zircolite_tag` — the engine's exact source (the
  version string alone is not enough).
- `provenance.environment` — `python_version`, `platform`, `sqlite_version`, and the
  `engine_deps` versions (pySigma + backend, orjson, lxml).

If two `run_hash` values differ, diff the provenance blocks and the SHAs to find the
axis — engine commit, a pySigma version, sqlite, the OS. This makes a mismatch
diagnosable, not mysterious. It does **not** guarantee identical output: that requires
pinning the whole environment (a container), which sigmaforge does not ship.

---
*Honest measurement over flattering numbers. AI-pair-programmed; designed, reviewed, and
gated by Christian Huhn.*
