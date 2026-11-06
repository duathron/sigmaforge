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
# 1. fetch the engine (not bundled — large third-party tool), then name it
bash scripts/setup_engine.sh
export SIGMAFORGE_HOME="$PWD"      # the directory that CONTAINS Zircolite/ (or pass --engine-home)

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
| `--engine-home` | no | config / `$SIGMAFORGE_HOME` | Engine root containing `Zircolite/zircolite.py` |
| `--config` | no | `~/.sigmaforge/config.yaml` | Path to a config YAML (engine override) |

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
| `--config` | `~/.sigmaforge/config.yaml` | Path to a config YAML |
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
| 1 | the engine failed: its process exited non-zero, or the in-process rule compile raised or exited (a short, sanitized tail of its output is shown) |
| 2 | usage error (bad/missing flags), OR a config file that cannot be used (an explicit `--config` that does not exist, not a regular file such as a FIFO or device, larger than 1 MiB, unreadable, not UTF-8, invalid YAML, not a mapping, or a field of the wrong type; one line naming the file and the field names, never the values) |
| 3 | engine not found or `--engine-home` / `engine_home` empty — run `scripts/setup_engine.sh` (then `--engine-home`, config `engine_home` or `$SIGMAFORGE_HOME`) |
| 4 | corpus / required input missing, OR a run that would be pooled-recall (refused) — use `hunt` if you have no corpora; also `backtest` when a rule file, the technique map, the benign sample or the COMISET mapping cannot be read or parsed (missing, not a regular file such as a FIFO or device, over the size cap, or malformed; one line naming the file; the file's contents are never echoed) |
| 5 | acceptance gate FAILED (engine fires ≠ scored fires) |

Input files are opened without blocking and read only if they are regular files within a size cap: config 1 MiB, COMISET mapping 1 MiB, technique map 64 MiB, benign sample 1 GiB; a larger file is refused as `too large`.

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
order `--config <path>`, then `~/.sigmaforge/config.yaml` (first-found wins; the files are
**not** merged). A `config.yaml` in the current directory is **not** read. Individual CLI
flags then override single values from that file, and built-in defaults (`None`, `floor`
1000) sit underneath. The defaults bake no repo paths into the package, so outside the
repo you must point the config or flags at your corpora.

**Paths in a config file** — all six (`rules`, `attack_corpus`, `technique_map`,
`benign_sample`, `comiset_mapping`, `engine_home`) are resolved relative to the directory
of that config file, with `~` expanded; the current directory plays no part. Absolute
paths are used as they are. (Flags such as `--rules` are ordinary command-line paths,
relative to where you run the command.)

```yaml
backtest:
  # relative values below resolve against THIS file's directory
  rules: data/rulesets/sigmaforge_loaded.json   # .json = pre-compiled; a dir/.yml is auto-compiled
  attack_corpus: ~/sigmaforge-v0/attack_data_corpus
  technique_map: data/comiset/attack_data_technique_map.json
  benign_sample: data/comiset/combined_optc_benign_sample.jsonl
  comiset_mapping: data/mappings/comiset.yaml
  engine_home: ~/engine     # dir containing Zircolite/  (else $SIGMAFORGE_HOME; never the cwd)
  floor: 1000               # precision coverage floor
```

## Where the engine comes from

The engine (Zircolite) is third-party code that sigmaforge executes and imports, so it
is taken only from a place **you name** — never from the current directory.

1. `--engine-home <dir>` (flag, `hunt` and `backtest`)
2. `backtest.engine_home` in the config file (relative to that file, `~` expanded)
3. `$SIGMAFORGE_HOME`

`<dir>` is the directory that **contains** `Zircolite/zircolite.py`. The first source that
is set wins and is not retried elsewhere: a path without the engine, or an empty value
(`--engine-home ""`, `engine_home: ""`), exits 3; the environment variable is not used as
a fallback for it.

`SIGMAFORGE_ZIRCOLITE` is an optional override of the interpreter prefix only (default:
the Python running sigmaforge); the absolute path of the engine script is always
appended, and the engine runs with its own root as working directory.

**Trust boundary.** The engine path, `SIGMAFORGE_HOME` and `SIGMAFORGE_ZIRCOLITE` are
treated as your own trusted environment: whatever they point at is executed with your
privileges. A relative `SIGMAFORGE_HOME` resolves against the current directory, so
prefer an absolute path. Do not set them from untrusted input.

**Engine output is not streamed.** The engine subprocess's stdout and stderr are captured: rule
titles are untrusted text and the engine echoes them. On success nothing from the engine is
printed; on failure only a short sanitized tail of its stderr (stdout when stderr is empty) is
shown. While the rule compiler runs in-process, its Python-level stdout and stderr, warnings and
logging (what Zircolite v3.7.6 uses) are captured: output is discarded on success, and log records
(the engine's own loggers, the root logger and loggers without handlers) are flattened to one line
and stripped of control characters before they reach stderr. If the compile fails, a short
sanitized tail of the captured text is printed to stderr and `hunt` reports
`Detection engine failed` with a sanitized one-line message (exit 1); the engine's own exception
text is never printed raw.

Known open: writes below the Python level are not captured (`os.write`, `sys.__stdout__` /
`sys.__stderr__`, rebinding of `sys.stdout`, subprocesses that inherit the file descriptors, and
threads or `atexit` hooks that outlive the call). Only a malicious engine can use them, and a
malicious engine already runs with your privileges.
There is also no timeout on the engine subprocess: a hung engine hangs the command.

Error messages from the engine are cut at about 600 characters (a `[truncated]` marker shows a cut; escaping square brackets for the terminal can make the printed line somewhat longer),
and a detection file that is missing or not valid JSON after an exit status of 0 is reported as
`Detection engine failed` (exit 1).

**Untrusted rule text.** Rule titles and other rule-derived text are escaped at the terminal
(Rich markup, control characters, line breaks) and in the Markdown report (control
characters and line breaks removed, `|` written as `&#124;`, backslashes doubled). `&` is written as `&amp;`, so a literal `&#124;` typed in a title is displayed as typed. Markdown links and HTML inside a rule title are **not** neutralised: treat a report built from
untrusted rules as untrusted Markdown when you render it.

The escaping targets GitHub (cmark-gfm), markdown-it and Python-Markdown, which render `|` and
`&` correctly from `&#124;` and `&amp;`. mistune shows the literal entities instead: a known
trade-off.

## Reproduce a backtest

The engine and corpora are not bundled (engine = large third-party tool; corpora =
large and separately licensed):

```bash
uv sync --group backtest        # script deps (pyyaml, evtx, gdown)
bash scripts/setup_engine.sh    # fetch Zircolite 3.7.6 + its runtime deps
```

Run `setup_engine.sh` **after** `uv sync` and do not re-sync afterwards: an exact `uv sync`
uninstalls the engine's dependencies again (re-run the script if you do).

Then obtain the corpora (see the README table) into `~/sigmaforge-v0/`, build the
combined samples with the `scripts/build_*` helpers, and run `sigmaforge backtest`
(or the `scripts/run*_backtest.py` runs, which call the **same** `sigmaforge.pipeline`;
they use this checkout as the engine root when `SIGMAFORGE_HOME` is unset).
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
