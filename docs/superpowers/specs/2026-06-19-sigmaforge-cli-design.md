# Sigmaforge functional CLI — design spec

**Status:** approved (MeetUp 2026-06-19, 7-1, Skeptic-gated). See
`__obsidian_vault/AI/PROJECTS/CODING/_sigmaforge/MeetUp Logs/2026-06-19-cli-design.md`.

## Goal
Give a user one command to run their own rules against the harness honestly, plus a
pip-runnable path that works with no corpora. Today the real pipeline is the hardcoded
`scripts/run7_backtest.py`; the shipped `sigmaforge backtest` is a weaker, dishonest
(pooled-recall, no manifest) path. Bridge that gap.

## Core reframe (the spine)
"Run it yourself" ≠ "reproduce run7." On a fresh `pip install` the engine (Zircolite)
and the labeled corpora are absent, so `backtest` cannot produce a measured number and
`unmeasured` is the **default** state. Design around the absence, not around the report
that assumed presence. → Two honesty-separated verbs.

## Commands

### `sigmaforge hunt` — pip-runnable, no corpora
Rules × arbitrary logs → **hits only**. The default runnable experience after install.
- Flags: `--rules PATH` (required; `.yml` file OR dir), `--logs PATH` (required; EVTX
  or JSON, file or dir), `--out PATH` (default `hits.json`), `--config PATH` (engine +
  mapping overrides).
- Preflight: engine resolvable (else exit 3, teaching error). **No corpora required.**
- Behavior: compile rules → `run_shard` over the logs → emit hits (rule, event, count).
  Compile IN-PROCESS via a library function: lift `compile_ruleset(paths)` out of
  `scripts/compile_loaded_ruleset.py` into an importable home (e.g. `sigmaforge.ingest`)
  and call it — do NOT rely on Zircolite ingesting raw `.yml`. This keeps `hunt` and
  `backtest` on the SAME compile path (the one-source invariant). (This lift can land in
  C1 with the extraction or in C3 with `hunt`; name it in the plan.)
- Honesty: every quality field renders `unmeasured: no labeled corpus`; output carries
  an explicit "hits only — NOT a quality measurement (logs are unlabeled)" banner. The
  `unmeasured` is a structural token in JSON, not an absence.
- Exit: 0 ok, 2 usage, 3 no-engine.

### `sigmaforge backtest` — labeled corpora, the real measurement
Rules × stored labeled corpora → per-technique recall + label-aware precision + honesty
gates + `report.md` + `manifest.json` (run7-equivalent).
- Flags: `--rules PATH` (`.yml` file OR dir; default from config), `--config PATH`,
  `--out PATH` (default `reports/run.md`), `--floor INT` (override scoring floor).
- Preflight (BEFORE any subprocess): engine resolvable? attack corpus + technique-map
  present? benign corpus + mapping present? If any missing → **teaching error**, name
  exactly what to run (`scripts/setup_engine.sh`, corpus-build scripts), and redirect to
  `hunt`. Never a traceback or an empty report.
- Behavior: resolve config → compile rules (report `loaded N / excluded M` with reasons)
  → `pipeline.run_backtest_pipeline(cfg)` → write report + manifest.
- **Never silently pooled-recall:** if per-technique inputs are absent, refuse (exit 4)
  rather than fall back to pooled. Add a **net-new** `recall_mode` manifest field
  (`per-technique` | `pooled`) — it does NOT exist today; set it in the
  pipeline and pass it through `build_manifest` (which is pure-kwargs, so this is a new
  key, not a preserved one). The silent pooled fallback lives in `orchestrate.run_backtest`
  (the `n_attack_events` branch) and must be gated, not relied on.
- Exit: 0 ok, 2 usage, 3 no-engine, 4 no-corpus/missing-inputs, 5 gate-FAIL.

### Removed
- `classify` (template-leftover demo). Verify it is dead beyond `main.py`/`detect.py`/
  its tests first, then remove the command + its tests; leave `detect.py` only if used
  elsewhere.
- The current weak `backtest` body — replaced by the pipeline call.

## Architecture

### `sigmaforge/pipeline.py` (new) — the extracted, reusable pipeline
`run_backtest_pipeline(cfg: PipelineConfig) -> BacktestResult` (NOTE: `PipelineConfig`
is the pipeline's resolved input dataclass — distinct from the user-facing
`config.BacktestConfig` YAML block; the CLI resolves the latter into the former) lifting the glue from
`scripts/run7_backtest.py::main` (compile → recall pass → precision pass →
`orchestrate.run_backtest` → render report + manifest). The hardcoded module constants
(corpus paths, technique map, floor, run-specific provenance) become `cfg` fields.
`scripts/run7_backtest.py` becomes a thin caller passing the run7 constants.

**Extraction gate (semantic equivalence, NOT byte-identical):** regenerating run7 via
the extracted pipeline MUST reproduce run7's `run_hash` + the AGGREGATE scored metrics
that ARE in the committed `reports/run7_manifest.json` (`rules_recall_measurable`,
`rules_precision_measurable`, `attack_fires`, `benign_fires`, `run_hash` — verified
present). The manifest does NOT contain per-rule/per-technique recall rows today (they
land only in `reports/run7.md` and in the pipeline's returned `rows`), so assert the
per-technique rows against the pipeline's returned `rows` (not the manifest). Cosmetic
`.md` differences are allowed. (Byte-identical was rejected: it pins bytes not
semantics — blocks later report/UX fixes and could pass a silent metric change after
regeneration.)

### Honesty caveats move into the render
run7's caveat text currently lives in a script-local `header` string
(`run7_backtest.py:337+`). Move the caveat generation into the report/manifest renderer,
**generated from data** (corpus SHAs, OpTC path-form split, the actual floor), so the
CLI path emits the same honesty discipline. Run-specific provenance is passed as data,
not lifted as prose.

### Config — reuse the existing system
Extend `sigmaforge/config.py` `AppConfig` (currently only `output`) with: rules path,
attack corpus + technique_map, benign corpus + mapping, engine_home, floor. Keep the
existing `shipwright_kit.config` loader + YAML discovery chain (explicit > 
`~/.sigmaforge/config.yaml` > `./config.yaml` > defaults). Do **NOT** introduce
`sigmaforge.toml` (second config system) and do **NOT** bake repo `data/` absolute paths
into the pip-package defaults — defaults are repo-relative/None and produce a teaching
error when unset outside the repo. Precedence: flags > `--config` file > discovery >
in-code defaults; **echo the resolved value + its source per key into the manifest**.

### `unmeasured` — one source, two renders (NET-NEW construction)
Today `unmeasured` is a bare sentinel (`score/recall.py` `UNMEASURED = "unmeasured"`)
and the three conditions exist but are UNNAMED. This build INTRODUCES reason-codes and
threads them through — it is new code, not "render an existing field":
- `no-tag` and `technique-0-events` originate in `score/recall.py` (the two
  unmeasured branches);
- `below-floor` originates in `score/gates.py` (the floor check).
Carry the code on the row → into both the manifest/JSON (`status` + reason-code) and the
report (inline human reason rendered from the same field). Never a bare token. Budget:
touches `recall.py`, `gates.py`, and the renderer (`render.py`), not just the renderer.
(Detection-Engineering: a lone new rule is `unmeasured` by construction; `backtest` is a
corpus-regression tool, so the WHY is the actionable signal.)

## Concrete bug to fix in C1
`pyyaml` is imported by shipped `sigmaforge/config.py` + `main.py` but is not in
`[project.dependencies]` (and not transitively provided — shipwright-kit 0.8.0 has no
runtime deps) → hard `ModuleNotFoundError` on config paths in PyPI 0.2.0. Move `pyyaml`
to `[project.dependencies]`; verify via clean-room wheel `Requires-Dist` install.

## Testing
- Pipeline extraction regression: run7-via-pipeline `run_hash` + scored manifest metrics
  == committed `run7_manifest.json` (semantic-equivalence test).
- Config: defaults, override precedence, resolved-value+source echo.
- CLI: `backtest`/`hunt` arg parsing; exit codes; teaching errors (no-engine/no-corpus)
  exit non-zero with guidance and NO traceback/empty report.
- e2e smoke: extend the existing `data/fixtures/smoke/` + `test_smoke_pipeline.py`,
  `skipif` engine absent (CI stays green). NOTE: the current fixture is benign-only (no
  attack corpus, no technique map), so: (1) `hunt` runs CLEAN on it → assert hits;
  (2) `backtest` on it hits the no-corpus TEACHING-ERROR path → assert exit 4 + guidance
  (NOT a measured run). To smoke a MEASURED `backtest`, ADD a tiny attack fixture
  (wrapped `<Events>` XML EID-1 + a 1-entry technique map) — optional, may be deferred;
  the minimum gate is the teaching-error + hunt-clean assertions.
- pyyaml: clean-room import / wheel `Requires-Dist` assertion.

## Deferred (named, not this build)
- Per-FP benign **witness events** in the report ("66× Ninite installer" insight) — a
  feature, needs corpora.
- Verb-level `--json` + `ci-gate` / `diff` / `badge` verbs — the existing manifest is
  the schema basis; defer the verbs, don't freeze a formal schema prematurely.
- Full migration of run4–6 to the pipeline (run7 only for now; older runs frozen).

## Build order (each Skeptic-gated)
- **C1** — extract `pipeline.py` (semantic-equivalence gate) + pyyaml fix.
- **C2** — wire `backtest` (config + pipeline; drop `classify`; kill pooled fallback;
  teaching errors + exit codes).
- **C3** — `hunt`.
