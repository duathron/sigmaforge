# Sigmaforge functional CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship two honest CLI verbs — `hunt` (pip-runnable, no corpora → hits only) and `backtest` (labeled corpora → run7-equivalent recall/precision/gates/report+manifest) — backed by one extracted, reusable pipeline.

**Architecture:** Extract the hardcoded `scripts/run7_backtest.py::main` glue into `sigmaforge/pipeline.py:run_backtest_pipeline(cfg)`; `run7_backtest.py` becomes a thin caller and is the semantic-equivalence regression oracle. The CLI (`sigmaforge/main.py`, Typer via `shipwright_kit.cli.build_typer`) calls the same pipeline; config comes from the existing `sigmaforge/config.py` (`shipwright_kit.config`, YAML).

**Tech Stack:** Python 3.11, Typer, pydantic, shipwright_kit, vendored Zircolite 3.7.6, pytest. Spec: `docs/superpowers/specs/2026-06-19-sigmaforge-cli-design.md`. MeetUp: `__obsidian_vault/AI/PROJECTS/CODING/_sigmaforge/MeetUp Logs/2026-06-19-cli-design.md`.

**QA policy (NON-NEGOTIABLE):** every task is gated by the independent-review-agent (Skeptic) — no self-review. Loop fix→re-review until clean APPROVE before the next task.

---

## File structure

| File | Responsibility | C |
|------|----------------|---|
| `pyproject.toml` | move `pyyaml` to `[project.dependencies]` | C1 |
| `sigmaforge/pipeline.py` (new) | `run_backtest_pipeline(cfg) -> BacktestResult`; the extracted glue | C1 |
| `scripts/run7_backtest.py` | thin caller passing run7 constants; the regression oracle | C1 |
| `tests/test_pipeline.py` (new) | semantic-equivalence gate vs committed run7 manifest + rows | C1 |
| `sigmaforge/config.py` | extend `AppConfig` with a `BacktestConfig` block + resolved-source map | C2 |
| `sigmaforge/score/recall.py` | net-new reason-codes on the unmeasured branches | C2 |
| `sigmaforge/score/gates.py` | net-new `below-floor` reason-code | C2 |
| `sigmaforge/orchestrate.py` | thread reason-code onto rows; emit `recall_mode` | C2 |
| `sigmaforge/report/render.py` | render reason-codes + data-generated caveats | C2 |
| `sigmaforge/runmanifest.py` | accept `recall_mode` + reason fields (pure kwargs, no change needed) | C2 |
| `sigmaforge/main.py` | `backtest` command (config+pipeline, preflight, exit codes); drop `classify` | C2 |
| `sigmaforge/ingest/ruleload.py` or new `compile.py` | importable `compile_ruleset(paths)` lifted from the script | C3 |
| `sigmaforge/main.py` | `hunt` command | C3 |
| `tests/test_smoke_pipeline.py` | drive `backtest` (teaching-error) + `hunt` (clean) on fixtures | C3 |

Exit-code table (canonical, owned by `main.py`): `0` ok · `2` usage · `3` no-engine · `4` no-corpus/missing-inputs · `5` gate-FAIL.

---

# C1 — Extract pipeline + fix pyyaml (no behavior change)

### Task 1.1: pyyaml is a real runtime dependency

**Files:** Modify `pyproject.toml`; Create `tests/test_packaging.py`.

- [ ] **Step 1 — failing test (clean-room intent via metadata).**
```python
# tests/test_packaging.py
import tomllib
from pathlib import Path

def test_pyyaml_is_a_runtime_dependency():
    # shipped sigmaforge/config.py + main.py `import yaml`; it must be a direct
    # runtime dep (NOT transitively provided — shipwright-kit 0.8.0 has no runtime deps),
    # else `pip install sigmaforge` + `sigmaforge backtest` => ModuleNotFoundError.
    pp = tomllib.loads(Path("pyproject.toml").read_text())
    deps = " ".join(pp["project"]["dependencies"])
    assert "pyyaml" in deps.lower() or "PyYAML" in deps
```
- [ ] **Step 2 — run, expect FAIL** (`uv run pytest tests/test_packaging.py -v` → pyyaml only in the `backtest` group).
- [ ] **Step 3 — fix.** In `pyproject.toml` `[project] dependencies` add `"pyyaml>=6.0"`; remove the now-duplicate `pyyaml>=6.0` from `[dependency-groups] backtest` (keep `evtx`, `gdown` there).
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — clean-room verify.** `uv build` then in a fresh venv `pip install dist/sigmaforge-*.whl` and `python -c "import sigmaforge.config"` → must NOT raise. Confirm wheel `Requires-Dist` lists pyyaml.
- [ ] **Step 6 — commit** `fix(deps): declare pyyaml as a runtime dependency (shipped config import; was ModuleNotFoundError on clean install)`.

### Task 1.2: Extract `run_backtest_pipeline` and reduce run7 to a caller

**Files:** Create `sigmaforge/pipeline.py`; Modify `scripts/run7_backtest.py`; Create `tests/test_pipeline.py`.

Context: `scripts/run7_backtest.py::main` currently does: load loaded rules (`partition_rules`), read the compiled ruleset + technique map, `run_shard` over the attack corpus (xml_input) → `attack_fires` + `event_technique`, `run_shard` over the benign corpus (json_input + comiset mapping) → `benign_fires`, build `benign_events`, positive-control, `assert_one_source`, `run_backtest(...)`, `run_hash`, `build_manifest(...)`, render header+report. `orchestrate.run_backtest(loaded_rules, attack_fires, benign_fires, benign_events, n_attack_events, positive_control_fired, min_events, source, event_technique, technique_event_counts) -> (rows, funnel, report_md)`.

- [ ] **Step 1 — define the config + result dataclasses (failing import test).**
```python
# tests/test_pipeline.py
from sigmaforge.pipeline import PipelineConfig, BacktestResult, run_backtest_pipeline  # noqa: F401

def test_pipeline_exports_exist():
    assert PipelineConfig and BacktestResult and run_backtest_pipeline
```
- [ ] **Step 2 — run, expect FAIL** (module missing).
- [ ] **Step 3 — create `sigmaforge/pipeline.py`.** A frozen dataclass `PipelineConfig` (NOTE: distinct from the user-facing `config.BacktestConfig` added in C2.1 — `PipelineConfig` is the pipeline's resolved input, `config.BacktestConfig` is the YAML/flag config the CLI resolves INTO a `PipelineConfig`) with the fields run7 hardcodes: `compiled_ruleset: str`, `loaded_rules_glob: str`, `attack_corpus: str`, `technique_map: str`, `benign_sample: str`, `comiset_mapping: str`, `evtx_cfg: str`, `min_events: int = 1000`, `source: str = "COMISET"`, plus optional `report_extras: dict` (run-specific provenance passed as DATA, e.g. run6 slice info / path-form note). A `BacktestResult` dataclass: `rows`, `funnel`, `manifest: dict`, `report_md: str`, `run_hash: str`, `recall_mode: str`. `run_backtest_pipeline(cfg: PipelineConfig)` = the lifted body of `run7_backtest.main` with the module constants replaced by `cfg.*` and the run7-specific header text replaced by data passed via `cfg.report_extras` (do NOT inline run7 prose). Return a `BacktestResult`.
- [ ] **Step 4 — rewrite `scripts/run7_backtest.py`** to: keep its module constants + the run6-slice/path-form provenance, expose a `run() -> BacktestResult` that builds a `PipelineConfig`, calls `run_backtest_pipeline`, writes `reports/run7.md` + `reports/run7_manifest.json` from the result, and returns it; `main()` calls `run()`. ~15-30 lines of caller. Do not change run4/5/6.
- [ ] **Step 5 — semantic-equivalence regression test (the gate).**
```python
# tests/test_pipeline.py  (engine-dependent; skip when Zircolite absent)
import json, os
from pathlib import Path
import pytest

REPO = Path(__file__).resolve().parent.parent
ZIRC = REPO / "Zircolite" / "zircolite.py"

@pytest.mark.skipif(not ZIRC.exists(), reason="engine absent (scripts/setup_engine.sh)")
def test_run7_via_pipeline_matches_committed_manifest(monkeypatch):
    monkeypatch.setenv("SIGMAFORGE_HOME", str(REPO))
    committed = json.loads((REPO / "reports/run7_manifest.json").read_text())
    import scripts.run7_backtest as r7   # now a thin caller
    res = r7.run()                        # expose a run() returning BacktestResult
    for k in ("rules_recall_measurable", "rules_precision_measurable",
              "attack_fires", "benign_fires", "run_hash"):
        assert res.manifest[k] == committed[k], k
    # per-technique rows are NOT in the manifest -> assert against the returned rows
    fired = sorted(r for r in res.rows if isinstance(r["recall"], float) and r["recall"] > 0)
    assert len(fired) == 70  # run7 observed firing-recall rows
```
- [ ] **Step 6 — run the gate** (`uv run pytest tests/test_pipeline.py -v`); locally with engine → PASS, asserting the extraction preserved run7's `run_hash` + aggregates + 70 firing rows. If any metric drifts, the extraction changed semantics — fix before commit. Run full `uv run pytest -q` + `uv run ruff check . && uv run ruff format --check .`.
- [ ] **Step 7 — commit** `refactor(pipeline): extract run_backtest_pipeline from run7 script (semantic-equivalence gated)`.

**C1 Skeptic gate:** verify the extraction is behavior-preserving (run_hash + aggregates + 70 rows identical), run7 prose was passed as data not inlined, run4/5/6 untouched, pyyaml clean-room verified.

---

# C2 — `backtest` command + honesty plumbing

### Task 2.1: Extend config with a backtest block

**Files:** Modify `sigmaforge/config.py`; Create `tests/test_config_backtest.py`.

- [ ] **Step 1 — failing test.**
```python
# tests/test_config_backtest.py
from sigmaforge.config import AppConfig

def test_backtest_config_defaults_and_override():
    c = AppConfig()
    assert c.backtest.floor == 1000
    assert c.backtest.attack_corpus is None  # no repo-data path baked into the pip default
    c2 = AppConfig.model_validate({"backtest": {"floor": 500, "attack_corpus": "/x"}})
    assert c2.backtest.floor == 500 and c2.backtest.attack_corpus == "/x"
```
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.** Add `class BacktestConfig(BaseModel)` with `rules: Optional[str] = None`, `attack_corpus: Optional[str] = None`, `technique_map: Optional[str] = None`, `benign_sample: Optional[str] = None`, `comiset_mapping: Optional[str] = None`, `engine_home: Optional[str] = None`, `floor: int = 1000`. Add `backtest: BacktestConfig = BacktestConfig()` to `AppConfig`. Defaults are `None` (NOT repo paths) → the CLI raises a teaching error when unset outside the repo.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit** `feat(config): add backtest block (corpus/mapping/floor, None defaults)`.

### Task 2.2: Net-new reason-codes on unmeasured

**Files:** Modify `sigmaforge/score/recall.py`, `sigmaforge/score/gates.py`; Tests in `tests/test_recall.py`, `tests/test_gates.py`.

Reason-codes (constants): `REASON_NO_TAG = "no-tag"`, `REASON_TECH_0_EVENTS = "technique-0-events"`, `REASON_BELOW_FLOOR = "below-floor"`.

- [ ] **Step 1 — failing test (recall).**
```python
# tests/test_recall.py (add)
from sigmaforge.score.recall import per_technique_recall_reason, REASON_NO_TAG, REASON_TECH_0_EVENTS

def test_recall_reason_no_tag():
    assert per_technique_recall_reason(set(), {"T1059.001": 10}) == REASON_NO_TAG

def test_recall_reason_technique_zero_events():
    assert per_technique_recall_reason({"T9999"}, {"T1059.001": 10}) == REASON_TECH_0_EVENTS
```
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** `per_technique_recall_reason(techniques, technique_event_counts) -> str | None`: `REASON_NO_TAG` if not techniques; else compute denom via `_technique_event_count_for_rule`; `REASON_TECH_0_EVENTS` if denom == 0; else `None` (measured). Do NOT change `per_technique_recall`'s existing numeric return (preserve C1 semantic gate).
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — gates reason test + impl.**
```python
# tests/test_gates.py (add)
from sigmaforge.score.gates import precision_reason, REASON_BELOW_FLOOR
from sigmaforge.records import RuleScore
def test_precision_reason_below_floor():
    s = RuleScore("r", tp=0, fp=0, tn=0, fn=0, events_evaluated=10)
    assert precision_reason(s, min_events=1000) == REASON_BELOW_FLOOR
```
Implement `precision_reason(s, min_events) -> str | None`: `REASON_BELOW_FLOOR` if `s.events_evaluated < min_events` else `None`. Leave `precision_or_unmeasured` unchanged.
- [ ] **Step 6 — run full suite + commit** `feat(score): net-new unmeasured reason-codes (no-tag/technique-0-events/below-floor)`.

### Task 2.3: Thread reason-code onto rows + emit recall_mode

**Files:** Modify `sigmaforge/orchestrate.py`; Test `tests/test_orchestrate.py`.

- [ ] **Step 1 — failing test.** Assert each row carries `recall_reason` / `precision_reason` (None when measured, the code when unmeasured), and that `run_backtest` returns/records a `recall_mode` of `"per-technique"` when technique inputs present and `"pooled"` when absent. Add to the existing `test_orchestrate.py` patterns.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.** In `run_backtest`, where a row's recall is set, also set `row["recall_reason"] = per_technique_recall_reason(...)`; where precision is set, `row["precision_reason"] = precision_reason(...)`. Compute `recall_mode` ("per-technique" if `event_technique`+`technique_event_counts` given, else "pooled") and return it (extend the return or set on funnel/manifest input). Keep existing numeric outputs identical (re-run the C1 gate after).
- [ ] **Step 4 — run, expect PASS; re-run `tests/test_pipeline.py` C1 gate (metrics must still match).**
- [ ] **Step 5 — commit** `feat(orchestrate): row reason-codes + recall_mode`.

### Task 2.4: Render reason-codes + data-generated caveats

**Files:** Modify `sigmaforge/report/render.py`; Test `tests/test_render.py`.

- [ ] **Step 1 — failing test.** An unmeasured row renders with its inline reason (e.g. `unmeasured (technique-0-events)`); a caveat block is generated from passed data (corpus SHAs, floor) not a hardcoded string.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.** In `render_report`, when recall/precision is `"unmeasured"`, append the row's `recall_reason`/`precision_reason` inline. Add a `caveats: dict` param (floor, recommended_floor, corpus path-form split if provided) and render it; the run7 caller passes its path-form data via this param instead of the script header string.
- [ ] **Step 4 — run, expect PASS; re-run C1 gate (cosmetic .md change OK; aggregates/run_hash unchanged).**
- [ ] **Step 5 — commit** `feat(render): inline unmeasured reasons + data-generated caveats`.

### Task 2.5: Wire `sigmaforge backtest`, drop `classify`

**Files:** Modify `sigmaforge/main.py`; remove `classify` + `sigmaforge/detect.py` + `tests/test_detect.py` + the classify case in `tests/test_cli.py`; Test additions in `tests/test_cli.py`.

- [ ] **Step 1 — failing tests (CliRunner, width-safe per existing helper).**
```python
# tests/test_cli.py (replace classify tests)
from typer.testing import CliRunner
from sigmaforge.main import app

def test_classify_removed():
    assert CliRunner().invoke(app, ["classify", "x"]).exit_code != 0

def test_backtest_missing_corpus_is_teaching_error_not_traceback(tmp_path, monkeypatch):
    # no corpora configured -> exit 4, guidance text, no traceback
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    res = CliRunner().invoke(app, ["backtest", "--rules", str(tmp_path)])
    assert res.exit_code == 4
    assert "corpus" in res.output.lower() and "hunt" in res.output.lower()
    assert "Traceback" not in res.output
```
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.** Remove `classify` (+ `detect.py`, `test_detect.py`). New `backtest(rules, config, out, floor)` command: load config (`config.load(...)`), resolve effective corpus/engine paths (flags > config > None), **preflight** — engine resolvable (`Zircolite/zircolite.py` under `engine_home`/SIGMAFORGE_HOME) else `raise typer.Exit(3)` with a teaching message; attack/benign corpus + technique map present else `typer.Exit(4)` naming `scripts/setup_engine.sh` + corpus build + "use `sigmaforge hunt`". Resolve the `config.BacktestConfig` into a `pipeline.PipelineConfig`, call `run_backtest_pipeline`, write report+manifest, print summary. If `recall_mode == "pooled"` → refuse with `typer.Exit(4)` (never silently pool). Exit `5` if a gate FAILs.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — full suite + ruff + commit** `feat(cli): real backtest command (config+pipeline, preflight exit codes); drop classify`.

**C2 Skeptic gate:** numeric metrics still match the C1 gate; reason-codes net-new + threaded; recall_mode set + pooled refused; teaching errors exit 3/4 without traceback; classify gone; no repo-data path baked into pip defaults.

---

# C3 — `hunt` command

### Task 3.1: Importable `compile_ruleset`

**Files:** Create `sigmaforge/ingest/compile.py` (or add to `ingest/ruleload.py`); Modify `scripts/compile_loaded_ruleset.py` to import it; Test `tests/test_compile.py`.

- [ ] **Step 1 — failing test.** `from sigmaforge.ingest.compile import compile_ruleset` ; compiling the smoke fixture rule (`data/fixtures/smoke/rules/`) returns a 1-rule ruleset titled "Smoke PowerShell". (skipif engine absent — needs pySigma from the engine reqs.)
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.** Move `compile_ruleset(paths: list[Path]) -> tuple[list[dict], int]` from `scripts/compile_loaded_ruleset.py` into `sigmaforge/ingest/compile.py`; have the script import it. Same Zircolite pySigma backend, one source.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit** `refactor(ingest): make compile_ruleset importable (shared compile path)`.

### Task 3.2: `sigmaforge hunt`

**Files:** Modify `sigmaforge/main.py`; Test `tests/test_cli.py`.

- [ ] **Step 1 — failing test.** `hunt --rules <fixture> --logs <fixture benign.jsonl>` exits 0, output carries the "hits only — NOT a quality measurement" banner and every quality field reads `unmeasured: no labeled corpus`; with engine absent → exit 3 teaching error.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** `hunt(rules, logs, out, config)`: preflight engine (exit 3); compile rules (Task 3.1) → `run_shard` over logs (detect EVTX vs JSON) → collect hits (rule_id, event_id, count). Write `hits.json` with a top-level `"precision": "unmeasured — unlabeled corpus"` + `"recall": "unmeasured — unlabeled corpus"` and the banner; print the banner to stdout. Exit 0.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit** `feat(cli): hunt command (rules x arbitrary logs -> hits only, unmeasured)`.

### Task 3.3: e2e smoke for both verbs

**Files:** Modify `tests/test_smoke_pipeline.py`.

- [ ] **Step 1 — add tests (skipif engine absent).** (a) `hunt` on `data/fixtures/smoke/` runs clean → asserts the powershell hit + the unmeasured banner; (b) `backtest` on the benign-only fixture → exit 4 teaching error (no attack corpus). Optionally add a tiny attack fixture (wrapped `<Events>` EID-1 XML + 1-entry technique map) to smoke a measured `backtest` → assert a report is written; defer if time-boxed.
- [ ] **Step 2 — run** (`uv run pytest tests/test_smoke_pipeline.py -v`) → PASS (or skip without engine).
- [ ] **Step 3 — full suite + ruff + commit** `test(smoke): drive hunt (clean) + backtest (teaching-error) on fixtures`.

**C3 Skeptic gate:** hunt is pip-only-correct (engine only, no corpora); unmeasured is structural not absent; compile path shared with backtest; smoke covers both verbs + skips cleanly without the engine.

---

## Final review
After C3: dispatch a final Skeptic over the whole CLI — `--help` leads with the one-line contrast; `sigmaforge backtest` with nothing configured teaches (exit 4) not crashes; `hunt` works after a clean `pip install` + `setup_engine.sh`; the README "Reproduce a backtest" section updated to use the verbs. Then a release (`feat:` → release-please minor) ships the pyyaml fix + the CLI.

## Deferred (named, NOT this plan)
Per-FP benign witness events in the report; verb-level `--json` + `ci-gate`/`diff`/`badge`; full run4–6 migration to the pipeline.
