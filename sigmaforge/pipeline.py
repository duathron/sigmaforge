"""The extracted, reusable backtest pipeline.

`run_backtest_pipeline(cfg)` is the corpus-AGNOSTIC glue lifted from
`scripts/run7_backtest.py::main`: compile/load the ruleset, run the engine over
the attack corpus (recall) and the benign corpus (precision), run the acceptance
gate, score via `orchestrate.run_backtest`, build the generic manifest body, and
render the generic report body. It computes everything a caller needs to rebuild
a run-specific header (the acceptance-gate rows, event counts, measurable counts,
the run hash, the firing rows) WITHOUT inlining any run-specific prose: any
run7/OpTC-specific caveat (e.g. the OpTC Image path-form split) is computed by the
CALLER from the corpus it owns and injected via the report renderer / manifest
merge.

`PipelineConfig` is the pipeline's resolved input dataclass — distinct from the
user-facing `config.BacktestConfig` YAML block; the CLI resolves the latter into
the former.
"""

from __future__ import annotations

import glob
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from sigmaforge import safe_yaml
from sigmaforge.ingest.ruleload import RuleLoadError, partition_rules
from sigmaforge.ingest.zircolite_runner import run_shard
from sigmaforge.orchestrate import run_backtest
from sigmaforge.provenance import provenance
from sigmaforge.records import MatchRecord
from sigmaforge.runmanifest import build_manifest, run_hash
from sigmaforge.safe_read import ReadRefused, iter_lines_capped, open_regular, read_capped
from sigmaforge.score.acceptance import GateResult, assert_one_source
from sigmaforge.score.recall import rule_techniques


@dataclass(frozen=True)
class PipelineConfig:
    """Resolved inputs for one backtest run. Module constants the run7 script used
    to hardcode become these fields; the CLI resolves `config.BacktestConfig` into
    this."""

    compiled_ruleset: str  # path to the compiled-from-loaded ruleset JSON
    loaded_rules_glob: str  # glob of the loaded source .yml rules (recall titles)
    attack_corpus: str  # native-EVTX attack corpus dir (recall)
    technique_map: str  # attack_data technique map JSON
    benign_sample: str  # benign corpus JSONL (precision)
    comiset_mapping: str  # COMISET _source -> Sigma field mapping YAML
    evtx_cfg: str  # Zircolite EVTX field-mapping config
    min_events: int = 1000
    source: str = "COMISET"
    engine_home: str | None = None  # engine root; None -> $SIGMAFORGE_HOME (never the cwd)


@dataclass
class BacktestResult:
    """Everything a caller needs to rebuild a run-specific header WITHOUT the
    pipeline inlining prose. `funnel` carries `recall_mode`."""

    rows: list[dict]
    funnel: dict
    manifest: dict
    report_md: str
    run_hash: str
    # COMPUTED provenance the run7 header embeds today:
    acceptance_gate: list[GateResult]  # attack/benign engine/scored/dropped/ok rows
    n_attack_events: int
    technique_event_counts: dict[str, int]
    rules_recall_measurable: int
    rules_precision_measurable: int
    loaded_rule_count: int


def _sha256_file(path: str | Path, cap: int, what: str) -> str:
    """SHA-256 of a regular file of at most `cap` bytes, streamed through the safe reader."""
    h = hashlib.sha256()
    try:
        with open_regular(path, cap) as fh:
            seen = 0
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                seen += len(chunk)
                if seen > cap:
                    raise ReadRefused("too large")
                h.update(chunk)
    except ReadRefused as e:
        raise InputLoadError(path, what, e.reason) from None
    except OSError:
        raise InputLoadError(path, what, "unreadable") from None
    return h.hexdigest()


#: Size caps per user-supplied input (refused as "too large" beyond these).
#: A parsed document costs memory far beyond its bytes (a 100 MB benign sample is ~1.2 GB of dicts,
#: nested empty lists ~25x), so the byte caps are sized to the real data with ample headroom: the
#: largest real benign sample has 97,400 events, technique maps are kilobytes.
TECHNIQUE_MAP_MAX_BYTES = 8 * 1024 * 1024
COMISET_MAPPING_MAX_BYTES = 1024 * 1024
BENIGN_SAMPLE_MAX_BYTES = 256 * 1024 * 1024
BENIGN_SAMPLE_MAX_EVENTS = 500_000  # scripts/build_benign_sample.py scans at most 5M raw lines (EID-1 subset)
RULE_FILE_MAX_BYTES = 1024 * 1024
RULESET_HASH_MAX_BYTES = 64 * 1024 * 1024
BENIGN_LINE_MAX_BYTES = 1024 * 1024  # real events are a few KB
#: Rule loading budget (the SigmaHQ corpus is ~3,000 files, a few MB, well under 1M YAML nodes).
MAX_RULE_FILES = 20_000
RULES_MAX_TOTAL_BYTES = 64 * 1024 * 1024
RULE_FILE_MAX_NODES = 100_000
RULES_MAX_TOTAL_NODES = 2_000_000


class InputLoadError(ValueError):
    """A user-supplied non-rule input (technique map, benign sample, COMISET mapping) could not be
    read or parsed. `path` is the offending file (untrusted text: sanitize at the sink); `what`
    names the input; the message is value-free (no JSON/YAML snippet, no line content)."""

    def __init__(self, path: object, what: str, reason: str):
        super().__init__(reason)
        self.path = path
        self.what = what


def _limit_error(path: object, what: str, e: BaseException) -> InputLoadError:
    """Depth, size or int-conversion limits hit while parsing (value-free reason)."""
    if isinstance(e, RecursionError):
        return InputLoadError(path, what, "too deeply nested")
    return InputLoadError(path, what, "value out of range")


def _is_int(x: object) -> bool:
    """A count: an int (not a bool) that is not negative."""
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _tmap_ok(tmap: object) -> bool:
    if not isinstance(tmap, dict):
        return False
    counts, files, total = tmap.get("technique_event_counts"), tmap.get("file_technique"), tmap.get("total_pc")
    return (
        isinstance(counts, dict)
        and all(isinstance(k, str) and _is_int(v) for k, v in counts.items())
        and isinstance(files, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in files.items())
        and _is_int(total)
    )


def _load_technique_map(path: str) -> dict:
    what = "technique map"
    try:
        tmap = json.loads(read_capped(path, TECHNIQUE_MAP_MAX_BYTES).decode("utf-8"))
    except ReadRefused as e:
        raise InputLoadError(path, what, e.reason) from None
    except json.JSONDecodeError:
        raise InputLoadError(path, what, "invalid JSON") from None
    except UnicodeDecodeError:
        raise InputLoadError(path, what, "unreadable") from None
    except (RecursionError, ValueError) as e:
        raise _limit_error(path, what, e) from None
    except Exception:
        raise InputLoadError(path, what, "malformed structure") from None
    try:
        ok = _tmap_ok(tmap)
    except Exception:
        ok = False
    if not ok:
        raise InputLoadError(path, what, "malformed structure")
    return tmap


def _load_comiset_field_map(comiset_mapping: str) -> dict[str, str]:
    what = "COMISET mapping"
    try:
        cfg = safe_yaml.load(read_capped(comiset_mapping, COMISET_MAPPING_MAX_BYTES).decode("utf-8"))
    except ReadRefused as e:
        raise InputLoadError(comiset_mapping, what, e.reason) from None
    except safe_yaml.YamlAliasError:
        raise InputLoadError(comiset_mapping, what, "YAML aliases are not allowed") from None
    except yaml.YAMLError:
        raise InputLoadError(comiset_mapping, what, "invalid YAML") from None
    except UnicodeDecodeError:
        raise InputLoadError(comiset_mapping, what, "unreadable") from None
    except (RecursionError, ValueError) as e:
        raise _limit_error(comiset_mapping, what, e) from None
    except Exception:
        raise InputLoadError(comiset_mapping, what, "malformed structure") from None
    mappings = cfg.get("mappings") if isinstance(cfg, dict) else None
    if not isinstance(cfg, dict) or not (mappings is None or isinstance(mappings, dict)):
        raise InputLoadError(comiset_mapping, what, "malformed structure")
    out = {}
    for raw, sigma in (mappings or {}).items():
        if not isinstance(raw, str) or not isinstance(sigma, str):
            raise InputLoadError(comiset_mapping, what, "malformed structure")
        if raw.startswith("_source."):
            out[raw[len("_source.") :]] = sigma
    return out


def _load_benign_sample(path: str, field_map: dict[str, str]) -> list[dict]:
    what = "benign sample"
    events: list[dict] = []
    try:
        for raw in iter_lines_capped(path, BENIGN_SAMPLE_MAX_BYTES, BENIGN_LINE_MAX_BYTES):
            try:
                doc = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise InputLoadError(path, what, "unreadable") from None
            except json.JSONDecodeError:
                raise InputLoadError(path, what, "invalid JSON on a line") from None
            except (RecursionError, ValueError) as e:  # nesting / int-conversion limits
                raise _limit_error(path, what, e) from None
            src = doc.get("_source", {}) if isinstance(doc, dict) else None
            if not isinstance(src, dict) or not isinstance(src.get("sigmaforge_label", "benign"), str):
                raise InputLoadError(path, what, "malformed line (not an object with an object _source)")
            ev = _project_event(src, field_map)
            ev["sigmaforge_label"] = src.get("sigmaforge_label", "benign")
            events.append(ev)
            if len(events) > BENIGN_SAMPLE_MAX_EVENTS:
                raise InputLoadError(path, what, "too many events")
    except InputLoadError:
        raise
    except ReadRefused as e:
        raise InputLoadError(path, what, e.reason) from None
    except Exception:
        raise InputLoadError(path, what, "malformed structure") from None
    return events


def _project_event(src: dict, field_map: dict[str, str]) -> dict:
    ev = {}
    for k, v in src.items():
        ev[field_map.get(k, k)] = v
    return ev


def _count_json_nodes(root: object, limit: int) -> int:
    """Nodes of a parsed JSON value (containers, dict keys, scalars), iteratively (no recursion).
    Stops counting just past `limit`."""
    n = 0
    stack = [root]
    while stack:
        n += 1
        if n > limit:
            return n
        x = stack.pop()
        if isinstance(x, dict):
            n += len(x)  # the keys
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return n


def _check_rule_fields(path: str, rule: dict) -> None:
    """The fields later stages index into, for rules that are in scope (level high/critical): a bad
    shape is one value-free refusal here instead of a KeyError/TypeError deep in the run."""
    if str(rule.get("level", "")).lower() not in ("high", "critical"):
        return
    title, tags, detection = rule.get("title"), rule.get("tags"), rule.get("detection", {})
    if (
        not isinstance(title, str)
        or not title
        or not (tags is None or (isinstance(tags, list) and all(isinstance(t, str) for t in tags)))
        or not isinstance(detection, dict)
    ):
        raise RuleLoadError(path, "malformed rule structure")


def _load_loaded_rules(loaded_rules_glob: str) -> list[dict]:
    rules = []
    files = glob.glob(loaded_rules_glob)
    if len(files) > MAX_RULE_FILES:
        raise RuleLoadError(loaded_rules_glob, "too many rule files")
    total_bytes = total_nodes = 0
    for f in files:
        try:
            # a compiled ruleset (.json, passed as --rules) is far larger than one Sigma YAML rule
            cap = RULESET_HASH_MAX_BYTES if f.lower().endswith(".json") else RULE_FILE_MAX_BYTES
            raw = read_capped(f, cap)
            total_bytes += len(raw)
            if total_bytes > RULES_MAX_TOTAL_BYTES:
                raise RuleLoadError(loaded_rules_glob, "rule files too large in total")
            if f.lower().endswith(".json"):
                # a compiled ruleset: parsed by the C JSON parser (never the pure-Python YAML one), and a
                # file that is not valid JSON is refused, not retried as YAML
                # a compiled ruleset is one big file: it gets the whole remaining budget
                budget = RULES_MAX_TOTAL_NODES - total_nodes
                # cheap upper-bound check BEFORE parsing: every container opens with [ or {, so a
                # file of millions of nested empty lists is refused without allocating them
                if raw.count(b"[") + raw.count(b"{") > max(budget, 0):
                    raise RuleLoadError(f, "too many JSON nodes")
                top = json.loads(raw.decode("utf-8"))
                nodes = _count_json_nodes(top, max(budget, 0))
                if nodes > max(budget, 0):
                    raise RuleLoadError(f, "too many JSON nodes")
                total_nodes += nodes
                docs = top if isinstance(top, list) else [top]
            else:
                budget = min(RULE_FILE_MAX_NODES, RULES_MAX_TOTAL_NODES - total_nodes)
                docs, nodes = safe_yaml.load_all(raw.decode("utf-8"), max_nodes=max(budget, 0))
                total_nodes += nodes
            for doc in docs:
                if not doc:
                    continue
                if not isinstance(doc, dict):  # a Sigma rule is a mapping: refuse before any deep walk
                    raise RuleLoadError(f, "malformed rule structure")
                _check_rule_fields(f, doc)
                rules.append(doc)
        except ReadRefused as e:
            raise RuleLoadError(f, e.reason) from None
        except safe_yaml.YamlAliasError:
            raise RuleLoadError(f, "YAML aliases are not allowed") from None
        except safe_yaml.YamlTooComplexError:
            raise RuleLoadError(f, "too many YAML nodes") from None
        except yaml.YAMLError:
            raise RuleLoadError(f, "invalid YAML") from None
        except json.JSONDecodeError:
            raise RuleLoadError(f, "invalid JSON") from None
        except RecursionError:
            raise RuleLoadError(f, "too deeply nested") from None
        except RuleLoadError:
            raise
        except (OSError, ValueError):  # unreadable, or not valid text
            raise RuleLoadError(f, "unreadable") from None
        except Exception:  # whatever else a hostile document makes a parser raise: never echo it
            raise RuleLoadError(f, "unreadable") from None
    try:
        loaded, _ = partition_rules(rules)
    except Exception:
        raise RuleLoadError(loaded_rules_glob, "malformed rule structure") from None
    return loaded


def run_backtest_pipeline(cfg: PipelineConfig) -> BacktestResult:
    """The lifted body of run7_backtest.main, corpus-agnostic, module constants
    replaced by cfg.*."""
    loaded = _load_loaded_rules(cfg.loaded_rules_glob)
    loaded_titles = {r["title"] for r in loaded}
    n_tagged = sum(1 for r in loaded if rule_techniques(r))

    # Parse every user-supplied non-rule input BEFORE the engine passes: a broken file is refused
    # up front as one clean error instead of after minutes of engine work.
    tmap = _load_technique_map(cfg.technique_map)
    field_map = _load_comiset_field_map(cfg.comiset_mapping)
    benign_events = _load_benign_sample(cfg.benign_sample, field_map)
    technique_event_counts = tmap["technique_event_counts"]
    file_technique = tmap["file_technique"]
    n_pc = tmap["total_pc"]

    # --- Recall pass — native-EVTX attack corpus, per-technique ---
    event_technique: dict[str, str] = {}
    attack_fires = run_shard(
        cfg.attack_corpus,
        cfg.compiled_ruleset,
        mapping_path=cfg.evtx_cfg,
        json_input=False,
        xml_input=True,
        corpus_label="malicious",
        file_technique_map=file_technique,
        event_technique_out=event_technique,
        engine_home=cfg.engine_home,
    )

    # --- Precision pass — benign corpus, SAME one-source ruleset ---
    benign_fires = run_shard(
        cfg.benign_sample,
        cfg.compiled_ruleset,
        mapping_path=cfg.comiset_mapping,
        json_input=True,
        engine_home=cfg.engine_home,
    )

    n_mal = sum(1 for e in benign_events if e.get("sigmaforge_label") == "malicious")
    n_ben = len(benign_events) - n_mal

    pc_fired = any(f.event_label == "malicious" for f in benign_fires)

    set_attack: set[MatchRecord] = set(attack_fires)
    set_benign: set[MatchRecord] = set(benign_fires)
    gate = assert_one_source(loaded_titles, set_attack, set_benign)

    rows, funnel, report_md = run_backtest(
        loaded_rules=loaded,
        attack_fires=set_attack,
        benign_fires=set_benign,
        benign_events=benign_events,
        n_attack_events=n_pc,
        positive_control_fired=pc_fired,
        min_events=cfg.min_events,
        source=cfg.source,
        event_technique=event_technique,
        technique_event_counts=technique_event_counts,
    )

    n_measurable = sum(1 for r in rows if r["recall_measurable"])
    n_unmeasured = len(rows) - n_measurable
    prec_key = f"precision@{cfg.source}"
    n_prec_measurable = sum(1 for r in rows if isinstance(r.get(prec_key), float))

    rh = run_hash(set_attack | set_benign)

    # Generic, corpus-agnostic manifest body. The caller merges run-specific
    # provenance keys (corpus prose, OpTC slice/path-form provenance, etc.) onto
    # this before writing.
    manifest = build_manifest(
        recommended_precision_floor=max(200, int(0.10 * len(benign_events))),
        ruleset_path=str(cfg.compiled_ruleset),
        ruleset_sha=_sha256_file(cfg.compiled_ruleset, RULESET_HASH_MAX_BYTES, "ruleset"),
        loaded_rule_count=len(loaded),
        mapping_path=str(cfg.comiset_mapping),
        mapping_hash=_sha256_file(cfg.comiset_mapping, COMISET_MAPPING_MAX_BYTES, "COMISET mapping"),
        precision_floor=cfg.min_events,
        benign_corpus_path=str(cfg.benign_sample),
        benign_corpus_sha=_sha256_file(cfg.benign_sample, BENIGN_SAMPLE_MAX_BYTES, "benign sample"),
        benign_eid1_total=len(benign_events),
        benign_label_split={"benign": n_ben, "malicious": n_mal},
        attack_process_creation_events=n_pc,
        recall_technique_map=str(cfg.technique_map),
        recall_technique_map_sha=_sha256_file(cfg.technique_map, TECHNIQUE_MAP_MAX_BYTES, "technique map"),
        rules_with_technique_tag=n_tagged,
        rules_recall_measurable=n_measurable,
        rules_recall_unmeasured=n_unmeasured,
        rules_precision_measurable=n_prec_measurable,
        attack_fires=len(set_attack),
        benign_fires=len(set_benign),
        positive_control_fired=pc_fired,
        run_hash=rh,
        provenance=provenance(engine_home=cfg.engine_home),
    )

    return BacktestResult(
        rows=rows,
        funnel=funnel,
        manifest=manifest,
        report_md=report_md,
        run_hash=rh,
        acceptance_gate=gate,
        n_attack_events=n_pc,
        technique_event_counts=technique_event_counts,
        rules_recall_measurable=n_measurable,
        rules_precision_measurable=n_prec_measurable,
        loaded_rule_count=len(loaded),
    )
