import hashlib
import json
import os
import subprocess
import tempfile

from sigmaforge.records import MatchRecord

# The Zircolite engine is NOT bundled with the pip package (large third-party tool).
# Both the invocation and its working directory are configurable so a clone/install on
# any machine works — no hardcoded path. SIGMAFORGE_HOME is the dir that CONTAINS the
# `Zircolite/` checkout (defaults to the current working directory, which is the repo
# root when the run scripts are launched from there). SIGMAFORGE_ZIRCOLITE overrides the
# engine command (e.g. to point at a system install).
ZIRCOLITE = os.environ.get("SIGMAFORGE_ZIRCOLITE", "uv run python Zircolite/zircolite.py").split()


def _zircolite_home() -> str:
    """Working dir for the engine subprocess: SIGMAFORGE_HOME or the current dir."""
    return os.environ.get("SIGMAFORGE_HOME", os.getcwd())


def _stable_event_id(row: dict) -> str:
    """Globally-unique event key (fix C). EventRecordID is a PER-EVTX-FILE counter, so using it
    alone collapses record 42 of fileA with record 42 of fileB across a multi-file attack run and
    silently deflates recall. Hash the whole flattened row instead: it carries Computer/UtcTime/
    Image/CommandLine/... which differ across files even when EventRecordID repeats. Two genuinely
    identical events still hash-collapse — that is correct dedup, not a collision bug.
    (On real data each row also carries Zircolite's autoincrement `row_id`, globally unique
    across a single multi-file run, so real events never over-split. NB: if `--parallel`
    ingestion is ever enabled, `row_id` resets per chunk — uniqueness then rests on the
    content fields, UtcTime/ProcessGuid/etc., which the whole-row hash already includes.)"""
    canonical = json.dumps(row, sort_keys=True, default=str)
    return hashlib.sha1(canonical.encode()).hexdigest()


def parse_detections(
    detections: list[dict],
    corpus_label: str | None = None,
    file_technique_map: dict[str, str] | None = None,
    event_technique_out: dict[str, str] | None = None,
) -> list[MatchRecord]:
    """Parse Zircolite detections into MatchRecords.

    FIX B: when ``file_technique_map`` (source-EVTX basename -> ATT&CK technique) and
    ``event_technique_out`` are supplied, also populate ``event_technique_out`` mapping
    each fired event's ``event_id`` -> its ground-truth technique. The technique is keyed
    on the SAME identity the engine emits (``_stable_event_id``), so a fire and its
    technique join correctly downstream. The source file is read from each match row's
    ``OriginalLogfile`` (the EVTX basename, set by Zircolite's streaming flattener)."""
    out: list[MatchRecord] = []
    for d in detections:
        for m in d.get("matches", []):
            # benign COMISET rows carry the injected hash; native-EVTX rows do NOT -> derive a
            # globally-unique key from the row (NOT bare EventRecordID, which collides across files).
            eid = m.get("sigmaforge_eid") or _stable_event_id(m)
            label = m.get("sigmaforge_label") or corpus_label or "benign"
            out.append(MatchRecord(rule_id=d["title"], event_id=str(eid), event_label=label))
            if file_technique_map is not None and event_technique_out is not None:
                src = m.get("OriginalLogfile")
                tech = file_technique_map.get(src) if src else None
                if tech:
                    event_technique_out[str(eid)] = tech
    return out


def run_shard(
    events_path: str,
    ruleset_glob: str,
    mapping_path: str | None = None,
    json_input: bool = True,
    xml_input: bool = False,
    corpus_label: str | None = None,
    file_technique_map: dict[str, str] | None = None,
    event_technique_out: dict[str, str] | None = None,
) -> list[MatchRecord]:
    """Run Zircolite over a shard and parse detections.

    FIX B: pass ``file_technique_map`` + ``event_technique_out`` to also harvest the
    per-event ground-truth technique (see ``parse_detections``).

    FIX B3: ``xml_input=True`` ingests EVTX-converted-to-XML files (one wrapped
    ``<Events>...</Events>`` document per file, Zircolite ``--xml-input``). Like the
    native-EVTX path, each event's ``OriginalLogfile`` is set to the .xml basename,
    so the same ``file_technique_map`` (basename -> (sub-)technique) recall join
    applies. ``json_input`` and ``xml_input`` are mutually exclusive."""
    if json_input and xml_input:
        raise ValueError("json_input and xml_input are mutually exclusive")
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    cmd = [*ZIRCOLITE, "--events", events_path, "--ruleset", ruleset_glob, "--outfile", out]
    if json_input:
        cmd += ["--json-input"]
    if xml_input:
        cmd += ["--xml-input"]
    if mapping_path:
        cmd += ["--config", mapping_path]
    subprocess.run(cmd, check=True, cwd=_zircolite_home())
    with open(out) as fh:
        return parse_detections(
            json.load(fh),
            corpus_label=corpus_label,
            file_technique_map=file_technique_map,
            event_technique_out=event_technique_out,
        )
