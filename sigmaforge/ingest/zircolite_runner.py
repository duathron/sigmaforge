import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from sigmaforge.engine import engine_script, require_engine_home
from sigmaforge.records import MatchRecord

# The Zircolite engine is NOT bundled with the pip package (large third-party tool). Its
# root (the dir that CONTAINS `Zircolite/`) comes from the caller (`engine_home`) or
# $SIGMAFORGE_HOME — never from the current directory (see sigmaforge.engine).
# SIGMAFORGE_ZIRCOLITE replaces ONLY the interpreter prefix of the engine command
# (default: the interpreter running sigmaforge); the absolute engine script path is always
# appended. Setting it is an explicit trust decision about your environment.


class EngineRunError(RuntimeError):
    """The engine process failed; the message carries a short, UNSANITIZED stderr tail."""


def _engine_cmd() -> list[str]:
    """Interpreter prefix of the engine command, built at call time (no import-time state)."""
    override = os.environ.get("SIGMAFORGE_ZIRCOLITE")
    return override.split() if override else [sys.executable]


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
    engine_home: str | Path | None = None,
) -> list[MatchRecord]:
    """Run Zircolite over a shard and parse detections.

    FIX B: pass ``file_technique_map`` + ``event_technique_out`` to also harvest the
    per-event ground-truth technique (see ``parse_detections``).

    FIX B3: ``xml_input=True`` ingests EVTX-converted-to-XML files (one wrapped
    ``<Events>...</Events>`` document per file, Zircolite ``--xml-input``). Like the
    native-EVTX path, each event's ``OriginalLogfile`` is set to the .xml basename,
    so the same ``file_technique_map`` (basename -> (sub-)technique) recall join
    applies. ``json_input`` and ``xml_input`` are mutually exclusive.

    ``engine_home`` (else $SIGMAFORGE_HOME) names the engine root; there is no CWD fallback.
    The engine runs with ``cwd=<engine home>``, so caller paths are made absolute first."""
    if json_input and xml_input:
        raise ValueError("json_input and xml_input are mutually exclusive")
    home = require_engine_home(engine_home)
    events_path = os.path.abspath(events_path)
    ruleset_glob = os.path.abspath(ruleset_glob)
    if mapping_path:
        mapping_path = os.path.abspath(mapping_path)
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    cmd = [*_engine_cmd(), str(engine_script(home)), "--events", events_path, "--ruleset", ruleset_glob]
    cmd += ["--outfile", out]
    if json_input:
        cmd += ["--json-input"]
    if xml_input:
        cmd += ["--xml-input"]
    if mapping_path:
        cmd += ["--config", mapping_path]
    # The engine echoes rule titles (attacker text) to its own stdout/stderr: capture both so
    # raw terminal escapes / Rich markup never reach the user's tty. Nothing is streamed on
    # success; on failure only a short tail of stderr is surfaced (sanitized by the CLI).
    try:
        subprocess.run(cmd, check=True, cwd=str(home), capture_output=True, text=True, errors="replace")
    except subprocess.CalledProcessError as e:
        tail = "\n".join((e.stderr or "").strip().splitlines()[-5:])[-600:]
        raise EngineRunError(f"engine exited with status {e.returncode}: {tail}") from None
    with open(out) as fh:
        return parse_detections(
            json.load(fh),
            corpus_label=corpus_label,
            file_technique_map=file_technique_map,
            event_technique_out=event_technique_out,
        )
