import hashlib
import json
import subprocess
import tempfile

from sigmaforge.records import MatchRecord

ZIRCOLITE = ["uv", "run", "python", "Zircolite/zircolite.py"]  # vendored 3.7.6


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


def parse_detections(detections: list[dict], corpus_label: str | None = None) -> list[MatchRecord]:
    out: list[MatchRecord] = []
    for d in detections:
        for m in d.get("matches", []):
            # benign COMISET rows carry the injected hash; native-EVTX rows do NOT -> derive a
            # globally-unique key from the row (NOT bare EventRecordID, which collides across files).
            eid = m.get("sigmaforge_eid") or _stable_event_id(m)
            label = m.get("sigmaforge_label") or corpus_label or "benign"
            out.append(MatchRecord(rule_id=d["title"], event_id=str(eid), event_label=label))
    return out


def run_shard(
    events_path: str,
    ruleset_glob: str,
    mapping_path: str | None = None,
    json_input: bool = True,
    corpus_label: str | None = None,
) -> list[MatchRecord]:
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    cmd = [*ZIRCOLITE, "--events", events_path, "--ruleset", ruleset_glob, "--outfile", out]
    if json_input:
        cmd += ["--json-input"]
    if mapping_path:
        cmd += ["--config", mapping_path]
    subprocess.run(cmd, check=True, cwd="/Users/christianhuhn/PycharmProjects/ai_project1/sigmaforge")
    with open(out) as fh:
        return parse_detections(json.load(fh), corpus_label=corpus_label)
