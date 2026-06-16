import json
import subprocess
import tempfile

from sigmaforge.records import MatchRecord

ZIRCOLITE = ["uv", "run", "python", "Zircolite/zircolite.py"]  # vendored 3.7.6


def parse_detections(detections: list[dict], corpus_label: str | None = None) -> list[MatchRecord]:
    out: list[MatchRecord] = []
    for d in detections:
        for m in d.get("matches", []):
            eid = m.get("sigmaforge_eid") or m.get("EventRecordID")
            label = m.get("sigmaforge_label") or corpus_label or "benign"
            out.append(MatchRecord(rule_id=d["title"], event_id=str(eid), event_label=label))
    return out


def run_shard(events_path: str, ruleset_glob: str, mapping_path: str | None = None,
              json_input: bool = True, corpus_label: str | None = None) -> list[MatchRecord]:
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    cmd = [*ZIRCOLITE, "--events", events_path, "--ruleset", ruleset_glob, "--outfile", out]
    if json_input:
        cmd += ["--json-input"]
    if mapping_path:
        cmd += ["--config", mapping_path]
    subprocess.run(cmd, check=True, cwd="/Users/christianhuhn/PycharmProjects/ai_project1/sigmaforge")
    with open(out) as fh:
        return parse_detections(json.load(fh), corpus_label=corpus_label)
