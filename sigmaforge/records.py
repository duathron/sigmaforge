from dataclasses import dataclass

@dataclass(frozen=True)
class MatchRecord:
    rule_id: str
    event_id: str
    event_label: str  # "benign" | "malicious"

@dataclass
class RuleScore:
    rule_id: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    events_evaluated: int = 0
