def events_evaluated_for_rule(events: list[dict], selection_fields: set[str]) -> int:
    """A2 coverage counter: how many events actually carry ALL of a rule's selection fields
    (present + non-empty). Distinguishes 'low FP' from 'rule never ran'."""
    return sum(1 for e in events if all(e.get(f) not in (None, "") for f in selection_fields))


def selection_fields(rule: dict) -> set[str]:
    """Extract the Sigma field names a rule's detection.selection* blocks reference.
    Field names may carry Sigma modifiers (e.g. 'CommandLine|contains') -> strip at the pipe."""
    fields: set[str] = set()
    detection = rule.get("detection", {})
    for key, block in detection.items():
        if key == "condition" or not isinstance(block, dict):
            continue
        for field in block:
            fields.add(str(field).split("|", 1)[0])
    return fields
