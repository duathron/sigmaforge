def _is_stateful(rule: dict) -> bool:
    if "correlation" in rule:
        return True
    cond = str(rule.get("detection", {}).get("condition", ""))
    return any(tok in cond for tok in ("count(", "sum(", "avg(", "| near", "temporal"))


def select_by_level(rules: list[dict], levels: tuple[str, ...]) -> list[dict]:
    return [r for r in rules if str(r.get("level", "")).lower() in levels]


def partition_rules(rules: list[dict], levels: tuple[str, ...] = ("high", "critical")) -> tuple[list[dict], list[dict]]:
    in_scope = select_by_level(rules, levels)
    loaded = [r for r in in_scope if not _is_stateful(r)]
    excluded = [r for r in in_scope if _is_stateful(r)]
    return loaded, excluded


class RuleLoadError(ValueError):
    """A rule file could not be read or parsed. `path` is the offending file (untrusted text:
    sanitize at the sink); the message is value-free (no YAML snippet, which echoes rule text)."""

    def __init__(self, path: str, reason: str):
        super().__init__(reason)
        self.path = path
