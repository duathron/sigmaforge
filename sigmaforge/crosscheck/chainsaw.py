def compare_loaded_intersection(z_hits, c_hits, z_loaded, c_loaded) -> dict:
    """A6 cross-engine integrity: compare Zircolite vs Chainsaw ONLY over rules BOTH engines
    loaded. Rules only one engine loaded are a load artifact, reported separately — never as
    detection disagreement. z_hits/c_hits: dict[rule -> set[event_id]]."""
    both = z_loaded & c_loaded
    agree = {r for r in both if z_hits.get(r, set()) == c_hits.get(r, set())}
    return {
        "compared_rules": both,
        "agree": agree,
        "disagree": both - agree,
        "load_artifact_only": z_loaded ^ c_loaded,  # symmetric difference = load artifact
    }
